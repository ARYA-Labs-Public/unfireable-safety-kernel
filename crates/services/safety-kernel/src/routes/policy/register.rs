//! `POST /policy/module/register` — Slice 2 handler (ADR-018 §2.1).
//!
//! Order of operations (binding):
//!  1. Role check (`caller_role == "worker"`).
//!  2. Validate `required_patterns_regex_set` — count + length bounds
//!     per ADR-018 §5, then compile each pattern via `regex::Regex::new`.
//!  3. Build a `regex::RegexSet` with `dfa_size_limit(10 MiB)` to
//!     enforce the DFA-size cap.
//!  4. Capture `now` from the injected `Clock`.
//!  5. IPC: `op=policy_register` to the sidecar (it owns the `SQLite`
//!     `module_registry` table). On `conflict=true` ⇒ 409.
//!  6. Build `ModuleRegisterClaims`, sign via `sign_kernel_token`,
//!     compute `token_sha256`.
//!  7. Audit-append a `policy_register` entry (fail-OPEN — the signed
//!     receipt has already left the building).
//!  8. Respond 201 with the signed receipt envelope.

use std::collections::BTreeMap;

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use regex::{Regex, RegexSetBuilder};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::warn;

use qorch_adapters::policy_engine_client::{
    AuditAppendRequest, PolicyModuleRegisterRequest as IpcRegisterRequest,
};
use qorch_domain::safety::{
    params_fingerprint,
    policy::{
        is_valid_module_path, ModuleRegisterClaims, ModuleRegisterRequest,
        MODULE_PATH_INVALID_CHARSET_REASON, POLICY_REGISTER_ACTION, POLICY_REGISTER_AUD,
    },
    sign_kernel_token, stable_json, token_sha256, ToClaimsMap,
};

use crate::auth::CallerRole;
use crate::dto::ErrorResponse;
use crate::state::AppState;

/// ADR-018 §5 bounds — frozen with the handler.
const MAX_PATTERN_LENGTH_BYTES: usize = 512;
const MAX_PATTERNS_PER_MODULE: usize = 32;
const MAX_DFA_SIZE_BYTES: usize = 10 * 1024 * 1024;

/// Default register-receipt TTL — receipts are long-lived so operators
/// can verify them post-rotation. Configurable via env in slice 5+.
const REGISTER_TOKEN_TTL_S: f64 = 60.0;

/// Helper — error response shorthand.
fn deny(status: StatusCode, body: ErrorResponse) -> Response {
    (status, Json(body)).into_response()
}

/// Convert a `BTreeMap<String, Value>` to a `Value::Object` preserving
/// the sorted key order (matches the existing pattern in
/// `routes/authorize.rs::btree_to_value`).
fn btree_to_value(m: &BTreeMap<String, Value>) -> Value {
    let mut obj = serde_json::Map::with_capacity(m.len());
    for (k, v) in m {
        obj.insert(k.clone(), v.clone());
    }
    Value::Object(obj)
}

/// `POST /policy/module/register` — registers a module path + its
/// required-patterns regex set. Returns a signed receipt token the
/// caller can verify later against the kernel's public key.
///
/// Linear shape — each block ports one step from ADR-018 §2.1. Length
/// is the cost of binding the order against equivalence review.
#[allow(clippy::too_many_lines)]
pub async fn register(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerRole>,
    Json(body): Json<ModuleRegisterRequest>,
) -> Response {
    let caller_role = caller.0.as_str();

    // Step 1: role check.
    if caller_role != "worker" {
        return deny(
            StatusCode::FORBIDDEN,
            ErrorResponse::with_reason("forbidden", "caller_role_not_worker"),
        );
    }

    // Step 1b: canonical `module_path` charset validation (slice-3
    // PT-L1 fold-in, ADR-018 §2.5). Runs BEFORE any pattern
    // compilation or IPC — keeps the per-event work below the
    // validator the minimum needed to reject malformed input.
    if !is_valid_module_path(&body.module_path) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "invalid_request",
                "reason": MODULE_PATH_INVALID_CHARSET_REASON,
            })),
        )
            .into_response();
    }

    // Step 2a: count cap.
    if body.required_patterns_regex_set.len() > MAX_PATTERNS_PER_MODULE {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "invalid_request",
                "reason": format!("too_many_patterns:{}", body.required_patterns_regex_set.len()),
            })),
        )
            .into_response();
    }

    // Step 2b: per-pattern length cap + compile probe + ReDoS heuristic.
    //
    // The Rust `regex` crate is DFA-based and immune to catastrophic
    // backtracking, but the Python sidecar's `_evaluate_patterns` runs
    // `re.Pattern.search` on the hot path and IS vulnerable. To keep the
    // kernel/sidecar accept set in sync — and to fail-fast on the kernel
    // side rather than via a 503 from a hung sidecar — apply the same
    // nested-quantifier heuristic that the sidecar applies. Purple-team
    // finding ARY-2028-PT-C1 (2026-05-14).
    for (idx, pattern) in body.required_patterns_regex_set.iter().enumerate() {
        if pattern.len() > MAX_PATTERN_LENGTH_BYTES {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "ok": false,
                    "error": "invalid_request",
                    "reason": format!("pattern_too_long:{idx}"),
                })),
            )
                .into_response();
        }
        if has_nested_quantifier(pattern) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "ok": false,
                    "error": "invalid_request",
                    "reason": format!(
                        "regex_compile_failed:{idx}:regex_redos_nested_quantifier"
                    ),
                })),
            )
                .into_response();
        }
        if let Err(e) = Regex::new(pattern) {
            // Sanitize the error kind — regex-crate errors include
            // internal state we don't want to leak.
            let kind = error_kind(&e);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "ok": false,
                    "error": "invalid_request",
                    "reason": format!("regex_compile_failed:{idx}:{kind}"),
                })),
            )
                .into_response();
        }
    }

    // Step 3: DFA-size cap on the combined `RegexSet`.
    let set_build = RegexSetBuilder::new(&body.required_patterns_regex_set)
        .dfa_size_limit(MAX_DFA_SIZE_BYTES)
        .build();
    if let Err(e) = set_build {
        let kind = error_kind_from_setbuilder(&e);
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "invalid_request",
                "reason": format!("regex_dfa_too_large:{kind}"),
            })),
        )
            .into_response();
    }

    // Step 4: capture wall-clock entry time.
    let now = state.clock.now();

    // Step 5: IPC call to sidecar for the registry write.
    let ipc_req = IpcRegisterRequest {
        module_path: body.module_path.clone(),
        required_patterns_regex_set: body.required_patterns_regex_set.clone(),
        caller_subject: body.caller_subject.clone(),
    };
    let ipc_resp = match state.policy_client.policy_register(ipc_req).await {
        Ok(r) => r,
        Err(e) => {
            warn!(
                kind = e.kind(),
                detail = %e.detail(),
                "policy_register IPC failed — returning 503"
            );
            return deny(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorResponse::with_reason(
                    "kernel_unavailable",
                    format!("policy_error:{}", e.kind()),
                ),
            );
        }
    };

    if ipc_resp.conflict {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "error": "module_already_registered",
                "module_path": body.module_path,
                "registered_at_unix_ms": ipc_resp.registered_at_unix_ms,
            })),
        )
            .into_response();
    }

    // Step 6: build the signed receipt claims.
    let nonce = state.nonce.nonce_b64();
    let iss = build_iss(&state);

    // SHA-256 hex of stable_json({"patterns":[...]}) — binds the regex
    // set into the receipt without re-sending it.
    let patterns_fp = patterns_fingerprint(&body.required_patterns_regex_set);

    // params_fingerprint over the full register payload — required
    // claim slot per verify_kernel_token.
    let params_fp = params_fingerprint(&json!({
        "module_path": body.module_path,
        "required_patterns_regex_set": body.required_patterns_regex_set,
    }));

    let claims_struct = ModuleRegisterClaims {
        // PT-S2-M1 (ARY-2028 slice 5): mint with the canonical
        // policy/module/register audience tag. Same rationale as
        // policy/authorize — closes cross-tenant replay.
        aud: POLICY_REGISTER_AUD.to_string(),
        iss,
        iat: now,
        exp: now + REGISTER_TOKEN_TTL_S,
        subject: body.caller_subject.clone(),
        // register has no per-run context — use caller_subject per ADR.
        run_id: body.caller_subject.clone(),
        module_path: body.module_path.clone(),
        required_patterns_regex_set_fingerprint: patterns_fp,
        registered_at_unix_ms: ipc_resp.registered_at_unix_ms,
        params_fingerprint: params_fp,
        nonce,
    };
    let token = sign_kernel_token(&claims_struct, state.signing_key.as_ref());
    let tok_sha = token_sha256(&token);
    let claims_map = claims_struct.to_btreemap();

    // Step 7: audit append (fail-OPEN per the existing pattern).
    let audit_payload = json!({
        "request": {
            "module_path": body.module_path,
            "required_patterns_regex_set": body.required_patterns_regex_set,
            "caller_subject": body.caller_subject,
            "caller_role": caller_role,
        },
        "decision": {
            "allowed": true,
            "reason": "registered",
            "metadata": {
                "registered_at_unix_ms": ipc_resp.registered_at_unix_ms,
                "action": POLICY_REGISTER_ACTION,
            },
        },
        "token_sha256": tok_sha,
        "claims": btree_to_value(&claims_map),
    });
    let audit_req = AuditAppendRequest {
        unit_id: "safety_kernel".to_string(),
        action_name: "policy_register".to_string(),
        payload: audit_payload,
        success: true,
        error: None,
        started_at: now,
        ended_at: state.clock.now(),
    };
    if let Err(e) = state.policy_client.audit_append(audit_req).await {
        warn!(
            kind = e.kind(),
            detail = %e.detail(),
            "audit_append failed on policy_register (fail-open: continuing)"
        );
    }

    // Step 8: 201 Created.
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "module_path": body.module_path,
            "registered_at_unix_ms": ipc_resp.registered_at_unix_ms,
            "token": token,
            "token_sha256": tok_sha,
            "claims": btree_to_value(&claims_map),
        })),
    )
        .into_response()
}

/// Stable kind string for a `regex::Error`. We do NOT echo the full
/// inner detail — the regex crate's error strings can carry internal
/// state. We map the variants to a small stable set so the wire
/// reason is predictable.
fn error_kind(e: &regex::Error) -> &'static str {
    match e {
        regex::Error::Syntax(_) => "Syntax",
        regex::Error::CompiledTooBig(_) => "CompiledTooBig",
        _ => "Other",
    }
}

/// Detect a nested-quantifier ReDoS pattern: a parenthesized group
/// whose body contains either an unbounded quantifier (`+`/`*`) or a
/// top-level alternation (`|`), AND whose closing paren is immediately
/// followed by another quantifier (`+`, `*`, or `{n,...}`).
///
/// This is the same heuristic the Python sidecar applies in
/// `apps/safety_kernel/policy_module_registry.py::_NESTED_QUANTIFIER_REGEX`.
/// Pre-rejecting in the Rust kernel keeps the kernel/sidecar accept set
/// in sync and avoids a misleading 503 when the sidecar would reject
/// what Rust accepted.
///
/// Linear single-pass scan, O(n) in the (≤512-byte) pattern length.
/// We track top-level paren depth and look for `\(` that contains a
/// vulnerable construct + is followed by a quantifier.
#[allow(clippy::doc_markdown, clippy::match_same_arms)]
fn has_nested_quantifier(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip escaped characters (don't count `\(` as a real paren).
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'(' {
            // Find the matching close, skipping nested parens. Track
            // whether the body contains `+`, `*`, or top-level `|`.
            let mut depth: i32 = 1;
            let mut j = i + 1;
            let mut has_vuln = false;
            while j < bytes.len() && depth > 0 {
                if bytes[j] == b'\\' {
                    j += 2;
                    continue;
                }
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    b'+' | b'*' if depth == 1 => has_vuln = true,
                    b'|' if depth == 1 => has_vuln = true,
                    _ => {}
                }
                if depth == 0 {
                    break;
                }
                j += 1;
            }
            if depth == 0 && has_vuln {
                // Check what's immediately after the close paren.
                let after = j + 1;
                if after < bytes.len() {
                    match bytes[after] {
                        b'+' | b'*' => return true,
                        b'{' => {
                            // `{N,...}` form. Find `}` and require a comma.
                            let mut k = after + 1;
                            let mut has_comma = false;
                            while k < bytes.len() && bytes[k] != b'}' {
                                if bytes[k] == b',' {
                                    has_comma = true;
                                }
                                k += 1;
                            }
                            if k < bytes.len() && has_comma {
                                return true;
                            }
                        }
                        _ => {}
                    }
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    false
}

/// Same mapping for set-builder errors (a `RegexSetBuilder::build`
/// failure is also a `regex::Error`).
fn error_kind_from_setbuilder(e: &regex::Error) -> &'static str {
    error_kind(e)
}

/// SHA-256 hex of `stable_json({"patterns": <patterns>})` — binds the
/// regex set into the receipt without sending it. Matches ADR-018 §3
/// `required_patterns_regex_set_fingerprint` field.
fn patterns_fingerprint(patterns: &[String]) -> String {
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    let arr: Vec<Value> = patterns.iter().cloned().map(Value::String).collect();
    map.insert("patterns".to_string(), Value::Array(arr));
    let canonical = stable_json(&map);
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    hex::encode(h.finalize())
}

/// Build the `iss` claim — `qorch-safety-kernel/<build_version>@<pk_fpr[:16]>`.
fn build_iss(state: &AppState) -> String {
    let fpr = &state.public_key_fingerprint;
    let prefix: String = fpr.chars().take(16).collect();
    format!(
        "qorch-safety-kernel/{}@{}",
        state.settings.build_version, prefix
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::has_nested_quantifier;

    /// ReDoS-vulnerable patterns MUST be rejected by the heuristic
    /// (purple-team ARY-2028-PT-C1, 2026-05-14).
    #[test]
    fn nested_quantifier_redos_patterns_are_rejected() {
        for pat in [
            "(a+)+b",
            "(a*)*b",
            "(a|a)*b",
            "(?:a*)*b",
            "([a-z]+)+y",
            r"(a+)+\.b",
            "(a+){2,}b",
            "(foo|bar)*x",
        ] {
            assert!(has_nested_quantifier(pat), "MUST flag ReDoS pattern: {pat}");
        }
    }

    /// Safe patterns MUST NOT be flagged (false-positive guard).
    #[test]
    fn safe_patterns_pass_the_heuristic() {
        for pat in [
            "^pkg\\.",
            "pkg\\.[a-z_]+",
            "(foo|bar)", // alternation but no trailing quantifier
            "[a-z]+",    // single quantifier
            "(?:abc)+",  // quantified group, body has no quantifier or |
            "a+b*",
            "(a+)b+", // group then non-group quantifier
            "^[A-Za-z0-9_.-]+$",
        ] {
            assert!(
                !has_nested_quantifier(pat),
                "false positive on safe pattern: {pat}",
            );
        }
    }

    /// Escape handling: `\(` is NOT a real group opener.
    #[test]
    fn escaped_parens_are_not_treated_as_groups() {
        // `\(a+\)+b` is literal '(', 'a+', ')', '+b' — no real group.
        assert!(!has_nested_quantifier(r"\(a+\)+b"));
    }
}
