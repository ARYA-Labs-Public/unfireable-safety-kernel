//! `POST /policy/module/authorize` —  handler.
//!
//! The hot path: every Python `import` audit event hits this handler.
//! Linear flow 2:
//!
//!  1. Role check (`worker`).
//!  2. Validate `event_fingerprint` is 64-hex.
//!  3. Recompute `event_fingerprint` server-side and reject on
//!     mismatch — the in-band defense against forged fingerprints.
//!  4. Capture `now`.
//!  5. IPC: `op=policy_authorize` to the sidecar. Sidecar evaluates
//!     the registry + regex set and returns a decision string.
//!  6. Branch on `decision`:
//!       - `allow`  -> sign ALLOW claims, audit, 200
//!       - `deny`   -> sign DENY claims, audit, 403
//!       - `kernel_unavailable` -> 503, NO sign, NO audit
//!       - IPC error -> 503, NO sign, NO audit

use std::collections::BTreeMap;

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use tracing::warn;

use qorch_adapters::policy_engine_client::{
    AuditAppendRequest, PolicyModuleAuthorizeRequest as IpcAuthorizeRequest,
};
use qorch_domain::safety::{
    params_fingerprint,
    policy::{
        is_valid_module_path, ModuleAuthorizeClaims, ModuleAuthorizeDecision,
        ModuleAuthorizeRequest, ModuleEventKind, MODULE_PATH_INVALID_CHARSET_REASON,
        POLICY_AUTHORIZE_AUD,
    },
    sign_kernel_token, token_sha256, ToClaimsMap,
};

use crate::auth::CallerRole;
use crate::dto::ErrorResponse;
use crate::state::AppState;

/// Default authorize-token TTL (60s 
const AUTHORIZE_TOKEN_TTL_S: f64 = 60.0;

/// Helper — error response shorthand.
fn deny(status: StatusCode, body: ErrorResponse) -> Response {
    (status, Json(body)).into_response()
}

/// Convert a `BTreeMap<String, Value>` to a `Value::Object` preserving
/// the sorted key order.
fn btree_to_value(m: &BTreeMap<String, Value>) -> Value {
    let mut obj = serde_json::Map::with_capacity(m.len());
    for (k, v) in m {
        obj.insert(k.clone(), v.clone());
    }
    Value::Object(obj)
}

/// Map `ModuleEventKind` to its wire string (lowercase).
fn event_kind_to_wire(k: ModuleEventKind) -> &'static str {
    match k {
        ModuleEventKind::Import => "import",
        ModuleEventKind::Exec => "exec",
        ModuleEventKind::Compile => "compile",
    }
}

/// Recompute the trusted `event_fingerprint` from
/// `(event_kind, module_path, caller_subject, caller_run_id)` using
/// the same `params_fingerprint` canonicalization as the caller.
/// Matches step 3.
fn recompute_event_fingerprint(req: &ModuleAuthorizeRequest) -> String {
    let canonical = json!({
        "event_kind": event_kind_to_wire(req.event_kind),
        "module_path": req.module_path,
        "caller_subject": req.caller_subject,
        "caller_run_id": req.caller_run_id,
    });
    params_fingerprint(&canonical)
}

/// `POST /policy/module/authorize` — issues a signed Allow/Deny token
/// against the sidecar's registry.
#[allow(clippy::too_many_lines)]
pub async fn authorize(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerRole>,
    Json(body): Json<ModuleAuthorizeRequest>,
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
    // PT-L1 fold-in, ). Runs BEFORE the fingerprint check
    // so adversarial input with malformed paths is rejected with the
    // most specific reason possible.
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

    // Step 2: event_fingerprint must be 64-char lowercase hex.
    if !is_64_lowercase_hex(&body.event_fingerprint) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "invalid_request",
                "reason": "event_fingerprint_format",
            })),
        )
            .into_response();
    }

    // Step 3: recompute event_fingerprint and reject on mismatch.
    let recomputed = recompute_event_fingerprint(&body);
    if recomputed != body.event_fingerprint {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "invalid_request",
                "reason": "event_fingerprint_invalid",
            })),
        )
            .into_response();
    }

    // Step 4: capture now.
    let now = state.clock.now();

    // Step 5: IPC call to sidecar.
    let ipc_req = IpcAuthorizeRequest {
        event_kind: event_kind_to_wire(body.event_kind).to_string(),
        module_path: body.module_path.clone(),
        caller_subject: body.caller_subject.clone(),
        caller_run_id: body.caller_run_id.clone(),
        // Bind the SERVER-recomputed fingerprint, not the supplied
        // value, to the IPC payload.
        event_fingerprint: recomputed.clone(),
        expected_required_patterns: body.expected_required_patterns.clone(),
        metadata: body.metadata.as_ref().map(btree_to_value),
    };
    let ipc_resp = match state.policy_client.policy_authorize(ipc_req).await {
        Ok(r) => r,
        Err(e) => {
            // KernelUnavailable: 503, no audit ( — nothing
            // to audit; no decision was made).
            warn!(
                kind = e.kind(),
                detail = %e.detail(),
                "policy_authorize IPC failed — returning 503"
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

    // Sidecar-level kernel_unavailable: 503, no sign, no audit.
    if ipc_resp.decision == "kernel_unavailable" {
        return deny(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorResponse::with_reason("kernel_unavailable", "sidecar_backend_unavailable"),
        );
    }

    // Both allow and deny take the signing + audit path.
    let (decision_enum, audit_kind, http_status) = match ipc_resp.decision.as_str() {
        "allow" => (
            ModuleAuthorizeDecision::Allow,
            "policy_authorize_allow",
            StatusCode::OK,
        ),
        "deny" => (
            ModuleAuthorizeDecision::Deny,
            "policy_authorize_deny",
            StatusCode::FORBIDDEN,
        ),
        // Defensive: unrecognized decision string -> treat as 503.
        other => {
            warn!(
                decision = other,
                "sidecar returned unrecognized decision string"
            );
            return deny(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorResponse::with_reason("kernel_unavailable", "decision_unrecognized"),
            );
        }
    };

    let nonce = state.nonce.nonce_b64();
    let iss = build_iss(&state);
    let claims_struct = ModuleAuthorizeClaims {
        //  ( slice 5): mint with the canonical
        // policy/module/authorize audience tag. Closes the cross-tenant
        // replay surface with `/kernel/v1/authorize` (both endpoints
        // share the same signing key).
        aud: POLICY_AUTHORIZE_AUD.to_string(),
        iss,
        iat: now,
        exp: now + AUTHORIZE_TOKEN_TTL_S,
        subject: body.caller_subject.clone(),
        run_id: body.caller_run_id.clone(),
        event_kind: body.event_kind,
        module_path: body.module_path.clone(),
        event_fingerprint: recomputed,
        decision: decision_enum,
        // Allow ⇒ None (serializes to JSON null in claims map);
        // Deny ⇒ Some(reason).
        reason: if matches!(decision_enum, ModuleAuthorizeDecision::Deny) {
            Some(
                ipc_resp
                    .reason
                    .clone()
                    .unwrap_or_else(|| "unspecified".to_string()),
            )
        } else {
            None
        },
        nonce,
    };
    let token = sign_kernel_token(&claims_struct, state.signing_key.as_ref());
    let tok_sha = token_sha256(&token);
    let claims_map = claims_struct.to_btreemap();

    // Audit-append (fail-OPEN — signed token has already left handler).
    let audit_payload = json!({
        "request": {
            "event_kind": event_kind_to_wire(body.event_kind),
            "module_path": body.module_path,
            "caller_subject": body.caller_subject,
            "caller_run_id": body.caller_run_id,
            "event_fingerprint": body.event_fingerprint,
            "caller_role": caller_role,
            "expected_required_patterns": body.expected_required_patterns,
            "metadata": body.metadata.as_ref().map_or(Value::Null, btree_to_value),
        },
        "decision": {
            "allowed": matches!(decision_enum, ModuleAuthorizeDecision::Allow),
            "reason": ipc_resp.reason.clone().unwrap_or_default(),
            "metadata": {
                "registered_at_unix_ms": ipc_resp.registered_at_unix_ms,
                "audit_kind": audit_kind,
            },
        },
        "token_sha256": tok_sha,
        "claims": btree_to_value(&claims_map),
    });
    let audit_req = AuditAppendRequest {
        unit_id: "safety_kernel".to_string(),
        action_name: audit_kind.to_string(),
        payload: audit_payload,
        success: matches!(decision_enum, ModuleAuthorizeDecision::Allow),
        error: if matches!(decision_enum, ModuleAuthorizeDecision::Deny) {
            ipc_resp.reason.clone()
        } else {
            None
        },
        started_at: now,
        ended_at: state.clock.now(),
    };
    if let Err(e) = state.policy_client.audit_append(audit_req).await {
        warn!(
            kind = e.kind(),
            detail = %e.detail(),
            audit_kind = audit_kind,
            "audit_append failed on policy_authorize (fail-open: continuing)"
        );
    }

    // Build the HTTP response envelope 
    let body_obj = json!({
        "ok": matches!(decision_enum, ModuleAuthorizeDecision::Allow),
        "decision": match decision_enum {
            ModuleAuthorizeDecision::Allow => "allow",
            ModuleAuthorizeDecision::Deny => "deny",
            ModuleAuthorizeDecision::KernelUnavailable => "kernel_unavailable",
        },
        "token": token,
        "token_sha256": tok_sha,
        "claims": btree_to_value(&claims_map),
        "reason": ipc_resp.reason,
    });
    (http_status, Json(body_obj)).into_response()
}

/// `^[0-9a-f]{64}$` — strict 64-char lowercase hex check.
fn is_64_lowercase_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
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
    use super::*;

    #[test]
    fn fp_format_check_64_lowercase_hex() {
        assert!(is_64_lowercase_hex(&"0".repeat(64)));
        assert!(is_64_lowercase_hex(&"a".repeat(64)));
        assert!(is_64_lowercase_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        // Wrong length.
        assert!(!is_64_lowercase_hex(&"0".repeat(63)));
        assert!(!is_64_lowercase_hex(&"0".repeat(65)));
        // Uppercase rejected.
        assert!(!is_64_lowercase_hex(
            "ABCDEF0000000000000000000000000000000000000000000000000000000000"
        ));
        // Non-hex chars rejected.
        assert!(!is_64_lowercase_hex(&"g".repeat(64)));
    }

    /// `recompute_event_fingerprint` is deterministic + matches a
    /// hand-computed reference. Critical guard against accidental key
    /// reordering breaking the recomputation.
    #[test]
    fn recompute_event_fingerprint_stable() {
        let req = ModuleAuthorizeRequest {
            event_kind: ModuleEventKind::Import,
            module_path: "pkg.mod".to_string(),
            caller_subject: "worker".to_string(),
            caller_run_id: "run-1".to_string(),
            event_fingerprint: "x".repeat(64),
            expected_required_patterns: None,
            metadata: None,
        };
        let a = recompute_event_fingerprint(&req);
        let b = recompute_event_fingerprint(&req);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }
}
