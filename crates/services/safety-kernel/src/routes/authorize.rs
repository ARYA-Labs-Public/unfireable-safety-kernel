//! `/kernel/v1/authorize` handler — implements ADR-014 Slice 1 §4.2
//! step-for-step.
//!
//! Order of operations (binding):
//!  1. Role check (`caller_role` in {worker, api}).
//!  2. API-action allowlist (when `caller_role` == "api").
//!  3. `params_fingerprint` verify (when body.params present).
//!  4. TTL clamp.
//!  5. Capture `now`.
//!  6. Build IPC payload, send to Python policy sidecar.
//!  7. On allow: build claims, sign, compute `token_sha256`.
//!  8. Audit append via IPC. Fail-OPEN — log + continue.
//!  9. Respond 200 / 403.

use std::collections::BTreeMap;

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::Value;
use tracing::warn;

use qorch_adapters::policy_engine_client::{AuditAppendRequest, AuthorizePolicyRequest};
use qorch_domain::safety::{
    api_action_allowlist::is_api_action_allowed, claims::AuthorizeClaims, params_fingerprint,
    sign_kernel_token, token_sha256, ToClaimsMap,
};

use crate::auth::CallerRole;
#[cfg(feature = "test-seams")]
use crate::auth::TestOverrides;
use crate::dto::{AuthorizeRequest, AuthorizeResponse, ErrorResponse};
use crate::state::AppState;

/// Helper — error response shorthand.
fn deny(status: StatusCode, body: ErrorResponse) -> Response {
    (status, Json(body)).into_response()
}

/// Convert a `BTreeMap<String, Value>` to a `Value::Object` while
/// preserving sort order (insertion order in `serde_json::Map`
/// matches `BTreeMap` iteration, which is lex-sorted).
fn btree_to_value(m: &BTreeMap<String, Value>) -> Value {
    let mut obj = serde_json::Map::with_capacity(m.len());
    for (k, v) in m {
        obj.insert(k.clone(), v.clone());
    }
    Value::Object(obj)
}

/// `POST /kernel/v1/authorize`.
///
/// Long but linear: each block ports one ADR-014 Slice 1 §4.2 step.
/// Splitting it would make the equivalence review harder.
#[allow(clippy::too_many_lines)]
pub async fn authorize(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerRole>,
    #[cfg(feature = "test-seams")] overrides: Option<Extension<TestOverrides>>,
    Json(body): Json<AuthorizeRequest>,
) -> Response {
    let caller_role = caller.0.as_str();

    // Test-seam values (None unless feature on AND headers present).
    #[cfg(feature = "test-seams")]
    let (fixed_clock, fixed_nonce) = match overrides {
        Some(Extension(o)) => (o.fixed_clock, o.fixed_nonce),
        None => (None, None),
    };
    #[cfg(not(feature = "test-seams"))]
    let (fixed_clock, fixed_nonce): (Option<f64>, Option<String>) = (None, None);

    // Step 1: role check.
    if !matches!(caller_role, "worker" | "api") {
        return deny(
            StatusCode::FORBIDDEN,
            ErrorResponse::with_reason("forbidden", "caller_role_forbidden"),
        );
    }

    // Step 2: API-action allowlist.
    if caller_role == "api" {
        let action_norm = body.action.trim();
        if !is_api_action_allowed(action_norm) {
            return deny(
                StatusCode::FORBIDDEN,
                ErrorResponse::with_reason("forbidden", "api_action_forbidden"),
            );
        }
    }

    // Step 3: params_fingerprint verify.
    // Python uses `ensure_ascii_dict(body.params)` — for serde, we
    // already have a `BTreeMap<String, Value>` with String keys, so
    // `ensure_ascii_dict` is the identity (Python's helper exists to
    // coerce dict-like inputs to a real dict-with-string-keys; serde
    // gives us that for free at deserialize time).
    if let Some(params) = body.params.as_ref() {
        let computed = params_fingerprint(&btree_to_value(params));
        if computed != body.params_fingerprint {
            return deny(
                StatusCode::FORBIDDEN,
                ErrorResponse::with_reason("forbidden", "params_fingerprint_mismatch"),
            );
        }
    }

    // Step 3.5: ttl_s validation — Python Pydantic rejects ttl_s < 1
    // or > 3600 with 422 (`AuthorizeRequest.ttl_s = Field(ge=1, le=3600)`).
    // We mirror that here at the same status (422) so equivalence holds.
    if let Some(ttl_req) = body.ttl_s {
        if !(1..=3600).contains(&ttl_req) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "invalid_request",
                    "reason": format!("ttl_s_out_of_range:{ttl_req}"),
                })),
            )
                .into_response();
        }
    }

    // Step 4: TTL clamp — `max(1, min(max_ttl, max(1, requested or default)))`.
    let requested = body.ttl_s.unwrap_or(state.settings.default_token_ttl_s);
    let ttl = state.settings.max_token_ttl_s.min(requested.max(1)).max(1);

    // Step 5: capture `now` (or use the test-seam override).
    let now = fixed_clock.unwrap_or_else(|| state.clock.now());

    // Step 6: build IPC `metadata`.
    //
    // Python (`routes/authorize.py:107-111`):
    //   md = {"run_id": str(body.run_id), "caller_role": caller_role}
    //   if body.params is not None:
    //       md["params"] = ensure_ascii_dict(body.params)
    //   if body.metadata:
    //       md.update(ensure_ascii_dict(body.metadata))
    //
    // Per ADR §10 note 8: omit `params` when body.params is None.
    let mut md_obj = serde_json::Map::new();
    md_obj.insert("run_id".to_string(), Value::String(body.run_id.clone()));
    md_obj.insert(
        "caller_role".to_string(),
        Value::String(caller_role.to_string()),
    );
    if let Some(params) = body.params.as_ref() {
        md_obj.insert("params".to_string(), btree_to_value(params));
    }
    if let Some(extra) = body.metadata.as_ref() {
        for (k, v) in extra {
            md_obj.insert(k.clone(), v.clone());
        }
    }

    let policy_req = AuthorizePolicyRequest {
        action: body.action.clone(),
        // §4.2 step 5 / §10 note 4: bind `subject` (sent to policy) to
        // the trusted caller_role, NOT body.subject.
        subject: caller_role.to_string(),
        now,
        metadata: Value::Object(md_obj),
    };

    let policy_decision_result = state.policy_client.authorize(policy_req).await;
    let (decision_allowed, decision_reason, decision_metadata) = match policy_decision_result {
        Ok(d) => (d.allowed, d.reason, d.metadata),
        Err(e) => {
            // Fail-CLOSED per §3.5: synth a deny decision with
            // `policy_error:<kind>` reason. The reason string is the
            // stable kind from `IpcError::kind()`.
            let kind = e.kind();
            (
                false,
                format!("policy_error:{kind}"),
                serde_json::json!({"error": e.detail()}),
            )
        }
    };

    if !decision_allowed {
        // 8a (deny): audit-append the deny decision before returning,
        // matching Python which logs the deny audit record. (Python
        // calls record_outcome with success=False and error=reason.)
        // Then 403.
        let audit_payload = serde_json::json!({
            "request": {
                "action": body.action,
                "run_id": body.run_id,
                "subject": body.subject,
                "caller_role": caller_role,
                "params_fingerprint": body.params_fingerprint,
                "ttl_s_requested": requested,
                "ttl_s_issued": ttl,
                "metadata": body.metadata.as_ref().map_or(Value::Null, btree_to_value),
            },
            "decision": {
                "allowed": false,
                "reason": decision_reason.clone(),
                "metadata": decision_metadata,
            },
            "token_sha256": Value::Null,
            "claims": Value::Null,
        });
        let audit_req = AuditAppendRequest {
            unit_id: "safety_kernel".to_string(),
            action_name: "kernel_authorize".to_string(),
            payload: audit_payload,
            success: false,
            error: Some(decision_reason.clone()),
            started_at: now,
            ended_at: state.clock.now(),
        };
        // Fail-OPEN: log + continue.
        if let Err(e) = state.policy_client.audit_append(audit_req).await {
            warn!(
                kind = e.kind(),
                detail = %e.detail(),
                "audit_append failed on deny path (fail-open: continuing)"
            );
        }

        return deny(
            StatusCode::FORBIDDEN,
            ErrorResponse::with_reason("denied", decision_reason),
        );
    }

    // Step 7: build + sign claims (allow path). Nonce override for
    // test-seams; production uses `state.nonce`.
    let nonce = fixed_nonce
        .clone()
        .unwrap_or_else(|| state.nonce.nonce_b64());
    let claims_struct = AuthorizeClaims {
        action: body.action.clone(),
        run_id: body.run_id.clone(),
        // §10 note 4: signed subject is the trusted caller_role.
        subject: caller_role.to_string(),
        params_fingerprint: body.params_fingerprint.clone(),
        issued_at: now,
        #[allow(clippy::cast_precision_loss)]
        expires_at: now + (ttl as f64),
        nonce,
    };
    let token = sign_kernel_token(&claims_struct, state.signing_key.as_ref());
    let tok_sha = token_sha256(&token);

    // Convert claims to BTreeMap<String, Value> for the response body.
    let claims_map = claims_struct.to_btreemap();

    // Step 8: audit append (fail-OPEN).
    let audit_payload = serde_json::json!({
        "request": {
            "action": body.action,
            "run_id": body.run_id,
            "subject": body.subject,
            "caller_role": caller_role,
            "params_fingerprint": body.params_fingerprint,
            "ttl_s_requested": requested,
            "ttl_s_issued": ttl,
            "metadata": body.metadata.as_ref().map_or(Value::Null, btree_to_value),
        },
        "decision": {
            "allowed": true,
            "reason": decision_reason,
            "metadata": decision_metadata,
        },
        "token_sha256": tok_sha,
        "claims": btree_to_value(&claims_map),
    });
    let audit_req = AuditAppendRequest {
        unit_id: "safety_kernel".to_string(),
        action_name: "kernel_authorize".to_string(),
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
            "audit_append failed on allow path (fail-open: continuing)"
        );
    }

    // Step 9: 200 success.
    let resp = AuthorizeResponse {
        ok: true,
        token,
        token_sha256: tok_sha,
        claims: claims_map,
    };
    Json(resp).into_response()
}
