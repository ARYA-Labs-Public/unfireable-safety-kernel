//! `/kernel/v1/approvals/{item_id}/{approve,reject}` handlers — port
//! of `apps/safety_kernel/routes/approvals.py`.
//!
//! Order of operations (ADR-014 Slice 1 §4.3):
//!  1. Role check (must be `caller_role == "operator"`).
//!  2. Skipped (no API-action gate for approvals).
//!  3. Compute `proposal_fingerprint` (`params_fingerprint` over the
//!     decision payload).
//!  4. TTL: `max(60, settings.approval_token_ttl_s)`.
//!  5. (No policy decision — operator role IS the authority.)
//!  6. Build claims (with extras `decision`, `reason`, `approver`,
//!     `proposal_fingerprint`), sign, compute `token_sha256`.
//!  7. Audit append (fail-OPEN).
//!  8. 200 `SignedDecisionResponse`.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::Value;
use tracing::warn;

use qorch_adapters::policy_engine_client::AuditAppendRequest;
use qorch_domain::safety::{
    claims::ApprovalClaims, params_fingerprint, sign_kernel_token, token_sha256, ToClaimsMap,
};

use crate::auth::CallerRole;
#[cfg(feature = "test-seams")]
use crate::auth::TestOverrides;
use crate::dto::{ApproveRequest, ErrorResponse, RejectRequest, SignedDecisionResponse};
use crate::state::AppState;

fn deny(status: StatusCode, body: ErrorResponse) -> Response {
    (status, Json(body)).into_response()
}

/// Compute the `params_fingerprint` over the canonical approval
/// payload — mirrors `apps/safety_kernel/routes/approvals.py:73-80`.
fn compute_decision_fingerprint(
    item_id: &str,
    decision: &str,
    approver: &str,
    reason: Option<&str>,
    proposal_fingerprint: &str,
) -> String {
    let payload = serde_json::json!({
        "item_id": item_id,
        "decision": decision,
        "approver": approver,
        "reason": match reason {
            None => Value::Null,
            Some(s) => Value::String(s.to_string()),
        },
        "proposal_fingerprint": proposal_fingerprint,
    });
    params_fingerprint(&payload)
}

/// Convert a `BTreeMap<String, Value>` to a `Value::Object` (sorted
/// key order preserved by `BTreeMap` iteration).
fn btree_to_value(m: &std::collections::BTreeMap<String, Value>) -> Value {
    let mut obj = serde_json::Map::with_capacity(m.len());
    for (k, v) in m {
        obj.insert(k.clone(), v.clone());
    }
    Value::Object(obj)
}

/// Shared core for both approve / reject.
#[allow(clippy::too_many_arguments)] // 9 args ports `_sign_decision` from the Python source 1:1.
async fn sign_decision(
    state: &AppState,
    caller_role: &str,
    item_id: &str,
    decision: &str,
    approver: &str,
    reason: Option<&str>,
    proposal_fingerprint: &str,
    metadata: Option<&std::collections::BTreeMap<String, Value>>,
    fixed_clock: Option<f64>,
    fixed_nonce: Option<String>,
) -> Response {
    if caller_role != "operator" {
        return deny(
            StatusCode::FORBIDDEN,
            ErrorResponse::with_reason("forbidden", "caller_role_not_operator"),
        );
    }

    let now = fixed_clock.unwrap_or_else(|| state.clock.now());
    let ttl = state.settings.approval_token_ttl_s.max(60);
    let fp =
        compute_decision_fingerprint(item_id, decision, approver, reason, proposal_fingerprint);

    let nonce = fixed_nonce.unwrap_or_else(|| state.nonce.nonce_b64());
    let claims_struct = ApprovalClaims {
        action: "approval_decision".to_string(),
        run_id: item_id.to_string(),
        subject: "operator".to_string(),
        params_fingerprint: fp,
        issued_at: now,
        #[allow(clippy::cast_precision_loss)]
        expires_at: now + (ttl as f64),
        nonce,
        decision: decision.to_string(),
        reason: reason.map(str::to_string),
        approver: approver.to_string(),
        proposal_fingerprint: proposal_fingerprint.to_string(),
    };
    let token = sign_kernel_token(&claims_struct, state.signing_key.as_ref());
    let tok_sha = token_sha256(&token);
    let claims_map = claims_struct.to_btreemap();

    // Audit append (fail-OPEN). Mirrors
    // `routes/approvals.py:107-166`.
    let audit_payload = serde_json::json!({
        "request": {
            "item_id": item_id,
            "decision": decision,
            "approver": approver,
            "reason": match reason {
                None => Value::Null,
                Some(s) => Value::String(s.to_string()),
            },
            "proposal_fingerprint": proposal_fingerprint,
            "metadata": metadata.map_or(Value::Null, btree_to_value),
            "caller_role": caller_role,
        },
        "token_sha256": tok_sha,
        "claims": btree_to_value(&claims_map),
    });
    let audit_req = AuditAppendRequest {
        unit_id: "safety_kernel".to_string(),
        action_name: "kernel_signed_approval".to_string(),
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
            "audit_append failed on approval (fail-open: continuing)"
        );
    }

    Json(SignedDecisionResponse {
        ok: true,
        item_id: item_id.to_string(),
        decision: decision.to_string(),
        token,
        token_sha256: tok_sha,
        claims: claims_map,
    })
    .into_response()
}

/// Pull the test-seam overrides out of the request extensions, with
/// the feature flag consumed at compile time. Returns (None, None) on
/// non-test builds.
#[cfg(feature = "test-seams")]
fn pull_overrides(o: Option<Extension<TestOverrides>>) -> (Option<f64>, Option<String>) {
    match o {
        Some(Extension(o)) => (o.fixed_clock, o.fixed_nonce),
        None => (None, None),
    }
}

/// `POST /kernel/v1/approvals/{item_id}/approve`.
pub async fn approve(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerRole>,
    Path(item_id): Path<String>,
    #[cfg(feature = "test-seams")] overrides: Option<Extension<TestOverrides>>,
    Json(body): Json<ApproveRequest>,
) -> Response {
    #[cfg(feature = "test-seams")]
    let (fixed_clock, fixed_nonce) = pull_overrides(overrides);
    #[cfg(not(feature = "test-seams"))]
    let (fixed_clock, fixed_nonce): (Option<f64>, Option<String>) = (None, None);

    sign_decision(
        &state,
        caller.0.as_str(),
        &item_id,
        "approved",
        &body.approver,
        None,
        &body.proposal_fingerprint,
        body.metadata.as_ref(),
        fixed_clock,
        fixed_nonce,
    )
    .await
}

/// `POST /kernel/v1/approvals/{item_id}/reject`.
pub async fn reject(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerRole>,
    Path(item_id): Path<String>,
    #[cfg(feature = "test-seams")] overrides: Option<Extension<TestOverrides>>,
    Json(body): Json<RejectRequest>,
) -> Response {
    #[cfg(feature = "test-seams")]
    let (fixed_clock, fixed_nonce) = pull_overrides(overrides);
    #[cfg(not(feature = "test-seams"))]
    let (fixed_clock, fixed_nonce): (Option<f64>, Option<String>) = (None, None);

    sign_decision(
        &state,
        caller.0.as_str(),
        &item_id,
        "rejected",
        &body.approver,
        body.reason.as_deref(),
        &body.proposal_fingerprint,
        body.metadata.as_ref(),
        fixed_clock,
        fixed_nonce,
    )
    .await
}
