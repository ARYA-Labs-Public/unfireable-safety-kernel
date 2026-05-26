//! `POST /policy/audit-event` —  handler.
//!
//! Surfaces non-decision audit events from the audit-hook reference.
//! Does NOT render a verdict, does NOT sign a token. Appends one
//! entry to the chain and returns 202 Accepted.
//!
//! Order of operations:
//!  1. Role check (`worker`).
//!  2. IPC: `op=policy_audit_event` to the sidecar.
//!  3. Audit-append a `policy_audit_event` chain entry (fail-CLOSED:
//!     unlike `module_authorize`, no signed artifact has left the
//!     building; the caller can retry).
//!  4. 202 Accepted.

use std::collections::BTreeMap;

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use qorch_adapters::policy_engine_client::{
    AuditAppendRequest, PolicyAuditEventRequest as IpcAuditEventRequest,
};
use qorch_domain::safety::policy::{
    is_valid_module_path, AuditEventKind, ModuleAuditEventRequest,
    MODULE_PATH_INVALID_CHARSET_REASON,
};

use crate::auth::CallerRole;
use crate::dto::ErrorResponse;
use crate::state::AppState;

fn deny(status: StatusCode, body: ErrorResponse) -> Response {
    (status, Json(body)).into_response()
}

fn btree_to_value(m: &BTreeMap<String, Value>) -> Value {
    let mut obj = serde_json::Map::with_capacity(m.len());
    for (k, v) in m {
        obj.insert(k.clone(), v.clone());
    }
    Value::Object(obj)
}

fn event_kind_to_wire(k: AuditEventKind) -> &'static str {
    match k {
        AuditEventKind::HookInstallViolation => "hook_install_violation",
        AuditEventKind::SubprocessPropagationFailed => "subprocess_propagation_failed",
        AuditEventKind::RegistryConsistencyWarning => "registry_consistency_warning",
    }
}

/// `POST /policy/audit-event`.
pub async fn audit_event(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerRole>,
    Json(body): Json<ModuleAuditEventRequest>,
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
    // PT-L1 fold-in, ). The audit-event request body has
    // no top-level `module_path` field — many event kinds
    // (`subprocess_propagation_failed` argv0, `hook_install_violation`
    // reason strings) carry no module path at all. We validate
    // `metadata.module_path` ONLY when it is present and is a string;
    // any other shape is left for the sidecar to handle. Keeping the
    // accept-set uniform across the four endpoints is the architect §7
    // mandate; this is the audit-event endpoint's slice of that
    // uniformity.
    if let Some(metadata) = body.metadata.as_ref() {
        if let Some(Value::String(mp)) = metadata.get("module_path") {
            if !is_valid_module_path(mp) {
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
        }
    }

    let now = state.clock.now();

    // Step 2: IPC to sidecar.
    let ipc_req = IpcAuditEventRequest {
        event_kind: event_kind_to_wire(body.event_kind).to_string(),
        subject: body.subject.clone(),
        metadata: body.metadata.clone(),
    };
    let ts_unix_ms = match state.policy_client.policy_audit_event(ipc_req).await {
        Ok(ts) => ts,
        Err(e) => {
            // Fail-CLOSED here 3 — return 502 so the
            // caller can retry. No audit append (the chain write IS
            // what failed).
            tracing::warn!(
                kind = e.kind(),
                detail = %e.detail(),
                "policy_audit_event IPC failed — returning 502"
            );
            return deny(
                StatusCode::BAD_GATEWAY,
                ErrorResponse::with_reason(
                    "audit_event_failed",
                    format!("policy_error:{}", e.kind()),
                ),
            );
        }
    };

    // Step 3: audit append (fail-OPEN per the existing pattern — the
    // sidecar has already recorded the event via op=policy_audit_event;
    // this is the dual-write to the main audit chain).
    let audit_payload = json!({
        "request": {
            "event_kind": event_kind_to_wire(body.event_kind),
            "subject": body.subject,
            "caller_role": caller_role,
            "metadata": body.metadata.as_ref().map_or(Value::Null, btree_to_value),
        },
        "decision": {
            "allowed": true,
            "reason": "audit_event",
            "metadata": { "ts_unix_ms": ts_unix_ms },
        },
        "token_sha256": Value::Null,
        "claims": Value::Null,
    });
    let audit_req = AuditAppendRequest {
        unit_id: "safety_kernel".to_string(),
        action_name: "policy_audit_event".to_string(),
        payload: audit_payload,
        success: true,
        error: None,
        started_at: now,
        ended_at: state.clock.now(),
    };
    if let Err(e) = state.policy_client.audit_append(audit_req).await {
        tracing::warn!(
            kind = e.kind(),
            detail = %e.detail(),
            "audit_append failed on policy_audit_event (fail-open: continuing)"
        );
    }

    // Step 4: 202 Accepted.
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "ok": true,
            "audit_kind": "policy_audit_event",
            "ts_unix_ms": ts_unix_ms,
        })),
    )
        .into_response()
}
