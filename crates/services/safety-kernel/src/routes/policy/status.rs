//! `GET /policy/module/{module_path}/status` —  handler
//!.
//!
//! Read-only. Returns the current registration record + last 20
//! decision rows for the path. 404 when no registration exists.
//!
//! Order of operations:
//!  1. Role check (`worker` OR `operator`).
//!  2. Decode + validate `module_path` (`^[A-Za-z0-9_.-]{1,256}$`).
//!  3. IPC: `op=policy_status` to the sidecar.
//!  4. None ⇒ 404. Some ⇒ 200 with the response payload.
//!  5. NO audit-chain write (read-only).

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::warn;

use qorch_adapters::policy_engine_client::PolicyModuleStatusRequest as IpcStatusRequest;
use qorch_domain::safety::policy::{is_valid_module_path, MODULE_PATH_INVALID_CHARSET_REASON};

use crate::auth::CallerRole;
use crate::dto::ErrorResponse;
use crate::state::AppState;

fn deny(status: StatusCode, body: ErrorResponse) -> Response {
    (status, Json(body)).into_response()
}

// Canonical `module_path` charset (, slice-3 PT-L1 fold-in)
// lives in `qorch_domain::safety::policy::validation`. The slice-2
// status handler used a hyphen-permissive charset
// (`^[A-Za-z0-9_.-]{1,256}$`); slice 3 tightens that to the canonical
// dotted-name OR sha256-hex form across ALL four policy endpoints.
//
// Backward-compat note: hyphenated paths registered in slice 2 are now
// unqueryable via status (the dotted-name form rejects `-`). Approved
// by architect-3 — Python dotted module names cannot contain hyphens,
// so any hyphenated entry was malformed at registration time. The
// audit chain still contains those entries; only the status read-path
// rejects them.

/// `GET /policy/module/{module_path}/status`.
pub async fn status(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerRole>,
    Path(module_path): Path<String>,
) -> Response {
    let caller_role = caller.0.as_str();

    // Step 1: role check (worker OR operator).
    if !matches!(caller_role, "worker" | "operator") {
        return deny(
            StatusCode::FORBIDDEN,
            ErrorResponse::with_reason("forbidden", "caller_role_forbidden"),
        );
    }

    // Step 2: URL-decode happens automatically in axum's Path
    // extractor; validate the decoded value against the canonical
    // charset (slice-3 PT-L1 fold-in, ).
    if !is_valid_module_path(&module_path) {
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

    // Step 3: IPC lookup.
    let ipc_req = IpcStatusRequest {
        module_path: module_path.clone(),
    };
    let resp = match state.policy_client.policy_module_status(ipc_req).await {
        Ok(r) => r,
        Err(e) => {
            warn!(
                kind = e.kind(),
                detail = %e.detail(),
                "policy_status IPC failed — returning 503"
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

    // Step 4: None ⇒ 404.
    let Some(inner) = resp else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": "module_not_registered",
                "module_path": module_path,
            })),
        )
            .into_response();
    };

    // Build the response 4. The sidecar already shapes
    // the inner payload; we re-emit the registration + decisions
    // sub-objects directly.
    let recent: Vec<serde_json::Value> = inner
        .recent_decisions
        .iter()
        .map(|d| {
            json!({
                "ts_unix_ms": d.ts_unix_ms,
                "decision": d.decision,
                "caller_run_id": d.caller_run_id,
                "token_sha256": d.token_sha256,
            })
        })
        .collect();

    let body = json!({
        "ok": true,
        "module_path": inner.module_path,
        "registration": {
            "registered_at_unix_ms": inner.registered_at_unix_ms,
            "registered_by": inner.registered_by,
            "required_patterns_regex_set": inner.required_patterns_regex_set,
            "revoked_at_unix_ms": inner.revoked_at_unix_ms,
        },
        "recent_decisions": recent,
    });
    (StatusCode::OK, Json(body)).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Smoke test — the status handler now defers charset validation to
    /// `qorch_domain::safety::policy::is_valid_module_path`. The domain
    /// module owns the full charset matrix; this asserts the smoke shape
    /// the status route relies on.
    #[test]
    fn module_path_canonical_charset_smoke() {
        // Accept: dotted-name form.
        assert!(is_valid_module_path("pkg.mod"));
        assert!(is_valid_module_path("pkg.sub.mod"));
        assert!(is_valid_module_path("a"));
        // Reject: hyphenated path (slice-3 PT-L1 tightening — was
        // accepted by slice-2 status route, rejected now).
        assert!(!is_valid_module_path("my-pkg_v1.mod"));
        // Reject: forbidden characters.
        assert!(!is_valid_module_path("pkg/mod"));
        assert!(!is_valid_module_path("pkg mod"));
        assert!(!is_valid_module_path("pkg:mod"));
        // Reject: empty and over-length.
        assert!(!is_valid_module_path(""));
        assert!(!is_valid_module_path(&"a".repeat(257)));
    }
}
