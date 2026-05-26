//! `x-api-key` middleware for the transparency-log service (
//!  §3,  Step 5).
//!
//! Mirrors the kernel's `auth.rs::auth_layer` pattern. Only the kernel
//! is expected to call this service, so the auth model is "single
//! shared key" — the middleware accepts ONE value, configured via
//! `QORCH_TRANSPARENCY_API_KEY` and held on `AppState::api_key`. mTLS
//! (when enabled in `tls.rs`) is an orthogonal second factor: the
//! rustls listener verifies the client certificate chain BEFORE the
//! request ever reaches this middleware.
//!
//! Public paths (no auth):
//!   - `/health` — liveness check; safe for service-mesh probes.
//!
//! All other paths (`/v1/append`, `/v1/verify/*`, `/v1/sth`,
//! `/v1/consistency`) require `x-api-key` match. Returns 401 on
//! mismatch / missing header; 503 if the service is misconfigured
//! (api_key empty in non-dev).

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use crate::error::ErrorResponse;
use crate::state::AppState;

/// Constant-time string compare. Mirrors the kernel helper.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// True if the path is allow-listed for unauthenticated access.
fn is_public_path(path: &str) -> bool {
    matches!(path, "/health")
}

fn deny(status: StatusCode, body: ErrorResponse) -> Response {
    (status, Json(body)).into_response()
}

/// Auth middleware. Reads the per-request `x-api-key` header and
/// constant-time compares against `state.api_key`.
pub async fn auth_layer(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if is_public_path(path) {
        return next.run(request).await;
    }

    let configured = state.api_key.as_str();
    if configured.is_empty() {
        // No api_key configured — only acceptable in dev. Settings.rs
        // already fail-closes in prod, but we double-check here so a
        // mis-wired test fixture cannot silently bypass auth.
        return deny(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorResponse::simple("auth_misconfigured"),
        );
    }

    let supplied = request
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if supplied.is_empty() {
        return deny(
            StatusCode::UNAUTHORIZED,
            ErrorResponse::simple("unauthorized"),
        );
    }
    if !constant_time_eq(supplied.as_bytes(), configured.as_bytes()) {
        return deny(
            StatusCode::UNAUTHORIZED,
            ErrorResponse::simple("unauthorized"),
        );
    }

    next.run(request).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abc", b""));
    }

    #[test]
    fn public_paths() {
        assert!(is_public_path("/health"));
        assert!(!is_public_path("/v1/append"));
        assert!(!is_public_path("/v1/sth"));
    }
}
