//! Middleware rejection type.
//!
//! Per the fail-closed contract is:
//!
//! - SK unreachable (transport, breaker, 5xx) → HTTP 503.
//! - SK reachable + denied → HTTP 403 with reason in body.
//! - SK reachable + token forged / verification failed → HTTP 403.
//!
//! Never 200, never 5xx-with-allow.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

/// All rejection modes the middleware can return.
///
/// Each variant is mapped to an HTTP status code by
/// [`IntoResponse`]. The fail-closed invariant is **structural**:
/// every variant produces a 4xx/5xx, never a 2xx.
#[derive(Debug, Error)]
pub enum MiddlewareError {
    /// Kernel was not reachable (transport, breaker open, 5xx). Returns
    /// HTTP 503.
    #[error("kernel unavailable: {reason}")]
    KernelUnavailable {
        /// Human-readable reason for the unavailability.
        reason: String,
    },

    /// Kernel was reachable and denied the request. Returns HTTP 403.
    #[error("kernel denied: {reason}")]
    Denied {
        /// Reason string from the kernel's 403 body.
        reason: String,
    },

    /// Kernel response signature did not verify against the pinned key,
    /// or any other token-verification step failed. Returns HTTP 403 —
    /// treated as forgery, not as a transport problem (a tampered
    /// kernel must NOT be confusable with a stopped one).
    #[error("kernel response forged: {reason}")]
    Forged {
        /// Token-verification failure detail.
        reason: String,
    },

    /// The middleware could not extract the required request metadata
    /// (e.g. missing run-id header on a gated route). Returns HTTP 400.
    #[error("bad request: {reason}")]
    BadRequest {
        /// Detail string for the operator.
        reason: String,
    },
}

impl IntoResponse for MiddlewareError {
    fn into_response(self) -> Response {
        let (status, reason) = match &self {
            Self::KernelUnavailable { reason } => (StatusCode::SERVICE_UNAVAILABLE, reason.clone()),
            Self::Denied { reason } | Self::Forged { reason } => (StatusCode::FORBIDDEN, reason.clone()),
            Self::BadRequest { reason } => (StatusCode::BAD_REQUEST, reason.clone()),
        };
        let body = Json(json!({
            "ok": false,
            "error": self.kind_str(),
            "reason": reason,
        }));
        (status, body).into_response()
    }
}

impl MiddlewareError {
    /// Short tag string used in the JSON error envelope. Stable for
    /// callers that switch on it instead of the HTTP status.
    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::KernelUnavailable {.. } => "kernel_unavailable",
            Self::Denied {.. } => "denied",
            Self::Forged {.. } => "forged",
            Self::BadRequest {.. } => "bad_request",
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;

    async fn body_string(resp: Response) -> (StatusCode, String) {
        let (parts, body) = resp.into_parts();
        let bytes = body
            .collect()
            .await
            .expect("body collect")
            .to_bytes();
        (parts.status, String::from_utf8(bytes.to_vec()).expect("utf8"))
    }

    #[tokio::test]
    async fn unavailable_maps_to_503() {
        let e = MiddlewareError::KernelUnavailable {
            reason: "circuit breaker open".into(),
        };
        let (status, body) = body_string(e.into_response()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("kernel_unavailable"));
        assert!(body.contains("circuit"));
        // structural: never 2xx
        let _ = Request::<Body>::new(Body::empty());
    }

    #[tokio::test]
    async fn denied_maps_to_403() {
        let e = MiddlewareError::Denied {
            reason: "policy_rejected".into(),
        };
        let (status, body) = body_string(e.into_response()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("denied"));
    }

    #[tokio::test]
    async fn forged_maps_to_403_not_5xx() {
        // A forged response signature is a HARD refusal, distinct
        // from "kernel stopped". Must surface as 403, not 503 —
        // operators read 503 as "outage" but the safety property is
        // intact; 403 is the correct signal that a token failed
        // verification.
        let e = MiddlewareError::Forged {
            reason: "signature mismatch".into(),
        };
        let (status, body) = body_string(e.into_response()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("forged"));
    }

    #[test]
    fn kind_str_stable_taxonomy() {
        assert_eq!(MiddlewareError::KernelUnavailable { reason: String::new() }.kind_str(), "kernel_unavailable");
        assert_eq!(MiddlewareError::Denied { reason: String::new() }.kind_str(), "denied");
        assert_eq!(MiddlewareError::Forged { reason: String::new() }.kind_str(), "forged");
        assert_eq!(MiddlewareError::BadRequest { reason: String::new() }.kind_str(), "bad_request");
    }
}
