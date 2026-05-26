//! Extracts request metadata into an `AuthorizeRequest`.
//!
//! Per the extractor pulls four fields:
//!
//! - `action` — derived from the route. The default extractor uses
//!   `{method}:{path}` (e.g. `POST:/gated/run`); callers with their
//!   own action namespace plug a custom [`RequestClaimsExtractor`].
//! - `run_id` — caller-provided HTTP header `x-run-id`. Required for
//!   `Gated` routes; missing → 400.
//! - `subject` — caller-provided HTTP header `x-subject`. Required
//!   for `Gated` routes; missing → 400.
//! - `params_fingerprint` — SHA-256 of the canonical request body.
//!   For routes that do not buffer the body the extractor uses a
//!   sentinel `"0"*64` and the receiver-side kernel handles the
//!   mismatch as a contract drift.
//!
//! The pure-defaults extractor is good enough for the reference app
//! and the adversarial suite. Production deployments should plug a
//! custom [`RequestClaimsExtractor`] that knows about their tool /
//! action namespace.

use crate::error::MiddlewareError;
use http::{HeaderMap, Method};
use qorch_safety_kernel_client::AuthorizeRequest;
use sha2::{Digest, Sha256};

/// Per-route metadata the middleware needs to issue the kernel call.
#[derive(Debug, Clone)]
pub struct ExtractedClaims {
    /// The authorize-request body that goes on the wire.
    pub request: AuthorizeRequest,
}

/// Pluggable claims extractor. The default impl is a free function
/// [`default_extract`]; the trait exists so callers with bespoke
/// action namespaces can swap it.
pub trait RequestClaimsExtractor: Send + Sync + 'static {
    /// Extract the claims for a single request. `body_bytes` is `None`
    /// when the middleware does not buffer the request body.
    fn extract(
        &self,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        body_bytes: Option<&[u8]>,
    ) -> Result<ExtractedClaims, MiddlewareError>;
}

/// Default extractor used by the reference app + adversarial tests.
///
/// - `action`             = `"{method}:{path}"` (e.g. `POST:/gated/run`)
/// - `run_id`             = header `x-run-id` (required for gated)
/// - `subject`            = header `x-subject` (required for gated)
/// - `params_fingerprint` = sha256(body) or `"0"*64` when body absent
pub struct DefaultExtractor;

impl RequestClaimsExtractor for DefaultExtractor {
    fn extract(
        &self,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        body_bytes: Option<&[u8]>,
    ) -> Result<ExtractedClaims, MiddlewareError> {
        let action = format!("{method}:{path}");
        let run_id = header_str(headers, "x-run-id")
            .ok_or_else(|| MiddlewareError::BadRequest {
                reason: "missing required header: x-run-id".into(),
            })?
            .to_string();
        let subject = header_str(headers, "x-subject")
            .ok_or_else(|| MiddlewareError::BadRequest {
                reason: "missing required header: x-subject".into(),
            })?
            .to_string();
        let params_fingerprint = match body_bytes {
            Some(b) if !b.is_empty() => {
                let mut h = Sha256::new();
                h.update(b);
                hex::encode(h.finalize())
            }
            _ => "0".repeat(64),
        };
        let traceparent = header_str(headers, "traceparent").map(str::to_string);
        Ok(ExtractedClaims {
            request: AuthorizeRequest {
                action,
                params_fingerprint,
                run_id,
                subject,
                traceparent,
            },
        })
    }
}

fn header_str<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key).and_then(|v| v.to_str().ok())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers_with(run_id: Option<&str>, subject: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = run_id {
            h.insert("x-run-id", HeaderValue::from_str(v).unwrap());
        }
        if let Some(v) = subject {
            h.insert("x-subject", HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn default_extractor_succeeds_with_required_headers() {
        let h = headers_with(Some("run-1"), Some("worker"));
        let claims = DefaultExtractor
            .extract(&Method::POST, "/gated/run", &h, Some(b"hello"))
            .expect("must extract");
        assert_eq!(claims.request.action, "POST:/gated/run");
        assert_eq!(claims.request.run_id, "run-1");
        assert_eq!(claims.request.subject, "worker");
        assert_eq!(claims.request.params_fingerprint.len(), 64);
        // Not the sentinel — we actually hashed the body.
        assert_ne!(claims.request.params_fingerprint, "0".repeat(64));
    }

    #[test]
    fn default_extractor_uses_zero_fingerprint_when_body_absent() {
        let h = headers_with(Some("run-1"), Some("worker"));
        let claims = DefaultExtractor
            .extract(&Method::POST, "/gated/run", &h, None)
            .expect("must extract");
        assert_eq!(claims.request.params_fingerprint, "0".repeat(64));
    }

    #[test]
    fn default_extractor_rejects_missing_run_id() {
        let h = headers_with(None, Some("worker"));
        let r = DefaultExtractor.extract(&Method::POST, "/gated/run", &h, None);
        assert!(matches!(r, Err(MiddlewareError::BadRequest { .. })));
    }

    #[test]
    fn default_extractor_rejects_missing_subject() {
        let h = headers_with(Some("run-1"), None);
        let r = DefaultExtractor.extract(&Method::POST, "/gated/run", &h, None);
        assert!(matches!(r, Err(MiddlewareError::BadRequest { .. })));
    }
}
