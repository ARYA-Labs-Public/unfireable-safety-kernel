//! `SafetyService<S>` — the wrapped service produced by [`crate::SafetyLayer`].
//!
//! Per:
//!
//! 1. Resolve the request's [`MiddlewarePolicy`] from
//!    `(method, path)`.
//! 2. If `Unrestricted` → call inner immediately, no kernel.
//! 3. If `Supervised` → spawn a fire-and-forget kernel call, then
//!    call inner. The kernel call result is logged at `info`/`warn`
//!    but does NOT block the request.
//! 4. If `Gated` → buffer the body, build an `AuthorizeRequest` via
//!    the [`crate::RequestClaimsExtractor`], call `client.authorize`
//!    synchronously, and:
//!    - `Ok(KernelDecision::Allow { token, claims })` → attach a
//!      [`crate::SafetyToken`] extension + reconstruct the request
//!      with the buffered body, then call inner.
//!    - `Ok(KernelDecision::Deny { reason })` → return 403
//!      [`MiddlewareError::Denied`].
//!    - `Err(KernelClientError::Verification(_))` → return 403
//!      [`MiddlewareError::Forged`].
//!    - `Err(KernelClientError::Decision(Unavailable { reason }))` /
//!      `Err(KernelClientError::Transport(_))` /
//!      `Err(KernelClientError::Decode(_))` → return 503
//!      [`MiddlewareError::KernelUnavailable`].
//!    - `Err(KernelClientError::Decision(Refused { reason }))` →
//!      return 403 [`MiddlewareError::Denied`].
//!
//! The service is generic over the inner service `S` so it composes
//! cleanly with `axum::Router` or any other `tower::Service`.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response};
use axum::response::IntoResponse;
use bytes::Bytes;
use http_body_util::BodyExt;
use qorch_safety_kernel_client::{KernelClientError, KernelDecision, KernelDecisionError};
use tower::Service;
use tracing::{debug, info, warn};

use crate::client_trait::SafetyKernelClientTrait;
use crate::error::MiddlewareError;
use crate::extractor::RequestClaimsExtractor;
use crate::policy::{MiddlewarePolicy, MiddlewarePolicyResolver};
use crate::token::SafetyToken;

/// Wrapped service that gates every request through the SK.
///
/// Construct via [`crate::SafetyLayer::layer`].
pub struct SafetyService<S> {
    pub(crate) inner: S,
    pub(crate) client: Arc<dyn SafetyKernelClientTrait>,
    pub(crate) policy: Arc<dyn MiddlewarePolicyResolver>,
    pub(crate) extractor: Arc<dyn RequestClaimsExtractor>,
}

impl<S: Clone> Clone for SafetyService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            client: Arc::clone(&self.client),
            policy: Arc::clone(&self.policy),
            extractor: Arc::clone(&self.extractor),
        }
    }
}

impl<S> Service<Request<Body>> for SafetyService<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // Clone the inner service so the future owns its readiness;
        // standard axum middleware pattern. Capture the ready inner
        // (it has been `poll_ready`-ed) by `mem::replace`-ing with a
        // fresh clone of the not-necessarily-ready inner.
        let clone = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, clone);
        let client = Arc::clone(&self.client);
        let policy = Arc::clone(&self.policy);
        let extractor = Arc::clone(&self.extractor);
        Box::pin(handle(req, inner, client, policy, extractor))
    }
}

/// Async core. Pulled out of `Service::call` so the future can own its
/// state cleanly.
async fn handle<S>(
    req: Request<Body>,
    mut inner: S,
    client: Arc<dyn SafetyKernelClientTrait>,
    policy: Arc<dyn MiddlewarePolicyResolver>,
    extractor: Arc<dyn RequestClaimsExtractor>,
) -> Result<Response<Body>, Infallible>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>,
{
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let policy_tier = policy.resolve(&method, &path);

    match policy_tier {
        MiddlewarePolicy::Unrestricted => {
            debug!(?method, %path, "safety_middleware: unrestricted, pass-through");
            inner.call(req).await
        }
        MiddlewarePolicy::Supervised => {
            debug!(?method, %path, "safety_middleware: supervised, fire-and-forget kernel call");
            // Build claims best-effort; on extraction error, skip the
            // kernel call (this tier is observability-only).
            let (parts, body) = req.into_parts();
            let bytes = match collect_bytes(body).await {
                Ok(b) => b,
                Err(e) => {
                    // Body collection failed — surface a 503 since we
                    // cannot reliably forward to inner without owning
                    // the body bytes.
                    warn!(error = %e, "safety_middleware: body collection failed");
                    return Ok(MiddlewareError::KernelUnavailable {
                        reason: format!("body collection failed: {e}"),
                    }
                    .into_response());
                }
            };
            if let Ok(claims) = extractor.extract(&method, &path, &parts.headers, Some(&bytes)) {
                let client_for_task = Arc::clone(&client);
                let req_clone = claims.request.clone();
                // Fire-and-forget: spawn the kernel call but don't
                // await it. Log the outcome for observability.
                tokio::spawn(async move {
                    match client_for_task.authorize(&req_clone).await {
                        Ok(KernelDecision::Allow {.. }) => {
                            info!("safety_middleware: supervised allow");
                        }
                        Ok(KernelDecision::Deny { reason }) => {
                            warn!(
                                reason = reason.as_str(),
                                "safety_middleware: supervised deny (not blocking)"
                            );
                        }
                        Err(e) => {
                            warn!(error = %e, "safety_middleware: supervised kernel call failed");
                        }
                    }
                });
            }
            let rebuilt = Request::from_parts(parts, Body::from(bytes));
            inner.call(rebuilt).await
        }
        MiddlewarePolicy::Gated => {
            debug!(?method, %path, "safety_middleware: gated, synchronous kernel call");
            let (parts, body) = req.into_parts();
            let bytes = match collect_bytes(body).await {
                Ok(b) => b,
                Err(e) => {
                    return Ok(MiddlewareError::KernelUnavailable {
                        reason: format!("body collection failed: {e}"),
                    }
                    .into_response());
                }
            };
            let claims = match extractor.extract(&method, &path, &parts.headers, Some(&bytes)) {
                Ok(c) => c,
                Err(e) => return Ok(e.into_response()),
            };

            // Map the SDK's Result<KernelDecision, KernelClientError>
            // onto the middleware's `MiddlewareError` taxonomy. The
            // groupings below mirror:
            //
            //  - Allow             → attach SafetyToken + forward.
            //  - Deny (any source) → 403 Denied.
            //  - Verification      → 403 Forged.
            //  - Transport / Decode / Unavailable → 503 KernelUnavailable.
            //
            // We collapse the deny + unavailable groups with `|` so
            // clippy::match_same_arms is satisfied AND the cases stay
            // readable (no scattered duplicates).
            match client.authorize(&claims.request).await {
                Ok(KernelDecision::Allow { token, claims: vc }) => {
                    let mut rebuilt = Request::from_parts(parts, Body::from(bytes));
                    rebuilt
                        .extensions_mut()
                        .insert(SafetyToken::new(token, vc));
                    inner.call(rebuilt).await
                }
                Ok(KernelDecision::Deny { reason })
                | Err(KernelClientError::Decision(KernelDecisionError::Denied { reason })) => {
                    Ok(MiddlewareError::Denied { reason }.into_response())
                }
                Err(KernelClientError::Verification(e)) => {
                    Ok(MiddlewareError::Forged {
                        reason: e.to_string(),
                    }
                    .into_response())
                }
                Err(
                    KernelClientError::Decision(KernelDecisionError::Unavailable { reason })
                    | KernelClientError::Transport(reason)
                    | KernelClientError::Decode(reason),
                ) => Ok(MiddlewareError::KernelUnavailable { reason }.into_response()),
            }
        }
    }
}

/// Collect an `axum::body::Body` into a `Bytes` for fingerprinting +
/// re-forwarding. Failures surface as transport errors at the caller.
async fn collect_bytes(body: Body) -> Result<Bytes, axum::Error> {
    let collected = body.collect().await.map_err(axum::Error::new)?;
    Ok(collected.to_bytes())
}
