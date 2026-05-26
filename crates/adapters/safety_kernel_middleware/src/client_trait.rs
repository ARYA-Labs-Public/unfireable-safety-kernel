//! Abstract SK client surface the middleware calls.
//!
//! The production [`qorch_safety_kernel_client::SafetyKernelClient`]
//! is a concrete struct; the middleware would be hard to test in
//! isolation against it because every adversarial fixture would need
//! a full `wiremock` server. This module defines a narrow trait
//! [`SafetyKernelClientTrait`] that captures only the `authorize`
//! method, plus a blanket impl for the production SDK so the
//! reference app can wire it directly.
//!
//! The middleware is generic over `Arc<dyn SafetyKernelClientTrait>`
//! so a test mock and the real SDK plug into the same socket.

use async_trait::async_trait;
use qorch_safety_kernel_client::{
    AuthorizeRequest, KernelClientError, KernelDecision, SafetyKernelClient,
};

/// Narrow trait the middleware calls; abstracted over the concrete
/// reqwest-based SDK so adversarial tests can inject a mock without
/// standing up a full HTTP server.
#[async_trait]
pub trait SafetyKernelClientTrait: Send + Sync + 'static {
    /// Submit an authorization request. Fail-closed contract: any
    /// `Err` MUST be treated as a rejection by the caller.
    async fn authorize(
        &self,
        request: &AuthorizeRequest,
    ) -> Result<KernelDecision, KernelClientError>;
}

#[async_trait]
impl SafetyKernelClientTrait for SafetyKernelClient {
    async fn authorize(
        &self,
        request: &AuthorizeRequest,
    ) -> Result<KernelDecision, KernelClientError> {
        SafetyKernelClient::authorize(self, request).await
    }
}

// -----------------------------------------------------------------
// Test mock — exposed publicly so the reference app's smoke tests
// and the in-crate adversarial suite share one implementation. The
// mock has no network surface; every call is a closure-driven
// in-process response.
// -----------------------------------------------------------------

/// Boxed closure stored inside [`MockSafetyKernelClient`]. Extracted
/// into a type alias to satisfy `clippy::type_complexity`; the trade-off
/// is that `Send + Sync + 'static` are now hidden behind the alias,
/// but every public constructor still bounds them.
type MockHandler = Box<
    dyn Fn(&AuthorizeRequest) -> Result<KernelDecision, KernelClientError> + Send + Sync + 'static,
>;

/// In-memory mock client. Used by the adversarial fixtures and by
/// the reference app's local-dev mode.
///
/// The mock holds a [`MockHandler`] closure so each test can program
/// a deterministic response.
pub struct MockSafetyKernelClient {
    handler: MockHandler,
}

impl MockSafetyKernelClient {
    /// Build a mock that always returns the configured closure result.
    #[must_use]
    pub fn new<F>(handler: F) -> Self
    where
        F: Fn(&AuthorizeRequest) -> Result<KernelDecision, KernelClientError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            handler: Box::new(handler),
        }
    }
}

#[async_trait]
impl SafetyKernelClientTrait for MockSafetyKernelClient {
    async fn authorize(
        &self,
        request: &AuthorizeRequest,
    ) -> Result<KernelDecision, KernelClientError> {
        (self.handler)(request)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use qorch_safety_kernel_client::KernelDecisionError;

    #[tokio::test]
    async fn mock_returns_configured_unavailable() {
        let mock = MockSafetyKernelClient::new(|_| {
            Err(KernelClientError::Decision(
                KernelDecisionError::Unavailable {
                    reason: "test".into(),
                },
            ))
        });
        let req = AuthorizeRequest {
            action: "x".into(),
            params_fingerprint: "0".repeat(64),
            run_id: "r".into(),
            subject: "s".into(),
            traceparent: None,
        };
        let r = mock.authorize(&req).await;
        assert!(matches!(
            r,
            Err(KernelClientError::Decision(
                KernelDecisionError::Unavailable { .. }
            ))
        ));
    }
}
