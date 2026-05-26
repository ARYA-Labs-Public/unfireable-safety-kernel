//! `tower::Layer` factory that produces a [`crate::SafetyService`].
//!
//! The layer holds the three pieces of shared state every wrapped
//! request needs:
//!
//! - The SK client (behind `Arc<dyn SafetyKernelClientTrait>`)
//! - The policy resolver (behind `Arc<dyn MiddlewarePolicyResolver>`)
//! - The claims extractor (behind `Arc<dyn RequestClaimsExtractor>`)
//!
//! Construction is fluent: callers may swap the extractor; the
//! default is `DefaultExtractor`. The layer is `Clone` (cheap — all
//! three fields are `Arc`).

use std::sync::Arc;
use tower::Layer;

use crate::client_trait::SafetyKernelClientTrait;
use crate::extractor::{DefaultExtractor, RequestClaimsExtractor};
use crate::policy::MiddlewarePolicyResolver;
use crate::service::SafetyService;

/// `tower::Layer` that produces a [`SafetyService`] around any inner
/// `tower::Service` (typically an `axum::Router`).
#[derive(Clone)]
pub struct SafetyLayer {
    client: Arc<dyn SafetyKernelClientTrait>,
    policy: Arc<dyn MiddlewarePolicyResolver>,
    extractor: Arc<dyn RequestClaimsExtractor>,
}

impl SafetyLayer {
    /// Construct a layer with the default extractor
    /// ([`DefaultExtractor`]).
    #[must_use]
    pub fn new(
        client: Arc<dyn SafetyKernelClientTrait>,
        policy: Arc<dyn MiddlewarePolicyResolver>,
    ) -> Self {
        Self {
            client,
            policy,
            extractor: Arc::new(DefaultExtractor),
        }
    }

    /// Swap the extractor used to build `AuthorizeRequest` bodies.
    #[must_use]
    pub fn with_extractor(mut self, extractor: Arc<dyn RequestClaimsExtractor>) -> Self {
        self.extractor = extractor;
        self
    }
}

impl<S> Layer<S> for SafetyLayer {
    type Service = SafetyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SafetyService {
            inner,
            client: Arc::clone(&self.client),
            policy: Arc::clone(&self.policy),
            extractor: Arc::clone(&self.extractor),
        }
    }
}
