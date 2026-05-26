//! Request extension carrying the verified safety token.
//!
//! On a successful `Gated` authorization the middleware attaches a
//! [`SafetyToken`] to the request via `extensions_mut().insert(...)`.
//! Downstream handlers can require its presence as proof that the
//! middleware was invoked (defence against fixture #6,
//! "bypass-attempt-direct").
//!
//! The token bytes are intentionally opaque to the handler: anything
//! that needs to read claims must go back through the verifier.

use qorch_domain::safety::VerifiedClaims;
use std::sync::Arc;

/// Request extension stamped by the middleware on successful
/// authorize. Cloneable cheaply — the inner verified claims live
/// behind an `Arc`.
#[derive(Debug, Clone)]
pub struct SafetyToken {
    /// Compact Ed25519 token bytes (already verified against the
    /// pinned key by the SDK).
    pub token: String,
    /// Decoded + verified claims, re-derived from the token bytes by
    /// the SDK's pinned-key verifier.
    pub claims: Arc<VerifiedClaims>,
}

impl SafetyToken {
    /// Build a token extension from the SDK's `KernelDecision::Allow`
    /// outputs. Internal helper; the only caller is `service.rs`.
    #[must_use]
    pub(crate) fn new(token: String, claims: VerifiedClaims) -> Self {
        Self {
            token,
            claims: Arc::new(claims),
        }
    }
}
