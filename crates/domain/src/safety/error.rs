//! Kernel token error types — port of `packages/core/safety_tokens.py:127-145`.
//!
//! The Python module raises a small hierarchy: `KernelTokenError` (base)
//! plus four leaf subtypes (`Format`, `Signature`, `Claims`, `Expired`).
//! Rust mirrors this with one parent enum that wraps four kind-specific
//! errors so callers can `match` exhaustively while still pattern-matching
//! against the parent.
//!
//! All variants carry a stable machine-readable code (e.g.
//! `invalid_token_format`, `token_expired`) that exactly matches the
//! Python message strings. The codes are part of the equivalence
//! contract: the harness in W3 asserts deny-path `reason` strings are
//! byte-equal across implementations.

use thiserror::Error;

/// Format error — token shape is malformed (e.g. wrong number of dots,
/// invalid base64 in either half, claims payload that does not parse
/// as JSON, claims object that is not a dict).
#[derive(Debug, Error, PartialEq, Eq, Clone)]
#[error("{0}")]
pub struct KernelTokenFormatError(pub String);

/// Signature error — the Ed25519 signature did not validate against the
/// expected public key.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
#[error("{0}")]
pub struct KernelTokenSignatureError(pub String);

/// Claims error — claims payload is structurally JSON but fails type or
/// value validation (missing required key, wrong type, mismatch on a
/// caller-supplied expected value).
#[derive(Debug, Error, PartialEq, Eq, Clone)]
#[error("{0}")]
pub struct KernelTokenClaimsError(pub String);

/// Expired error — the token's `expires_at` is in the past relative to
/// the supplied `now` (after applying `leeway_s`).
#[derive(Debug, Error, PartialEq, Eq, Clone)]
#[error("{0}")]
pub struct KernelTokenExpiredError(pub String);

/// Parent error — wraps the four leaf kinds. Mirrors the Python
/// `KernelTokenError` parent class so callers can `match` either
/// the parent or a specific kind.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum KernelTokenError {
    /// Token format / encoding error.
    #[error(transparent)]
    Format(#[from] KernelTokenFormatError),
    /// Signature verification failed.
    #[error(transparent)]
    Signature(#[from] KernelTokenSignatureError),
    /// Claims structural / type validation failed.
    #[error(transparent)]
    Claims(#[from] KernelTokenClaimsError),
    /// Token has expired.
    #[error(transparent)]
    Expired(#[from] KernelTokenExpiredError),
}

impl KernelTokenError {
    /// Construct a Format error from a stable code.
    #[must_use]
    pub fn format(code: impl Into<String>) -> Self {
        Self::Format(KernelTokenFormatError(code.into()))
    }
    /// Construct a Signature error from a stable code.
    #[must_use]
    pub fn signature(code: impl Into<String>) -> Self {
        Self::Signature(KernelTokenSignatureError(code.into()))
    }
    /// Construct a Claims error from a stable code.
    #[must_use]
    pub fn claims(code: impl Into<String>) -> Self {
        Self::Claims(KernelTokenClaimsError(code.into()))
    }
    /// Construct an Expired error from a stable code.
    #[must_use]
    pub fn expired(code: impl Into<String>) -> Self {
        Self::Expired(KernelTokenExpiredError(code.into()))
    }
}
