//! Safety Kernel domain types — Slice 1 (ADR-014 / ARY-1990).
//!
//! This module is the pure, side-effect-free port of the Python
//! `packages/core/safety_tokens.py` token surface and the per-role
//! action allowlist at `packages/core/safety_kernel_routes.py`.
//!
//! The byte-stable wire format is binding across implementations: see
//! `docs/adr/adr-014-slice-1-equivalence.md` §1 for the JSON
//! serialization rules and §1.5 for the equivalence assertion.
//!
//! # Boundary
//!
//! Per `agent/boundaries.toml` and ADR-014 Slice 1 §6.1, this module
//! does NOT import:
//!
//! - `std::fs`, `std::env`, `std::net`, `std::time::SystemTime`
//! - `rand::*`, `sqlx::*`, `reqwest::*`, `tracing::*`, `log::*`
//!
//! Time and randomness are taken as parameters or via the `Clock` and
//! `NonceSource` traits below; production implementations live in
//! `crates/adapters/`.

pub mod api_action_allowlist;
pub mod claims;
pub mod client_state;
pub mod error;
pub mod token;

pub use api_action_allowlist::is_api_action_allowed;
pub use claims::{ApprovalClaims, AuthorizeClaims, ToClaimsMap};
pub use client_state::{CircuitConfig, CircuitState, CircuitTransition};
pub use error::{
    KernelTokenClaimsError, KernelTokenError, KernelTokenExpiredError, KernelTokenFormatError,
    KernelTokenSignatureError,
};
pub use token::{
    params_fingerprint, sign_kernel_token, stable_json, token_sha256, verify_kernel_token,
    VerifiedClaims,
};

/// Test seam — pure trait describing wall-clock time as `f64` epoch
/// seconds. The Safety Kernel sources `now` from a `Clock` so the
/// equivalence harness can pin both Python and Rust to the same value.
///
/// Per ADR-014 Slice 1 Appendix B, the production implementation lives
/// in `crates/adapters/src/clock.rs` and uses `SystemTime::now`; tests
/// inject a `FixedClock(f64)` via this trait.
pub trait Clock: Send + Sync {
    /// Returns the current time as f64 epoch seconds (UTC).
    fn now(&self) -> f64;
}

/// Test seam — pure trait describing a base64url-no-pad nonce source.
///
/// The production implementation in `crates/adapters/` uses `OsRng` and
/// the `base64::engine::general_purpose::URL_SAFE_NO_PAD` engine; tests
/// inject `FixedNonce(&'static str)` so the equivalence harness can
/// pin Rust to the same nonce Python produced via
/// `secrets.token_urlsafe(16)`.
pub trait NonceSource: Send + Sync {
    /// Returns a fresh base64url-no-pad nonce string (typically 16 bytes
    /// of entropy → 22-char string, matching Python's
    /// `secrets.token_urlsafe(16)`).
    fn nonce_b64(&self) -> String;
}
