//   Step 2: same scaffold-stage allows that the parent
// `crates/adapters/src/lib.rs` carried before the module was promoted to
// its own crate. Removing them is a separate code-quality pass (Step 3+).
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

//! Safety Kernel client adapter —.
//!
//! Rust client SDK for the Safety Kernel HTTP service shipped by
//!  (crates/services/safety-kernel/). Per 
//! reconciliation, this module is the Rust substrate equivalent of the
//! Python `packages/safety/client/` SDK; the two coexist while
//! per-slice ports complete.
//!
//! # Unfireability contract
//!
//! The whole point of this SDK is FAIL-CLOSED behaviour. When the
//! kernel is unreachable, `SafetyKernelClient::authorize()` MUST
//! return `KernelClientError::Decision(KernelDecisionError::Unavailable)`
//! — never auto-approve, never time
//! out silently. The circuit breaker enforces this property
//! structurally (see `circuit_breaker.rs`). The token verifier
//! (`token.rs`) refuses any response whose Ed25519 signature does not
//! match the pinned public key, preventing a tampered kernel from
//! issuing a forged ALLOW.
//!
//! # Module layout
//!
//! - `types`           — `KernelDecision` (re-exported from `qorch_domain::safety::decision`),
//!                        `KernelClientError`, request/response DTOs (re-exports from contracts)
//! - `client`          — `SafetyKernelClient` (reqwest-based HTTP client)
//! - `circuit_breaker` — Fail-closed breaker driven by `qorch_domain::safety::CircuitState`
//! - `mtls`            — rustls config factory for mTLS to the kernel
//! - `token`           — Ed25519 verifier wrapper using pinned public key
//! - `reqwest_client`  —   dispatcher SK client (
//!                       MED-2): `ReqwestSafetyKernelClient` impl of
//!                       `qorch_application::safety_kernel::SafetyKernelClient`.
//!                       Predates this SDK and is still used by
//!                       the `qorch-ddi-dispatch` binary; kept as a
//!                       submodule + re-exported so that import path
//!                       keeps resolving while the two SDKs converge.

pub mod circuit_breaker;
pub mod client;
pub mod mtls;
pub mod reqwest_client;
pub mod token;
pub mod types;

pub use circuit_breaker::CircuitBreaker;
pub use client::SafetyKernelClient;
pub use reqwest_client::{ReqwestSafetyKernelClient, ReqwestSafetyKernelConfig};
pub use token::PinnedKeyVerifier;
pub use types::{
    AuditEntry, AuthorizeRequest, AuthorizeResponse, HealthResponse, KernelClientError,
    KernelDecision, KernelDecisionError, PublicKeyResponse,
};
