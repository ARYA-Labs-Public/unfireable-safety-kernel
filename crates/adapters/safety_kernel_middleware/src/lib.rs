//! Safety Kernel middleware —   sub-deliverable 2c-rust.
//!
//! Axum/Tower middleware that wraps any inner service and gates
//! requests through the Safety Kernel HTTP service via the
//! `qorch-safety-kernel-client` SDK. See for the
//! design.
//!
//! # Surface
//!
//! - [`SafetyLayer`] — `tower::Layer<S>` implementation; clone-shareable.
//! - [`SafetyService`] — the wrapped service the layer produces.
//! - [`MiddlewarePolicy`] — three-tier enum (`Unrestricted`,
//!   `Supervised`, `Gated`).
//! - [`MiddlewarePolicyResolver`] — caller-provided trait that maps
//!   `(method, path)` to a [`MiddlewarePolicy`].
//! - [`MiddlewareError`] — rejection type; converts to HTTP 503 / 403.
//! - [`SafetyKernelClientTrait`] — the abstract client surface the
//!   middleware calls. The production impl lives in
//!   `qorch-safety-kernel-client`; tests inject a mock.
//! - [`SafetyToken`] — request extension attached on successful
//!   `Gated` authorization so downstream handlers can prove the
//!   middleware was actually invoked (defence against fixture #6,
//!   "bypass-attempt-direct").
//!
//! # Fail-closed contract
//!
//! For a `Gated` route, any `Err` from the SDK MUST short-circuit the
//! request with [`MiddlewareError`]. Never auto-allow. The unit tests
//! (`tests/adversarial.rs`) re-derive this property structurally.
//!
//! # Boundary
//!
//! This is an `adapters` crate. It depends on `qorch-safety-kernel-client`
//! and uses `tracing`/`axum`/`tower`/`reqwest`. The pure-types
//! substrate lives in `qorch-domain` and is reachable only by
//! re-export through the client SDK.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

mod client_trait;
mod error;
mod extractor;
mod layer;
mod policy;
mod service;
mod token;

pub use client_trait::{MockSafetyKernelClient, SafetyKernelClientTrait};
pub use error::MiddlewareError;
pub use extractor::{ExtractedClaims, RequestClaimsExtractor};
pub use layer::SafetyLayer;
pub use policy::{MiddlewarePolicy, MiddlewarePolicyResolver, StaticPolicy};
pub use service::SafetyService;
pub use token::SafetyToken;
