//! Policy-engine domain types —  scaffold (, ).
//!
//! This module hosts the pure, side-effect-free shapes for the
//! `/policy/module/authorize` family of endpoints added in.
//!  is **scaffold-only**: the four kernel routes return
//! `501 Not Implemented` and the registry / signing / audit-chain wiring
//! lands in slice 2. The types here exist so the slice-1 HTTP handlers,
//! contract tests, and the `OpenAPI` sketch in can typecheck
//! end-to-end against a single source of truth.
//!
//! # Boundary
//!
//! Per `agent/boundaries.toml` and the parent `crates/domain/` contract,
//! this module does NOT import:
//!
//! - `std::fs`, `std::env`, `std::net`, `std::time::SystemTime`
//! - `rand::*`, `sqlx::*`, `diesel::*`, `reqwest::*`, `rdkafka::*`,
//!   `tracing::*`, `log::*`
//!
//! Time and randomness reach this layer via the existing `Clock` and
//! `NonceSource` traits in `crates/domain/src/safety/mod.rs`. The
//! slice-1 types do not yet need either, but slice 2 will reuse those
//! traits unchanged.

pub mod claims;
pub mod types;
pub mod validation;

pub use claims::{
    ModuleAuthorizeClaims, ModuleRegisterClaims, POLICY_AUTHORIZE_ACTION, POLICY_AUTHORIZE_AUD,
    POLICY_REGISTER_ACTION, POLICY_REGISTER_AUD,
};
pub use types::{
    AuditEventKind, ModuleAuditEventRequest, ModuleAuditEventResponse, ModuleAuthorizeDecision,
    ModuleAuthorizeRequest, ModuleAuthorizeResponse, ModuleEventKind, ModuleRegisterRequest,
    ModuleRegisterResponse, ModuleStatusDecisionRow, ModuleStatusRegistration,
    ModuleStatusResponse,
};
pub use validation::{
    is_valid_module_path, MAX_MODULE_PATH_LEN, MODULE_PATH_INVALID_CHARSET_REASON,
};

#[cfg(test)]
mod import_discipline_test;
