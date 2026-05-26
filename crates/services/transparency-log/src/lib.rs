//! Transparency-log library surface (, ).
//!
//! Step 5 fills in the real handlers + storage wiring + Ed25519 STH
//! minting + mTLS server config. The library target lets integration
//! tests build a router in-process without spinning the bin + a real
//! Postgres pool. Mirrors the bin/lib pattern used by
//! `crates/services/safety-kernel`.
//!
//! Module map:
//!   - [`auth`]   — `x-api-key` middleware. Only the kernel may
//!                  append; reads are gated behind the same key.
//!   - [`dto`]    — wire-shape request / response types
//!   - [`error`]  — `ServiceError` taxonomy mapped to HTTP responses
//!   - [`routes`] — axum handlers (`append`, `verify`, `sth`,
//!                  `consistency`, `health`)
//!   - [`router`] — `build_router(state)` consumed by the bin and
//!                  the integration tests
//!   - [`settings`] — env-driven `Settings` (signing key, verifying
//!                  key fingerprint, TLS, API key, DB URL)
//!   - [`state`]  — `AppState` holder for the storage adapter +
//!                  signing key + clock + caller-fingerprint pin
//!   - [`tls`]    — `axum_server::tls_rustls` server config builder

#![forbid(unsafe_code)]
// Doc-comments in this crate use plain prose for service-level prose
// (`api_key`, `kernel_key_fingerprint_sha256`, etc.). The kernel
// crate's `dto.rs` applies the same allow for the same reason — these
// names show up in narrative docs across the kernel + transparency-log
// surfaces and per-occurrence backticks are visual noise.
#![allow(clippy::doc_markdown)]
// Routes return `Result<_, ServiceError>`. The error variants are
// catalogued centrally in `error.rs`; per-function `# Errors` blocks
// would duplicate that catalog. The lib-level allow keeps the route
// handlers readable.
#![allow(clippy::missing_errors_doc)]
// `mod.rs` re-export ordering is the audit trail (`append` first, etc.)
// — letting pedantic insist on alphabetical re-orders here would
// scramble the human reading order without value.
#![allow(clippy::doc_overindented_list_items)]

pub mod auth;
pub mod dto;
pub mod error;
pub mod router;
pub mod routes;
pub mod settings;
pub mod state;
pub mod tls;
