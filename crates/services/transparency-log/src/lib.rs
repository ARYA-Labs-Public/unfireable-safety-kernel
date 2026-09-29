//! Transparency-log library surface (ADR-014 Phase 3 §3, internal-ref).
//!
//! Step 5 fills in the real handlers + storage wiring + Ed25519 STH
//! minting + mTLS server config. The library target lets integration
//! tests build a router in-process without spinning the bin + a real
//! Postgres pool. Mirrors the bin/lib pattern used by
//! `crates/services/safety-kernel`.
//!
//! Module map:
//!   - [`clock`] — production `Clock` implementation reading
//!                 wall-clock seconds. Lives here rather than in a
//!                 shared adapter crate because arya-core has no
//!                 equivalent of the monorepo's `qorch-adapters`, where this
//!                 type originated. arya-core already carries several
//!                 private copies of the same type, so consolidating
//!                 them is worth doing separately rather than as part
//!                 of this relocation (internal-ref).
//!   - [`auth`]   — `x-api-key` middleware. Only the kernel may
//!                  append; reads are gated behind the same key.
//!   - [`dto`]    — wire-shape request / response types
//!   - [`env_source`] — the `EnvSource` seam that lets [`settings`] be
//!                  read from an in-memory map instead of the process
//!                  environment. Mirrors
//!                  `arya-core-safety-kernel-app`'s `db_env` rather
//!                  than depending on it — that dependency would pull
//!                  in 14 further crates (internal-ref).
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
// `Mutex<Connection>` guards a single owned sqlite handle in
// `wave_session_detail`. `lock().expect(...)` only panics on a
// poisoned mutex (a thread crashed while holding the lock) — a
// programming-error path documented at the module level. Per-function
// `# Panics` sections would duplicate that rationale without adding
// signal.
#![allow(clippy::missing_panics_doc)]
// `mod.rs` re-export ordering is the audit trail (`append` first, etc.)
// — letting pedantic insist on alphabetical re-orders here would
// scramble the human reading order without value.
#![allow(clippy::doc_overindented_list_items)]

pub mod auth;
pub mod clock;
pub mod dto;
pub mod env_source;
pub mod error;
/// internal-ref — per-skill HMAC `x-api-key` table for wave-session
/// writers. See module docs for the identity-vs-label rationale and
/// the back-compat (single-shared-key) fallback path.
pub mod per_skill_keys;
pub mod router;
pub mod routes;
pub mod settings;
pub mod state;
pub mod tls;
/// internal-ref — sqlite-backed `wave_session_detail` denorm side-table
/// that bounds the in-process residency of the per-leaf side data.
/// Schema-as-code via [`wave_session_detail::ensure_schema`]; see the
/// module-level docs for the rationale and rollback procedure.
pub mod wave_session_detail;
