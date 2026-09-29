//! qorch-domain — pure types and traits for the safety-kernel.
//!
//! This crate is the innermost layer of the workspace: types, traits,
//! and pure functions only — no I/O, no network, no clock, no randomness.
//! Anything that needs to do those things lives in
//! `safety-kernel-application` (orchestration) or a crate under
//! `crates/adapters/` (the actual side effect).
//!
//! Boundary check: the forbidden imports are `std::fs`, `std::env`,
//! `std::net`, `std::time::SystemTime`, `rand::`, `sqlx::`, `diesel::`,
//! `reqwest::`, `rdkafka::`, `tracing::`, `log::`. The machine-readable
//! declaration (`agent/boundaries.toml`) lives in the monorepo; in this
//! repo, code review plus `safety/policy/import_discipline_test.rs`
//! enforce the rule.
//!
//! Submodules:
//!
//! - [`safety`] — Safety-kernel domain: claims, tokens, decisions,
//!   client state, episodic chain, API-action allow-list, policy types
//!   + validation.
//! - [`transparency`] — Transparency-log Merkle ledger types: leaves,
//!   proofs, signed tree heads (STH).
//! - [`wave`] — Type-state for the ceremony pipeline used by the
//!   transparency-log `/v1/wave/session` route.

#![forbid(unsafe_code)]

pub mod mcp_audit;
pub mod safety;
pub mod transparency;
pub mod wave;
