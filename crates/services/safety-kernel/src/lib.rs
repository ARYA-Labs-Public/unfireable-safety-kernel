//! Library entrypoint for `qorch-safety-kernel`.
//!
//! The crate ships a binary (`bin/qorch-safety-kernel`, see `main.rs`),
//! but it also exposes a small library surface so integration tests
//! can exercise the route handlers in-process without spinning the
//! full binary + Python sidecar harness. The slice-1 scaffold tests in
//! `tests/policy_routes_scaffold.rs` rely on this — without the lib,
//! every adversarial-shape assertion would require a full
//! binary-spawn + Python-sidecar dance.
//!
//! Module visibility note: `main.rs` re-declares each module under its
//! own crate namespace via `mod...`. That works because `main.rs` and
//! `lib.rs` are separate compilation units; both can re-declare the
//! same `mod foo;` and the source file is shared. See
//! <https://doc.rust-lang.org/cargo/reference/cargo-targets.html#binaries>
//! for the canonical bin-and-lib pattern.
//!
//! Clippy note: a few handlers (`routes::meta::health`,
//! `routes::meta::public_key`) take `State<AppState>` and return
//! immediately without awaiting. Axum requires the function be `async`
//! anyway (handler trait bound), so the `unused_async` lint is
//! suppressed at the handler sites — that suppression existed
//! implicitly before this lib target landed (clippy didn't visit them
//! in bin-only builds); the explicit `#[allow]` keeps `cargo clippy
//! --workspace --all-targets -- -D warnings` green.

#![forbid(unsafe_code)]

// All four modules are re-exposed at `pub` so `qorch_safety_kernel::...`
// resolves from integration tests. None of these modules adds a public
// surface beyond what the bin already has — this is purely a target
// boundary.
pub mod auth;
pub mod dto;
/// Step-14R / ARY-1886: pluggable signing-key backend (env|gcp|…).
pub mod key_backend;
pub mod routes;
pub mod settings;
pub mod state;
///   Step 5 — outbound transparency-log client + trait
/// + idempotency-key helper. Lives in the kernel crate (not adapters)
/// because it's the kernel's private outbound dep; promote to a
/// shared adapter once a second caller appears.
pub mod transparency_client;
