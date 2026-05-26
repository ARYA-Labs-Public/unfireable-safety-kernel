//! qorch-adapters — I/O adapters for the safety-kernel.
//!
//! Implements the port traits declared in `qorch-application` and the
//! domain traits declared in `qorch-domain`. This is the only crate in
//! the workspace permitted to do I/O (HTTP, file system, network, clock,
//! RNG); the domain and application crates are pure.
//!
//! Modules:
//! - [`clock`]    — [`qorch_domain::safety::Clock`] implementation using
//!                  the system monotonic + wall clocks.
//! - [`nonce`]    — [`qorch_domain::safety::NonceSource`] implementation
//!                  using the OS CSPRNG (`getrandom`).
//! - [`policy_engine_client`] — IPC client for the policy engine sidecar
//!                              (Unix-socket transport, JSON wire format).
//!
//! Sibling crates that implement specific adapter surfaces:
//! - `qorch-safety-kernel-client`   — HTTP client SDK
//! - `qorch-safety-kernel-middleware` — axum `tower::Layer`
//! - `qorch-transparency-store`     — Postgres-backed log storage

pub mod clock;
pub mod nonce;
pub mod policy_engine_client;
