//! qorch-application — use-case orchestration layer for the safety-kernel.
//!
//! Pure-Rust port-and-adapters (hexagonal) "application" layer. Holds the
//! use cases that orchestrate the domain, defines the port traits adapters
//! implement, and stays free of I/O, network, clock, and RNG access.
//!
//! Modules:
//! - [`safety_kernel`] — client-side trait + DTOs for the safety-kernel
//!   service. Adapters in `qorch-safety-kernel-client` implement
//!   [`safety_kernel::SafetyKernelClient`] over HTTP.
//!
//! The port traits and DTOs in this crate are the boundary between the
//! application code and the I/O adapters. Crates that implement those
//! ports live under `crates/adapters/`.

pub mod safety_kernel;
