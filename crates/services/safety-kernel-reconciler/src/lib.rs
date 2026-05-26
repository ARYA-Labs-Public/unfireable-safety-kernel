//! Safety Kernel reconciler library surface (,
//!  Step 3).
//!
//! The reconciler ships as a binary; this library surface exists so
//! the 3-step algorithm + its unit tests live inside the crate
//! without smuggling them through `main.rs`. Step 3 fills it in:
//! `Reconciler`, `ReconcilerConfig`, `TickOutcome`, the three trait
//! seams for injection (registry / manifest / audit / transparency
//! log), and the production HTTP-backed impls.

#![forbid(unsafe_code)]

pub mod reconciler;

// Re-exports — keep `main.rs` (and any external integrator) free of
// the `reconciler::` qualifier chain.
pub use reconciler::{
    AuditSink, DriftAuditEvent, HttpManifestFetcher, HttpTransparencyLogClient, ManifestFetcher,
    OciRegistryClient, ReconcileError, Reconciler, ReconcilerConfig, RegistryClient,
    ReleaseManifest, TickOutcome, TransparencyLogClient, DEFAULT_INTERVAL_SECONDS,
    DEFAULT_MANIFEST_STALENESS_SECONDS,
};
