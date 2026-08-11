#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

//! Control-plane Reaper library (Phase 1).
//!
//! A minimal privileged supervisor that verifies a signed `RevokeCompute` kill
//! minted by the Safety Kernel and stops the agent VM from OUTSIDE the agent's
//! failure domain. It holds only the pinned kernel PUBLIC key, a `reaper` API
//! key, and — behind [`executor::ComputeExecutor`] — the authority to stop a
//! compute instance.
//!
//! The shared wire contract (`RevokeComputeClaims` / `RestoreClaims`,
//! audiences, fingerprint recipes, DTOs) is CONSUMED from
//! `qorch_domain::safety::revoke`; nothing here redefines it.
//!
//! # Fail-safe posture
//!
//! - Every candidate is verified against the PINNED key before acting; any
//!   verify failure is a hard refuse (never a kill on an unverifiable token).
//! - A persistent seen-nonce store defeats replay (the kernel is stateless on
//!   nonce).
//! - If the kernel goes dark past the liveness deadline, the Reaper FAILS
//!   CLOSED and stops the configured target.
//! - The real cloud executor is INERT unless explicitly armed with a scratch
//!   target; live arming is operator-gated.
//! - A config-driven self-protection denylist (the Reaper's own host plus any
//!   configured protected instances) refuses a stop/start unconditionally,
//!   before every other guard.

pub mod config;
pub mod executor;
pub mod kernel_client;
pub mod nonce_store;
pub mod reaper;
pub mod tlog;

pub use config::{ConfigError, ReaperConfig};
pub use executor::{
    fetch_self_identity, ComputeExecutor, ExecutorError, GceInstanceOps, GcpComputeExecutor,
    MetadataGceOps, MockComputeExecutor, ProtectedCoord, StopOutcome,
};
pub use kernel_client::{KernelClient, KernelClientError, PendingPull, ReqwestKernelClient};
pub use nonce_store::{FileNonceStore, MemNonceStore, NonceKey, SeenNonceStore};
pub use reaper::{LivenessAction, Outcome, Reaper, RejectReason};
pub use tlog::{KillRecord, KillRecorder, KillRecorderError, ReqwestKillRecorder};
