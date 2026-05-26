//! Append-only Merkle transparency-log storage adapter (
//!  §5,  Step 4).
//!
//! Two impls are provided:
//!
//!   - [`memory::MemoryTransparencyStore`] — `Arc<Mutex<...>>`-backed
//!     in-memory store. Used by the transparency-log service's unit
//!     tests, by the reconciler in dev, and by anyone who wants to
//!     wire the trait without standing up Postgres.
//!   - [`postgres::PgTransparencyStore`] — Postgres-backed production
//!     store. Uses `SERIALIZABLE` isolation per;
//!     `INSERT... ON CONFLICT (idempotency_key) DO UPDATE...
//!     RETURNING` guarantees that retried appends return the
//!     **existing** row's index rather than minting a new one (ADR §6
//!     idempotency demand).
//!
//! The trait itself is in this module so consumers can write
//! `Arc<dyn TransparencyStore>` without pulling in either impl.
//!
//! Boundary: this crate imports `sqlx`, `tokio`, `tracing` —
//! permissible because it's an adapter. The `qorch-domain` types it
//! references (`MerkleLeaf`, `InclusionProof`, `VerificationError`)
//! stay pure.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod memory;
pub mod postgres;

use async_trait::async_trait;
use qorch_domain::transparency::{InclusionProof, MerkleLeaf, VerificationError};

/// Payload submitted by the kernel (or any other producer) to the
/// transparency-log adapter.
///
/// `idempotency_key` is a caller-chosen 32-byte fingerprint that the
/// store de-duplicates on. The kernel uses SHA-256(token bytes) per
///; this trait does not enforce that choice — it
/// just requires the key be stable across retries of the same logical
/// append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendInput {
    /// Stable 32-byte fingerprint the store uses for de-duplication.
    pub idempotency_key: [u8; 32],
    /// Serialized payload bytes; the store records these verbatim and
    /// hashes them per RFC-6962 to derive `leaf_hash`.
    pub payload: Vec<u8>,
    /// Wall-clock instant the underlying event happened, in seconds
    /// since the Unix epoch.
    pub occurred_at_epoch_seconds: u64,
}

/// Outcome of a successful append.
///
/// On a retry that hits the idempotency path, `leaf_index` and
/// `leaf_hash` reflect the **existing** row — the store returns the
/// original entry, never minting a new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendOutcome {
    /// 0-based ledger position.
    pub leaf_index: u64,
    /// RFC-6962 leaf hash recorded for this entry.
    pub leaf_hash: [u8; 32],
}

/// Errors returned by `TransparencyStore` implementations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// An idempotency-key collision was detected where the existing
    /// row's payload disagrees with the caller's payload. This is a
    /// genuine logic error (different bytes under the same key), not
    /// a benign retry; the store does NOT swallow it.
    #[error("idempotency key collision with mismatched payload")]
    Conflict,

    /// Backend-specific failure (DB connection, transaction abort,
    /// serialization failure that exhausted retry budget, etc.).
    /// The wrapped string carries the original message; structured
    /// detail belongs in `tracing` spans the impl emits.
    #[error("transparency-store backend error: {0}")]
    Backend(String),

    /// Pure-domain verification error surfaced from
    /// `qorch_domain::transparency::*`. Currently only reachable via
    /// `build_inclusion_proof` — but keeping the variant means
    /// consumers don't have to convert at every call site.
    #[error("transparency-store verification error: {0}")]
    Verification(#[from] VerificationError),
}

/// Async trait for transparency-log storage adapters.
///
/// All methods are `async` so the Postgres impl can `.await`
/// `sqlx::query`; the in-memory impl is still trivially `async`
/// (it just doesn't suspend).
///
/// Contract notes:
///
/// - `append` is idempotent on `idempotency_key`: a second call with
///   the same key + payload returns the **existing** outcome (not a
///   new index). A second call with the same key + *different*
///   payload returns [`StoreError::Conflict`].
/// - `current_size` / `current_root` reflect the state visible to
///   the calling task; under concurrent appends, both methods see a
///   consistent point-in-time snapshot.
/// - `build_inclusion_proof` is computed against the current tree
///   (whatever `current_size` returns at the moment of the call).
#[async_trait]
pub trait TransparencyStore: Send + Sync {
    /// Append a new leaf. Idempotent on `payload.idempotency_key`.
    async fn append(&self, payload: AppendInput) -> Result<AppendOutcome, StoreError>;

    /// Fetch a leaf by index. Returns `Ok(None)` when the index does
    /// not exist (i.e. it's past the current tree size).
    async fn get_leaf(&self, leaf_index: u64) -> Result<Option<MerkleLeaf>, StoreError>;

    /// Number of leaves currently in the ledger.
    async fn current_size(&self) -> Result<u64, StoreError>;

    /// Current Merkle root hash. Returns the all-zero sentinel for an
    /// empty tree (callers should check `current_size() == 0` if they
    /// need to distinguish; this avoids forcing `Option` through a
    /// frequently-called path).
    async fn current_root(&self) -> Result<[u8; 32], StoreError>;

    /// Build the RFC-6962 inclusion proof for `leaf_index` against
    /// the current tree.
    async fn build_inclusion_proof(
        &self,
        leaf_index: u64,
    ) -> Result<InclusionProof, StoreError>;
}
