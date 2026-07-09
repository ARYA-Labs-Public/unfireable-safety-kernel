//! In-memory `TransparencyStore` implementation for tests + dev.
//!
//! Backed by an async `Mutex<Inner>`; both reads and writes take the
//! lock so the semantics match the SERIALIZABLE Postgres impl
//! exactly. Not designed for production throughput — the lock is the
//! whole-store granularity, and the root recomputes on every read.
//!
//! Boundary: lives in the adapter crate, so `tokio` + `tracing` are
//! permitted.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use qorch_domain::transparency::{
    build_inclusion_proof as build_inclusion_proof_pure, compute_root, leaf_hash, InclusionProof,
    MerkleLeaf, VerificationError,
};
use tokio::sync::Mutex;

use crate::{AppendInput, AppendOutcome, StoreError, TransparencyStore};

/// In-memory store state. The `idempotency` map points to the
/// 0-based position in `leaves`; on retry we look the key up and
/// short-circuit.
#[derive(Default, Debug)]
struct Inner {
    leaves: Vec<MerkleLeaf>,
    /// Caller-supplied payload, kept so we can detect a real
    /// `Conflict` (same key, different bytes) vs. a benign retry.
    payloads: Vec<Vec<u8>>,
    /// `idempotency_key -> leaf_index`. Hash-map keyed on the 32-byte
    /// fingerprint directly.
    idempotency: HashMap<[u8; 32], u64>,
}

/// In-memory `TransparencyStore`. `Arc<Self>` is `Clone`, so the
/// transparency-log service can share a single store across axum
/// handlers.
#[derive(Default, Debug, Clone)]
pub struct MemoryTransparencyStore {
    inner: Arc<Mutex<Inner>>,
}

impl MemoryTransparencyStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TransparencyStore for MemoryTransparencyStore {
    async fn append(&self, payload: AppendInput) -> Result<AppendOutcome, StoreError> {
        let mut inner = self.inner.lock().await;

        // Idempotency check: if we've seen this key before, return the
        // existing outcome (or Conflict if the payload diverged).
        if let Some(&existing_idx) = inner.idempotency.get(&payload.idempotency_key) {
            let idx_usize = usize::try_from(existing_idx)
                .map_err(|_| StoreError::Backend("leaf_index overflow".into()))?;
            let existing_payload = &inner.payloads[idx_usize];
            if existing_payload != &payload.payload {
                return Err(StoreError::Conflict);
            }
            let existing_leaf = &inner.leaves[idx_usize];
            return Ok(AppendOutcome {
                leaf_index: existing_idx,
                leaf_hash: existing_leaf.hash,
                // Key already present: this is an idempotent replay.
                // Decided under the store mutex, so a concurrent
                // fresh insert of the same key cannot also see this.
                idempotent_replay: true,
            });
        }

        let leaf_index = u64::try_from(inner.leaves.len())
            .map_err(|_| StoreError::Backend("tree_size overflow".into()))?;
        let hash = leaf_hash(&payload.payload);
        let new_leaf = MerkleLeaf {
            hash,
            leaf_index,
            occurred_at_epoch_seconds: payload.occurred_at_epoch_seconds,
        };
        inner.leaves.push(new_leaf);
        inner.payloads.push(payload.payload);
        inner
            .idempotency
            .insert(payload.idempotency_key, leaf_index);

        Ok(AppendOutcome {
            leaf_index,
            leaf_hash: hash,
            // Fresh insert under the store mutex.
            idempotent_replay: false,
        })
    }

    async fn get_leaf(&self, leaf_index: u64) -> Result<Option<MerkleLeaf>, StoreError> {
        let inner = self.inner.lock().await;
        let Ok(idx_usize) = usize::try_from(leaf_index) else {
            return Ok(None);
        };
        Ok(inner.leaves.get(idx_usize).cloned())
    }

    async fn current_size(&self) -> Result<u64, StoreError> {
        let inner = self.inner.lock().await;
        u64::try_from(inner.leaves.len())
            .map_err(|_| StoreError::Backend("tree_size overflow".into()))
    }

    async fn current_root(&self) -> Result<[u8; 32], StoreError> {
        let inner = self.inner.lock().await;
        if inner.leaves.is_empty() {
            return Ok([0u8; 32]);
        }
        compute_root(&inner.leaves).map_err(StoreError::Verification)
    }

    async fn build_inclusion_proof(&self, leaf_index: u64) -> Result<InclusionProof, StoreError> {
        let inner = self.inner.lock().await;
        if inner.leaves.is_empty() {
            return Err(StoreError::Verification(VerificationError::EmptyTree));
        }
        if leaf_index >= u64::try_from(inner.leaves.len()).unwrap_or(u64::MAX) {
            return Err(StoreError::Verification(
                VerificationError::LeafIndexOutOfBounds,
            ));
        }
        build_inclusion_proof_pure(&inner.leaves, leaf_index).map_err(StoreError::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qorch_domain::transparency::verify_inclusion_proof;

    fn input(key_byte: u8, payload: &[u8], occurred: u64) -> AppendInput {
        AppendInput {
            idempotency_key: [key_byte; 32],
            payload: payload.to_vec(),
            occurred_at_epoch_seconds: occurred,
        }
    }

    #[tokio::test]
    async fn append_returns_monotonic_indices() {
        let store = MemoryTransparencyStore::new();
        for i in 0..10u8 {
            let outcome = store
                .append(input(i, &[i, i, i], u64::from(i)))
                .await
                .unwrap();
            assert_eq!(outcome.leaf_index, u64::from(i));
            assert_eq!(outcome.leaf_hash, leaf_hash(&[i, i, i]));
        }
        assert_eq!(store.current_size().await.unwrap(), 10);
    }

    #[tokio::test]
    async fn idempotent_append_returns_existing_index() {
        let store = MemoryTransparencyStore::new();
        let first = store.append(input(7, b"hello", 100)).await.unwrap();
        let second = store.append(input(7, b"hello", 100)).await.unwrap();
        // Same ledger position + hash on the retry...
        assert_eq!(first.leaf_index, second.leaf_index);
        assert_eq!(first.leaf_hash, second.leaf_hash);
        // ...but the fresh/replay flag distinguishes them: the first
        // call minted the leaf, the second is an idempotent replay.
        assert!(!first.idempotent_replay, "first call is a fresh insert");
        assert!(second.idempotent_replay, "second call is a replay");
        assert_eq!(store.current_size().await.unwrap(), 1);
        // Throwing in a third with different occurred timestamp but
        // same payload + key still returns the existing entry — we
        // de-dup on the idempotency key, not on the payload metadata.
        let third = store.append(input(7, b"hello", 9999)).await.unwrap();
        assert_eq!(third.leaf_index, first.leaf_index);
        assert_eq!(third.leaf_hash, first.leaf_hash);
        assert!(third.idempotent_replay, "third call is a replay");
        assert_eq!(store.current_size().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn idempotent_append_payload_mismatch_is_conflict() {
        let store = MemoryTransparencyStore::new();
        store.append(input(7, b"hello", 100)).await.unwrap();
        let err = store
            .append(input(7, b"hello-different", 100))
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict));
    }

    #[tokio::test]
    async fn current_root_reflects_appends() {
        let store = MemoryTransparencyStore::new();
        assert_eq!(store.current_root().await.unwrap(), [0u8; 32]);
        store.append(input(1, b"a", 1)).await.unwrap();
        let r1 = store.current_root().await.unwrap();
        store.append(input(2, b"b", 2)).await.unwrap();
        let r2 = store.current_root().await.unwrap();
        assert_ne!(r1, r2);
    }

    #[tokio::test]
    async fn inclusion_proof_verifies_against_current_root() {
        let store = MemoryTransparencyStore::new();
        for i in 0..7u8 {
            store
                .append(input(i, &[i, i + 1, i + 2], u64::from(i)))
                .await
                .unwrap();
        }
        let root = store.current_root().await.unwrap();
        for idx in 0u64..7 {
            let proof = store.build_inclusion_proof(idx).await.unwrap();
            verify_inclusion_proof(&proof, &root).expect("proof verifies");
        }
    }

    #[tokio::test]
    async fn get_leaf_returns_none_past_end() {
        let store = MemoryTransparencyStore::new();
        store.append(input(1, b"a", 1)).await.unwrap();
        assert!(store.get_leaf(0).await.unwrap().is_some());
        assert!(store.get_leaf(1).await.unwrap().is_none());
        assert!(store.get_leaf(u64::MAX).await.unwrap().is_none());
    }

    /// 100 simultaneous appends. Each task uses its own
    /// `idempotency_key` so none should de-duplicate. We assert:
    ///   - No errors.
    ///   - Indices are exactly the set {0..100} (no gaps, no dupes).
    ///   - Final size is 100 and the root verifies against per-leaf
    ///     inclusion proofs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_appends_linearize() {
        let store = MemoryTransparencyStore::new();
        let n: u32 = 100;
        let mut tasks = Vec::with_capacity(n as usize);
        for i in 0..n {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                // Idempotency key derived from `i` so each task has a
                // unique fingerprint — collisions across tasks would
                // de-dup and skew the assertion.
                let mut key = [0u8; 32];
                key[..4].copy_from_slice(&i.to_be_bytes());
                let payload = i.to_be_bytes().to_vec();
                store
                    .append(AppendInput {
                        idempotency_key: key,
                        payload,
                        occurred_at_epoch_seconds: u64::from(i),
                    })
                    .await
                    .unwrap()
            }));
        }
        let mut indices = Vec::with_capacity(n as usize);
        for t in tasks {
            indices.push(t.await.unwrap().leaf_index);
        }
        indices.sort_unstable();
        let expected: Vec<u64> = (0..u64::from(n)).collect();
        assert_eq!(indices, expected, "no gaps and no duplicates");
        assert_eq!(store.current_size().await.unwrap(), u64::from(n));

        // Spot-check: build + verify an inclusion proof for the
        // first, middle, last leaves under the final root.
        let root = store.current_root().await.unwrap();
        for &idx in &[0u64, u64::from(n) / 2, u64::from(n) - 1] {
            let proof = store.build_inclusion_proof(idx).await.unwrap();
            verify_inclusion_proof(&proof, &root)
                .expect("inclusion proof verifies under final root");
        }
    }
}
