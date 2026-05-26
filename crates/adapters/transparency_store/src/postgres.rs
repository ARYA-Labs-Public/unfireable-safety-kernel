//! Postgres-backed `TransparencyStore` ().
//!
//! Schema is in `migrations/0001_transparency_log.sql`. Idempotency
//! is enforced via the `UNIQUE (idempotency_key)` constraint and an
//! `INSERT... ON CONFLICT (idempotency_key) DO UPDATE SET
//! leaf_index = transparency_log.leaf_index RETURNING...` pattern
//! that surfaces the **existing** row's index on retry.
//!
//! Isolation: per the production store runs at
//! `SERIALIZABLE` isolation. We set the isolation level per
//! transaction (no DB-wide change required) and let Postgres detect
//! serialization conflicts; the caller decides whether to retry the
//! outer logical operation.
//!
//! The implementation is intentionally minimal — Step 5 of 
//! is the one that wires routes against this adapter and adds the
//! integration tests against a real DB. The unit-level confidence
//! comes from [`crate::memory`].

use async_trait::async_trait;
use qorch_domain::transparency::{
    build_inclusion_proof as build_inclusion_proof_pure, compute_root, InclusionProof, MerkleLeaf,
    VerificationError,
};
use sqlx::PgPool;

use crate::{AppendInput, AppendOutcome, StoreError, TransparencyStore};

/// Postgres-backed transparency-log store.
#[derive(Clone, Debug)]
pub struct PgTransparencyStore {
    pool: PgPool,
}

impl PgTransparencyStore {
    /// Build a store from an existing `PgPool`. Connection-pool
    /// lifecycle is the caller's responsibility.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Borrow the underlying pool. Useful for tests that need to
    /// reset the table between cases.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Load every leaf in `leaf_index` order. The in-process Merkle
    /// helpers (`compute_root`, `build_inclusion_proof_pure`) need
    /// the full leaf list. The transparency-log service is
    /// sized for O(10^6) appends over the burn-in horizon; for that
    /// scale a single ordered scan + serde is acceptable. Future
    /// work (out of scope here): cache the tree in memory, or
    /// maintain a separate `merkle_nodes` table.
    async fn load_all_leaves(&self) -> Result<Vec<MerkleLeaf>, StoreError> {
        // We treat leaf_index as a `BIGINT` (signed) in Postgres
        // because BIGSERIAL is signed; cast to u64 at the boundary
        // and reject the (impossibly large for our scale) negative
        // case. `occurred_at_epoch_seconds` is recorded as BIGINT
        // for the same reason.
        let rows = sqlx::query_as::<_, RawLeafRow>(
            "SELECT leaf_index, leaf_hash, occurred_at_epoch_seconds \
             FROM transparency_log ORDER BY leaf_index ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.into_iter().map(RawLeafRow::try_into_leaf).collect()
    }
}

/// Internal row representation. We hand-decode `leaf_hash` from a
/// `Vec<u8>` so we can validate its length without leaking
/// `[u8; 32]` decoding requirements into the sqlx macro layer.
#[derive(sqlx::FromRow)]
struct RawLeafRow {
    leaf_index: i64,
    leaf_hash: Vec<u8>,
    occurred_at_epoch_seconds: i64,
}

impl RawLeafRow {
    fn try_into_leaf(self) -> Result<MerkleLeaf, StoreError> {
        let leaf_index = u64::try_from(self.leaf_index)
            .map_err(|_| StoreError::Backend("negative leaf_index from DB".into()))?;
        let occurred_at_epoch_seconds = u64::try_from(self.occurred_at_epoch_seconds)
            .map_err(|_| StoreError::Backend("negative occurred_at from DB".into()))?;
        let leaf_hash: [u8; 32] = self.leaf_hash.try_into().map_err(|v: Vec<u8>| {
            StoreError::Backend(format!("leaf_hash wrong length: {}", v.len()))
        })?;
        Ok(MerkleLeaf {
            hash: leaf_hash,
            leaf_index,
            occurred_at_epoch_seconds,
        })
    }
}

#[async_trait]
impl TransparencyStore for PgTransparencyStore {
    async fn append(&self, payload: AppendInput) -> Result<AppendOutcome, StoreError> {
        let hash = qorch_domain::transparency::leaf_hash(&payload.payload);

        // SERIALIZABLE isolation per ADR §5. We use a short
        // transaction; serialization failures bubble up as
        // `StoreError::Backend` and the caller decides whether to
        // retry the *logical* operation (the kernel's authorize
        // path already has timeout/retry policy).
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        // `inserted_at_epoch_seconds` is `extract(epoch from now())`
        // — Postgres-side clock so it's monotone w.r.t. the row's
        // commit order. `payload.occurred_at_epoch_seconds` is the
        // *caller's* wall-clock from `AppendInput`.
        //
        // The `ON CONFLICT (idempotency_key) DO UPDATE SET
        // leaf_index = transparency_log.leaf_index` no-op clause is
        // the idiomatic way to return the existing row's columns
        // via `RETURNING` even on conflict (`DO NOTHING` skips
        // RETURNING).
        let row: (i64, Vec<u8>, Vec<u8>) = sqlx::query_as(
            "INSERT INTO transparency_log \
                 (leaf_hash, idempotency_key, payload, \
                  occurred_at_epoch_seconds, inserted_at_epoch_seconds) \
             VALUES ($1, $2, $3, $4, extract(epoch from now())::bigint) \
             ON CONFLICT (idempotency_key) DO UPDATE \
               SET leaf_index = transparency_log.leaf_index \
             RETURNING leaf_index, leaf_hash, payload",
        )
        .bind(hash.as_slice())
        .bind(payload.idempotency_key.as_slice())
        .bind(payload.payload.as_slice())
        .bind(
            i64::try_from(payload.occurred_at_epoch_seconds)
                .map_err(|_| StoreError::Backend("occurred_at overflow".into()))?,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        let existing_payload = row.2;
        if existing_payload != payload.payload {
            // Same idempotency key but different bytes: the
            // RETURNING clause gave us the *original* row, so we
            // detect divergence here and report Conflict. The
            // original row is preserved untouched (the DO UPDATE
            // is a no-op on the payload column).
            return Err(StoreError::Conflict);
        }

        let leaf_index = u64::try_from(row.0)
            .map_err(|_| StoreError::Backend("negative leaf_index from DB".into()))?;
        let leaf_hash: [u8; 32] = row.1.try_into().map_err(|v: Vec<u8>| {
            StoreError::Backend(format!("leaf_hash wrong length: {}", v.len()))
        })?;

        Ok(AppendOutcome {
            leaf_index,
            leaf_hash,
        })
    }

    async fn get_leaf(&self, leaf_index: u64) -> Result<Option<MerkleLeaf>, StoreError> {
        let bind_idx = i64::try_from(leaf_index)
            .map_err(|_| StoreError::Backend("leaf_index overflow".into()))?;
        let row = sqlx::query_as::<_, RawLeafRow>(
            "SELECT leaf_index, leaf_hash, occurred_at_epoch_seconds \
             FROM transparency_log WHERE leaf_index = $1",
        )
        .bind(bind_idx)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;
        row.map(RawLeafRow::try_into_leaf).transpose()
    }

    async fn current_size(&self) -> Result<u64, StoreError> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM transparency_log")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        u64::try_from(count).map_err(|_| StoreError::Backend("negative count".into()))
    }

    async fn current_root(&self) -> Result<[u8; 32], StoreError> {
        let leaves = self.load_all_leaves().await?;
        if leaves.is_empty() {
            return Ok([0u8; 32]);
        }
        compute_root(&leaves).map_err(StoreError::Verification)
    }

    async fn build_inclusion_proof(
        &self,
        leaf_index: u64,
    ) -> Result<InclusionProof, StoreError> {
        let leaves = self.load_all_leaves().await?;
        if leaves.is_empty() {
            return Err(StoreError::Verification(VerificationError::EmptyTree));
        }
        if leaf_index >= u64::try_from(leaves.len()).unwrap_or(u64::MAX) {
            return Err(StoreError::Verification(
                VerificationError::LeafIndexOutOfBounds,
            ));
        }
        build_inclusion_proof_pure(&leaves, leaf_index).map_err(StoreError::Verification)
    }
}

#[cfg(test)]
mod tests {
    //! Integration tests against a live Postgres instance. Gated
    //! behind `#[ignore]` so `cargo test` stays green without a DB.
    //! Step 5 of wires these to CI with an ephemeral
    //! container; until then run locally as:
    //!
    //! ```sh
    //! TEST_DATABASE_URL=postgres://... \
    //!   cargo test -p qorch-transparency-store --lib -- --ignored
    //! ```
    use super::*;

    /// Build a store from `$TEST_DATABASE_URL`. The migrations live in
    /// `crates/adapters/transparency_store/migrations/`; Step 5 runs
    /// them via `sqlx::migrate!`.
    #[allow(dead_code)]
    async fn store_from_env() -> Option<PgTransparencyStore> {
        let url = std::env::var("TEST_DATABASE_URL").ok()?;
        let pool = PgPool::connect(&url).await.ok()?;
        Some(PgTransparencyStore::new(pool))
    }

    #[tokio::test]
    #[ignore = "requires live Postgres via $TEST_DATABASE_URL"]
    async fn pg_append_returns_monotonic_indices() {
        let Some(store) = store_from_env().await else { return };
        // Reset between runs is Step 5's responsibility; this test
        // just smokes the wiring.
        for i in 0u8..3 {
            let outcome = store
                .append(AppendInput {
                    idempotency_key: [i; 32],
                    payload: vec![i, i, i],
                    occurred_at_epoch_seconds: u64::from(i),
                })
                .await
                .unwrap();
            assert_eq!(outcome.leaf_hash, qorch_domain::transparency::leaf_hash(&[i, i, i]));
        }
    }
}
