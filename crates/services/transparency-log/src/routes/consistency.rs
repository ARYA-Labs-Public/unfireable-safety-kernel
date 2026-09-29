//! `GET /v1/consistency?first=X&second=Y` — RFC-6962 consistency
//! proof between two tree sizes (internal-ref Step 5).
//!
//! Implementation note: the `TransparencyStore` trait exposes leaves
//! one at a time (`get_leaf(idx)`), and a consistency proof needs only
//! O(log n) subtree roots, not every leaf. The service keeps one
//! [`HashTree`] per process (`AppState::consistency_tree`): each request
//! extends it from the store only for leaves appended since the tree
//! was last touched, then builds the proof from cached internal nodes.
//! Steady-state cost per request is O(log n) plus O(new leaves); the
//! first request after boot pays the one-time O(n) warm-up. The earlier
//! shape — reload and re-hash every leaf `0..second` on every call — was
//! an O(n) resource amplification a public client could drive at will
//! (public repo issue #84).

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;

use qorch_domain::transparency::VerificationError;

use crate::dto::ConsistencyResponse;
use crate::error::ServiceError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ConsistencyParams {
    /// Earlier tree size (`first` in RFC-6962 §2.1.2).
    pub first: u64,
    /// Later tree size (`second` in RFC-6962 §2.1.2).
    pub second: u64,
}

/// `GET /v1/consistency?first=X&second=Y`.
pub async fn consistency(
    State(state): State<AppState>,
    Query(params): Query<ConsistencyParams>,
) -> Result<Json<ConsistencyResponse>, ServiceError> {
    if params.first == 0 {
        return Err(ServiceError::Verification(
            VerificationError::InvalidConsistencyRange,
        ));
    }
    if params.first > params.second {
        return Err(ServiceError::Verification(
            VerificationError::InvalidConsistencyRange,
        ));
    }

    let current = state.store.current_size().await?;
    if params.second > current {
        return Err(ServiceError::Verification(
            VerificationError::LeafIndexOutOfBounds,
        ));
    }

    // Extend the cached tree only over leaves it has not seen yet.
    // The ledger is append-only, so hashes already in the tree can
    // never change; holding the lock across the store reads keeps two
    // concurrent requests from racing to push the same leaf twice.
    let mut tree = state.consistency_tree.lock().await;
    for idx in tree.len()..params.second {
        let leaf = state
            .store
            .get_leaf(idx)
            .await?
            .ok_or_else(|| ServiceError::Backend(format!("gap at leaf_index {idx}")))?;
        tree.push_leaf(&leaf);
    }

    let proof = tree.consistency_proof(params.first, params.second)?;
    Ok(Json(ConsistencyResponse {
        consistency_proof: proof,
        ok: true,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use axum::{routing::get, Router};
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    use crate::clock::SystemClock;
    use qorch_domain::safety::Clock;
    use qorch_domain::transparency::{compute_root, verify_consistency_proof, MerkleLeaf};
    use qorch_transparency_store::{
        memory::MemoryTransparencyStore, AppendInput, TransparencyStore,
    };

    use crate::routes::consistency::consistency;
    use crate::state::AppState;

    async fn fixture_state_and_leaves(n: u8) -> (AppState, Vec<MerkleLeaf>) {
        let signing_key = SigningKey::from_bytes(&[0xAB; 32]);
        let mut h = Sha256::new();
        h.update(signing_key.verifying_key().to_bytes());
        let signing_fpr = hex::encode(h.finalize());
        let mut h2 = Sha256::new();
        h2.update([0u8; 32]);
        let kernel_fpr = hex::encode(h2.finalize());

        let store = Arc::new(MemoryTransparencyStore::new());
        let mut leaves = Vec::new();
        for i in 0..n {
            store
                .append(AppendInput {
                    idempotency_key: [i; 32],
                    payload: vec![i, i + 1],
                    occurred_at_epoch_seconds: u64::from(i),
                })
                .await
                .unwrap();
            leaves.push(store.get_leaf(u64::from(i)).await.unwrap().unwrap());
        }

        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let state = AppState::new(
            store,
            Arc::new(signing_key),
            signing_fpr,
            kernel_fpr,
            clock,
            "test-key".to_string(),
        );
        (state, leaves)
    }

    #[tokio::test]
    async fn proof_verifies_against_recomputed_roots() {
        let (state, leaves) = fixture_state_and_leaves(8).await;
        let router = Router::new()
            .route("/v1/consistency", get(consistency))
            .with_state(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/v1/consistency?first=3&second=7")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: crate::dto::ConsistencyResponse = serde_json::from_slice(&bytes).unwrap();

        let from_root = compute_root(&leaves[..3]).unwrap();
        let to_root = compute_root(&leaves[..7]).unwrap();
        verify_consistency_proof(&body.consistency_proof, &from_root, &to_root)
            .expect("consistency proof must verify");
    }

    #[tokio::test]
    async fn first_zero_returns_400() {
        let (state, _) = fixture_state_and_leaves(3).await;
        let router = Router::new()
            .route("/v1/consistency", get(consistency))
            .with_state(state);
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/v1/consistency?first=0&second=3")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn second_beyond_tree_returns_400() {
        let (state, _) = fixture_state_and_leaves(3).await;
        let router = Router::new()
            .route("/v1/consistency", get(consistency))
            .with_state(state);
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/v1/consistency?first=1&second=99")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    /// Wraps a store and counts `get_leaf` calls so a test can assert
    /// the route stops walking the ledger once the tree is warm.
    struct CountingStore {
        inner: MemoryTransparencyStore,
        get_leaf_calls: std::sync::atomic::AtomicU64,
    }

    #[async_trait::async_trait]
    impl TransparencyStore for CountingStore {
        async fn append(
            &self,
            payload: AppendInput,
        ) -> Result<qorch_transparency_store::AppendOutcome, qorch_transparency_store::StoreError>
        {
            self.inner.append(payload).await
        }
        async fn get_leaf(
            &self,
            leaf_index: u64,
        ) -> Result<Option<MerkleLeaf>, qorch_transparency_store::StoreError> {
            self.get_leaf_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.get_leaf(leaf_index).await
        }
        async fn current_size(&self) -> Result<u64, qorch_transparency_store::StoreError> {
            self.inner.current_size().await
        }
        async fn current_root(&self) -> Result<[u8; 32], qorch_transparency_store::StoreError> {
            self.inner.current_root().await
        }
        async fn build_inclusion_proof(
            &self,
            leaf_index: u64,
        ) -> Result<qorch_domain::transparency::InclusionProof, qorch_transparency_store::StoreError>
        {
            self.inner.build_inclusion_proof(leaf_index).await
        }
        async fn load_all_payloads(
            &self,
        ) -> Result<
            Vec<qorch_transparency_store::LeafPayloadRecord>,
            qorch_transparency_store::StoreError,
        > {
            self.inner.load_all_payloads().await
        }
    }

    async fn append_n(store: &dyn TransparencyStore, from: u8, to: u8) {
        for i in from..to {
            store
                .append(AppendInput {
                    idempotency_key: [i; 32],
                    payload: vec![i, i + 1],
                    occurred_at_epoch_seconds: u64::from(i),
                })
                .await
                .unwrap();
        }
    }

    async fn get_proof(
        router: &Router,
        first: u64,
        second: u64,
    ) -> (
        axum::http::StatusCode,
        Option<crate::dto::ConsistencyResponse>,
    ) {
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!("/v1/consistency?first={first}&second={second}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).ok())
    }

    #[tokio::test]
    async fn warm_tree_serves_repeat_proofs_without_reloading_leaves() {
        let counting = Arc::new(CountingStore {
            inner: MemoryTransparencyStore::new(),
            get_leaf_calls: std::sync::atomic::AtomicU64::new(0),
        });
        append_n(counting.as_ref(), 0, 16).await;

        let signing_key = SigningKey::from_bytes(&[0xAB; 32]);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let state = AppState::new(
            counting.clone(),
            Arc::new(signing_key),
            "fpr".to_string(),
            "kfpr".to_string(),
            clock,
            "test-key".to_string(),
        );
        let router = Router::new()
            .route("/v1/consistency", get(consistency))
            .with_state(state);

        let (s1, _) = get_proof(&router, 5, 16).await;
        assert_eq!(s1, axum::http::StatusCode::OK);
        let after_first = counting
            .get_leaf_calls
            .load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            after_first, 16,
            "first request warms the tree with one read per leaf"
        );

        // Same request, and a different range inside the same tree:
        // neither should touch the store's leaves again.
        let (s2, _) = get_proof(&router, 5, 16).await;
        let (s3, _) = get_proof(&router, 1, 16).await;
        let (s4, _) = get_proof(&router, 7, 9).await;
        assert_eq!(
            (s2, s3, s4),
            (
                axum::http::StatusCode::OK,
                axum::http::StatusCode::OK,
                axum::http::StatusCode::OK
            )
        );
        assert_eq!(
            counting
                .get_leaf_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            after_first,
            "warm tree must not re-read leaves"
        );

        // Append 3 more leaves: only those 3 are read, and the proof
        // across the boundary still verifies against recomputed roots.
        append_n(counting.as_ref(), 16, 19).await;
        let (s5, body) = get_proof(&router, 16, 19).await;
        assert_eq!(s5, axum::http::StatusCode::OK);
        assert_eq!(
            counting
                .get_leaf_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            after_first + 3,
            "extension reads exactly the new leaves"
        );
        let mut leaves = Vec::new();
        for i in 0..19u64 {
            leaves.push(counting.inner.get_leaf(i).await.unwrap().unwrap());
        }
        let from_root = compute_root(&leaves[..16]).unwrap();
        let to_root = compute_root(&leaves[..19]).unwrap();
        verify_consistency_proof(&body.unwrap().consistency_proof, &from_root, &to_root)
            .expect("proof across the extension boundary must verify");
    }
}
