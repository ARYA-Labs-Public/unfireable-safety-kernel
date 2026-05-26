//! `GET /v1/consistency?first=X&second=Y` — RFC-6962 consistency
//! proof between two tree sizes ( Step 5).
//!
//! Implementation note: the Step-4 `TransparencyStore` trait does not
//! expose a bulk-leaf view (only `get_leaf(idx)` and
//! `build_inclusion_proof(idx)`). The pure-domain
//! `build_consistency_proof` takes a `&[MerkleLeaf]` slice, so we
//! materialise the leaves up to `second` by looping `get_leaf` here.
//! For Step 5 boundary scale (10^4 leaves) that's acceptable. A
//! bulk-leaf adapter method is a candidate optimisation tracked in
//! the ADR §5 "future work" bullet.

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;

use qorch_domain::transparency::{build_consistency_proof, MerkleLeaf, VerificationError};

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

    let mut leaves: Vec<MerkleLeaf> =
        Vec::with_capacity(usize::try_from(params.second).unwrap_or(0));
    for idx in 0..params.second {
        let leaf = state
            .store
            .get_leaf(idx)
            .await?
            .ok_or_else(|| ServiceError::Backend(format!("gap at leaf_index {idx}")))?;
        leaves.push(leaf);
    }

    let proof = build_consistency_proof(&leaves, params.first, params.second)?;
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

    use qorch_adapters::clock::SystemClock;
    use qorch_domain::safety::Clock;
    use qorch_domain::transparency::{
        compute_root, verify_consistency_proof, MerkleLeaf,
    };
    use qorch_transparency_store::{memory::MemoryTransparencyStore, AppendInput, TransparencyStore};

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
}
