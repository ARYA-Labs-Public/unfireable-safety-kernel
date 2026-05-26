//! `GET /v1/verify/:entry_id` — return the leaf plus an RFC-6962
//! inclusion proof against the current tree ( Step 5).
//!
//! The proof is verified IN-PROCESS against the current root before
//! the handler returns, so a malformed proof never leaves the
//! service — defense-in-depth against a future bug in
//! `build_inclusion_proof_pure`.

use axum::extract::{Path, State};
use axum::Json;

use qorch_domain::transparency::verify_inclusion_proof;

use crate::dto::VerifyResponse;
use crate::error::ServiceError;
use crate::state::AppState;

/// `GET /v1/verify/:entry_id`.
pub async fn verify(
    State(state): State<AppState>,
    Path(entry_id): Path<String>,
) -> Result<Json<VerifyResponse>, ServiceError> {
    let leaf_index: u64 = entry_id
        .parse()
        .map_err(|_| ServiceError::InvalidQuery(format!("entry_id not a u64: {entry_id}")))?;

    let leaf = state
        .store
        .get_leaf(leaf_index)
        .await?
        .ok_or(ServiceError::NotFound)?;

    let proof = state.store.build_inclusion_proof(leaf_index).await?;
    let current_size = state.store.current_size().await?;
    let current_root = state.store.current_root().await?;

    // Defense in depth: verify the proof against the just-fetched root
    // before returning. A failure here means the storage adapter
    // disagrees with the pure-domain verifier — surface as 500 so
    // operators see the discrepancy.
    verify_inclusion_proof(&proof, &current_root).map_err(|e| {
        ServiceError::Backend(format!("internal proof verification failed: {e}"))
    })?;

    Ok(Json(VerifyResponse {
        current_root_hash: hex::encode(current_root),
        current_tree_size: current_size,
        entry: leaf,
        inclusion_proof: proof,
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
    use qorch_domain::transparency::verify_inclusion_proof;
    use qorch_transparency_store::{memory::MemoryTransparencyStore, AppendInput, TransparencyStore};

    use crate::routes::verify::verify;
    use crate::state::AppState;

    async fn state_with_some_leaves(n: u8) -> AppState {
        let signing_key = SigningKey::from_bytes(&[0x33u8; 32]);
        let pk = signing_key.verifying_key().to_bytes();
        let mut h = Sha256::new();
        h.update(pk);
        let signing_fpr = hex::encode(h.finalize());

        let kernel_signing = SigningKey::from_bytes(&[0x44u8; 32]);
        let kernel_pk = kernel_signing.verifying_key().to_bytes();
        let mut h2 = Sha256::new();
        h2.update(kernel_pk);
        let kernel_fpr = hex::encode(h2.finalize());

        let store = Arc::new(MemoryTransparencyStore::new());
        for i in 0..n {
            store
                .append(AppendInput {
                    idempotency_key: [i; 32],
                    payload: vec![i, i + 1, i + 2],
                    occurred_at_epoch_seconds: u64::from(i),
                })
                .await
                .unwrap();
        }
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        AppState::new(
            store,
            Arc::new(signing_key),
            signing_fpr,
            kernel_fpr,
            clock,
            "test-key".to_string(),
        )
    }

    #[tokio::test]
    async fn returns_inclusion_proof_that_verifies_against_returned_root() {
        let state = state_with_some_leaves(5).await;
        let router = Router::new()
            .route("/v1/verify/{entry_id}", get(verify))
            .with_state(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/v1/verify/2")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: crate::dto::VerifyResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v.current_tree_size, 5);
        assert_eq!(v.entry.leaf_index, 2);

        let root: [u8; 32] = hex::decode(&v.current_root_hash)
            .unwrap()
            .try_into()
            .unwrap();
        verify_inclusion_proof(&v.inclusion_proof, &root).expect("proof must verify");
    }

    #[tokio::test]
    async fn missing_entry_returns_404() {
        let state = state_with_some_leaves(3).await;
        let router = Router::new()
            .route("/v1/verify/{entry_id}", get(verify))
            .with_state(state);
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/v1/verify/999")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn non_numeric_entry_id_returns_400() {
        let state = state_with_some_leaves(2).await;
        let router = Router::new()
            .route("/v1/verify/{entry_id}", get(verify))
            .with_state(state);
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/v1/verify/not-a-number")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }
}
