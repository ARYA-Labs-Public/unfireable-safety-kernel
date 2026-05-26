//! `GET /v1/sth` — return the current Ed25519-signed tree head
//! ( Step 5).
//!
//! Mints the STH via `qorch_domain::transparency::mint_sth` so the
//! signing logic stays pure-domain. Timestamp is sourced from the
//! AppState `Clock` (production uses `SystemClock`, tests inject a
//! fixed-clock).

use axum::extract::State;
use axum::Json;

use qorch_domain::transparency::mint_sth;

use crate::dto::SignedTreeHeadResponse;
use crate::error::ServiceError;
use crate::state::AppState;

/// `GET /v1/sth`.
pub async fn sth(
    State(state): State<AppState>,
) -> Result<Json<SignedTreeHeadResponse>, ServiceError> {
    let tree_size = state.store.current_size().await?;
    let root_hash = state.store.current_root().await?;
    // Clock returns f64 epoch seconds — STH wants u64. Round down.
    let now_f = state.clock.now();
    let now_u = if now_f.is_finite() && now_f >= 0.0 {
        // `as` truncation is correct here: we want u64 floor of the
        // f64 epoch seconds. The cast is bounded (clock returns the
        // current epoch which fits in u64 for the next ~200 years).
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            now_f as u64
        }
    } else {
        0
    };

    let sth = mint_sth(root_hash, tree_size, now_u, state.signing_key.as_ref());
    Ok(Json(SignedTreeHeadResponse {
        ok: true,
        signing_key_fingerprint_sha256: state.signing_key_fingerprint_hex.clone(),
        sth,
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
    use qorch_domain::transparency::verify_sth;
    use qorch_transparency_store::{memory::MemoryTransparencyStore, AppendInput, TransparencyStore};

    use crate::routes::sth::sth;
    use crate::state::AppState;

    async fn fixture_state_with_leaves(n: u8) -> (AppState, SigningKey) {
        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = signing_key.verifying_key().to_bytes();
        let mut h = Sha256::new();
        h.update(pk);
        let signing_fpr = hex::encode(h.finalize());

        let kernel_signing = SigningKey::from_bytes(&[0x55u8; 32]);
        let kernel_pk = kernel_signing.verifying_key().to_bytes();
        let mut h2 = Sha256::new();
        h2.update(kernel_pk);
        let kernel_fpr = hex::encode(h2.finalize());

        let store = Arc::new(MemoryTransparencyStore::new());
        for i in 0..n {
            store
                .append(AppendInput {
                    idempotency_key: [i; 32],
                    payload: vec![i],
                    occurred_at_epoch_seconds: u64::from(i),
                })
                .await
                .unwrap();
        }

        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let key_for_verify = SigningKey::from_bytes(&signing_key.to_bytes());
        let state = AppState::new(
            store,
            Arc::new(signing_key),
            signing_fpr,
            kernel_fpr,
            clock,
            "test-key".to_string(),
        );
        (state, key_for_verify)
    }

    #[tokio::test]
    async fn sth_round_trip_verifies_with_signing_key() {
        let (state, key) = fixture_state_with_leaves(4).await;
        let verifying_key = key.verifying_key();
        let router = Router::new()
            .route("/v1/sth", get(sth))
            .with_state(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/v1/sth")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: crate::dto::SignedTreeHeadResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(body.ok);
        assert_eq!(body.sth.tree_size, 4);
        verify_sth(&body.sth, &verifying_key).expect("STH signature must verify");
    }

    #[tokio::test]
    async fn empty_tree_sth_signs_zero_root() {
        let (state, key) = fixture_state_with_leaves(0).await;
        let verifying_key = key.verifying_key();
        let router = Router::new()
            .route("/v1/sth", get(sth))
            .with_state(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/v1/sth")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: crate::dto::SignedTreeHeadResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body.sth.tree_size, 0);
        assert_eq!(body.sth.root_hash, [0u8; 32]);
        verify_sth(&body.sth, &verifying_key).expect("empty STH must verify");
    }
}
