//! `POST /v1/append` — append a kernel-signed token to the ledger
//! ( + §6,  Step 5).
//!
//! Flow:
//!   1. Validate `kernel_key_fingerprint_sha256` matches the pinned
//!      kernel public key. Mismatch → 403 (binds the ledger to ONE
//!      kernel; rotation requires a configured restart).
//!   2. Decode `token_b64` (base64url, padded or unpadded). Empty
//!      payload → 400.
//!   3. Decode `idempotency_key_hex` to 32 bytes. Wrong length → 400.
//!   4. Submit to the store. `StoreError::Conflict` (same key,
//!      different payload) → 409 with `idempotency_payload_mismatch`.
//!   5. Decide whether this was a fresh insert or a retry (compare the
//!      returned `leaf_index` against `current_size` before-shot).
//!      Fresh insert → 201; retry → 200 with `idempotent_replay: true`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use qorch_transparency_store::AppendInput;

use crate::dto::{AppendRequest, AppendResponse};
use crate::error::ServiceError;
use crate::state::AppState;

/// Decode a base64url string accepting both padded and unpadded inputs
/// — mirrors the kernel's `b64url_decode_padded_or_unpadded`.
fn b64url_decode(s: &str) -> Result<Vec<u8>, ServiceError> {
    URL_SAFE_NO_PAD
        .decode(s.trim().trim_end_matches('='))
        .map_err(|e| ServiceError::BadRequest(format!("base64url decode failed: {e}")))
}

/// Decode a hex string into exactly 32 bytes.
fn hex_to_32(s: &str) -> Result<[u8; 32], ServiceError> {
    let raw = hex::decode(s.trim())
        .map_err(|e| ServiceError::BadRequest(format!("hex decode failed: {e}")))?;
    if raw.len() != 32 {
        return Err(ServiceError::BadRequest(format!(
            "expected 32-byte hex value, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// `POST /v1/append`.
pub async fn append(
    State(state): State<AppState>,
    Json(body): Json<AppendRequest>,
) -> Result<Response, ServiceError> {
    // Step 1: kernel-key pinning. Compare hex-normalised both sides so
    // case differences don't reject a legitimate caller.
    let supplied_fpr = body
        .kernel_key_fingerprint_sha256
        .trim()
        .to_ascii_lowercase();
    let expected_fpr = state.kernel_key_fingerprint_hex.to_ascii_lowercase();
    if supplied_fpr != expected_fpr {
        return Err(ServiceError::KernelFingerprintMismatch);
    }

    // Step 2: decode payload.
    let payload = b64url_decode(&body.token_b64)?;
    if payload.is_empty() {
        return Err(ServiceError::BadRequest("token_b64 is empty".to_string()));
    }

    // Step 3: decode idempotency key.
    let idempotency_key = hex_to_32(&body.idempotency_key_hex)?;

    // Step 4: append. The store decides fresh-insert vs idempotent
    // retry atomically (under its lock/transaction) and reports it on
    // the outcome — see `AppendOutcome::idempotent_replay`. We must NOT
    // infer it from a separately-sampled `current_size`: that
    // check-then-act races (two identical concurrent requests can each
    // snapshot the pre-insert size and both mis-report 201-CREATED).
    let outcome = state
        .store
        .append(AppendInput {
            idempotency_key,
            payload,
            occurred_at_epoch_seconds: body.occurred_at_epoch_seconds,
        })
        .await?;

    // Step 5: classify from the atomic outcome flag.
    let idempotent_replay = outcome.idempotent_replay;
    let status = if idempotent_replay {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };

    let resp = AppendResponse {
        entry_id: outcome.leaf_index.to_string(),
        idempotent_replay,
        leaf_hash_hex: hex::encode(outcome.leaf_hash),
        leaf_index: outcome.leaf_index,
        ok: true,
    };
    Ok((status, Json(resp)).into_response())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use axum::{routing::post, Router};
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    use qorch_adapters::clock::SystemClock;
    use qorch_domain::safety::Clock;
    use qorch_transparency_store::memory::MemoryTransparencyStore;

    use crate::routes::append::append;
    use crate::state::AppState;

    /// Build a deterministic AppState backed by a fresh in-memory store.
    fn fixture_state() -> AppState {
        let seed = [0x11u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let signing_pk = signing_key.verifying_key().to_bytes();
        let mut h = Sha256::new();
        h.update(signing_pk);
        let signing_fpr = hex::encode(h.finalize());

        // Pretend the kernel uses a different key (different SHA-256).
        let kernel_seed = [0x22u8; 32];
        let kernel_signing = SigningKey::from_bytes(&kernel_seed);
        let kernel_pk = kernel_signing.verifying_key().to_bytes();
        let mut h2 = Sha256::new();
        h2.update(kernel_pk);
        let kernel_fpr = hex::encode(h2.finalize());

        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

        AppState::new(
            Arc::new(MemoryTransparencyStore::new()),
            Arc::new(signing_key),
            signing_fpr,
            kernel_fpr,
            clock,
            "test-key".to_string(),
        )
    }

    fn router(state: AppState) -> Router {
        Router::new()
            .route("/v1/append", post(append))
            .with_state(state)
    }

    fn append_body(state: &AppState, payload: &[u8], idem: [u8; 32]) -> Value {
        json!({
            "idempotency_key_hex": hex::encode(idem),
            "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
            "occurred_at_epoch_seconds": 1_700_000_000_u64,
            "token_b64": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload),
        })
    }

    async fn post_json(router: &Router, body: Value) -> (axum::http::StatusCode, Value) {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/append")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    #[tokio::test]
    async fn fresh_append_returns_201_and_index_zero() {
        let state = fixture_state();
        let router = router(state.clone());
        let body = append_body(&state, b"hello", [0x77; 32]);
        let (status, v) = post_json(&router, body).await;
        assert_eq!(status, axum::http::StatusCode::CREATED);
        assert_eq!(v["leaf_index"], 0);
        assert_eq!(v["idempotent_replay"], false);
        assert_eq!(v["ok"], true);
    }

    #[tokio::test]
    async fn duplicate_idempotency_same_payload_returns_200_replay() {
        let state = fixture_state();
        let router = router(state.clone());
        let body = append_body(&state, b"hello", [0x55; 32]);
        let (s1, _) = post_json(&router, body.clone()).await;
        assert_eq!(s1, axum::http::StatusCode::CREATED);
        let (s2, v2) = post_json(&router, body).await;
        assert_eq!(s2, axum::http::StatusCode::OK);
        assert_eq!(v2["idempotent_replay"], true);
        assert_eq!(v2["leaf_index"], 0);
    }

    #[tokio::test]
    async fn duplicate_idempotency_different_payload_returns_409() {
        let state = fixture_state();
        let router = router(state.clone());
        let first = append_body(&state, b"hello", [0x66; 32]);
        let second = append_body(&state, b"hello-different", [0x66; 32]);
        let (s1, _) = post_json(&router, first).await;
        assert_eq!(s1, axum::http::StatusCode::CREATED);
        let (s2, v2) = post_json(&router, second).await;
        assert_eq!(s2, axum::http::StatusCode::CONFLICT);
        assert_eq!(v2["reason"], "idempotency_payload_mismatch");
    }

    #[tokio::test]
    async fn fingerprint_mismatch_returns_403() {
        let state = fixture_state();
        let router = router(state.clone());
        let mut body = append_body(&state, b"hello", [0x99; 32]);
        body["kernel_key_fingerprint_sha256"] = Value::String(hex::encode([0xAB; 32]));
        let (status, v) = post_json(&router, body).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
        assert_eq!(v["reason"], "kernel_fingerprint_mismatch");
    }

    #[tokio::test]
    async fn empty_token_returns_400() {
        let state = fixture_state();
        let router = router(state.clone());
        let mut body = append_body(&state, b"x", [0xAA; 32]);
        body["token_b64"] = Value::String(String::new());
        let (status, _) = post_json(&router, body).await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn bad_idempotency_key_length_returns_400() {
        let state = fixture_state();
        let router = router(state.clone());
        let mut body = append_body(&state, b"x", [0x00; 32]);
        body["idempotency_key_hex"] = Value::String("aabbcc".to_string()); // 3 bytes
        let (status, _) = post_json(&router, body).await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    }
}
