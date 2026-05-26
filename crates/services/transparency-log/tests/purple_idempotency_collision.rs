//!   — Purple-Team adversarial tests against the
//! transparency-log idempotency surface.
//!
//! Campaigns:
//!   F1 — Idempotency-key COLLISION ATTACK: attacker submits a second
//!        append carrying the same idempotency_key but a different
//!        payload. The service MUST respond 409 conflict and the
//!        ledger MUST NOT be overwritten.
//!   F2 — Truncated / malformed idempotency_key (31-byte hex) MUST be
//!        rejected with 400.
//!
//! Both campaigns mirror the existing route-unit tests but live in the
//! `purple_*.rs` namespace per /purple-team convention so the report
//! can cite them by name.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::doc_markdown, clippy::doc_lazy_continuation)]

use std::sync::Arc;

use axum::{routing::post, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use qorch_adapters::clock::SystemClock;
use qorch_domain::safety::Clock;
use qorch_transparency_log::routes::append::append;
use qorch_transparency_log::state::AppState;
use qorch_transparency_store::memory::MemoryTransparencyStore;

fn fixture_state() -> AppState {
    // STH signer
    let seed = [0x11u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let signing_pk = signing_key.verifying_key().to_bytes();
    let mut h = Sha256::new();
    h.update(signing_pk);
    let signing_fpr = hex::encode(h.finalize());

    // Kernel pinned key (independent from STH signer — campaign-A separation)
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

fn append_body(state: &AppState, payload: &[u8], idem: &str) -> Value {
    json!({
        "idempotency_key_hex": idem,
        "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
        "occurred_at_epoch_seconds": 1_700_000_000_u64,
        "token_b64": URL_SAFE_NO_PAD.encode(payload),
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

// ---------------------------------------------------------------------------
// F1 — Idempotency-key collision attack
//
// Attacker model: a malicious caller has captured the kernel's
// idempotency_key for a token they want to overwrite. They submit a
// second append with the same key but a different payload, attempting
// to either (a) overwrite the original leaf or (b) cause the kernel
// retry path to confuse them with the legitimate token.
//
// Correct behaviour:
//   - First append → 201, leaf_index=0
//   - Same key + same payload (replay)     → 200, idempotent_replay=true, SAME leaf_index
//   - Same key + different payload (forge) → 409 conflict, reason=idempotency_payload_mismatch
//     AND the original leaf is preserved unchanged.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn purple_f1_idempotency_collision_with_different_payload_409s() {
    let state = fixture_state();
    let router = router(state.clone());

    let key_hex = hex::encode([0x66u8; 32]);
    let first = append_body(&state, b"legitimate-token-A", &key_hex);
    let attacker = append_body(&state, b"ATTACKER-FORGED-PAYLOAD", &key_hex);

    // First legitimate append.
    let (s1, v1) = post_json(&router, first.clone()).await;
    assert_eq!(s1, axum::http::StatusCode::CREATED, "body={v1:?}");
    let original_leaf_index = v1["leaf_index"].as_u64().unwrap();
    let original_leaf_hash = v1["leaf_hash_hex"].as_str().unwrap().to_string();

    // Attacker tries to forge with the same key + a different payload.
    let (s2, v2) = post_json(&router, attacker).await;
    assert_eq!(
        s2,
        axum::http::StatusCode::CONFLICT,
        "attacker collision must be 409, got status={s2:?} body={v2:?}"
    );
    assert_eq!(v2["reason"], "idempotency_payload_mismatch");
    assert_eq!(v2["error"], "conflict");

    // Counter-assertion: the legitimate replay still succeeds and
    // returns the SAME leaf_index + leaf_hash — i.e. the attacker's
    // 409 did not silently overwrite the ledger.
    let (s3, v3) = post_json(&router, first).await;
    assert_eq!(s3, axum::http::StatusCode::OK, "legitimate replay should 200");
    assert_eq!(v3["idempotent_replay"], true);
    assert_eq!(v3["leaf_index"], original_leaf_index);
    assert_eq!(v3["leaf_hash_hex"], original_leaf_hash);
}

// ---------------------------------------------------------------------------
// F2 — Truncated idempotency_key (31-byte hex) MUST be rejected 400
//
// Attacker model: probe the input validation. A 31-byte (or any
// non-32-byte) idempotency_key indicates a malformed client. The
// service MUST return 400, NOT silently truncate / zero-pad / accept.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn purple_f2_truncated_idempotency_key_rejected_400() {
    let state = fixture_state();
    let router = router(state.clone());

    // 62 hex chars = 31 bytes. Off-by-one truncation.
    let bad_hex = "a".repeat(62);
    let body = append_body(&state, b"payload", &bad_hex);
    let (status, _v) = post_json(&router, body).await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "31-byte idempotency_key must be 400"
    );

    // Counter-assertion: full 32-byte (64-char) hex is accepted.
    let ok_hex = hex::encode([0xAAu8; 32]);
    let body = append_body(&state, b"payload", &ok_hex);
    let (status, _v) = post_json(&router, body).await;
    assert_eq!(status, axum::http::StatusCode::CREATED);

    // Additional variant: odd-length hex (non-byte-aligned).
    let odd_hex = "abc";
    let body = append_body(&state, b"payload", odd_hex);
    let (status, _v) = post_json(&router, body).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

    // Additional variant: empty idempotency_key_hex.
    let body = append_body(&state, b"payload", "");
    let (status, _v) = post_json(&router, body).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

    // Additional variant: non-hex characters.
    let body = append_body(&state, b"payload", "zzzznotvalid");
    let (status, _v) = post_json(&router, body).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}
