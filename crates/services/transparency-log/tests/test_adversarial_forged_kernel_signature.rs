//!   — Rule-8 adversarial fixture: forged
//! `kernel_key_fingerprint_sha256` MUST be rejected by the
//! transparency-log service.
//!
//! Threat model: an attacker stands up a rogue "kernel" with its own
//! Ed25519 keypair and tries to append entries to a transparency-log
//! that was bootstrapped pinned to the real kernel's public key. The
//! service binds the ledger to ONE kernel key at startup; any append
//! whose `kernel_key_fingerprint_sha256` does not match the pinned
//! value gets 403 with `reason: "kernel_fingerprint_mismatch"`.
//!
//! This test drives the full router via tower oneshot, exercising the
//! auth middleware AND the append handler's fingerprint check.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::similar_names)]

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use qorch_adapters::clock::SystemClock;
use qorch_domain::safety::Clock;
use qorch_transparency_log::router::build_router;
use qorch_transparency_log::state::AppState;
use qorch_transparency_store::memory::MemoryTransparencyStore;

const TEST_API_KEY: &str = "forge-test-key";

/// SHA-256 hex of a verifying key's raw 32 bytes.
fn fpr(key: &SigningKey) -> String {
    let pk = key.verifying_key().to_bytes();
    let mut h = Sha256::new();
    h.update(pk);
    hex::encode(h.finalize())
}

fn fixture_state(pinned_kernel_fpr: &str) -> AppState {
    // The service's own STH-signing key (unrelated to the kernel
    // pin).
    let signing_key = SigningKey::from_bytes(&[0x77u8; 32]);
    let signing_fpr = fpr(&signing_key);

    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    AppState::new(
        Arc::new(MemoryTransparencyStore::new()),
        Arc::new(signing_key),
        signing_fpr,
        pinned_kernel_fpr.to_string(),
        clock,
        TEST_API_KEY.to_string(),
    )
}

/// Rogue kernel: a different keypair than what the t-log pins.
fn rogue_kernel_keypair() -> SigningKey {
    SigningKey::from_bytes(&[0xDDu8; 32])
}

/// Real kernel: the keypair the t-log pinned at boot.
fn real_kernel_keypair() -> SigningKey {
    SigningKey::from_bytes(&[0x11u8; 32])
}

async fn append_request(
    router: &axum::Router,
    kernel_fpr_to_send: &str,
    payload: &[u8],
    idem: [u8; 32],
) -> (axum::http::StatusCode, Value) {
    let body = json!({
        "idempotency_key_hex": hex::encode(idem),
        "kernel_key_fingerprint_sha256": kernel_fpr_to_send,
        "occurred_at_epoch_seconds": 1_700_000_000_u64,
        "token_b64": URL_SAFE_NO_PAD.encode(payload),
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/append")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// AC — append from rogue kernel (wrong fingerprint) MUST 403.
#[tokio::test]
async fn adversarial_forged_kernel_fingerprint_rejected_with_403() {
    let real = real_kernel_keypair();
    let pinned = fpr(&real);
    let router = build_router(fixture_state(&pinned));

    // Rogue kernel computes its own fingerprint and submits it.
    let rogue = rogue_kernel_keypair();
    let rogue_fpr = fpr(&rogue);
    assert_ne!(pinned, rogue_fpr, "test fixture must use distinct keys");

    let (status, v) = append_request(&router, &rogue_fpr, b"rogue-payload", [0x01; 32]).await;
    assert_eq!(
        status,
        axum::http::StatusCode::FORBIDDEN,
        "AC GATE: rogue kernel fingerprint MUST yield 403 (got: {status} body={v:?})",
    );
    assert_eq!(
        v["reason"], "kernel_fingerprint_mismatch",
        "AC GATE: rejection reason MUST be machine-stable",
    );
    assert_eq!(v["ok"], false);
}

/// AC — even a sha256 hash of an attacker-controlled value is not
/// enough: structural validity (32 bytes of hex) does NOT bypass the
/// pin. The handler does case-insensitive equality on the hex.
#[tokio::test]
async fn adversarial_arbitrary_32byte_fingerprint_rejected() {
    let pinned = fpr(&real_kernel_keypair());
    let router = build_router(fixture_state(&pinned));

    // 64-char structurally-valid hex that is NOT the pinned value.
    let forged_hex = hex::encode([0xAB; 32]);
    let (status, v) = append_request(&router, &forged_hex, b"attacker-payload", [0x02; 32]).await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(v["reason"], "kernel_fingerprint_mismatch");
}

/// Control: the REAL kernel fingerprint is accepted. If this fails,
/// the adversarial tests above might be passing for the wrong reason
/// (e.g. ALL appends are rejected).
#[tokio::test]
async fn control_real_kernel_fingerprint_accepted() {
    let real = real_kernel_keypair();
    let pinned = fpr(&real);
    let router = build_router(fixture_state(&pinned));

    let (status, v) = append_request(&router, &pinned, b"honest-payload", [0x03; 32]).await;
    assert_eq!(
        status,
        axum::http::StatusCode::CREATED,
        "control: pinned fingerprint MUST be accepted (got: {status} body={v:?})",
    );
    assert_eq!(v["ok"], true);
    assert_eq!(v["leaf_index"], 0);
}

/// AC — case-insensitive equality on the fingerprint hex. The
/// pinned-key check should not be a foot-gun where uppercase vs
/// lowercase trips a 403.
#[tokio::test]
async fn control_real_fingerprint_case_insensitive() {
    let real = real_kernel_keypair();
    let pinned = fpr(&real);
    let router = build_router(fixture_state(&pinned));

    let upper = pinned.to_uppercase();
    let (status, _) = append_request(&router, &upper, b"case-test", [0x04; 32]).await;
    assert_eq!(
        status,
        axum::http::StatusCode::CREATED,
        "control: uppercased fingerprint MUST be accepted",
    );
}

/// AC — missing x-api-key MUST 401 (auth layer denies before
/// fingerprint check runs).
#[tokio::test]
async fn adversarial_missing_api_key_rejected_before_fingerprint_check() {
    let pinned = fpr(&real_kernel_keypair());
    let router = build_router(fixture_state(&pinned));

    let body = json!({
        "idempotency_key_hex": hex::encode([0x05u8; 32]),
        "kernel_key_fingerprint_sha256": pinned,
        "occurred_at_epoch_seconds": 1_700_000_000_u64,
        "token_b64": URL_SAFE_NO_PAD.encode(b"payload"),
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/append")
        .header("content-type", "application/json")
        // Deliberately no x-api-key header.
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::UNAUTHORIZED,
        "AC GATE: missing api key MUST 401 even with correct fingerprint",
    );
}
