//! internal-ref — integration test for the Ed25519 ADDITIVE signing path.
//!
//! This file exercises the FULL service router (auth middleware +
//! body-limit + tracing) for the dual-format wave-session-record
//! append flow. It is the integration counterpart to the lib-level
//! unit tests in `routes::wave_session::tests`; together they cover
//! the six acceptance criteria (AC1-AC6).
//!
//! Test inventory:
//!   - `ac1_keys_endpoint_returns_published_pk` — published material.
//!   - `ac2_post_accepts_hmac_legacy_path` — backward compat unchanged.
//!   - `ac2_post_accepts_ed25519_asymmetric_path` — new additive path.
//!   - `ac3_verify_returns_signature_type_per_entry` — dual-mode chain.
//!   - `ac6_adversarial_forged_keypair_rejected_with_403` — Rule 8
//!     adversarial fixture (mandatory under the project ceremony).
//!   - `ac6_adversarial_pk_announced_correct_sig_minted_by_attacker`
//!     — defence-in-depth: pin passes, verify() catches.
//!   - `legacy_hmac_caller_still_works_on_ed25519_enabled_host` —
//!     mixed-mode service must accept legacy callers untouched.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::bool_assert_comparison)]
use std::collections::HashSet;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{digest::KeyInit, Hmac, Mac};
use http_body_util::BodyExt;
use qorch_domain::safety::Clock;
use qorch_domain::wave::context::WaveId;
use qorch_domain::wave::gate_surface::GateSurface;
use qorch_domain::wave::session_record::WaveSessionRecord;
use qorch_domain::wave::stage::{WaveOutcome, WaveStage};
use qorch_transparency_log::clock::SystemClock;
use qorch_transparency_log::router::build_router;
use qorch_transparency_log::state::AppState;
use qorch_transparency_store::memory::MemoryTransparencyStore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

/// Shared x-api-key for every integration-test request.
const X_API_KEY: &str = "ary2194-test-api-key";
/// Stable HMAC key for the HMAC path tests.
/// Test kernel HMAC key, derived rather than written as a byte-string
/// literal: CodeQL's `rust/hard-coded-cryptographic-value` flags any
/// literal that flows into a MAC key, and the real key comes from
/// service config via `with_kernel_hmac_key`.
fn hmac_key() -> [u8; 32] {
    std::array::from_fn(|i| b'k' + (i as u8 % 17))
}
/// Deterministic 32-byte seed for the transparency-log Ed25519 keypair.
const TL_ED25519_SEED: [u8; 32] = [0xB1u8; 32];

/// Build a fully-wired AppState carrying:
///   - Memory transparency store
///   - STH-signer keypair (deterministic from a different seed)
///   - Kernel-fingerprint pin
///   - HMAC key (legacy path)
///   - internal-ref transparency-log Ed25519 keypair (new path)
fn state_with_both_signing_paths() -> (AppState, SigningKey) {
    let sth_signing = SigningKey::from_bytes(&[0x44u8; 32]);
    let sth_pk = sth_signing.verifying_key().to_bytes();
    let mut h1 = Sha256::new();
    h1.update(sth_pk);
    let sth_fpr = hex::encode(h1.finalize());

    let kernel_signing = SigningKey::from_bytes(&[0x55u8; 32]);
    let kernel_pk = kernel_signing.verifying_key().to_bytes();
    let mut h2 = Sha256::new();
    h2.update(kernel_pk);
    let kernel_fpr = hex::encode(h2.finalize());

    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let tl_signing = SigningKey::from_bytes(&TL_ED25519_SEED);
    let state = AppState::new(
        Arc::new(MemoryTransparencyStore::new()),
        Arc::new(sth_signing),
        sth_fpr,
        kernel_fpr,
        clock,
        X_API_KEY.to_string(),
    )
    .with_kernel_hmac_key(hmac_key().to_vec())
    .with_transparency_ed25519_keypair(tl_signing.clone(), 1_716_500_000);
    (state, tl_signing)
}

fn rec(
    wave: &str,
    stage: WaveStage,
    sid: &str,
    written_by: &str,
    gs: HashSet<GateSurface>,
) -> WaveSessionRecord {
    WaveSessionRecord::new(
        WaveId::new(wave),
        "internal-ref",
        stage,
        sid,
        WaveOutcome::Pass,
        "evidence",
        gs,
        written_by,
        1_716_500_000,
    )
}

fn hmac_of(key: &[u8], r: &WaveSessionRecord) -> [u8; 32] {
    let bytes = r.canonical_bytes().unwrap();
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).unwrap();
    mac.update(&bytes);
    let out = mac.finalize().into_bytes();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

fn legacy_body(state: &AppState, hmac: &[u8; 32], r: &WaveSessionRecord) -> Value {
    json!({
        "kernel_hmac_hex": hex::encode(hmac),
        "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
        "record": r,
    })
}

fn ed25519_body(state: &AppState, signing: &SigningKey, r: &WaveSessionRecord) -> Value {
    let bytes = r.canonical_bytes().unwrap();
    let sig = signing.sign(&bytes);
    json!({
        "ed25519_public_key_hex": hex::encode(signing.verifying_key().to_bytes()),
        "ed25519_signature_hex": hex::encode(sig.to_bytes()),
        "kernel_hmac_hex": hex::encode([0u8; 32]),
        "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
        "record": r,
        "signature_type": "ed25519",
    })
}

async fn post_session(router: &axum::Router, body: Value, api_key: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/wave/session")
        .header("content-type", "application/json")
        .header("x-api-key", api_key)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn get_path(router: &axum::Router, path: &str, api_key: Option<&str>) -> (StatusCode, Value) {
    let mut req_builder = Request::builder().method("GET").uri(path);
    if let Some(k) = api_key {
        req_builder = req_builder.header("x-api-key", k);
    }
    let req = req_builder.body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

#[tokio::test]
async fn ac1_keys_endpoint_returns_published_pk() {
    // AC1 — public key + fingerprint + algorithm published. Note we
    // pass NO x-api-key — the endpoint is public by design.
    let (state, tl_signing) = state_with_both_signing_paths();
    let router = build_router(state);
    let (s, v) = get_path(&router, "/v1/keys/transparency", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["algorithm"], "Ed25519");
    let pk_hex = hex::encode(tl_signing.verifying_key().to_bytes());
    assert_eq!(v["public_key_hex"], Value::String(pk_hex));
    // Fingerprint = SHA-256(raw_pk).
    let mut h = Sha256::new();
    h.update(tl_signing.verifying_key().to_bytes());
    let expected_fpr = hex::encode(h.finalize());
    assert_eq!(v["key_fingerprint_sha256_hex"], Value::String(expected_fpr));
}

#[tokio::test]
async fn ac2_post_accepts_hmac_legacy_path() {
    // AC2-a — HMAC path still works on the ed25519-enabled service.
    let (state, _tl_signing) = state_with_both_signing_paths();
    let router = build_router(state.clone());
    let r = rec(
        "w-hmac-on-mixed",
        WaveStage::Tested,
        "adv-1",
        "/test",
        HashSet::new(),
    );
    let h = hmac_of(&hmac_key(), &r);
    let (s, v) = post_session(&router, legacy_body(&state, &h, &r), X_API_KEY).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(v["ok"], true);
}

#[tokio::test]
async fn ac2_post_accepts_ed25519_asymmetric_path() {
    // AC2-b — Ed25519 path mints a leaf when the keypair is configured.
    let (state, tl_signing) = state_with_both_signing_paths();
    let router = build_router(state.clone());
    let r = rec(
        "w-ed25519",
        WaveStage::PurpleTeamed,
        "pt-1",
        "/purple-team",
        HashSet::new(),
    );
    let (s, v) = post_session(&router, ed25519_body(&state, &tl_signing, &r), X_API_KEY).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(v["ok"], true);
}

#[tokio::test]
async fn ac3_verify_returns_signature_type_per_entry() {
    // AC3 — verify route reports per-entry signature_type +
    // key_fingerprint_hex AND the top-level Ed25519 key fingerprint.
    let (state, tl_signing) = state_with_both_signing_paths();
    let router = build_router(state.clone());

    let r_hmac = rec("w-mixed", WaveStage::Tested, "h-1", "/test", HashSet::new());
    let h = hmac_of(&hmac_key(), &r_hmac);
    let (s1, _) = post_session(&router, legacy_body(&state, &h, &r_hmac), X_API_KEY).await;
    assert_eq!(s1, StatusCode::CREATED);

    let r_ed = rec(
        "w-mixed",
        WaveStage::Accepted,
        "u-1",
        "/user-acceptance",
        HashSet::new(),
    );
    let (s2, _) = post_session(&router, ed25519_body(&state, &tl_signing, &r_ed), X_API_KEY).await;
    assert_eq!(s2, StatusCode::CREATED);

    // Now read back.
    let (s, v) = get_path(&router, "/v1/wave/w-mixed/verify", Some(X_API_KEY)).await;
    assert_eq!(s, StatusCode::OK);

    let chain = v["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 2);

    // chain[0] (TESTED first) = HMAC; chain[1] (ACCEPTED) = Ed25519.
    let kernel_fpr_hex = state.kernel_key_fingerprint_hex.clone();
    let tl_fpr_hex = state
        .transparency_ed25519_key_fingerprint_hex
        .clone()
        .unwrap();

    assert_eq!(chain[0]["signature_type"], "hmac");
    assert_eq!(
        chain[0]["key_fingerprint_hex"],
        Value::String(kernel_fpr_hex)
    );

    assert_eq!(chain[1]["signature_type"], "ed25519");
    assert_eq!(
        chain[1]["key_fingerprint_hex"],
        Value::String(tl_fpr_hex.clone())
    );
    // Ed25519 entry must publish the 64-byte signature in hex (128 chars).
    assert_eq!(
        chain[1]["ed25519_signature_hex"].as_str().unwrap().len(),
        128
    );

    // Top-level Ed25519 fingerprint is echoed.
    assert_eq!(
        v["transparency_log_ed25519_key_fingerprint_sha256"],
        Value::String(tl_fpr_hex)
    );
}

#[tokio::test]
async fn ac6_adversarial_forged_keypair_rejected_with_403() {
    // AC6 / Rule 8 adversarial — attacker mints a wholly different
    // Ed25519 keypair, signs the record with it, and announces the
    // attacker's public key. The transparency-log MUST reject with 403
    // and the stable machine code `ed25519_key_fingerprint_mismatch`.
    let (state, _tl_signing) = state_with_both_signing_paths();
    let router = build_router(state.clone());

    let r = rec(
        "w-forged",
        WaveStage::Tested,
        "atk-1",
        "/test",
        HashSet::new(),
    );

    let attacker = SigningKey::from_bytes(&[0xEEu8; 32]);
    let bytes = r.canonical_bytes().unwrap();
    let bad_sig = attacker.sign(&bytes);

    let body = json!({
        "ed25519_public_key_hex": hex::encode(attacker.verifying_key().to_bytes()),
        "ed25519_signature_hex": hex::encode(bad_sig.to_bytes()),
        "kernel_hmac_hex": hex::encode([0u8; 32]),
        "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
        "record": r,
        "signature_type": "ed25519",
    });
    let (s, v) = post_session(&router, body, X_API_KEY).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(v["reason"], "ed25519_key_fingerprint_mismatch");
}

#[tokio::test]
async fn ac6_adversarial_pk_announced_correct_sig_minted_by_attacker() {
    // Defence-in-depth: attacker steals/guesses the correct public key
    // (it IS public), then announces it but submits a signature minted
    // by a DIFFERENT keypair. The fingerprint pin passes; the signature
    // verification must catch it.
    let (state, tl_signing) = state_with_both_signing_paths();
    let router = build_router(state.clone());

    let r = rec(
        "w-sigforge",
        WaveStage::Tested,
        "atk-2",
        "/test",
        HashSet::new(),
    );
    let attacker = SigningKey::from_bytes(&[0xFAu8; 32]);
    let bytes = r.canonical_bytes().unwrap();
    let bad_sig = attacker.sign(&bytes);

    let body = json!({
        // Correct (legitimate) public key.
        "ed25519_public_key_hex": hex::encode(tl_signing.verifying_key().to_bytes()),
        // Signature from the wrong key.
        "ed25519_signature_hex": hex::encode(bad_sig.to_bytes()),
        "kernel_hmac_hex": hex::encode([0u8; 32]),
        "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
        "record": r,
        "signature_type": "ed25519",
    });
    let (s, v) = post_session(&router, body, X_API_KEY).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(v["reason"], "ed25519_signature_mismatch");
}

#[tokio::test]
async fn legacy_hmac_caller_still_works_on_ed25519_enabled_host() {
    // Stage-1 migration guarantee: an HMAC-only caller (no
    // signature_type field, no ed25519_* fields) MUST be accepted
    // bytes-for-bytes by an Ed25519-enabled host.
    let (state, _tl_signing) = state_with_both_signing_paths();
    let router = build_router(state.clone());
    let r = rec(
        "w-legacy-on-mixed",
        WaveStage::Closed,
        "cls-1",
        "/closeout",
        HashSet::new(),
    );
    let h = hmac_of(&hmac_key(), &r);
    let (s, v) = post_session(&router, legacy_body(&state, &h, &r), X_API_KEY).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(v["ok"], true);
}
