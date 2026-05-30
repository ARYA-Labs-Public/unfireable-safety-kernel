//!   — integration tests for the wave-session-record
//! routes. Exercises the full router (auth middleware + body-limit +
//! tracing layer) using axum's `tower::ServiceExt::oneshot` against a
//! fresh `MemoryTransparencyStore` per test. Six adversarial fixtures
//! (Rule 8) cover the threat surface called out in the spec.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::BodyExt;
use qorch_adapters::clock::SystemClock;
use qorch_domain::safety::Clock;
use qorch_domain::wave::context::WaveId;
use qorch_domain::wave::gate_surface::GateSurface;
use qorch_domain::wave::session_record::WaveSessionRecord;
use qorch_domain::wave::stage::{WaveOutcome, WaveStage};
use qorch_transparency_log::router::build_router;
use qorch_transparency_log::state::AppState;
use qorch_transparency_store::memory::MemoryTransparencyStore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

fn state_with_key(hmac_key: &[u8]) -> AppState {
    let seed = [0x33u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let signing_pk = signing_key.verifying_key().to_bytes();
    let mut h = Sha256::new();
    h.update(signing_pk);
    let signing_fpr = hex::encode(h.finalize());

    let kernel_seed = [0x44u8; 32];
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
        // Test API key — sent in every request via X_API_KEY constant.
        X_API_KEY.to_string(),
    )
    .with_kernel_hmac_key(hmac_key.to_vec())
}

/// Shared x-api-key for every integration-test request. The auth
/// middleware constant-time compares against `state.api_key`.
const X_API_KEY: &str = "integration-test-api-key";

fn rec(
    wave: &str,
    stage: WaveStage,
    sid: &str,
    written_by: &str,
    gs: HashSet<GateSurface>,
) -> WaveSessionRecord {
    WaveSessionRecord::new(
        WaveId::new(wave),
        "",
        stage,
        sid,
        WaveOutcome::Pass,
        "evidence",
        gs,
        written_by,
        1_716_400_000,
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

fn body(state: &AppState, hmac: &[u8; 32], r: &WaveSessionRecord) -> Value {
    json!({
        "kernel_hmac_hex": hex::encode(hmac),
        "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
        "record": r,
    })
}

async fn post(router: &axum::Router, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/wave/session")
        .header("content-type", "application/json")
        .header("x-api-key", X_API_KEY)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn get_verify(router: &axum::Router, wave_id: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/wave/{wave_id}/verify"))
        .header("x-api-key", X_API_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

// --------------------------------------------------------------------
// Happy path
// --------------------------------------------------------------------

#[tokio::test]
async fn happy_path_full_chain_with_gate_surface() {
    let key = b"integration-key-32-bytes-padding";
    let state = state_with_key(key);
    let router = build_router(state.clone());

    let mut gs = HashSet::new();
    gs.insert(GateSurface::SafetyKernel);

    let stages: Vec<(WaveStage, &str, &str, HashSet<GateSurface>)> = vec![
        (WaveStage::Tested, "adv-1", "/test", gs.clone()),
        (WaveStage::PurpleTeamed, "pt-1", "/purple-team", gs.clone()),
        (
            WaveStage::Accepted,
            "uat-1",
            "/user-acceptance",
            HashSet::new(),
        ),
        (WaveStage::Closed, "cls-1", "/closeout", HashSet::new()),
    ];
    for (stage, sid, wb, gs_local) in stages {
        let r = rec("wave-happy", stage, sid, wb, gs_local);
        let h = hmac_of(key, &r);
        let (s, _) = post(&router, body(&state, &h, &r)).await;
        assert_eq!(s, StatusCode::CREATED, "fresh append must return 201");
    }
    let (s, v) = get_verify(&router, "wave-happy").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["all_required_stages_present"], true);
    assert_eq!(v["wave_id"], "wave-happy");
    assert_eq!(v["chain"].as_array().unwrap().len(), 4);
}

// --------------------------------------------------------------------
// Rule 8 adversarial fixtures
// --------------------------------------------------------------------

#[tokio::test]
async fn adversarial_tampered_hmac_rejected() {
    let key = b"integration-key-32-bytes-padding";
    let state = state_with_key(key);
    let router = build_router(state.clone());
    let r = rec(
        "wave-tamper",
        WaveStage::Tested,
        "adv",
        "/test",
        HashSet::new(),
    );
    let mut h = hmac_of(key, &r);
    // Flip a single bit in the HMAC.
    h[0] ^= 0x01;
    let (s, v) = post(&router, body(&state, &h, &r)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(v["reason"], "kernel_hmac_mismatch");
}

#[tokio::test]
async fn adversarial_idempotency_replay_no_duplicate_append() {
    let key = b"integration-key-32-bytes-padding";
    let state = state_with_key(key);
    let router = build_router(state.clone());
    let r = rec(
        "wave-replay",
        WaveStage::Tested,
        "adv",
        "/test",
        HashSet::new(),
    );
    let h = hmac_of(key, &r);
    let b = body(&state, &h, &r);
    let (s1, v1) = post(&router, b.clone()).await;
    assert_eq!(s1, StatusCode::CREATED);
    let (s2, v2) = post(&router, b).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(v2["idempotent_replay"], true);
    assert_eq!(v1["leaf_index"], v2["leaf_index"]);
    // Chain length must still be 1 — no duplicate leaf was appended.
    let (_, v) = get_verify(&router, "wave-replay").await;
    assert_eq!(v["chain"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn adversarial_missing_stage_detected_in_verify() {
    let key = b"integration-key-32-bytes-padding";
    let state = state_with_key(key);
    let router = build_router(state.clone());
    let mut gs = HashSet::new();
    gs.insert(GateSurface::SafetyKernel);

    // Append only TESTED (with gate-surface) and CLOSED.
    for (stage, sid, wb, gs_local) in [
        (WaveStage::Tested, "adv", "/test", gs.clone()),
        (WaveStage::Closed, "cls", "/closeout", HashSet::new()),
    ] {
        let r = rec("wave-incomplete", stage, sid, wb, gs_local);
        let h = hmac_of(key, &r);
        let (s, _) = post(&router, body(&state, &h, &r)).await;
        assert_eq!(s, StatusCode::CREATED);
    }
    let (s, v) = get_verify(&router, "wave-incomplete").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        v["all_required_stages_present"], false,
        "missing PURPLE_TEAMED + ACCEPTED must fail the predicate"
    );
}

#[tokio::test]
async fn adversarial_malformed_stage_rejected() {
    let key = b"integration-key-32-bytes-padding";
    let state = state_with_key(key);
    let router = build_router(state.clone());
    // Hand-craft a body with an out-of-enum stage.
    let body = json!({
        "kernel_hmac_hex": hex::encode([0u8; 32]),
        "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
        "record": {
            "evidence": "x",
            "gate_surfaces": [],
            "linear_issue": "",
            "occurred_at_epoch_seconds": 0,
            "outcome": "PASS",
            "session_id": "sid",
            "stage": "FROBNICATED",
            "wave_id": "w",
            "written_by": "/test",
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/wave/session")
        .header("content-type", "application/json")
        .header("x-api-key", X_API_KEY)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY); // serde JSON rejection
}

#[tokio::test]
async fn adversarial_forged_kernel_fingerprint_rejected() {
    let key = b"integration-key-32-bytes-padding";
    let state = state_with_key(key);
    let router = build_router(state.clone());
    let r = rec("wave-fp", WaveStage::Tested, "adv", "/test", HashSet::new());
    let h = hmac_of(key, &r);
    let mut b = body(&state, &h, &r);
    b["kernel_key_fingerprint_sha256"] = Value::String(hex::encode([0xEE; 32]));
    let (s, v) = post(&router, b).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(v["reason"], "kernel_fingerprint_mismatch");
}

#[tokio::test]
async fn adversarial_append_purple_teamed_with_empty_gate_surfaces_allowed_chain_predicate_handles()
{
    // Spec requirement: a record claiming PURPLE_TEAMED with empty
    // gate_surfaces should be allowed (consistency check is at the
    // chain-level all_required_stages_present, not at append time).
    let key = b"integration-key-32-bytes-padding";
    let state = state_with_key(key);
    let router = build_router(state.clone());
    let r = rec(
        "wave-pt-empty",
        WaveStage::PurpleTeamed,
        "pt-1",
        "/purple-team",
        HashSet::new(),
    );
    let h = hmac_of(key, &r);
    let (s, _) = post(&router, body(&state, &h, &r)).await;
    assert_eq!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn idempotency_key_derived_correctly() {
    // Same wave_id+stage+session_id, different bytes inside record
    // (mutated evidence). Even before HMAC verify, this would conflict
    // — but HMAC check fires first, and the attacker who has the HMAC
    // key would have to recompute the key. So the legitimate
    // mutated-by-the-writer path: same wave/stage/session, different
    // evidence, new valid HMAC. That should hit Conflict at the store.
    let key = b"integration-key-32-bytes-padding";
    let state = state_with_key(key);
    let router = build_router(state.clone());
    let r1 = rec(
        "wave-conflict",
        WaveStage::Tested,
        "adv",
        "/test",
        HashSet::new(),
    );
    let h1 = hmac_of(key, &r1);
    let (s1, _) = post(&router, body(&state, &h1, &r1)).await;
    assert_eq!(s1, StatusCode::CREATED);

    let mut r2 = r1.clone();
    r2.evidence = "mutated evidence".to_string();
    let h2 = hmac_of(key, &r2);
    let (s2, v2) = post(&router, body(&state, &h2, &r2)).await;
    assert_eq!(s2, StatusCode::CONFLICT);
    assert_eq!(v2["reason"], "idempotency_payload_mismatch");
}
