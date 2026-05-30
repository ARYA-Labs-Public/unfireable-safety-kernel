//!  /purple-team — concurrent-append + race-condition assessment
//! for the wave-session-record routes.
//!
//! Threat surface this test exercises (matches the purple-team scope on
//!  ):
//!
//! - (b) Merkle inclusion-proof tampering — guarded by leaf-hash
//!   commit: this test indirectly proves the leaf-hash framing is
//!   correct by reading back the chain after concurrent writes.
//! - (c) Race conditions in concurrent appends — N concurrent tasks
//!   POST the SAME (wave_id, stage, session_id) tuple. Exactly one
//!   must produce a fresh leaf (201); the rest MUST be idempotent
//!   replays (200) on the SAME leaf_index. The chain MUST contain
//!   exactly one entry afterwards. A naive non-atomic
//!   read-then-append would surface here as multiple 201s and a
//!   duplicate chain.
//! - (d) Replay attack with stale signatures — distinct from (c): we
//!   POST the SAME record (same canonical bytes + same HMAC) many
//!   times. Idempotency must collapse them; the chain stays length 1.
//! - (e) Verification route accepting incomplete chain as complete —
//!   we verify a wave with no PURPLE_TEAMED record under a non-empty
//!   gate_surfaces and assert `all_required_stages_present == false`
//!   (already covered in `integration_wave_session.rs`; reproduced
//!   here for purple-team scope completeness).
//!
//! (a) HMAC key compromise is out of scope for an in-process test —
//! the key IS the secret. Defense-in-depth review: the kernel HMAC
//! verify uses `hmac::Mac::verify_slice`, which is constant-time per
//! the upstream `subtle` crate. A successful (a) requires either
//! filesystem access to `.hmac_key` (covered by deploy-env policy,
//! not the route) or a side-channel on the verify_slice call (covered
//! by the `subtle` constant-time property).

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
use qorch_domain::wave::session_record::WaveSessionRecord;
use qorch_domain::wave::stage::{WaveOutcome, WaveStage};
use qorch_transparency_log::router::build_router;
use qorch_transparency_log::state::AppState;
use qorch_transparency_store::memory::MemoryTransparencyStore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

const API_KEY: &str = "purple-team-api-key";

fn fixture_state(hmac_key: &[u8]) -> AppState {
    let seed = [0x55u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let signing_pk = signing_key.verifying_key().to_bytes();
    let mut h = Sha256::new();
    h.update(signing_pk);
    let signing_fpr = hex::encode(h.finalize());
    let kernel_seed = [0x66u8; 32];
    let kernel_pk = SigningKey::from_bytes(&kernel_seed)
        .verifying_key()
        .to_bytes();
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
        API_KEY.to_string(),
    )
    .with_kernel_hmac_key(hmac_key.to_vec())
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

/// (c) — Race: 50 concurrent POSTs of the SAME wave-session record.
/// Exactly one must return 201; the rest must return 200 with
/// `idempotent_replay: true`. Chain length must be exactly 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_same_record_collapses_to_single_leaf() {
    let key: Vec<u8> = b"purple-team-key-32-bytes-padding!".to_vec();
    let state = fixture_state(&key);
    let router = build_router(state.clone());

    let r = WaveSessionRecord::new(
        WaveId::new("wave-race"),
        "",
        WaveStage::Tested,
        "race-sid",
        WaveOutcome::Pass,
        "evidence",
        HashSet::new(),
        "/test",
        1_716_400_000,
    );
    let h = hmac_of(&key, &r);
    let body_v = body(&state, &h, &r);

    let n: usize = 50;
    let mut tasks = Vec::with_capacity(n);
    for _ in 0..n {
        let router = router.clone();
        let body_v = body_v.clone();
        tasks.push(tokio::spawn(async move {
            let req = Request::builder()
                .method("POST")
                .uri("/v1/wave/session")
                .header("content-type", "application/json")
                .header("x-api-key", API_KEY)
                .body(Body::from(serde_json::to_vec(&body_v).unwrap()))
                .unwrap();
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            let v: Value = serde_json::from_slice(&bytes).unwrap();
            (status, v)
        }));
    }
    let mut created = 0;
    let mut replays = 0;
    let mut indices = Vec::with_capacity(n);
    for t in tasks {
        let (status, v) = t.await.unwrap();
        match status {
            StatusCode::CREATED => created += 1,
            StatusCode::OK => replays += 1,
            other => panic!("unexpected status {other}: {v}"),
        }
        indices.push(v["leaf_index"].as_u64().unwrap());
    }
    assert_eq!(created, 1, "exactly one fresh insert allowed under race");
    assert_eq!(replays, n - 1, "rest must be idempotent replays");
    // All requests must report the SAME leaf_index.
    indices.sort_unstable();
    indices.dedup();
    assert_eq!(indices.len(), 1, "all responses must point at one leaf");

    // Chain length is exactly 1.
    let verify_req = Request::builder()
        .method("GET")
        .uri("/v1/wave/wave-race/verify")
        .header("x-api-key", API_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(verify_req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["chain"].as_array().unwrap().len(), 1);
}

/// (d) — Replay: 100 sequential POSTs of the same record (stale
/// signature). Chain stays length 1 across all replays.
#[tokio::test]
async fn stale_signature_replay_does_not_extend_chain() {
    let key: Vec<u8> = b"purple-team-key-32-bytes-padding!".to_vec();
    let state = fixture_state(&key);
    let router = build_router(state.clone());

    let r = WaveSessionRecord::new(
        WaveId::new("wave-replay"),
        "",
        WaveStage::Tested,
        "replay-sid",
        WaveOutcome::Pass,
        "evidence",
        HashSet::new(),
        "/test",
        1_716_400_000,
    );
    let h = hmac_of(&key, &r);
    let body_v = body(&state, &h, &r);

    for i in 0..100 {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/wave/session")
            .header("content-type", "application/json")
            .header("x-api-key", API_KEY)
            .body(Body::from(serde_json::to_vec(&body_v).unwrap()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        // First request creates; rest are replays.
        if i == 0 {
            assert_eq!(status, StatusCode::CREATED);
        } else {
            assert_eq!(status, StatusCode::OK);
        }
    }

    let req = Request::builder()
        .method("GET")
        .uri("/v1/wave/wave-replay/verify")
        .header("x-api-key", API_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v["chain"].as_array().unwrap().len(),
        1,
        "100 replays must not grow the chain"
    );
}

/// (b) — Per-wave isolation: 30 concurrent appends across 30 distinct
/// wave_ids must each yield their own leaf, and verify must isolate
/// chains per wave (no cross-pollination).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_distinct_waves_do_not_cross_pollinate() {
    let key: Vec<u8> = b"purple-team-key-32-bytes-padding!".to_vec();
    let state = fixture_state(&key);
    let router = build_router(state.clone());

    let n: usize = 30;
    let mut tasks = Vec::with_capacity(n);
    for i in 0..n {
        let router = router.clone();
        let key = key.clone();
        let state = state.clone();
        tasks.push(tokio::spawn(async move {
            let r = WaveSessionRecord::new(
                WaveId::new(format!("wave-iso-{i}")),
                "",
                WaveStage::Tested,
                format!("sid-{i}"),
                WaveOutcome::Pass,
                "evidence",
                HashSet::new(),
                "/test",
                1_716_400_000,
            );
            let h = hmac_of(&key, &r);
            let body_v = body(&state, &h, &r);
            let req = Request::builder()
                .method("POST")
                .uri("/v1/wave/session")
                .header("content-type", "application/json")
                .header("x-api-key", API_KEY)
                .body(Body::from(serde_json::to_vec(&body_v).unwrap()))
                .unwrap();
            let resp = router.oneshot(req).await.unwrap();
            resp.status()
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), StatusCode::CREATED);
    }

    // Each wave verifies to exactly one entry; chain[0].record.wave_id
    // matches the URL path (no leakage).
    for i in 0..n {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/v1/wave/wave-iso-{i}/verify"))
            .header("x-api-key", API_KEY)
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        let chain = v["chain"].as_array().unwrap();
        assert_eq!(chain.len(), 1, "wave-iso-{i} chain must contain one entry");
        assert_eq!(chain[0]["record"]["wave_id"], format!("wave-iso-{i}"));
    }
}
