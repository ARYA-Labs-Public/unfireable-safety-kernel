//! ARY-2181 Phase 1 — load test: 100 concurrent wave-session appends.
//! Spec requirement: p99 latency < 200ms.
//!
//! In-process load test against the same router used in production.
//! Each task uses a UNIQUE (wave_id, stage, session_id) tuple so no
//! requests de-duplicate — we're measuring fresh-append latency.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::Request;
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use qorch_adapters::clock::SystemClock;
use qorch_domain::safety::Clock;
use qorch_domain::wave::context::WaveId;
use qorch_domain::wave::session_record::WaveSessionRecord;
use qorch_domain::wave::stage::{WaveOutcome, WaveStage};
use qorch_transparency_log::router::build_router;
use qorch_transparency_log::state::AppState;
use qorch_transparency_store::memory::MemoryTransparencyStore;
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

const API_KEY: &str = "load-test-api-key";

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn p99_under_200ms_for_100_concurrent_appends() {
    let key: Vec<u8> = b"load-test-key-32-bytes-of-padding".to_vec();

    let seed = [0x77u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let signing_pk = signing_key.verifying_key().to_bytes();
    let mut h = Sha256::new();
    h.update(signing_pk);
    let signing_fpr = hex::encode(h.finalize());
    let kernel_seed = [0x88u8; 32];
    let kernel_pk = SigningKey::from_bytes(&kernel_seed)
        .verifying_key()
        .to_bytes();
    let mut h2 = Sha256::new();
    h2.update(kernel_pk);
    let kernel_fpr = hex::encode(h2.finalize());
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let state = AppState::new(
        Arc::new(MemoryTransparencyStore::new()),
        Arc::new(signing_key),
        signing_fpr,
        kernel_fpr.clone(),
        clock,
        API_KEY.to_string(),
    )
    .with_kernel_hmac_key(key.clone());
    let router = build_router(state.clone());

    let n: usize = 100;
    let mut tasks = Vec::with_capacity(n);
    for i in 0..n {
        let router = router.clone();
        let key = key.clone();
        let kernel_fpr = kernel_fpr.clone();
        tasks.push(tokio::spawn(async move {
            let r = WaveSessionRecord::new(
                WaveId::new(format!("wave-load-{i}")),
                "ARY-2181",
                WaveStage::Tested,
                format!("adv-{i}"),
                WaveOutcome::Pass,
                "load-test evidence",
                HashSet::new(),
                "/test",
                1_716_400_000 + i as u64,
            );
            let bytes = r.canonical_bytes().unwrap();
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).unwrap();
            mac.update(&bytes);
            let h_bytes = mac.finalize().into_bytes();
            let mut hmac = [0u8; 32];
            hmac.copy_from_slice(&h_bytes);

            let body = json!({
                "kernel_hmac_hex": hex::encode(hmac),
                "kernel_key_fingerprint_sha256": kernel_fpr,
                "record": r,
            });
            let req = Request::builder()
                .method("POST")
                .uri("/v1/wave/session")
                .header("content-type", "application/json")
                .header("x-api-key", API_KEY)
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap();

            let t0 = Instant::now();
            let resp = router.oneshot(req).await.unwrap();
            // Drain body for fair timing.
            let _ = resp.into_body().collect().await.unwrap();
            t0.elapsed()
        }));
    }
    let mut latencies = Vec::with_capacity(n);
    for t in tasks {
        latencies.push(t.await.unwrap());
    }
    latencies.sort();
    // p99 is index 98 for n=100 (0-indexed). For correctness against
    // tiny samples, compute index = ceil(0.99 * n) - 1 = 98.
    let p99 = latencies[98];
    let p50 = latencies[49];
    let max = latencies[99];
    eprintln!(
        "load-test wave-session: n={n}, p50={p50:?}, p99={p99:?}, max={max:?}"
    );
    assert!(
        p99.as_millis() < 200,
        "p99 latency {}ms exceeds 200ms spec",
        p99.as_millis()
    );
}
