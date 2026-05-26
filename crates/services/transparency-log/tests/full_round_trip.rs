//! Full round-trip integration test ( Step 5).
//!
//! Spins the full axum router (via `qorch_transparency_log::router::
//! build_router`) on a 127.0.0.1 ephemeral port backed by the
//! in-memory store, appends 10 entries via `POST /v1/append`, then:
//!
//!   1. Fetches `GET /v1/verify/:idx` for each entry and verifies the
//!      returned inclusion proof against the returned root.
//!   2. Fetches `GET /v1/sth` and verifies the Ed25519 signature with
//!      the service's signing key.
//!   3. Fetches `GET /v1/consistency?first=3&second=10` and verifies
//!      the consistency proof against `compute_root` over the
//!      appropriate leaf prefixes (recomputed from the original
//!      payloads).
//!   4. Re-POSTs an existing entry's idempotency-key + payload and
//!      asserts HTTP 200 + `idempotent_replay = true`.
//!   5. Confirms `x-api-key` is enforced (no header → 401).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::similar_names)]

use std::net::SocketAddr;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

use qorch_adapters::clock::SystemClock;
use qorch_domain::safety::Clock;
use qorch_domain::transparency::{
    compute_root, leaf_hash, verify_consistency_proof, verify_inclusion_proof, verify_sth,
    InclusionProof, MerkleLeaf,
};
use qorch_transparency_log::router::build_router;
use qorch_transparency_log::state::AppState;
use qorch_transparency_store::memory::MemoryTransparencyStore;

const TEST_API_KEY: &str = "trip-test-key";

async fn spawn_service() -> (SocketAddr, SigningKey, String) {
    let signing_key = SigningKey::from_bytes(&[0x1Au8; 32]);
    let signing_pk = signing_key.verifying_key().to_bytes();
    let mut h = Sha256::new();
    h.update(signing_pk);
    let signing_fpr = hex::encode(h.finalize());

    let kernel_signing = SigningKey::from_bytes(&[0x2Bu8; 32]);
    let kernel_pk = kernel_signing.verifying_key().to_bytes();
    let mut h2 = Sha256::new();
    h2.update(kernel_pk);
    let kernel_fpr = hex::encode(h2.finalize());

    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let state = AppState::new(
        Arc::new(MemoryTransparencyStore::new()),
        Arc::new(SigningKey::from_bytes(&signing_key.to_bytes())),
        signing_fpr,
        kernel_fpr.clone(),
        clock,
        TEST_API_KEY.to_string(),
    );
    let router = build_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    (addr, signing_key, kernel_fpr)
}

#[tokio::test]
async fn full_round_trip_append_verify_sth_consistency() {
    let (addr, signing_key, kernel_fpr) = spawn_service().await;
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // Append 10 leaves with deterministic payloads.
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    for i in 0u8..10 {
        let payload = format!("entry-{i}").into_bytes();
        payloads.push(payload.clone());
        let body = json!({
            "idempotency_key_hex": hex::encode([i; 32]),
            "kernel_key_fingerprint_sha256": kernel_fpr.clone(),
            "occurred_at_epoch_seconds": 1_700_000_000_u64 + u64::from(i),
            "token_b64": URL_SAFE_NO_PAD.encode(&payload),
        });
        let resp = client
            .post(format!("{base}/v1/append"))
            .header("x-api-key", TEST_API_KEY)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["leaf_index"], i);
        assert_eq!(v["idempotent_replay"], false);
        assert_eq!(v["leaf_hash_hex"].as_str().unwrap(), hex::encode(leaf_hash(&payload)));
    }

    // Verify each entry's inclusion proof against the response's root.
    for i in 0u64..10 {
        let resp = client
            .get(format!("{base}/v1/verify/{i}"))
            .header("x-api-key", TEST_API_KEY)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        let root_bytes: [u8; 32] = hex::decode(v["current_root_hash"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let proof: InclusionProof =
            serde_json::from_value(v["inclusion_proof"].clone()).unwrap();
        verify_inclusion_proof(&proof, &root_bytes).expect("each entry verifies");
        assert_eq!(v["entry"]["leaf_index"], i);
    }

    // STH round-trip.
    let resp = client
        .get(format!("{base}/v1/sth"))
        .header("x-api-key", TEST_API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: qorch_transparency_log::dto::SignedTreeHeadResponse = resp.json().await.unwrap();
    assert!(body.ok);
    assert_eq!(body.sth.tree_size, 10);
    verify_sth(&body.sth, &signing_key.verifying_key())
        .expect("STH signature verifies under signer key");

    // Consistency: first=3, second=10. Rebuild the leaf-hash slices
    // from the saved payloads + the public domain helpers so this test
    // doesn't reach into the storage adapter.
    let mut leaves: Vec<MerkleLeaf> = Vec::with_capacity(10);
    for (i, p) in payloads.iter().enumerate() {
        leaves.push(MerkleLeaf {
            hash: leaf_hash(p),
            leaf_index: i as u64,
            occurred_at_epoch_seconds: 1_700_000_000_u64 + i as u64,
        });
    }
    let from_root = compute_root(&leaves[..3]).unwrap();
    let to_root = compute_root(&leaves[..10]).unwrap();

    let resp = client
        .get(format!("{base}/v1/consistency?first=3&second=10"))
        .header("x-api-key", TEST_API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: qorch_transparency_log::dto::ConsistencyResponse = resp.json().await.unwrap();
    verify_consistency_proof(&body.consistency_proof, &from_root, &to_root)
        .expect("consistency proof must verify");

    // Idempotent retry: re-POST entry 0 (same idem-key, same payload).
    let body = json!({
        "idempotency_key_hex": hex::encode([0u8; 32]),
        "kernel_key_fingerprint_sha256": kernel_fpr.clone(),
        "occurred_at_epoch_seconds": 1_700_000_000_u64,
        "token_b64": URL_SAFE_NO_PAD.encode(&payloads[0]),
    });
    let resp = client
        .post(format!("{base}/v1/append"))
        .header("x-api-key", TEST_API_KEY)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["idempotent_replay"], true);
    assert_eq!(v["leaf_index"], 0);

    // Missing x-api-key → 401.
    let resp = client
        .get(format!("{base}/v1/sth"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}
