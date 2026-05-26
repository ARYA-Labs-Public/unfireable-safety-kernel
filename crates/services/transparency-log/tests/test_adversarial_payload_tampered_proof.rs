//!   — Rule-8 adversarial fixture: a payload-tampered
//! inclusion proof (bytewise mutation of any field except the path
//! length) MUST be rejected with `RootMismatch`.
//!
//! Threat model: a man-in-the-middle between the auditor and the
//! transparency-log mutates a single byte of the returned
//! `inclusion_proof` (the leaf_hash, an audit path entry, or the
//! tree_size) in flight. The verifier MUST detect the tamper at
//! verification time, not later.
//!
//! End-to-end: spin the real router on a 127.0.0.1 ephemeral port,
//! POST several leaves, GET an inclusion proof, mutate one byte, then
//! call `verify_inclusion_proof` and assert the failure mode.

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
use qorch_domain::transparency::{verify_inclusion_proof, InclusionProof, VerificationError};
use qorch_transparency_log::router::build_router;
use qorch_transparency_log::state::AppState;
use qorch_transparency_store::memory::MemoryTransparencyStore;

const TEST_API_KEY: &str = "tamper-test-key";

async fn spawn_service() -> (SocketAddr, String) {
    let signing_key = SigningKey::from_bytes(&[0x55u8; 32]);
    let signing_pk = signing_key.verifying_key().to_bytes();
    let mut h = Sha256::new();
    h.update(signing_pk);
    let signing_fpr = hex::encode(h.finalize());

    let kernel_signing = SigningKey::from_bytes(&[0x66u8; 32]);
    let kernel_pk = kernel_signing.verifying_key().to_bytes();
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
        TEST_API_KEY.to_string(),
    );
    let router = build_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (addr, kernel_fpr)
}

async fn append_n_leaves(base: &str, kernel_fpr: &str, n: u8, client: &reqwest::Client) {
    for i in 0..n {
        let body = json!({
            "idempotency_key_hex": hex::encode([i; 32]),
            "kernel_key_fingerprint_sha256": kernel_fpr,
            "occurred_at_epoch_seconds": 1_700_000_000_u64 + u64::from(i),
            "token_b64": URL_SAFE_NO_PAD.encode(format!("entry-{i}").as_bytes()),
        });
        let resp = client
            .post(format!("{base}/v1/append"))
            .header("x-api-key", TEST_API_KEY)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    }
}

async fn fetch_proof_and_root(
    base: &str,
    client: &reqwest::Client,
    idx: u64,
) -> (InclusionProof, [u8; 32]) {
    let resp = client
        .get(format!("{base}/v1/verify/{idx}"))
        .header("x-api-key", TEST_API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    let root: [u8; 32] = hex::decode(v["current_root_hash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let proof: InclusionProof = serde_json::from_value(v["inclusion_proof"].clone()).unwrap();
    (proof, root)
}

/// AC — flip 1 byte in the proof's `leaf_hash`. Must be RootMismatch.
#[tokio::test]
async fn adversarial_tampered_leaf_hash_rejected() {
    let (addr, kernel_fpr) = spawn_service().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    append_n_leaves(&base, &kernel_fpr, 8, &client).await;

    let (mut proof, root) = fetch_proof_and_root(&base, &client, 3).await;
    // Sanity: proof verifies before tampering.
    verify_inclusion_proof(&proof, &root).expect("proof must verify before tampering");

    proof.leaf_hash[0] ^= 0x01;
    let err = verify_inclusion_proof(&proof, &root).unwrap_err();
    assert_eq!(
        err,
        VerificationError::RootMismatch,
        "AC GATE: 1-byte leaf_hash mutation MUST yield RootMismatch",
    );
}

/// AC — flip 1 byte in the FIRST audit-path entry. Must be
/// RootMismatch.
#[tokio::test]
async fn adversarial_tampered_audit_path_entry_rejected() {
    let (addr, kernel_fpr) = spawn_service().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    append_n_leaves(&base, &kernel_fpr, 8, &client).await;

    let (mut proof, root) = fetch_proof_and_root(&base, &client, 3).await;
    assert!(!proof.path.is_empty(), "proof must have audit path entries");
    verify_inclusion_proof(&proof, &root).expect("proof must verify before tampering");

    proof.path[0][0] ^= 0x80;
    let err = verify_inclusion_proof(&proof, &root).unwrap_err();
    assert_eq!(
        err,
        VerificationError::RootMismatch,
        "AC GATE: 1-byte path-entry mutation MUST yield RootMismatch",
    );
}

/// AC — extra spurious entry appended to the audit path MUST be
/// ProofPathLengthMismatch.
#[tokio::test]
async fn adversarial_extra_path_entry_rejected() {
    let (addr, kernel_fpr) = spawn_service().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    append_n_leaves(&base, &kernel_fpr, 8, &client).await;

    let (mut proof, root) = fetch_proof_and_root(&base, &client, 3).await;
    proof.path.push([0xCCu8; 32]);
    let err = verify_inclusion_proof(&proof, &root).unwrap_err();
    assert_eq!(
        err,
        VerificationError::ProofPathLengthMismatch,
        "AC GATE: extra path entry MUST yield ProofPathLengthMismatch",
    );
}

/// AC — leaf_index swap (claim a different position) MUST fail.
#[tokio::test]
async fn adversarial_tampered_leaf_index_rejected() {
    let (addr, kernel_fpr) = spawn_service().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    append_n_leaves(&base, &kernel_fpr, 8, &client).await;

    let (mut proof, root) = fetch_proof_and_root(&base, &client, 3).await;
    // Re-aim the proof at index 5 instead of 3.
    proof.leaf_index = 5;
    let err = verify_inclusion_proof(&proof, &root).unwrap_err();
    // Either RootMismatch (most cases) or ProofPathLengthMismatch
    // (rare cases when the audit-path length happens to be the same
    // but recompute disagrees). Both are valid GATE outcomes.
    assert!(
        matches!(
            err,
            VerificationError::RootMismatch | VerificationError::ProofPathLengthMismatch
        ),
        "AC GATE: leaf_index swap MUST fail verification (got {err:?})",
    );
}

/// AC — tree_size swap (claim the proof was issued against a
/// different tree size) MUST fail.
#[tokio::test]
async fn adversarial_tampered_tree_size_rejected() {
    let (addr, kernel_fpr) = spawn_service().await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    append_n_leaves(&base, &kernel_fpr, 8, &client).await;

    let (mut proof, root) = fetch_proof_and_root(&base, &client, 3).await;
    proof.tree_size = 16; // claim a tree that's twice the size
    let err = verify_inclusion_proof(&proof, &root).unwrap_err();
    assert!(
        matches!(
            err,
            VerificationError::RootMismatch | VerificationError::ProofPathLengthMismatch
        ),
        "AC GATE: tree_size swap MUST fail verification (got {err:?})",
    );
}
