//!   AC6 — Rule-8 adversarial fixture: chain rejects a
//! synthetic "fake PASS" leaf whose content disagrees with ground
//! truth.
//!
//! Threat model: a compromised reconciler (or man-in-the-middle on
//! the reconciler -> transparency-log path) appends a leaf that
//! claims "running digest matches expected digest" while the digests
//! actually disagree. The gate must REJECT this claim by an honest
//! auditor recomputing the leaf hash from ground truth (running
//! digest sampled directly from the registry) and finding that the
//! re-derived hash does NOT match the chained hash.
//!
//! Rule 8: the fixture IS the gate. A "passing" suite that simply
//! trusts the ledger's say-so is malformed.
//!
//! Rule 9: the verifier MUST recompute the leaf hash in-process, not
//! label-match `outcome=match` in a string field.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::similar_names)]

use std::sync::Arc;

use qorch_domain::transparency::{
    compute_root, leaf_hash, verify_inclusion_proof, MerkleLeaf, VerificationError,
};
use qorch_transparency_store::{memory::MemoryTransparencyStore, AppendInput, TransparencyStore};

/// Honest drift-event payload (what an uncorrupted reconciler would
/// have written). Lex-sorted JSON so the bytes are deterministic.
fn drift_event_payload(running: &str, expected: &str, image: &str, at: u64) -> Vec<u8> {
    format!(
        r#"{{"detected_at_epoch_seconds":{at},"expected_digest":"{expected}","image_repository":"{image}","manifest_version":"v0.1.0","running_digest":"{running}"}}"#
    )
    .into_bytes()
}

/// Fake "everything is fine" payload (running == expected). The
/// adversary's claim.
fn fake_match_payload(digest: &str, image: &str, at: u64) -> Vec<u8> {
    format!(
        r#"{{"detected_at_epoch_seconds":{at},"expected_digest":"{digest}","image_repository":"{image}","manifest_version":"v0.1.0","running_digest":"{digest}"}}"#
    )
    .into_bytes()
}

/// AC6 — substituting the honest leaf hash into a proof of the fake
/// leaf trips `RootMismatch`. The chain is the gate.
#[tokio::test]
async fn ac6_fake_pass_detected_by_leaf_hash_recompute() {
    let store: Arc<dyn TransparencyStore> = Arc::new(MemoryTransparencyStore::new());

    let running = "sha256:running-drifted-bad";
    let expected = "sha256:expected-good";
    let image = "aryalabs/safety-kernel";
    let at: u64 = 1_700_000_000;

    // Adversary appends a fake "match" event.
    let fake = fake_match_payload(expected, image, at);
    let outcome = store
        .append(AppendInput {
            idempotency_key: [0xAA; 32],
            payload: fake.clone(),
            occurred_at_epoch_seconds: at,
        })
        .await
        .expect("ledger accepts adversarial append");
    assert_eq!(outcome.leaf_index, 0);

    let proof = store.build_inclusion_proof(0).await.expect("proof");
    let root = store.current_root().await.expect("root");
    // Ledger is honest about what it received — chain integrity holds.
    verify_inclusion_proof(&proof, &root).expect("fake leaf is chained correctly");
    assert_eq!(proof.leaf_hash, leaf_hash(&fake));

    // Rule 9: re-derive the leaf hash from GROUND TRUTH.
    let honest_payload = drift_event_payload(running, expected, image, at);
    let honest_leaf_hash = leaf_hash(&honest_payload);

    assert_ne!(
        honest_leaf_hash, proof.leaf_hash,
        "AC6 GATE: honest-drift leaf hash MUST differ from chained fake-PASS hash",
    );

    // Substituting honest_leaf_hash into the proof breaks chain
    // verification — the auditor catches the fake.
    let mut tampered_proof = proof.clone();
    tampered_proof.leaf_hash = honest_leaf_hash;
    let err = verify_inclusion_proof(&tampered_proof, &root).unwrap_err();
    assert_eq!(
        err,
        VerificationError::RootMismatch,
        "AC6 GATE: ground-truth leaf hash MUST fail proof verification against ledger root",
    );
}

/// AC6 stronger statement: the FULL honest-recompute root disagrees
/// with the ledger root when even one fake-PASS leaf is present.
#[tokio::test]
async fn ac6_fake_pass_root_disagrees_with_honest_recompute() {
    let store: Arc<dyn TransparencyStore> = Arc::new(MemoryTransparencyStore::new());

    let running = "sha256:running-drifted";
    let expected = "sha256:expected";
    let image = "aryalabs/safety-kernel";

    // 3 honest drift events.
    for i in 0..3u8 {
        let p = drift_event_payload(running, expected, image, 1_700_000_000 + u64::from(i));
        store
            .append(AppendInput {
                idempotency_key: [i; 32],
                payload: p,
                occurred_at_epoch_seconds: 1_700_000_000 + u64::from(i),
            })
            .await
            .expect("honest append");
    }

    // Adversary slips a fake at position 3.
    let fake = fake_match_payload(expected, image, 1_700_000_010);
    store
        .append(AppendInput {
            idempotency_key: [0xFE; 32],
            payload: fake,
            occurred_at_epoch_seconds: 1_700_000_010,
        })
        .await
        .expect("ledger appends fake");

    let ledger_root = store.current_root().await.expect("root");
    let ledger_size = store.current_size().await.expect("size");
    assert_eq!(ledger_size, 4);

    // Honest auditor reconstruction.
    let honest_leaves: Vec<MerkleLeaf> = (0..4u8)
        .map(|i| {
            let at = 1_700_000_000 + if i == 3 { 10 } else { u64::from(i) };
            MerkleLeaf {
                hash: leaf_hash(&drift_event_payload(running, expected, image, at)),
                leaf_index: u64::from(i),
                occurred_at_epoch_seconds: at,
            }
        })
        .collect();
    let honest_root = compute_root(&honest_leaves).expect("compute honest root");

    assert_ne!(
        ledger_root, honest_root,
        "AC6 GATE: ledger-with-fake root MUST diverge from honest-recompute root",
    );

    // And: the fake's inclusion proof verifies against the LEDGER
    // root (honest chain) but NOT against the honest-recompute root.
    let proof = store.build_inclusion_proof(3).await.expect("proof at 3");
    verify_inclusion_proof(&proof, &ledger_root).expect("verifies vs ledger root");
    let err = verify_inclusion_proof(&proof, &honest_root).unwrap_err();
    assert_eq!(
        err,
        VerificationError::RootMismatch,
        "AC6 GATE: fake leaf's proof MUST fail under honest-recompute root",
    );
}
