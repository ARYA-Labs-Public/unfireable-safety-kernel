//! internal-ref (Phase 0) — authoritative-store concurrency + clobber-detection
//! demonstration for the ceremony transparency log.
//!
//! The Rust transparency log is the SINGLE AUTHORITATIVE store for ceremony
//! verdicts; the `.claude/state/*.jsonl` files are a derived cache. This test
//! exercises the authoritative store's two load-bearing guarantees at the
//! Merkle layer:
//!
//!   AC2 (a) — two SIMULTANEOUS distinct ceremony writes both land, get
//!             distinct ledger positions, and each leaf's RFC-6962 inclusion
//!             proof verifies against the final published root (hashes verify).
//!   AC2 (b) — a simulated CLOBBER of already-committed evidence (an attacker
//!             overwriting a stored leaf's bytes) is DETECTED, not silently
//!             absorbed: it moves the authoritative Merkle root, and an
//!             inclusion proof for the clobbered leaf FAILS against the
//!             originally-published root (Rule 8 adversarial fixture → RED).
//!
//! These are pure re-derivations (Rule 9): every assertion recomputes the
//! Merkle root / replays the inclusion-proof verifier in-process rather than
//! trusting any status label.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use qorch_domain::transparency::{
    build_inclusion_proof, compute_root, leaf_hash, verify_inclusion_proof, MerkleLeaf,
    VerificationError,
};
use qorch_transparency_store::{memory::MemoryTransparencyStore, AppendInput, TransparencyStore};

/// A distinct ceremony record's opaque leaf payload. In production these are
/// the length-prefixed `record_bytes || kernel_hmac` framings the wave-session
/// route builds; here we use representative opaque bytes since the Merkle
/// guarantees are payload-agnostic.
fn ceremony_payload(tag: &str) -> Vec<u8> {
    format!("{{\"wave_id\":\"internal-ref\",\"session\":\"{tag}\",\"verdict\":\"PASS\"}}")
        .into_bytes()
}

fn key_for(tag: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = tag;
    k
}

/// AC2 (a): two simultaneous distinct ceremony writes both present + verify.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_distinct_ceremony_writes_both_present_and_verify() {
    let store = MemoryTransparencyStore::new();

    // Two distinct ceremony records (different sessions of the SAME wave)
    // written CONCURRENTLY — the canonical concurrent-ceremony-write scenario.
    let s1 = store.clone();
    let s2 = store.clone();
    let t1 = tokio::spawn(async move {
        s1.append(AppendInput {
            idempotency_key: key_for(1),
            payload: ceremony_payload("test-sid"),
            occurred_at_epoch_seconds: 1_716_400_000,
        })
        .await
        .unwrap()
    });
    let t2 = tokio::spawn(async move {
        s2.append(AppendInput {
            idempotency_key: key_for(2),
            payload: ceremony_payload("closeout-sid"),
            occurred_at_epoch_seconds: 1_716_400_005,
        })
        .await
        .unwrap()
    });
    let o1 = t1.await.unwrap();
    let o2 = t2.await.unwrap();

    // Both writes minted a fresh leaf (neither was absorbed as a replay).
    assert!(
        o1.created && o2.created,
        "both distinct writes must be fresh"
    );

    // Both present with distinct positions {0,1} — no gap, no collapse.
    assert_eq!(store.current_size().await.unwrap(), 2, "both must persist");
    let mut idxs = [o1.leaf_index, o2.leaf_index];
    idxs.sort_unstable();
    assert_eq!(idxs, [0, 1], "distinct ledger positions");

    // Hashes verify: each leaf's inclusion proof checks out against the final
    // published root (re-derived in-process).
    let root = store.current_root().await.unwrap();
    for idx in 0u64..2 {
        let proof = store.build_inclusion_proof(idx).await.unwrap();
        verify_inclusion_proof(&proof, &root)
            .expect("each concurrent write's inclusion proof must verify");
    }
}

/// AC2 (b): a simulated clobber of committed evidence is DETECTED.
///
/// This is the Rule-8 adversarial fixture: we take a legitimately-committed
/// two-leaf ledger, publish its root `r_published`, then synthesize the state
/// an attacker who overwrote leaf 0's stored bytes would produce, and assert
/// the gate goes RED — the root moves and the old published root no longer
/// admits the clobbered leaf.
#[test]
fn simulated_clobber_of_committed_leaf_is_detected() {
    // Legitimate committed ledger: two distinct ceremony leaves.
    let good: Vec<MerkleLeaf> = [
        ceremony_payload("test-sid"),
        ceremony_payload("closeout-sid"),
    ]
    .iter()
    .enumerate()
    .map(|(i, p)| MerkleLeaf {
        hash: leaf_hash(p),
        leaf_index: i as u64,
        occurred_at_epoch_seconds: 1_716_400_000 + i as u64,
    })
    .collect();
    let r_published = compute_root(&good).expect("published root");

    // Sanity: honest inclusion proofs verify against the published root.
    for idx in 0u64..2 {
        let proof = build_inclusion_proof(&good, idx).unwrap();
        verify_inclusion_proof(&proof, &r_published).expect("honest proof verifies");
    }

    // ADVERSARY: clobber leaf 0's committed bytes (flip the verdict to a fake
    // PASS on a different session). This is the "concurrent-session clobber"
    // hazard applied to already-committed evidence.
    let clobbered_payload = ceremony_payload("attacker-injected-sid");
    let mut clobbered = good.clone();
    clobbered[0].hash = leaf_hash(&clobbered_payload);
    let r_clobbered = compute_root(&clobbered).expect("clobbered root");

    // DETECTION 1 — the authoritative root moves. Any auditor pinning the
    // published root sees the divergence immediately.
    assert_ne!(
        r_published, r_clobbered,
        "a clobber MUST change the authoritative Merkle root"
    );

    // DETECTION 2 — an inclusion proof for the clobbered leaf does NOT verify
    // against the originally-published root: the clobber is rejected, never
    // silently absorbed.
    let clobbered_proof = build_inclusion_proof(&clobbered, 0).unwrap();
    let verdict = verify_inclusion_proof(&clobbered_proof, &r_published);
    assert!(
        matches!(verdict, Err(VerificationError::RootMismatch)),
        "clobbered leaf must be REJECTED against the published root, got {verdict:?}"
    );

    // GREEN control — the untouched second leaf still verifies against the
    // published root, proving the detector is specific (does not blanket-fail).
    let honest_proof = build_inclusion_proof(&good, 1).unwrap();
    verify_inclusion_proof(&honest_proof, &r_published)
        .expect("untouched leaf still verifies (detector is specific, not a blanket reject)");
}
