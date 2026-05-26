//!   AC7 — Rule-8 adversarial fixture: chain detects
//! the gap when an entry is deleted from the ledger.
//!
//! Threat model: a database operator with direct table access deletes
//! one (or more) rows from `transparency_log`, hoping to erase a
//! controversial decision. The gate must DETECT the gap. Detection
//! mechanism: every external auditor caches the previous STH (root +
//! tree_size) at periodic intervals; an attempt to surface a smaller
//! tree, or a tree of the same size whose root has changed, is
//! caught by:
//!
//!   1. A consistency proof from the previous (cached) size to the
//!      current size — if the previous tree is no longer a prefix of
//!      the current one, verify_consistency_proof returns
//!      `RootMismatch`.
//!   2. Re-verifying an existing inclusion proof against the new
//!      root — if any earlier leaf was deleted, the proof now fails.
//!
//! Note: Postgres-level "deletion" cannot be done through the
//! `TransparencyStore` trait (no `delete` method by design). The
//! threat is operator-level row deletion. We simulate by spinning up
//! TWO stores: the "original" with 10 leaves, and a "tampered" with
//! the same 9 leaves at the corresponding indices but with leaf 5
//! omitted (i.e. leaf 5's payload+key is dropped, indices 0..4 and
//! 6..9 keep their content but indices 5..8 shift down by 1 — exactly
//! what happens when a row is hard-deleted under BIGSERIAL).
//!
//! Rule 9 demands: every check re-derives evidence in-process.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::similar_names)]

use std::sync::Arc;

use qorch_domain::transparency::{
    build_consistency_proof, leaf_hash, verify_consistency_proof, verify_inclusion_proof,
    VerificationError,
};
use qorch_transparency_store::{memory::MemoryTransparencyStore, AppendInput, TransparencyStore};

/// Build a store with `n` deterministic leaves.
async fn store_with_n_leaves(n: u8) -> Arc<dyn TransparencyStore> {
    let store: Arc<dyn TransparencyStore> = Arc::new(MemoryTransparencyStore::new());
    for i in 0..n {
        store
            .append(AppendInput {
                idempotency_key: [i; 32],
                payload: format!("entry-{i}").into_bytes(),
                occurred_at_epoch_seconds: 1_700_000_000 + u64::from(i),
            })
            .await
            .expect("append");
    }
    store
}

/// Build a store with the same leaves, EXCEPT entry at index
/// `omit_index` is omitted (indices above it shift down). This is
/// exactly what an operator-side row deletion would look like on a
/// freshly-recreated BIGSERIAL table.
async fn store_with_leaf_omitted(n: u8, omit_index: u8) -> Arc<dyn TransparencyStore> {
    let store: Arc<dyn TransparencyStore> = Arc::new(MemoryTransparencyStore::new());
    for i in 0..n {
        if i == omit_index {
            continue;
        }
        store
            .append(AppendInput {
                idempotency_key: [i; 32],
                payload: format!("entry-{i}").into_bytes(),
                occurred_at_epoch_seconds: 1_700_000_000 + u64::from(i),
            })
            .await
            .expect("append");
    }
    store
}

/// AC7 — a previously-issued inclusion proof for a leaf whose
/// predecessor was later deleted fails against the tampered root.
#[tokio::test]
async fn ac7_deletion_invalidates_prior_inclusion_proof() {
    // Original ledger: 10 leaves.
    let original = store_with_n_leaves(10).await;
    let original_root = original.current_root().await.expect("root");
    assert_eq!(original.current_size().await.unwrap(), 10);

    // Auditor cached a proof for leaf 7 against the original root.
    let proof_7 = original
        .build_inclusion_proof(7)
        .await
        .expect("proof at 7");
    verify_inclusion_proof(&proof_7, &original_root).expect("proof verifies originally");

    // Operator deletes leaf 5 — the tampered ledger has 9 leaves,
    // with indices 5..8 carrying the original 6..9 content.
    let tampered = store_with_leaf_omitted(10, 5).await;
    let tampered_root = tampered.current_root().await.expect("tampered root");
    assert_eq!(tampered.current_size().await.unwrap(), 9);

    // Roots must differ — chain integrity catches the deletion.
    assert_ne!(
        original_root, tampered_root,
        "AC7 GATE: deletion MUST change the Merkle root",
    );

    // Re-verifying the cached proof against the tampered root: the
    // proof's leaf_index (7) now refers to a different leaf in the
    // tampered ledger, but more importantly the path no longer
    // recomputes to the new root — RootMismatch.
    let err = verify_inclusion_proof(&proof_7, &tampered_root).unwrap_err();
    assert_eq!(
        err,
        VerificationError::RootMismatch,
        "AC7 GATE: cached inclusion proof MUST fail against post-deletion root",
    );
}

/// AC7 — the consistency proof between the original tree (size 10)
/// and the tampered tree (size 9) cannot be constructed honestly —
/// the tampered tree is NOT an extension of the original, so any
/// "proof" the tampered server might produce must fail
/// verify_consistency_proof.
#[tokio::test]
async fn ac7_deletion_breaks_consistency_proof() {
    let original = store_with_n_leaves(10).await;
    let original_root = original.current_root().await.expect("root");

    let tampered = store_with_leaf_omitted(10, 5).await;
    let tampered_root = tampered.current_root().await.expect("tampered root");

    // The honest direction (small -> big) cannot even be REQUESTED
    // when big is smaller than small. Asking for consistency from
    // size 10 (cached) to size 9 (tampered) — InvalidConsistencyRange
    // because from_size > to_size.
    let leaves_for_tampered: Vec<_> = (0..9u8)
        .map(|i| qorch_domain::transparency::MerkleLeaf {
            hash: leaf_hash(
                format!("entry-{}", if i < 5 { i } else { i + 1 }).as_bytes(),
            ),
            leaf_index: u64::from(i),
            occurred_at_epoch_seconds: 1_700_000_000 + u64::from(i),
        })
        .collect();
    let err = build_consistency_proof(&leaves_for_tampered, 10, 9).unwrap_err();
    assert_eq!(
        err,
        VerificationError::InvalidConsistencyRange,
        "AC7 GATE: cannot construct a consistency proof from a larger to a smaller tree (deletion)",
    );

    // Auditor cached a STH at size 10 with original_root. Even an
    // attempt by the tampered server to build "consistency from size
    // 9 (now) to size 10 (cached)" would have to prove that the
    // tampered prefix matches original — but it does NOT. Construct
    // such a "proof" by treating the tampered ledger as the past and
    // simulate by re-issuing 10 leaves in the tampered ledger
    // (impossible at the trait level, so we ASSERT the inequality of
    // roots directly).
    assert_ne!(
        original_root, tampered_root,
        "AC7 GATE: an honest auditor's cached root MUST differ from the tampered root",
    );
}

/// AC7 — deletion at the END of the ledger (the easy case) is also
/// detected: the tampered root differs from the cached root.
#[tokio::test]
async fn ac7_tail_deletion_detected() {
    let original = store_with_n_leaves(8).await;
    let original_root = original.current_root().await.expect("root");

    // Tail deletion: drop leaf 7. Tampered ledger has 7 leaves.
    let tampered = store_with_leaf_omitted(8, 7).await;
    let tampered_root = tampered.current_root().await.expect("tampered root");
    assert_eq!(tampered.current_size().await.unwrap(), 7);

    assert_ne!(
        original_root, tampered_root,
        "AC7 GATE: tail deletion MUST change the root (auditor detects)",
    );

    // Auditor's consistency check from the cached size 7 (snapshot
    // taken when the ledger held leaves 0..6, root R7) to the
    // tampered size 7 (which now holds leaves 0..6 of the ORIGINAL
    // — leaf 7 was the deleted one). In this scenario the two
    // size-7 trees coincide; tail deletion is the gentlest form,
    // detected only by comparing the cached root R8 with current
    // root R7. We assert that distinguishability.
    let snapshot_7 = store_with_n_leaves(7).await;
    let r7 = snapshot_7.current_root().await.expect("r7");
    let auditor_view = tampered.current_root().await.expect("auditor-view");
    assert_eq!(
        r7, auditor_view,
        "AC7 control: identical leaf sets produce identical roots (sanity for the test setup)",
    );

    // The key check: the auditor's CACHED root R8 ≠ current R7.
    assert_ne!(original_root, auditor_view);

    // And consistency from R8 to R7 cannot even be built.
    let snapshot_8 = store_with_n_leaves(8).await;
    let leaves_8: Vec<_> = (0..8u8)
        .map(|i| qorch_domain::transparency::MerkleLeaf {
            hash: leaf_hash(format!("entry-{i}").as_bytes()),
            leaf_index: u64::from(i),
            occurred_at_epoch_seconds: 1_700_000_000 + u64::from(i),
        })
        .collect();
    let err = build_consistency_proof(&leaves_8, 8, 7).unwrap_err();
    assert_eq!(err, VerificationError::InvalidConsistencyRange);
    let _ = snapshot_8; // suppress unused warning
}

/// AC7 — honest growth (size 8 -> size 10) verifies cleanly. This is
/// the control case: the consistency proof MUST succeed for honest
/// extensions, so the failure modes above are genuine deletion
/// signals rather than false positives.
#[tokio::test]
async fn ac7_honest_growth_passes_consistency_check() {
    let store_at_8 = store_with_n_leaves(8).await;
    let r8 = store_at_8.current_root().await.expect("r8");

    let store_at_10 = store_with_n_leaves(10).await;
    let r10 = store_at_10.current_root().await.expect("r10");

    let leaves_10: Vec<_> = (0..10u8)
        .map(|i| qorch_domain::transparency::MerkleLeaf {
            hash: leaf_hash(format!("entry-{i}").as_bytes()),
            leaf_index: u64::from(i),
            occurred_at_epoch_seconds: 1_700_000_000 + u64::from(i),
        })
        .collect();
    let proof = build_consistency_proof(&leaves_10, 8, 10).expect("build consistency");
    verify_consistency_proof(&proof, &r8, &r10).expect("honest growth verifies");
}
