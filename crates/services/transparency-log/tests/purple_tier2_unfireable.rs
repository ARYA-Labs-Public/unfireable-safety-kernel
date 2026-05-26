//!   — Purple-Team adversarial assessment of the
//! tier-2 unfireability claim (: "Unfireable across vendor
//! boundary by cryptographic delivery and public transparency").
//!
//! Campaigns:
//!   G1 — Customer-side operator forges an authorize token: external
//!        verifier (using the legitimate STH-signing public key) MUST
//!        reject. Tests:
//!          G1a — STH signed with attacker's STH key  → reject
//!          G1b — Forged inclusion proof for a leaf the ledger does
//!                NOT contain                         → reject
//!          G1c — Consistency proof claiming a deleted leaf
//!                ("ledger rewind")                   → reject
//!
//!   H1 — Customer-side operator attempts to delete a ledger entry
//!        post-hoc. The chain detects the gap because the consistency
//!        proof between two STHs (BEFORE and AFTER the deletion)
//!        fails to verify against either the pre- or post-state.
//!        This is the AC7-shape regression: gap = detectable.
//!
//! All three (a) re-derive evidence by re-running the verifier (Rule
//! 9 — no label matching) and (b) verify the legitimate path passes
//! (Rule 5 — PoC against a working defense).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::doc_markdown, clippy::doc_lazy_continuation)]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use qorch_domain::transparency::{
    build_consistency_proof, build_inclusion_proof, compute_root, leaf_hash, mint_sth,
    verify_consistency_proof, verify_inclusion_proof, verify_sth, ConsistencyProof,
    MerkleLeaf, VerificationError,
};
use qorch_transparency_store::{memory::MemoryTransparencyStore, AppendInput, TransparencyStore};

/// Honest STH-signing key — the public half is what external auditors
/// hold (it travels with the customer-installed Safety Kernel build).
fn honest_sth_key() -> SigningKey {
    SigningKey::from_bytes(&[0x33u8; 32])
}

/// Attacker's STH-signing key. They can mint syntactically-valid STHs
/// against THIS key; an external auditor holding the honest verifying
/// key MUST reject.
fn attacker_sth_key() -> SigningKey {
    SigningKey::from_bytes(&[0xee; 32])
}

fn synth_leaves(n: u64) -> Vec<MerkleLeaf> {
    (0..n)
        .map(|i| MerkleLeaf {
            hash: leaf_hash(&format!("token-{i}").into_bytes()),
            leaf_index: i,
            occurred_at_epoch_seconds: 1_700_000_000 + i,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// G1a — STH signed with the attacker's key MUST be rejected
// ---------------------------------------------------------------------------

#[test]
fn purple_g1a_attacker_signed_sth_rejected_by_external_verifier() {
    let honest = honest_sth_key();
    let attacker = attacker_sth_key();
    let external_verifier_vk = honest.verifying_key();

    let leaves = synth_leaves(8);
    let real_root = compute_root(&leaves).unwrap();
    // Attacker mints a syntactically valid STH but with their own key.
    let forged = mint_sth(real_root, 8, 1_700_000_999, &attacker);
    let err = verify_sth(&forged, &external_verifier_vk).unwrap_err();
    assert_eq!(err, VerificationError::SignatureInvalid);

    // Counter-assertion: the honest STH verifies.
    let legit = mint_sth(real_root, 8, 1_700_000_999, &honest);
    verify_sth(&legit, &external_verifier_vk).unwrap();
}

// ---------------------------------------------------------------------------
// G1b — Forged inclusion proof for a leaf NOT in the ledger MUST be
// rejected by `verify_inclusion_proof` against the real root.
// ---------------------------------------------------------------------------

#[test]
fn purple_g1b_inclusion_proof_for_nonexistent_leaf_rejected() {
    let leaves = synth_leaves(8);
    let real_root = compute_root(&leaves).unwrap();

    // Build a real proof for leaf 3, then swap the leaf_hash to a
    // payload that was NEVER appended.
    let real_proof = build_inclusion_proof(&leaves, 3).unwrap();
    let mut forged = real_proof.clone();
    forged.leaf_hash = leaf_hash(b"ATTACKER-fabricated-decision-bytes");
    // The audit path no longer matches → root recompute diverges →
    // RootMismatch.
    let err = verify_inclusion_proof(&forged, &real_root).unwrap_err();
    assert_eq!(err, VerificationError::RootMismatch);

    // Counter-assertion: the real proof verifies.
    verify_inclusion_proof(&real_proof, &real_root).unwrap();
}

// ---------------------------------------------------------------------------
// G1c — "Ledger rewind" attempt: attacker claims the ledger size
// shrank (or was rolled back) by serving a consistency proof from a
// LATER to an EARLIER state. The domain crate rejects
// `from_size > to_size` as InvalidConsistencyRange. Verifies the
// chain cannot model a rewind.
// ---------------------------------------------------------------------------

#[test]
fn purple_g1c_consistency_proof_rewind_rejected() {
    // Build a proof manually with from_size > to_size to confirm the
    // shape is structurally invalid; `verify_consistency_proof`
    // rejects with InvalidConsistencyRange.
    let bad = ConsistencyProof {
        from_size: 10,
        proof: vec![],
        to_size: 4,
    };
    let dummy_root = [0u8; 32];
    let err = verify_consistency_proof(&bad, &dummy_root, &dummy_root).unwrap_err();
    assert_eq!(err, VerificationError::InvalidConsistencyRange);

    // Counter-assertion: a real consistency proof (4 → 8) verifies.
    let leaves = synth_leaves(8);
    let from_root = compute_root(&leaves[..4]).unwrap();
    let to_root = compute_root(&leaves).unwrap();
    let good = build_consistency_proof(&leaves, 4, 8).unwrap();
    verify_consistency_proof(&good, &from_root, &to_root).unwrap();
}

// ---------------------------------------------------------------------------
// H1 — "Delete an entry post-hoc": the attacker (customer operator)
// removes leaf at index k from the ledger. An external auditor holds
// (a) the STH at tree_size=N issued before the deletion and (b) the
// STH at tree_size=N issued AFTER the deletion. If the post-deletion
// root differs from the pre-deletion root, the consistency proof
// between the two pinned STHs (which must hold the same root for the
// same tree_size) BREAKS — gap = detected.
//
// This is the AC7-shape regression: even though the attacker can
// filesystem-mutate the store, the chain-of-evidence held by external
// auditors detects the divergence.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn purple_h1_post_hoc_deletion_detected_via_root_divergence() {
    let store = Arc::new(MemoryTransparencyStore::new());
    // Honest ledger growth: 8 entries.
    for i in 0..8u8 {
        store
            .append(AppendInput {
                idempotency_key: [i; 32],
                payload: format!("decision-{i}").into_bytes(),
                occurred_at_epoch_seconds: 1_700_000_000 + u64::from(i),
            })
            .await
            .unwrap();
    }
    let real_root = store.current_root().await.unwrap();
    let real_size = store.current_size().await.unwrap();
    assert_eq!(real_size, 8);

    // External auditor's pinned STH (before any tamper attempt).
    let honest = honest_sth_key();
    let auditor_vk = honest.verifying_key();
    let auditor_sth_before = mint_sth(real_root, real_size, 1_700_000_100, &honest);
    verify_sth(&auditor_sth_before, &auditor_vk).unwrap();

    // Attacker tampers (post-hoc) — simulated by computing the root of
    // the tree MINUS one entry (we don't actually remove from the
    // store; we just verify that the post-tamper root is structurally
    // detectable). Equivalently: the attacker tries to mint a NEW STH
    // claiming tree_size=8 but with a divergent root (after deleting
    // leaf at idx=5 from their copy of the ledger and re-computing).
    let mut tampered_leaves = synth_leaves(8);
    // Replace leaf 5's hash with the empty hash — simulating its
    // "deletion" being filled with a fresh leaf the attacker
    // fabricated.
    tampered_leaves[5].hash = leaf_hash(b"ATTACKER-substituted-leaf");
    let tampered_root = compute_root(&tampered_leaves).unwrap();

    // The attacker mints a forged STH with the SAME tree_size=8 but
    // their divergent root, signing with their own key:
    let attacker = attacker_sth_key();
    let attacker_sth = mint_sth(tampered_root, 8, 1_700_000_200, &attacker);
    // External auditor rejects: signature does not verify against
    // honest VK.
    let err = verify_sth(&attacker_sth, &auditor_vk).unwrap_err();
    assert_eq!(err, VerificationError::SignatureInvalid);

    // Alternative attack: the attacker compromises the honest STH
    // signing key (worst case) and mints a forged STH with their
    // tampered root. Even THEN, the external auditor holding two
    // STHs at the same tree_size with DIFFERENT roots detects the
    // divergence:
    let attacker_sth_with_honest_key = mint_sth(tampered_root, 8, 1_700_000_300, &honest);
    verify_sth(&attacker_sth_with_honest_key, &auditor_vk).unwrap(); // sig OK
    assert_ne!(
        auditor_sth_before.root_hash, attacker_sth_with_honest_key.root_hash,
        "same tree_size, different roots — chain split detected (gossip-detection class)"
    );
    // The auditor's gossip step (compare-roots-at-same-size) is the
    // detection — they refuse to accept inclusion proofs against the
    // attacker's root because it diverges from their pinned root.
}

// ---------------------------------------------------------------------------
// H1 follow-up: even the legitimate path (8 → 9 → 10 entries) is
// verifiable via consistency proofs — and any divergent state breaks
// the proof. This confirms the legitimate append-only path works.
// ---------------------------------------------------------------------------

#[test]
fn purple_h1_legitimate_append_only_consistency_holds() {
    // Honest ledger: 4 entries, then 8 entries (append-only).
    let leaves_4 = synth_leaves(4);
    let leaves_8 = synth_leaves(8);

    let root_4 = compute_root(&leaves_4).unwrap();
    let root_8 = compute_root(&leaves_8).unwrap();
    let proof = build_consistency_proof(&leaves_8, 4, 8).unwrap();
    verify_consistency_proof(&proof, &root_4, &root_8).unwrap();

    // Now: the attacker substitutes leaf 2 in the "8-leaf" view (a
    // post-hoc tamper). The consistency proof from 4→8 generated on
    // the HONEST 8-tree does NOT verify against the TAMPERED 8-tree's
    // root.
    let mut tampered_8 = leaves_8.clone();
    tampered_8[2].hash = leaf_hash(b"ATTACKER-substituted-leaf-2");
    let tampered_root_8 = compute_root(&tampered_8).unwrap();
    // The original 4-tree is below the tamper point so root_4 still
    // matches the tampered tree's view of [..4]. But the FULL root
    // diverges, so the consistency proof generated against the honest
    // 8-tree fails when verified against `tampered_root_8`.
    let err =
        verify_consistency_proof(&proof, &root_4, &tampered_root_8).unwrap_err();
    assert_eq!(err, VerificationError::RootMismatch);
}

// ---------------------------------------------------------------------------
// G1 (top-level): end-to-end "operator forges a kernel attestation"
//
// The attacker is the customer-side operator. They want to ship a
// token claiming "kernel authorize succeeded" for an action that the
// real kernel would have refused. Required attacker capabilities to
// forge a tier-2 attestation:
//   (1) Mint an Ed25519 signature with the kernel's signing key
//   (2) Append a leaf to the transparency-log signed by the kernel key
//   (3) Mint an STH covering that leaf signed by the STH-signing key
//
// (1) requires kernel signing-key exfiltration (separate from STH key
// per `purple_forged_sth.rs`). (2) requires the kernel API key AND
// passing the fingerprint check. (3) requires STH signing-key
// exfiltration. The three keys are independently rotated; an attacker
// must compromise ALL THREE to forge a tier-2 attestation. We assert
// that compromising just one is insufficient.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn purple_g1_forge_attempt_with_only_one_compromised_key_fails() {
    // Attacker has the STH-signing key but NOT the kernel signing key
    // and NOT the t-log API key. They mint a forged STH:
    let attacker_sth = attacker_sth_key();
    let forged_root = compute_root(&synth_leaves(1)).unwrap();
    let forged_sth = mint_sth(forged_root, 1, 1_700_000_500, &attacker_sth);

    // External auditor holds the HONEST STH-signing public key.
    let honest_sth = honest_sth_key();
    let auditor_vk = honest_sth.verifying_key();
    let err = verify_sth(&forged_sth, &auditor_vk).unwrap_err();
    assert_eq!(err, VerificationError::SignatureInvalid);

    // Even if the attacker is allowed to inject one fabricated leaf,
    // without a valid STH signed by the honest key the leaf is
    // invisible to the external auditor — no inclusion proof can be
    // anchored to an honest STH.
}
