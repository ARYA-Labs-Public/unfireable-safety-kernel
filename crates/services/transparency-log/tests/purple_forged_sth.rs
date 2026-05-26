//!   — Purple-Team adversarial tests against the
//! transparency-log chain primitives.
//!
//! Session id: see ~/.claude/state/purple_team_runs.jsonl.
//!
//! Campaigns covered here:
//!   A1 — Forged STH (signed with attacker key) MUST be rejected by
//!        verify_sth against the legitimate verifying key. The
//!        legitimate STH MUST verify.
//!   B1 — Tampered inclusion proof (1-byte flip in the audit path)
//!        MUST be rejected by verify_inclusion_proof. The clean
//!        proof MUST verify.
//!   B2 — STH for the WRONG root (attacker computes a valid sig
//!        with their own key over a divergent root) MUST be rejected
//!        when verified against the legitimate verifying key
//!        (covers the "fake STH for fake root" class). The legitimate
//!        path MUST verify.
//!
//! Each test asserts BOTH that the attack is rejected AND that the
//! corresponding legitimate operation succeeds — Rule 5 (PoC) and the
//! anti-checklist invariant.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::doc_markdown, clippy::doc_lazy_continuation)]

use ed25519_dalek::SigningKey;

use qorch_domain::transparency::{
    build_inclusion_proof, compute_root, leaf_hash, mint_sth, verify_inclusion_proof,
    verify_sth, MerkleLeaf, VerificationError,
};

/// Deterministic legitimate ledger STH-signing key (the "honest" key
/// the world knows the public half of).
fn honest_sth_key() -> SigningKey {
    SigningKey::from_bytes(&[0x33u8; 32])
}

/// Deterministic attacker STH-signing key — different bytes, different
/// public key. Used to forge STHs that an external verifier should
/// reject when checking against the honest verifying key.
fn attacker_sth_key() -> SigningKey {
    SigningKey::from_bytes(&[0xee; 32])
}

fn ledger_leaves(n: u64) -> Vec<MerkleLeaf> {
    (0..n)
        .map(|i| MerkleLeaf {
            hash: leaf_hash(&format!("decision-{i}").into_bytes()),
            leaf_index: i,
            occurred_at_epoch_seconds: 1_700_000_000 + i,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// A1 — Forged STH with attacker key MUST be rejected
// ---------------------------------------------------------------------------

#[test]
fn purple_a1_forged_sth_with_attacker_key_rejected() {
    let honest = honest_sth_key();
    let attacker = attacker_sth_key();
    let honest_vk = honest.verifying_key();

    let leaves = ledger_leaves(8);
    let root = compute_root(&leaves).unwrap();

    // Attacker mints a perfectly valid Ed25519 STH — but signs with
    // their own key. Distribution-wise this is what an STH stamp on a
    // squatter t-log looks like; the legitimate verifier holds the
    // honest verifying key and MUST reject.
    let forged = mint_sth(root, leaves.len() as u64, 1_700_000_999, &attacker);
    let err = verify_sth(&forged, &honest_vk).unwrap_err();
    assert_eq!(
        err,
        VerificationError::SignatureInvalid,
        "forged STH must be rejected by the honest verifying key",
    );

    // Counter-assertion (Rule 5): the legitimate flow accepts a
    // legitimately-signed STH for the same root.
    let legitimate = mint_sth(root, leaves.len() as u64, 1_700_000_999, &honest);
    verify_sth(&legitimate, &honest_vk).unwrap();
}

// ---------------------------------------------------------------------------
// B1 — Tampered inclusion proof (1-byte flip in path) MUST be rejected
// ---------------------------------------------------------------------------

#[test]
fn purple_b1_tampered_inclusion_proof_rejected() {
    let leaves = ledger_leaves(16);
    let root = compute_root(&leaves).unwrap();

    // Pick a non-leftmost leaf so the proof has a non-trivial path.
    let proof = build_inclusion_proof(&leaves, 5).unwrap();
    assert!(!proof.path.is_empty(), "proof for n=16 idx=5 must have a non-empty path");

    // Tamper: flip ONE bit in the first sibling hash.
    let mut tampered = proof.clone();
    tampered.path[0][0] ^= 0x01;

    let err = verify_inclusion_proof(&tampered, &root).unwrap_err();
    assert_eq!(
        err,
        VerificationError::RootMismatch,
        "1-byte tamper of the audit path must produce a root mismatch",
    );

    // Counter-assertion: the clean proof verifies.
    verify_inclusion_proof(&proof, &root).unwrap();

    // Additional adversarial variant: tamper the leaf_hash itself (the
    // attacker substituted a different leaf at the same position).
    let mut tampered_leaf = proof.clone();
    tampered_leaf.leaf_hash[0] ^= 0xff;
    let err2 = verify_inclusion_proof(&tampered_leaf, &root).unwrap_err();
    assert_eq!(err2, VerificationError::RootMismatch);
}

// ---------------------------------------------------------------------------
// B2 — STH for the WRONG root (attacker signs a divergent root with
// their own key) MUST be rejected when verified against the honest VK.
//
// This is the "split-view" attack: the attacker fabricates a t-log
// state showing root R' instead of the real root R. They sign R' with
// their own key (they don't have the honest signing key). An external
// auditor holding the honest verifying key MUST reject the forgery.
// ---------------------------------------------------------------------------

#[test]
fn purple_b2_sth_for_wrong_root_rejected() {
    let honest = honest_sth_key();
    let attacker = attacker_sth_key();
    let honest_vk = honest.verifying_key();

    let real_leaves = ledger_leaves(8);
    let real_root = compute_root(&real_leaves).unwrap();

    // Attacker fabricates a divergent ledger (different leaf content)
    // and computes its root.
    let fake_leaves: Vec<MerkleLeaf> = (0..8u64)
        .map(|i| MerkleLeaf {
            hash: leaf_hash(&format!("ATTACKER-decision-{i}").into_bytes()),
            leaf_index: i,
            occurred_at_epoch_seconds: 1_700_000_000 + i,
        })
        .collect();
    let fake_root = compute_root(&fake_leaves).unwrap();
    assert_ne!(real_root, fake_root, "fake root must differ from real root");

    // Attacker signs the fake root with THEIR key (they don't have the
    // honest signing key).
    let forged = mint_sth(fake_root, 8, 1_700_000_999, &attacker);

    // External auditor uses the honest verifying key → MUST reject.
    let err = verify_sth(&forged, &honest_vk).unwrap_err();
    assert_eq!(err, VerificationError::SignatureInvalid);

    // Counter-assertion: real STH (honest key over real root) verifies.
    let real_sth = mint_sth(real_root, 8, 1_700_000_999, &honest);
    verify_sth(&real_sth, &honest_vk).unwrap();

    // Variant: even if the attacker uses the honest verifying key
    // bytes inside their forged signature (impossible without the
    // private key), Ed25519 verification still fails. We model this by
    // tampering the signature bytes directly.
    let mut tampered = real_sth.clone();
    tampered.signature[0] ^= 0x01;
    let err2 = verify_sth(&tampered, &honest_vk).unwrap_err();
    assert_eq!(err2, VerificationError::SignatureInvalid);
}

// ---------------------------------------------------------------------------
// Sanity / coverage: an STH over the SAME root but with a tampered
// tree_size (size A signed, payload claims size B) is also a forgery
// class — covered by the canonical-payload binding.
// ---------------------------------------------------------------------------

#[test]
fn purple_b2_tree_size_swap_rejected() {
    let honest = honest_sth_key();
    let vk = honest.verifying_key();
    let leaves = ledger_leaves(4);
    let root = compute_root(&leaves).unwrap();
    let mut sth = mint_sth(root, 4, 1_700_000_500, &honest);
    sth.tree_size = 5;
    let err = verify_sth(&sth, &vk).unwrap_err();
    assert_eq!(err, VerificationError::SignatureInvalid);
}
