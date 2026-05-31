//! AF-key seed fixture — ARY-1887 release-gate adversarial taxonomy.
//!
//! See `docs/release-gate/af-taxonomy.md` for the 7-class taxonomy this
//! file fills. Sister Python seed: `tests/adversarial/python/af_key_seed.py`.
//!
//! **What this seed asserts.** The `PinnedKeyVerifier` MUST refuse a
//! kernel-issued token signed by any key other than the one pinned at
//! construction time. This is the structural defence against operator
//! key substitution at the client side.
//!
//! **Why "seed".** The production code under test (`PinnedKeyVerifier`)
//! is mature and already has unit tests in `src/token.rs`. This file
//! adds the **canonical AF-key entry** to the seed taxonomy directory
//! used by the release gate; it tests the same property as the existing
//! `pinned_verifier_rejects_token_signed_with_attacker_key` unit test,
//! but lives under `tests/seed_af_key.rs` so the coverage script can
//! find it under the canonical `af_<class>_*` naming convention.
//!
//! **Synthetic fake.** An Ed25519 keypair `(attacker_signing, _)` whose
//! public bytes are NOT the pinned key. A token signed by
//! `attacker_signing` MUST NOT verify under the pinned key.
//!
//! Run with:
//!
//! ```bash
//! cargo test -p qorch-safety-kernel-client --test seed_af_key
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use ed25519_dalek::SigningKey;
use qorch_domain::safety::{sign_kernel_token, AuthorizeClaims, KERNEL_AUTHORIZE_AUD};
use qorch_safety_kernel_client::PinnedKeyVerifier;

fn fixed_keypair() -> (SigningKey, [u8; 32]) {
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let public = signing.verifying_key().to_bytes();
    (signing, public)
}

fn sample_claims(now: f64) -> AuthorizeClaims {
    AuthorizeClaims {
        action: "af_key_seed_action".to_string(),
        aud: KERNEL_AUTHORIZE_AUD.to_string(),
        run_id: "af-key-seed-run".to_string(),
        subject: "af-key-seed-worker".to_string(),
        params_fingerprint: "a".repeat(64),
        issued_at: now,
        expires_at: now + 300.0,
        nonce: "af-key-seed-nonce-22ch".to_string(),
    }
}

#[test]
fn af_key_seed_rejects_token_signed_with_non_pinned_key() {
    // The pinned key is the legitimate operator key.
    let (_pinned_signing, pinned_public) = fixed_keypair();

    // The attacker uses a different Ed25519 key.
    let attacker_signing = SigningKey::from_bytes(&[99u8; 32]);

    let now = 1_700_000_000.0_f64;
    let attacker_token = sign_kernel_token(&sample_claims(now), &attacker_signing);

    let verifier = PinnedKeyVerifier::from_pubkey_bytes(pinned_public)
        .expect("pinned pubkey must be valid Ed25519");

    let result = verifier.verify(&attacker_token, now + 1.0);

    // Rule 9: the rejection is observed via the Result type, not via
    // regex-matching a log line. The verifier returns Err for any of:
    // signature mismatch, expiry, malformed claim. For this seed, we
    // assert is_err() — the specific error variant is exercised by the
    // richer unit tests in src/token.rs.
    assert!(
        result.is_err(),
        "AF-key seed: PinnedKeyVerifier MUST reject a token signed by a non-pinned key. \
         The kernel-pinning property is the structural defence against operator key \
         substitution; if this assertion fires, the release gate must NOT sign v1.0."
    );
}

#[test]
fn af_key_seed_accepts_token_signed_with_pinned_key() {
    // Counter-assertion: the seed REJECTS a forged token AND ACCEPTS a
    // legitimate one. Without the counter-assertion the seed could pass
    // by rejecting all tokens (false-negative).
    let (signing, public) = fixed_keypair();
    let now = 1_700_000_000.0_f64;
    let token = sign_kernel_token(&sample_claims(now), &signing);
    let verifier = PinnedKeyVerifier::from_pubkey_bytes(public).expect("valid pubkey");
    let verified = verifier
        .verify(&token, now + 1.0)
        .expect("AF-key seed counter-assertion: legitimate token MUST verify under the pinned key");
    assert_eq!(
        verified.claims.get("action").and_then(|v| v.as_str()),
        Some("af_key_seed_action"),
        "verified claim must round-trip the action field"
    );
}
