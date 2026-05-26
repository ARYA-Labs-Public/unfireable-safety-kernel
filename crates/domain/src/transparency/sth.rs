//! Signed Tree Head minting + verification (b,
//!  Step 4).
//!
//! A `SignedTreeHead` is the authoritative public statement of
//! "ledger state as of `timestamp_epoch_seconds`". The signed payload
//! is the canonical concatenation:
//!
//! ```text
//!     root_hash (32 bytes)
//!  || tree_size.to_be_bytes() (8 bytes, big-endian u64)
//!  || timestamp_epoch_seconds.to_be_bytes() (8 bytes, big-endian u64)
//! ```
//!
//! 48 bytes total. No JSON: STHs are a wire-format primitive and we
//! want a compact + byte-stable representation. Big-endian matches
//! the convention used elsewhere in the workspace ( token
//! envelope, RFC-6962 nonce framing).
//!
//! No key material lives here — this module signs / verifies given a
//! caller-supplied `SigningKey` / `VerifyingKey`. Boundary check: no
//! I/O, no clock, no RNG, no logging. The caller supplies
//! `timestamp_epoch_seconds`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use super::merkle::{SignedTreeHead, VerificationError};

/// Canonical signing payload for a `SignedTreeHead` (48 bytes).
const STH_PAYLOAD_LEN: usize = 32 + 8 + 8;

#[must_use]
fn canonical_payload(
    root_hash: &[u8; 32],
    tree_size: u64,
    timestamp_epoch_seconds: u64,
) -> [u8; STH_PAYLOAD_LEN] {
    let mut buf = [0u8; STH_PAYLOAD_LEN];
    buf[..32].copy_from_slice(root_hash);
    buf[32..40].copy_from_slice(&tree_size.to_be_bytes());
    buf[40..48].copy_from_slice(&timestamp_epoch_seconds.to_be_bytes());
    buf
}

/// Mint a `SignedTreeHead` for `(root_hash, tree_size,
/// timestamp_epoch_seconds)` using `signing_key`.
///
/// The signature is over the canonical payload described in the
/// module doc; the result is independent of any JSON / serde
/// framing.
#[must_use]
pub fn mint_sth(
    root_hash: [u8; 32],
    tree_size: u64,
    timestamp_epoch_seconds: u64,
    signing_key: &SigningKey,
) -> SignedTreeHead {
    let payload = canonical_payload(&root_hash, tree_size, timestamp_epoch_seconds);
    let signature: Signature = signing_key.sign(&payload);
    SignedTreeHead {
        root_hash,
        signature: signature.to_bytes(),
        timestamp_epoch_seconds,
        tree_size,
    }
}

/// Verify a `SignedTreeHead` against `verifying_key`.
///
/// # Errors
///
/// Returns [`VerificationError::SignatureInvalid`] if the Ed25519
/// signature does not validate over the canonical payload.
pub fn verify_sth(
    sth: &SignedTreeHead,
    verifying_key: &VerifyingKey,
) -> Result<(), VerificationError> {
    let payload = canonical_payload(&sth.root_hash, sth.tree_size, sth.timestamp_epoch_seconds);
    let signature = Signature::from_bytes(&sth.signature);
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| VerificationError::SignatureInvalid)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::unreadable_literal
)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Deterministic signing key for tests (no RNG in the domain
    /// crate — boundary). The same seed-bytes pattern is used in
    /// `safety::token` tests.
    fn test_signing_key() -> SigningKey {
        let seed: [u8; 32] = [
            0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
            0xe1, 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc,
            0xcd, 0xde, 0xef, 0xf0,
        ];
        SigningKey::from_bytes(&seed)
    }

    fn alt_signing_key() -> SigningKey {
        let seed: [u8; 32] = [0xa5; 32];
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn mint_then_verify_round_trip() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let root = [0x77u8; 32];
        let sth = mint_sth(root, 42, 1_700_000_000, &sk);
        assert_eq!(sth.root_hash, root);
        assert_eq!(sth.tree_size, 42);
        assert_eq!(sth.timestamp_epoch_seconds, 1_700_000_000);
        verify_sth(&sth, &vk).unwrap();
    }

    #[test]
    fn verify_with_wrong_key_rejected() {
        let sk = test_signing_key();
        let wrong_vk = alt_signing_key().verifying_key();
        let sth = mint_sth([0x11u8; 32], 7, 1_700_000_100, &sk);
        let err = verify_sth(&sth, &wrong_vk).unwrap_err();
        assert_eq!(err, VerificationError::SignatureInvalid);
    }

    #[test]
    fn verify_with_tampered_root_rejected() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let mut sth = mint_sth([0x22u8; 32], 9, 1_700_000_200, &sk);
        sth.root_hash[0] ^= 0x01;
        let err = verify_sth(&sth, &vk).unwrap_err();
        assert_eq!(err, VerificationError::SignatureInvalid);
    }

    #[test]
    fn verify_with_tampered_tree_size_rejected() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let mut sth = mint_sth([0x33u8; 32], 100, 1_700_000_300, &sk);
        sth.tree_size = 101;
        let err = verify_sth(&sth, &vk).unwrap_err();
        assert_eq!(err, VerificationError::SignatureInvalid);
    }

    #[test]
    fn verify_with_tampered_timestamp_rejected() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let mut sth = mint_sth([0x44u8; 32], 5, 1_700_000_400, &sk);
        sth.timestamp_epoch_seconds += 1;
        let err = verify_sth(&sth, &vk).unwrap_err();
        assert_eq!(err, VerificationError::SignatureInvalid);
    }

    #[test]
    fn canonical_payload_byte_layout() {
        let root = [0x01u8; 32];
        let p = canonical_payload(&root, 0x0102030405060708, 0x1112131415161718);
        assert_eq!(p[..32], [0x01u8; 32]);
        assert_eq!(p[32..40], [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(p[40..48], [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
    }
}
