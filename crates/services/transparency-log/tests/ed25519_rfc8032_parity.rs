//! internal-ref — Step 2 (/test) Rule-9 evidence-recompute: RFC 8032 §7.1
//! Test 1 Ed25519 golden vector parity from the Rust side.
//!
//! Companion to `tools/test_adversarial_transparency_log_ed25519.py`
//! function `test_rust_python_signature_parity`. Both tests sign the
//! SAME 32-byte seed over the SAME message and assert the resulting
//! 64-byte signature matches the SAME pinned RFC 8032 vector. Any
//! drift in either `ed25519-dalek` (Rust) or `cryptography` /
//! `pynacl` (Python) trips one of these tests.
//!
//! Why both: a single-stack test could mask a library that drifted in
//! lockstep with the test. The byte-identical RFC vector is the
//! oracle; the two-stack assertion is the cross-check.

#![allow(clippy::all)] // generated parity gate: reference-vector data, not idiomatic Rust
#![allow(clippy::unwrap_used)]

use ed25519_dalek::{Signer, SigningKey};

const RFC8032_T1_SEED_HEX: &str =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC8032_T1_PK_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RFC8032_T1_MSG_HEX: &str = "";
const RFC8032_T1_SIG_HEX: &str = concat!(
    "e5564300c360ac729086e2cc806e828a",
    "84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b",
    "d25bf5f0595bbe24655141438e7a100b",
);

#[test]
fn rfc8032_test1_signature_byte_identical() {
    let seed_bytes = hex::decode(RFC8032_T1_SEED_HEX).unwrap();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let sk = SigningKey::from_bytes(&seed);

    // Derived public key must match the RFC pinned vector.
    let derived_pk = sk.verifying_key().to_bytes();
    assert_eq!(
        hex::encode(derived_pk),
        RFC8032_T1_PK_HEX,
        "ed25519-dalek derived public key diverges from RFC 8032 Test 1"
    );

    let msg = hex::decode(RFC8032_T1_MSG_HEX).unwrap(); // empty
    let sig = sk.sign(&msg).to_bytes();
    assert_eq!(
        hex::encode(sig),
        RFC8032_T1_SIG_HEX,
        "ed25519-dalek signature diverges from RFC 8032 Test 1 (cross-stack parity oracle)"
    );
}
