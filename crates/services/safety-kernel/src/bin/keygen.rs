//! `safety-kernel-keygen` — generate a fresh Ed25519 signing seed for
//! the Safety Kernel (Step-14R / ARY-1886 first-boot key init).
//!
//! Prints the 32-byte seed as a base64url (no-pad) string on **stdout** —
//! the exact format `QORCH_KERNEL_SIGNING_KEY_B64` and the `gcp` Secret
//! Manager payload expect. The matching public key + SHA-256 fingerprint
//! go to **stderr** for operator verification, so the seed pipes cleanly:
//!
//! ```text
//! # GCP Secret Manager (managed backend, prod):
//! safety-kernel-keygen | gcloud secrets versions add \
//!     safety-kernel-signing-key --data-file=-
//!
//! # env backend (dev/staging only):
//! export QORCH_KERNEL_SIGNING_KEY_B64="$(safety-kernel-keygen 2>/dev/null)"
//! ```
//!
//! Least privilege by design: the kernel's *runtime* service account
//! needs only read (`roles/secretmanager.secretAccessor`); seed
//! generation + upload is an operator / Terraform step, never the
//! kernel's own write path.

#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

fn main() {
    // Cryptographically-secure OS RNG (getrandom-backed via rand_core).
    let signing = SigningKey::generate(&mut rand_core::OsRng);
    let seed_b64 = URL_SAFE_NO_PAD.encode(signing.to_bytes());

    // Public key + fingerprint (sha256_hex of the raw 32-byte public
    // key) to stderr — matches the kernel's /kernel/v1/public_key
    // fingerprint so an operator can confirm the loaded seed.
    let vk = signing.verifying_key();
    let pk_raw = vk.to_bytes();
    let pk_b64 = URL_SAFE_NO_PAD.encode(pk_raw);
    let fp = hex::encode(Sha256::digest(pk_raw));
    eprintln!("public_key_b64url:   {pk_b64}");
    eprintln!("public_key_fp_sha256: {fp}");

    // The seed — and only the seed — to stdout.
    println!("{seed_b64}");
}
