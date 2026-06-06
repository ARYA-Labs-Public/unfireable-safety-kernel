//! LIVE GCP Secret Manager key-backend test (Step-14R / ARY-1886).
//!
//! `#[ignore]` by default: it makes a real network call to GCP Secret
//! Manager and therefore only runs where Application Default Credentials
//! resolve — i.e. on GCE/GKE/Cloud Run with an attached service account
//! holding `roles/secretmanager.secretAccessor` on the test secret.
//! CI (no GCP) skips it; it is run explicitly on the box:
//!
//! ```text
//! KERNEL_KEY_GCP_PROJECT=<proj> \
//! KERNEL_KEY_GCP_SECRET=<secret> \
//! GCP_KEY_TEST_EXPECT_SEED_B64=<seed-b64url> \
//!   cargo test -p qorch-safety-kernel --test gcp_key_backend_live -- --ignored
//! ```
//!
//! Rule 9 (evidence over labels): the test does NOT trust a status
//! string. It re-derives the public-key fingerprint from the fetched
//! seed and asserts the fetched seed byte-equals the seed the operator
//! stored — proving the backend pulled the *correct* key, not merely
//! *some* 200 response.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use qorch_safety_kernel::key_backend::resolve_signing_key_b64;
use qorch_safety_kernel::settings::Settings;

fn decode_seed(b64: &str) -> [u8; 32] {
    let raw = URL_SAFE_NO_PAD
        .decode(b64.trim().trim_end_matches('='))
        .expect("seed base64url decode");
    let mut a = [0u8; 32];
    a.copy_from_slice(&raw);
    a
}

#[tokio::test]
#[ignore = "live GCP Secret Manager call; run with --ignored on GCE/GKE"]
async fn gcp_backend_fetches_exact_stored_seed() {
    let project = std::env::var("KERNEL_KEY_GCP_PROJECT").expect("KERNEL_KEY_GCP_PROJECT");
    let secret = std::env::var("KERNEL_KEY_GCP_SECRET").expect("KERNEL_KEY_GCP_SECRET");
    let expect_seed_b64 =
        std::env::var("GCP_KEY_TEST_EXPECT_SEED_B64").expect("GCP_KEY_TEST_EXPECT_SEED_B64");

    // Build settings via the real env path. staging ⇒ gcp backend
    // allowed (not prod-blocked) and operator key not required.
    std::env::set_var("QORCH_ENV", "staging");
    std::env::set_var("KERNEL_KEY_BACKEND", "gcp");
    std::env::set_var("KERNEL_KEY_GCP_PROJECT", &project);
    std::env::set_var("KERNEL_KEY_GCP_SECRET", &secret);
    // Other fail-closed required secrets (values irrelevant to this test).
    std::env::set_var("QORCH_KERNEL_AUDIT_PEPPER_B64", "AAAAAAAAAAAAAAAAAAAAAA");
    std::env::set_var("QORCH_KERNEL_API_KEY_WORKER", "test-worker");
    std::env::set_var("QORCH_KERNEL_API_KEY_API", "test-api");

    let settings = Settings::from_env().expect("Settings::from_env (gcp backend)");
    assert_eq!(settings.key_backend.as_str(), "gcp");
    assert!(
        settings.signing_key_b64.is_empty(),
        "gcp backend must NOT read the seed from the env var at from_env time"
    );

    let fetched = resolve_signing_key_b64(&settings)
        .await
        .expect("live GCP Secret Manager fetch");

    // Rule 9: byte-equal the stored seed + re-derive the pubkey fp.
    assert_eq!(
        fetched.trim(),
        expect_seed_b64.trim(),
        "fetched seed must byte-equal the stored seed"
    );
    let fetched_pk = SigningKey::from_bytes(&decode_seed(&fetched)).verifying_key();
    let expect_pk = SigningKey::from_bytes(&decode_seed(&expect_seed_b64)).verifying_key();
    assert_eq!(
        hex::encode(Sha256::digest(fetched_pk.to_bytes())),
        hex::encode(Sha256::digest(expect_pk.to_bytes())),
        "derived public-key fingerprint must match"
    );
}
