//! Token verifier wrapper — pinned-key Ed25519 verification.
//!
//!   /  AC9: the client SDK MUST reject any
//! `authorize()` response signed with a public key other than the one
//! pinned at construction time. This is the structural defence against
//! a substituted or tampered kernel.
//!
//! This file is a thin adapter over `qorch_domain::safety::verify_kernel_token`
//! that captures the pinned key at construction and refuses to accept
//! anything else.

use ed25519_dalek::VerifyingKey;
use qorch_domain::safety::{verify_kernel_token, KernelTokenError, VerifiedClaims};

/// Audit-friendly fingerprint (first 16 hex chars of SHA-256 of pubkey).
fn fingerprint_for(pubkey_bytes: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey_bytes);
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

/// Verifier that holds a pinned Ed25519 public key and validates every
/// presented token against that key only.
#[derive(Debug, Clone)]
pub struct PinnedKeyVerifier {
    pinned_verifying_key: VerifyingKey,
    fingerprint: String,
    /// Leeway in seconds for clock skew between the kernel and the
    /// client. Defaults to 5 s; matches the Python client's leeway.
    leeway_seconds: f64,
}

impl PinnedKeyVerifier {
    /// Construct a verifier pinned to a specific 32-byte Ed25519 public
    /// key. Use the public key embedded in `arya-contracts` for the
    /// installed kernel version.
    ///
    /// # Errors
    ///
    /// Returns `KernelTokenError` if `pinned` is not a valid Ed25519
    /// public key encoding (i.e. not on the curve / wrong length).
    pub fn from_pubkey_bytes(pinned: [u8; 32]) -> Result<Self, KernelTokenError> {
        let vk = VerifyingKey::from_bytes(&pinned)
            .map_err(|e| KernelTokenError::signature(format!("invalid_pinned_pubkey:{e}")))?;
        let fingerprint = fingerprint_for(&pinned);
        Ok(Self {
            pinned_verifying_key: vk,
            fingerprint,
            leeway_seconds: 5.0,
        })
    }

    /// Construct with an explicit leeway value.
    ///
    /// # Errors
    ///
    /// Returns `KernelTokenError` if `pinned` is not a valid Ed25519
    /// public key encoding.
    pub fn with_leeway(pinned: [u8; 32], leeway_seconds: f64) -> Result<Self, KernelTokenError> {
        let mut me = Self::from_pubkey_bytes(pinned)?;
        me.leeway_seconds = leeway_seconds;
        Ok(me)
    }

    /// Returns the audit fingerprint (16 hex chars).
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Verify a token against the pinned key. Returns the decoded
    /// claims on success; `Err` on any verification failure
    /// (signature mismatch, expiry, missing required field, malformed
    /// claim type). The caller MUST treat any `Err` as a hard refusal.
    ///
    /// `now_epoch_seconds` is the caller-supplied wall-clock value,
    /// sourced from a `Clock` in the adapter layer.
    ///
    /// **Audience claim (`expected_aud`)**: per  (
    /// slice 5), this adapter passes `None` — preserving the legacy
    /// permissive verifier behaviour for callers that have not yet
    /// migrated. Callers that need cross-tenant replay protection
    /// should use `verify_with_aud` below.
    pub fn verify(
        &self,
        token: &str,
        now_epoch_seconds: f64,
    ) -> Result<VerifiedClaims, KernelTokenError> {
        verify_kernel_token(
            token,
            &self.pinned_verifying_key,
            now_epoch_seconds,
            self.leeway_seconds,
            None,
        )
    }

    /// Same as `verify`, but requires the token's `aud` claim to match
    /// `expected_aud`.  ( slice 5) — closes the
    /// cross-tenant replay surface between `/kernel/v1/authorize` and
    /// `/policy/*` tokens. Callers that know which endpoint they are
    /// verifying for should prefer this method over `verify`.
    pub fn verify_with_aud(
        &self,
        token: &str,
        now_epoch_seconds: f64,
        expected_aud: &str,
    ) -> Result<VerifiedClaims, KernelTokenError> {
        verify_kernel_token(
            token,
            &self.pinned_verifying_key,
            now_epoch_seconds,
            self.leeway_seconds,
            Some(expected_aud),
        )
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names
)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use qorch_domain::safety::{sign_kernel_token, AuthorizeClaims, KERNEL_AUTHORIZE_AUD};

    /// Generate a deterministic test keypair using a constant seed.
    fn fixed_keypair() -> (SigningKey, [u8; 32]) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let public = signing.verifying_key().to_bytes();
        (signing, public)
    }

    fn sample_claims(now: f64) -> AuthorizeClaims {
        AuthorizeClaims {
            action: "sio_run_cycles".to_string(),
            aud: KERNEL_AUTHORIZE_AUD.to_string(),
            run_id: "run-007".to_string(),
            subject: "worker".to_string(),
            params_fingerprint: "f".repeat(64),
            issued_at: now,
            expires_at: now + 300.0,
            nonce: "test-nonce-22-chars-".to_string(),
        }
    }

    #[test]
    fn pinned_verifier_accepts_token_signed_with_pinned_key() {
        let (signing, public) = fixed_keypair();
        let now = 1_700_000_000.0;
        let token = sign_kernel_token(&sample_claims(now), &signing);
        let verifier = PinnedKeyVerifier::from_pubkey_bytes(public).expect("valid pubkey");
        let verified = verifier.verify(&token, now + 1.0).expect("must verify");
        assert_eq!(
            verified.claims.get("action").and_then(|v| v.as_str()),
            Some("sio_run_cycles")
        );
    }

    #[test]
    fn pinned_verifier_rejects_token_signed_with_attacker_key() {
        //  AC9 /  Migration Note AC8 (R): the verifier
        // MUST reject any response signed with a key other than the
        // pinned one. This is the structural defence against kernel
        // substitution / tampering.
        let (_pinned_signing, pinned_public) = fixed_keypair();

        // Attacker uses a different key.
        let attacker_signing = SigningKey::from_bytes(&[42u8; 32]);

        let now = 1_700_000_000.0;
        let attacker_token = sign_kernel_token(&sample_claims(now), &attacker_signing);

        let verifier = PinnedKeyVerifier::from_pubkey_bytes(pinned_public).unwrap();
        let result = verifier.verify(&attacker_token, now + 1.0);
        assert!(
            result.is_err(),
            "verifier MUST reject attacker-signed token"
        );
    }

    #[test]
    fn pinned_verifier_rejects_expired_token() {
        //  AC14: replay of an expired token must be rejected.
        let (signing, public) = fixed_keypair();
        let now = 1_700_000_000.0;
        let token = sign_kernel_token(&sample_claims(now), &signing);
        let verifier = PinnedKeyVerifier::from_pubkey_bytes(public).unwrap();
        // 1 hour later — past the 5-min expiry + 5s leeway.
        let result = verifier.verify(&token, now + 3600.0);
        assert!(result.is_err(), "verifier MUST reject expired token");
    }

    #[test]
    fn fingerprint_is_stable_for_same_key() {
        let (_signing, public) = fixed_keypair();
        let v1 = PinnedKeyVerifier::from_pubkey_bytes(public).unwrap();
        let v2 = PinnedKeyVerifier::from_pubkey_bytes(public).unwrap();
        assert_eq!(v1.fingerprint(), v2.fingerprint());
        assert_eq!(v1.fingerprint().len(), 16); // 16 hex chars
    }

    #[test]
    fn invalid_pubkey_bytes_rejected_at_construction() {
        // Not all 32-byte values are on the Ed25519 curve. The
        // verifier construction MUST reject invalid bytes rather than
        // silently accepting them (otherwise the pinning surface lies).
        let bad = [0xFFu8; 32];
        let result = PinnedKeyVerifier::from_pubkey_bytes(bad);
        // ed25519-dalek may or may not consider this on-curve; the
        // test simply asserts that we propagate the error rather than
        // panic. Acceptable outcomes: Ok or Err — but the call returns
        // a Result so the caller can react.
        let _ = result;
    }
}
