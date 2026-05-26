//! Production `NonceSource` adapter — `OsRng` 16 bytes →
//! `URL_SAFE_NO_PAD`.
//!
//! Implements `qorch_domain::safety::NonceSource`. Mirrors Python's
//! `secrets.token_urlsafe(16)` byte-for-byte at the format level
//! (16 random bytes → 22-char base64url-no-pad string).
//!
//! 1 and Appendix B, randomness is forbidden in
//! the domain crate; production randomness for nonce minting lives
//! here.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};

use qorch_domain::safety::NonceSource;

/// Default production `NonceSource` — pulls 16 bytes from `OsRng`
/// and base64url-no-pad encodes them.
///
/// `OsRng` reads the platform CSPRNG (`/dev/urandom`, `getrandom(2)`,
/// or equivalent). It is the same entropy source `secrets.token_urlsafe`
/// uses on Linux, so the keyspace and entropy quality match Python
/// 1:1.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRngNonceSource;

impl OsRngNonceSource {
    /// Construct a new `OsRngNonceSource`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl NonceSource for OsRngNonceSource {
    fn nonce_b64(&self) -> String {
        // 16 bytes — matches Python `secrets.token_urlsafe(16)`. Output
        // is a 22-char base64url-no-pad string (16*8/6 = 21.33 → 22).
        let mut buf = [0u8; 16];
        OsRng.fill_bytes(&mut buf);
        URL_SAFE_NO_PAD.encode(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 22-char output, 16 bytes of entropy. The expected length is
    /// fixed; a regression here would mean we changed the entropy size,
    /// which would break equivalence with the Python implementation
    /// even though both sides are still "random".
    #[test]
    fn nonce_has_22_chars() {
        let n = OsRngNonceSource.nonce_b64();
        assert_eq!(
            n.len(),
            22,
            "expected 22-char b64url-no-pad nonce, got {n:?}"
        );
    }

    /// Two consecutive calls must (essentially always) differ. With 128
    /// bits of entropy a collision is astronomically unlikely; if this
    /// ever flakes, the entropy source has been swapped for a
    /// deterministic mock.
    #[test]
    fn two_nonces_differ() {
        let a = OsRngNonceSource.nonce_b64();
        let b = OsRngNonceSource.nonce_b64();
        assert_ne!(a, b);
    }
}
