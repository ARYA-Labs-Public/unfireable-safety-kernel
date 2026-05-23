//! Episodic chain — tamper-evident audit record for ARYA language decisions.
//!
//! Per ARY-2102. Each committed answer ARYA produces during inference is
//! recorded as an [`EpisodicChainEntry`] whose `entry_hash` covers all
//! other fields plus the previous entry's hash, producing a Merkle-like
//! sequence the Safety Kernel can re-verify on demand.
//!
//! # Cross-layer parity
//!
//! Hash primitive: `sha2::Sha256` (32-byte digest). The Safety Kernel's
//! `policy_audit_chain_integrity` surface already uses this primitive;
//! the cogcore `episodic.rs` lane (arya-speaks-language-core commit
//! `a0dc571`, currently FNV-1a) MUST adopt it so the language-layer
//! audit chain and the enforcement-layer policy chain can share
//! cross-layer audit proofs.
//!
//! # Boundary
//!
//! Pure types and pure functions only. No I/O, no clock, no RNG. The
//! crate-level `#![forbid(unsafe_code)]` in
//! [`crate`] guarantees no unsafe construction path exists for any
//! type defined here, including in tests.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Sentinel `prev_hash` value for the genesis entry (`seq == 0`). All
/// zeros — distinguishable from any real SHA-256 output with
/// overwhelming probability.
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

/// One immutable record in the episodic chain.
///
/// Field semantics:
///
/// * `seq` — strictly monotonic per `tenant_id`, starting at 0.
/// * `tenant_id` — the customer (or `"shared"` for non-tenanted runs).
/// * `atom_id` — which arya-speaks atom drove the decision.
/// * `domain` — coarse semantic domain (e.g. `"physics"`, `"benchmark"`).
/// * `committed` — `true` when ARYA committed an answer; `false` on
///   abstain.
/// * `correct` — `Some(bool)` only when ground truth was available at
///   commit time; `None` for inference-only context. See
///   [`crate::invariant::GroundTruthContext`] for the type-state
///   witness that should gate writers.
/// * `confidence` — model confidence in `[0.0, 1.0]`.
/// * `ts_utc` — RFC3339 UTC timestamp string (e.g. `"2026-05-22T18:00:00Z"`).
/// * `prev_hash` — `entry_hash` of the chain's previous entry, or
///   [`GENESIS_PREV_HASH`] for the genesis entry.
/// * `entry_hash` — SHA-256 over the canonical byte serialization of
///   every other field, including `prev_hash`. Computed by
///   [`compute_entry_hash`].
// Eq is not derived because `confidence: f32` does not implement `Eq`
// (NaN-vs-NaN). `PartialEq` is sufficient for the test assertions and
// for the hash-equality checks in `verify_chain_integrity`, which
// operate on the `[u8; 32]` `entry_hash` field rather than the struct
// itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EpisodicChainEntry {
    /// Monotonic sequence number within `tenant_id`. Genesis = 0.
    pub seq: u64,
    /// Tenant identifier (multi-tenant deployments) or `"shared"`.
    pub tenant_id: String,
    /// arya-speaks atom that drove the decision (commit `a0dc571`).
    pub atom_id: String,
    /// Coarse semantic domain (e.g. `"physics"`, `"benchmark"`).
    pub domain: String,
    /// `true` when ARYA committed an answer; `false` when it abstained.
    pub committed: bool,
    /// `Some(true)` / `Some(false)` only when ground truth was
    /// available at commit time. `None` otherwise.
    pub correct: Option<bool>,
    /// Model confidence in `[0.0, 1.0]`.
    pub confidence: f32,
    /// RFC3339 UTC timestamp string.
    pub ts_utc: String,
    /// `entry_hash` of the previous entry, or
    /// [`GENESIS_PREV_HASH`] for genesis.
    pub prev_hash: [u8; 32],
    /// SHA-256 over the canonical serialization of every other field
    /// (including `prev_hash`).
    pub entry_hash: [u8; 32],
}

/// Compute the canonical SHA-256 over every field of `entry` except
/// `entry_hash`. Deterministic and byte-stable across implementations.
///
/// Serialization layout (all integers little-endian):
///
/// ```text
/// seq         : u64
/// tenant_id   : len(u32) + utf-8 bytes
/// atom_id     : len(u32) + utf-8 bytes
/// domain      : len(u32) + utf-8 bytes
/// committed   : u8 (0 or 1)
/// correct     : u8 (0xFF=None, 0x00=Some(false), 0x01=Some(true))
/// confidence  : f32 (little-endian IEEE-754 bits)
/// ts_utc      : len(u32) + utf-8 bytes
/// prev_hash   : [u8; 32]
/// ```
///
/// Length prefixes prevent ambiguity between adjacent variable-length
/// fields; without them, `("a", "bc")` and `("ab", "c")` would hash to
/// the same digest. The `correct` discriminator uses `0xFF` for `None`
/// to make a forgotten-init-to-zero accident map to `Some(false)`
/// rather than `None`, which a downstream auditor would notice as a
/// sudden run of "correct=false" rather than a silent disappearance.
#[must_use]
pub fn compute_entry_hash(entry: &EpisodicChainEntry) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(entry.seq.to_le_bytes());
    h.update(u32_len(&entry.tenant_id).to_le_bytes());
    h.update(entry.tenant_id.as_bytes());
    h.update(u32_len(&entry.atom_id).to_le_bytes());
    h.update(entry.atom_id.as_bytes());
    h.update(u32_len(&entry.domain).to_le_bytes());
    h.update(entry.domain.as_bytes());
    h.update([u8::from(entry.committed)]);
    h.update([match entry.correct {
        None => 0xFFu8,
        Some(false) => 0x00,
        Some(true) => 0x01,
    }]);
    h.update(entry.confidence.to_le_bytes());
    h.update(u32_len(&entry.ts_utc).to_le_bytes());
    h.update(entry.ts_utc.as_bytes());
    h.update(entry.prev_hash);
    h.finalize().into()
}

/// `s.len() as u32`, saturating at `u32::MAX`. We saturate rather than
/// panic so a pathological input on a 64-bit host (string > 4 GiB) just
/// produces a hash that won't verify, rather than aborting the process.
/// Real episodic entries are tens to hundreds of bytes; this is a
/// defense-in-depth check.
#[inline]
#[allow(clippy::cast_possible_truncation)]
fn u32_len(s: &str) -> u32 {
    u32::try_from(s.len()).unwrap_or(u32::MAX)
}

/// Verify chain integrity end-to-end.
///
/// Returns `Ok(())` when:
///
/// * every entry's `entry_hash` matches the canonical hash of its
///   other fields (computed by [`compute_entry_hash`]), AND
/// * every non-genesis entry's `prev_hash` matches the previous
///   entry's `entry_hash`.
///
/// Empty slices return `Ok(())` (vacuous truth — no integrity claim
/// to make).
///
/// Cost: O(n) hashes — one SHA-256 per entry.
///
/// # Errors
///
/// Returns `Err(i)` where `i` is the index of the first failing
/// entry. `Err(0)` means the genesis entry's `entry_hash` is
/// tampered; `Err(i)` for `i > 0` means either the entry's own
/// `entry_hash` was tampered OR its `prev_hash` does not match the
/// previous entry's `entry_hash` (chain break).
pub fn verify_chain_integrity(entries: &[EpisodicChainEntry]) -> Result<(), usize> {
    for (i, entry) in entries.iter().enumerate() {
        let expected = compute_entry_hash(entry);
        if expected != entry.entry_hash {
            return Err(i);
        }
        if i > 0 && entry.prev_hash != entries[i - 1].entry_hash {
            return Err(i);
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_entry(seq: u64, prev_hash: [u8; 32]) -> EpisodicChainEntry {
        let mut e = EpisodicChainEntry {
            seq,
            tenant_id: "tenant-acme".to_string(),
            atom_id: format!("atom-{seq}"),
            domain: "physics".to_string(),
            committed: true,
            correct: Some(true),
            confidence: 0.9,
            ts_utc: format!("2026-05-22T18:00:{:02}Z", seq % 60),
            prev_hash,
            entry_hash: GENESIS_PREV_HASH,
        };
        e.entry_hash = compute_entry_hash(&e);
        e
    }

    fn build_chain(n: usize) -> Vec<EpisodicChainEntry> {
        let mut out = Vec::with_capacity(n);
        let mut prev = GENESIS_PREV_HASH;
        for s in 0..n {
            let e = make_entry(s as u64, prev);
            prev = e.entry_hash;
            out.push(e);
        }
        out
    }

    /// AC3 — valid 10-entry chain returns `Ok(())`.
    #[test]
    fn valid_ten_entry_chain_is_ok() {
        let chain = build_chain(10);
        assert!(verify_chain_integrity(&chain).is_ok());
    }

    /// AC4 — tampered `entry_hash` returns `Err(i)`.
    #[test]
    fn tampered_entry_hash_returns_err_index() {
        let mut chain = build_chain(10);
        chain[3].entry_hash[0] ^= 0xFF;
        assert_eq!(verify_chain_integrity(&chain), Err(3));
    }

    /// AC5 — broken `prev_hash` link returns `Err(i)`.
    ///
    /// Because `entry_hash` covers `prev_hash`, mutating `prev_hash`
    /// alone surfaces as the AC4 path (`entry_hash` mismatch). To
    /// exercise AC5's distinct error path we mutate `prev_hash` AND
    /// recompute `entry_hash` for that entry, so its own fields
    /// hash-verify but the chain link is broken.
    #[test]
    fn broken_prev_hash_returns_err_index() {
        let mut chain = build_chain(10);
        chain[5].prev_hash[0] ^= 0xFF;
        chain[5].entry_hash = compute_entry_hash(&chain[5]);
        assert_eq!(verify_chain_integrity(&chain), Err(5));
    }

    /// Tampering at idx 0 (genesis) surfaces as `Err(0)`.
    #[test]
    fn tampered_genesis_returns_err_zero() {
        let mut chain = build_chain(5);
        chain[0].entry_hash[31] ^= 0x01;
        assert_eq!(verify_chain_integrity(&chain), Err(0));
    }

    /// Empty slice is vacuously ok.
    #[test]
    fn empty_chain_is_ok() {
        let chain: Vec<EpisodicChainEntry> = Vec::new();
        assert!(verify_chain_integrity(&chain).is_ok());
    }

    /// Single-entry genesis chain is ok.
    #[test]
    fn single_entry_chain_is_ok() {
        let chain = build_chain(1);
        assert!(verify_chain_integrity(&chain).is_ok());
    }

    /// AC7 — serde round-trip preserves all fields.
    #[test]
    fn serde_roundtrip_preserves_fields() {
        let chain = build_chain(3);
        let s = serde_json::to_string(&chain).expect("serialize");
        let back: Vec<EpisodicChainEntry> = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, chain);
    }

    /// Cross-check: hash distinguishes adjacent variable-length fields
    /// (length prefixes work). `("a","bc")` and `("ab","c")` must hash
    /// to different digests.
    #[test]
    fn length_prefixes_disambiguate_string_split() {
        let mut a = EpisodicChainEntry {
            seq: 0,
            tenant_id: "a".to_string(),
            atom_id: "bc".to_string(),
            domain: "d".to_string(),
            committed: true,
            correct: None,
            confidence: 0.0,
            ts_utc: "t".to_string(),
            prev_hash: GENESIS_PREV_HASH,
            entry_hash: GENESIS_PREV_HASH,
        };
        let h_a = compute_entry_hash(&a);
        a.tenant_id = "ab".to_string();
        a.atom_id = "c".to_string();
        let h_b = compute_entry_hash(&a);
        assert_ne!(h_a, h_b);
    }

    /// `correct` discriminator: None / Some(false) / Some(true) all
    /// produce distinct hashes.
    #[test]
    fn correct_variants_hash_distinctly() {
        let mut e = EpisodicChainEntry {
            seq: 0,
            tenant_id: "t".to_string(),
            atom_id: "a".to_string(),
            domain: "d".to_string(),
            committed: true,
            correct: None,
            confidence: 0.5,
            ts_utc: "ts".to_string(),
            prev_hash: GENESIS_PREV_HASH,
            entry_hash: GENESIS_PREV_HASH,
        };
        let h_none = compute_entry_hash(&e);
        e.correct = Some(false);
        let h_false = compute_entry_hash(&e);
        e.correct = Some(true);
        let h_true = compute_entry_hash(&e);
        assert_ne!(h_none, h_false);
        assert_ne!(h_false, h_true);
        assert_ne!(h_none, h_true);
    }

    /// Full 32-byte digest is preserved end-to-end (no accidental
    /// truncation to 8 / 16 / 24 bytes). Two entries that differ only
    /// in the 32nd byte of `prev_hash` must hash differently.
    #[test]
    fn full_32_byte_digest_is_preserved() {
        let mut e = EpisodicChainEntry {
            seq: 1,
            tenant_id: "t".to_string(),
            atom_id: "a".to_string(),
            domain: "d".to_string(),
            committed: true,
            correct: Some(true),
            confidence: 1.0,
            ts_utc: "ts".to_string(),
            prev_hash: [0u8; 32],
            entry_hash: GENESIS_PREV_HASH,
        };
        let h_a = compute_entry_hash(&e);
        e.prev_hash[31] = 1;
        let h_b = compute_entry_hash(&e);
        assert_ne!(h_a, h_b);
    }
}
