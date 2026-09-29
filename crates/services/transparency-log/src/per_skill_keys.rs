//! internal-ref — per-skill (per-stage) HMAC API keys for transparency-log
//! writers.
//!
//! ## Why this exists
//!
//! Until internal-ref, the transparency-log used a single shared
//! `x-api-key` (`QORCH_TRANSPARENCY_API_KEY`). Every writer skill
//! (`/test`, `/purple-team`, `/user-acceptance`, `/closeout`) carried
//! the same secret. The `POST /v1/wave/session` route enforced
//! `written_by_matches_stage` — a CONSISTENCY check between the
//! `record.written_by` string and the `record.stage` tag — but a
//! compromised `/test` skill with the shared key could simply
//! re-label itself `written_by: "/closeout"` and write a `Closed`
//! attestation. The label is self-asserted; only the key proves
//! identity. Sharing the key collapses identity.
//!
//! internal-ref issues a DISTINCT `x-api-key` per writer skill and binds
//! each key to a single [`WaveStage`]. The route checks `(stage,
//! supplied_key)` against this map: a mismatch returns 403
//! `stage_key_mismatch`. A compromised `/test` key can no longer
//! impersonate `/closeout` because `/closeout`'s key — distinct,
//! independently rotated — is not in the attacker's possession.
//!
//! ## Backward compatibility
//!
//! When NONE of the per-skill env vars are set, the service falls
//! through to the legacy single-shared-key path
//! (`QORCH_TRANSPARENCY_API_KEY`). This is the deployment shape on
//! every host that has not yet rotated to per-skill keys. The
//! `auth_layer` middleware still enforces the shared key on EVERY
//! authenticated route, including `/v1/wave/session` — per-skill
//! enforcement is layered ON TOP of that, inside the wave-session
//! handler, after the stage is decoded from the request body.
//!
//! ## What's NOT here
//!
//! - **Ed25519 path is untouched.** Per-skill keys gate the HMAC
//!   path only. The Ed25519 path verifies a per-leaf signature against
//!   the transparency-log's published public key; identity binding
//!   there is the kernel-fingerprint pin + the signature itself.
//!   Anti-scope per internal-ref.
//! - **Other endpoints (`/v1/append`, `/v1/sth`, ...) are untouched.**
//!   The kernel — the only authorized caller for those — continues
//!   to use `QORCH_TRANSPARENCY_API_KEY`. Per-skill keys are scoped to
//!   writers of wave-session records; the kernel's append surface is
//!   already protected by Ed25519 signature verification on every leaf.
//!
//! ## Identity vs label
//!
//! The pre-internal-ref contract gave the route two CONSISTENCY checks
//! and zero IDENTITY checks for wave-session writes:
//! 1. `kernel_key_fingerprint_sha256` matches the pinned kernel key
//!    (consistency: "this is the canonical kernel").
//! 2. `written_by_matches_stage(written_by, stage)` (consistency: "the
//!    label and the stage agree").
//!
//! Neither proves that the caller IS who they claim to be. internal-ref
//! adds the missing identity check on the symmetric path: the
//! `x-api-key` BYTES bind the caller to a stage, so the
//! `written_by` LABEL becomes a redundant cross-check rather than the
//! load-bearing identity assertion.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use qorch_domain::wave::stage::WaveStage;

/// Env var the `/test` skill uses for its dedicated HMAC `x-api-key`.
pub const ENV_KEY_TEST: &str = "QORCH_TRANSPARENCY_KEY_TEST";

/// Env var the `/purple-team` skill uses for its dedicated HMAC
/// `x-api-key`.
pub const ENV_KEY_PURPLE_TEAM: &str = "QORCH_TRANSPARENCY_KEY_PURPLE_TEAM";

/// Env var the `/user-acceptance` skill uses for its dedicated HMAC
/// `x-api-key`.
pub const ENV_KEY_USER_ACCEPTANCE: &str = "QORCH_TRANSPARENCY_KEY_USER_ACCEPTANCE";

/// Env var the `/closeout` skill uses for its dedicated HMAC
/// `x-api-key`.
pub const ENV_KEY_CLOSEOUT: &str = "QORCH_TRANSPARENCY_KEY_CLOSEOUT";

/// Stages that internal-ref issues per-skill keys for. The four writer
/// skills in the ceremony. `Planned` / `Decomposed` are intentionally
/// excluded — they are produced by `/plan` and `/team`, which do not
/// today own a writer slot on the transparency-log (the kernel's
/// canonical-append path is what records those transitions).
///
/// Append-only: if a future skill needs its own key, add a new variant
/// to [`WaveStage`] (ordered append, never insert) and extend this
/// table. Reordering would scramble persisted records.
pub const STAGES_WITH_KEYS: &[WaveStage] = &[
    WaveStage::Tested,
    WaveStage::PurpleTeamed,
    WaveStage::Accepted,
    WaveStage::Closed,
];

/// Per-stage HMAC `x-api-key` table. Backs the
/// `state.per_skill_keys: Option<PerSkillKeys>` field. `None` on the
/// state means back-compat single-shared-key mode; `Some(_)` means
/// the per-stage check is ARMED and a stage with no entry in the
/// table will be REJECTED (403 `stage_key_mismatch`).
///
/// `BTreeMap` (not `HashMap`) so the published `/v1/keys/transparency`
/// fingerprints come out in deterministic lex-sorted stage order —
/// matches the rest of the DTO's byte-stable JSON contract.
#[derive(Debug, Clone)]
pub struct PerSkillKeys {
    /// Stage → raw `x-api-key` bytes the caller must present.
    keys: BTreeMap<WaveStage, String>,
}

impl PerSkillKeys {
    /// Build a fresh table. Used by tests; production loads from env
    /// via [`Self::from_env`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Insert a `(stage, key)` pair. Overwrites any prior entry for
    /// the stage. Returns `self` for chained construction in tests.
    #[must_use]
    pub fn with_key(mut self, stage: WaveStage, key: impl Into<String>) -> Self {
        self.keys.insert(stage, key.into());
        self
    }

    /// `true` when no per-stage keys have been configured. The route
    /// treats an empty table as "fall through to the legacy shared
    /// key" — same shape as `state.per_skill_keys.is_none()` but lets
    /// callers wrap a sentinel empty table without changing the
    /// semantics.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Number of configured per-stage keys (0..=4). Useful for the
    /// startup log line on the bin.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when this table has an entry for `stage`. The per-stage
    /// route check uses this together with [`Self::matches`] to
    /// distinguish "no key configured for this stage" (still a
    /// rejection when the table is armed) from "wrong key supplied".
    #[must_use]
    pub fn has_stage(&self, stage: WaveStage) -> bool {
        self.keys.contains_key(&stage)
    }

    /// Constant-time compare the supplied `x-api-key` against the
    /// expected key for `stage`. Returns `false` when:
    ///   - `stage` has no key configured in this table (no
    ///     `/<skill>` was issued a key for it), OR
    ///   - the supplied key bytes do not match the configured bytes.
    ///
    /// `true` only when the configured key for `stage` exists AND
    /// matches `supplied` byte-for-byte. The compare is constant-time
    /// to avoid leaking which byte of the configured key differs.
    #[must_use]
    pub fn matches(&self, stage: WaveStage, supplied: &str) -> bool {
        let Some(expected) = self.keys.get(&stage) else {
            return false;
        };
        constant_time_eq(expected.as_bytes(), supplied.as_bytes())
    }

    /// Render the table as a `BTreeMap<wire_stage_string, fingerprint_hex>`
    /// suitable for inclusion in the public `/v1/keys/transparency`
    /// response. The map exposes only SHA-256 fingerprints — never the
    /// raw key bytes — so external verifiers can prove that the
    /// per-skill rotation actually happened (fingerprints differ
    /// across rotations) without learning the secrets.
    ///
    /// Stage names use the SCREAMING_SNAKE wire form (e.g. `"TESTED"`,
    /// `"PURPLE_TEAMED"`) — same shape `WaveStage` serializes to in
    /// `WaveSessionRecord`. Lex-sorted by stage name because `BTreeMap`
    /// is sorted by key + serde keeps that order on serialise.
    #[must_use]
    pub fn public_fingerprints(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for (stage, key) in &self.keys {
            out.insert(stage_wire_name(*stage), fingerprint_hex(key.as_bytes()));
        }
        out
    }

    /// Read the four `QORCH_TRANSPARENCY_KEY_*` env vars and build a
    /// table. Returns `None` when NONE of the four are set (legacy
    /// shared-key mode). Returns `Some(_)` as soon as ANY one is set
    /// — operators rotating skill-by-skill can configure one at a
    /// time and the route will require it for that stage only.
    ///
    /// Reads from the real process environment. See
    /// [`Self::from_env_source`] for the injectable variant used by
    /// tests — this one cannot be exercised in parallel with any
    /// other test that touches these env vars.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        Self::from_env_source(&crate::env_source::SystemEnv::new())
    }

    /// Same as [`Self::from_env`] but reads through an injectable
    /// [`crate::env_source::EnvSource`] instead of the real process
    /// environment — lets tests supply an in-memory map and run in
    /// parallel without racing every other test in the binary over
    /// shared global env state.
    ///
    /// Empty / whitespace-only values are TREATED AS UNSET so a stray
    /// `=` in the env file does not silently arm a stage with an
    /// empty secret.
    ///
    /// The 4-tuple is hard-coded against [`STAGES_WITH_KEYS`] — adding
    /// a new writer skill means adding a `WaveStage` variant AND
    /// updating this function in lock-step.
    #[must_use]
    pub fn from_env_source<E: crate::env_source::EnvSource>(env: &E) -> Option<Self> {
        let mut table = Self::new();
        let mut any_set = false;
        for (stage, env_name) in [
            (WaveStage::Tested, ENV_KEY_TEST),
            (WaveStage::PurpleTeamed, ENV_KEY_PURPLE_TEAM),
            (WaveStage::Accepted, ENV_KEY_USER_ACCEPTANCE),
            (WaveStage::Closed, ENV_KEY_CLOSEOUT),
        ] {
            if let Some(trimmed) = crate::env_source::trimmed_non_empty(env, env_name) {
                table = table.with_key(stage, trimmed);
                any_set = true;
            }
        }
        if any_set {
            Some(table)
        } else {
            None
        }
    }
}

impl Default for PerSkillKeys {
    fn default() -> Self {
        Self::new()
    }
}

/// Stage → wire-form string. Mirrors the
/// `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]` projection on
/// [`WaveStage`] but exposed as a `&'static str` so we do not need a
/// JSON round-trip to print it.
fn stage_wire_name(stage: WaveStage) -> String {
    match stage {
        WaveStage::Planned => "PLANNED".to_string(),
        WaveStage::Decomposed => "DECOMPOSED".to_string(),
        WaveStage::Tested => "TESTED".to_string(),
        WaveStage::PurpleTeamed => "PURPLE_TEAMED".to_string(),
        WaveStage::Accepted => "ACCEPTED".to_string(),
        WaveStage::Closed => "CLOSED".to_string(),
    }
}

/// SHA-256 fingerprint (hex) over the raw key bytes. Used for the
/// public `/v1/keys/transparency` response — fingerprint surfaces
/// rotation events without leaking the secret.
fn fingerprint_hex(key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(key);
    hex::encode(h.finalize())
}

/// Constant-time byte-equality. Local to this module so the route
/// layer does not need to import `auth::constant_time_eq` (private).
/// Same shape as the helper in `auth.rs`.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// In-memory `EnvSource` for tests — lets each test supply its
    /// own environment without touching the real process environment
    /// (and without racing every other test in the binary over that
    /// shared global state).
    struct MapEnv(HashMap<&'static str, &'static str>);

    impl crate::env_source::EnvSource for MapEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).map(|v| v.to_string())
        }
    }

    #[test]
    fn empty_table_matches_nothing() {
        let t = PerSkillKeys::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        // Even an empty supplied key against an empty table must NOT
        // match — vacuous truth is the wrong default for an auth check.
        assert!(!t.matches(WaveStage::Tested, ""));
        assert!(!t.matches(WaveStage::Tested, "anything"));
        assert!(!t.has_stage(WaveStage::Tested));
    }

    #[test]
    fn with_key_inserts_and_matches() {
        let t = PerSkillKeys::new()
            .with_key(WaveStage::Tested, "test-secret-aaa")
            .with_key(WaveStage::Closed, "closeout-secret-zzz");
        assert_eq!(t.len(), 2);
        assert!(t.has_stage(WaveStage::Tested));
        assert!(t.has_stage(WaveStage::Closed));
        assert!(!t.has_stage(WaveStage::Accepted));

        assert!(t.matches(WaveStage::Tested, "test-secret-aaa"));
        assert!(t.matches(WaveStage::Closed, "closeout-secret-zzz"));
        // Cross-stage mismatch — the closeout key MUST NOT validate
        // for the Tested stage even though it is a valid key.
        assert!(!t.matches(WaveStage::Tested, "closeout-secret-zzz"));
        assert!(!t.matches(WaveStage::Closed, "test-secret-aaa"));
    }

    #[test]
    fn matches_is_byte_for_byte() {
        let t = PerSkillKeys::new().with_key(WaveStage::Tested, "exact-bytes-only");
        assert!(t.matches(WaveStage::Tested, "exact-bytes-only"));
        assert!(!t.matches(WaveStage::Tested, "exact-bytes-onl")); // truncated
        assert!(!t.matches(WaveStage::Tested, "exact-bytes-only ")); // trailing space
        assert!(!t.matches(WaveStage::Tested, "EXACT-BYTES-ONLY")); // case-sensitive
    }

    #[test]
    fn public_fingerprints_lex_sorted_and_redacted() {
        let t = PerSkillKeys::new()
            .with_key(WaveStage::Tested, "tk")
            .with_key(WaveStage::PurpleTeamed, "ptk")
            .with_key(WaveStage::Accepted, "uak")
            .with_key(WaveStage::Closed, "cok");
        let fpr = t.public_fingerprints();
        let keys: Vec<&String> = fpr.keys().collect();
        // BTreeMap iter is lex-sorted on the keys: ACCEPTED, CLOSED,
        // PURPLE_TEAMED, TESTED.
        assert_eq!(keys, vec!["ACCEPTED", "CLOSED", "PURPLE_TEAMED", "TESTED"]);
        // Each value MUST be a 64-char hex SHA-256 fingerprint, NOT
        // the raw key.
        for v in fpr.values() {
            assert_eq!(v.len(), 64);
            assert!(v.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(!v.contains("tk"));
            assert!(!v.contains("ptk"));
            assert!(!v.contains("uak"));
            assert!(!v.contains("cok"));
        }
    }

    #[test]
    fn fingerprint_changes_on_key_rotation() {
        // Two different keys for the same stage must produce
        // different fingerprints — that's the audit signal a rotation
        // actually happened. Without it the published surface cannot
        // distinguish "rotated" from "stalled".
        let a = PerSkillKeys::new().with_key(WaveStage::Tested, "old");
        let b = PerSkillKeys::new().with_key(WaveStage::Tested, "new");
        let fa = a.public_fingerprints();
        let fb = b.public_fingerprints();
        assert_ne!(fa.get("TESTED"), fb.get("TESTED"));
    }

    #[test]
    fn stages_with_keys_matches_writer_skills() {
        // The constant table MUST list exactly the four writer skills.
        // Append-only — extending it is a deliberate ceremony change.
        assert_eq!(STAGES_WITH_KEYS.len(), 4);
        assert!(STAGES_WITH_KEYS.contains(&WaveStage::Tested));
        assert!(STAGES_WITH_KEYS.contains(&WaveStage::PurpleTeamed));
        assert!(STAGES_WITH_KEYS.contains(&WaveStage::Accepted));
        assert!(STAGES_WITH_KEYS.contains(&WaveStage::Closed));
        // Plan / decomposition stages MUST NOT be in the table — they
        // do not own a writer slot on this surface.
        assert!(!STAGES_WITH_KEYS.contains(&WaveStage::Planned));
        assert!(!STAGES_WITH_KEYS.contains(&WaveStage::Decomposed));
    }

    #[test]
    fn from_env_source_none_set_returns_none() {
        let env = MapEnv(HashMap::new());
        // Back-compat path: no per-skill vars configured at all means
        // the legacy single-shared-key mode stays in force.
        assert!(PerSkillKeys::from_env_source(&env).is_none());
    }

    #[test]
    fn from_env_source_one_stage_set() {
        let mut m = HashMap::new();
        m.insert(ENV_KEY_TEST, "only-test-secret");
        let env = MapEnv(m);
        let t = PerSkillKeys::from_env_source(&env).expect("one var set must arm the table");
        assert_eq!(t.len(), 1);
        assert!(t.has_stage(WaveStage::Tested));
        assert!(t.matches(WaveStage::Tested, "only-test-secret"));
        assert!(!t.has_stage(WaveStage::PurpleTeamed));
        assert!(!t.has_stage(WaveStage::Accepted));
        assert!(!t.has_stage(WaveStage::Closed));
    }

    #[test]
    fn from_env_source_all_four_set_no_cross_wiring() {
        let mut m = HashMap::new();
        m.insert(ENV_KEY_TEST, "secret-test-1");
        m.insert(ENV_KEY_PURPLE_TEAM, "secret-purple-2");
        m.insert(ENV_KEY_USER_ACCEPTANCE, "secret-accept-3");
        m.insert(ENV_KEY_CLOSEOUT, "secret-closeout-4");
        let env = MapEnv(m);
        let t = PerSkillKeys::from_env_source(&env).expect("all four vars set must arm the table");
        assert_eq!(t.len(), 4);
        assert!(t.matches(WaveStage::Tested, "secret-test-1"));
        assert!(t.matches(WaveStage::PurpleTeamed, "secret-purple-2"));
        assert!(t.matches(WaveStage::Accepted, "secret-accept-3"));
        assert!(t.matches(WaveStage::Closed, "secret-closeout-4"));
        // Cross-wiring check: a table this small is exactly where a
        // copy-paste swap would hide — none of the secrets may
        // validate against a stage other than the one it was
        // configured for.
        assert!(!t.matches(WaveStage::PurpleTeamed, "secret-test-1"));
        assert!(!t.matches(WaveStage::Accepted, "secret-purple-2"));
        assert!(!t.matches(WaveStage::Closed, "secret-accept-3"));
        assert!(!t.matches(WaveStage::Tested, "secret-closeout-4"));
    }

    #[test]
    fn from_env_source_empty_and_whitespace_only_treated_as_unset() {
        let mut m = HashMap::new();
        m.insert(ENV_KEY_TEST, "");
        m.insert(ENV_KEY_PURPLE_TEAM, "   ");
        let env = MapEnv(m);
        // Both configured vars are empty / whitespace-only, so
        // neither arms the table — the result MUST be `None`, not
        // `Some` of an empty table. An empty-but-armed table would
        // silently authorise nobody while looking configured.
        assert!(PerSkillKeys::from_env_source(&env).is_none());
    }

    #[test]
    fn from_env_source_trims_surrounding_whitespace() {
        let mut m = HashMap::new();
        m.insert(ENV_KEY_CLOSEOUT, "  padded-secret  ");
        let env = MapEnv(m);
        let t = PerSkillKeys::from_env_source(&env).expect("var set must arm the table");
        assert!(t.matches(WaveStage::Closed, "padded-secret"));
        assert!(!t.matches(WaveStage::Closed, "  padded-secret  "));
    }

    #[test]
    fn from_env_source_unknown_var_ignored() {
        let mut m = HashMap::new();
        // Misspelled / unknown var name — not one of the four
        // recognised `QORCH_TRANSPARENCY_KEY_*` vars.
        m.insert("QORCH_TRANSPARENCY_KEY_TSET", "typo-secret");
        let env = MapEnv(m);
        assert!(PerSkillKeys::from_env_source(&env).is_none());
    }
}
