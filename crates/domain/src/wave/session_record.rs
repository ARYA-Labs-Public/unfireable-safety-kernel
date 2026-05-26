//! `WaveSessionRecord` — wire-shape for a single ceremony-stage
//! session record persisted to the transparency-log.
//!
//!. One record per (wave_id, stage, session_id).
//! The transparency-log indexes by `idempotency_key =
//! SHA-256(wave_id || stage || session_id)`; the field set below is
//! the *canonical content*, agnostic of HMAC framing (the kernel
//! signs the canonical-JSON serialization before append).
//!
//! Domain-layer responsibilities:
//!   - Define the wire shape (this module).
//!   - Define the completeness predicate
//!     [`all_required_stages_present`].
//!   - Define the canonical-JSON projection
//!     [`WaveSessionRecord::canonical_bytes`] the kernel HMACs.
//!
//! Out of scope (lives in the service crate):
//!   - The actual HMAC computation (uses an OS-supplied key).
//!   - HTTP routing.
//!   - Idempotency-key derivation against the store.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::context::WaveId;
use super::gate_surface::GateSurface;
use super::stage::{WaveOutcome, WaveStage};

/// A single ceremony-stage session record. Persisted as a Merkle leaf;
/// the leaf payload IS the canonical-JSON serialization of this struct.
///
/// Field ordering is alphabetic so the derived `Serialize` produces
/// byte-stable JSON across compilations (mirrors the lex-sorted
/// convention from
/// `crates/services/transparency-log/src/dto.rs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaveSessionRecord {
    /// Free-form evidence summary — re-derived hash, replay output,
    /// Linear comment URL. Bounded length is enforced at the route
    /// (the domain layer carries the bytes verbatim).
    pub evidence: String,

    /// Set of gate surfaces this session record attests to. Required
    /// for stages where gate-surface coverage is the verdict
    /// (PurpleTeamed); informational on others. An empty set means
    /// "no gate surfaces touched at this stage".
    pub gate_surfaces: HashSet<GateSurface>,

    /// Originating Linear issue (e.g. `""`). Carried so the
    /// verify route can render a human-readable chain.
    pub linear_issue: String,

    /// Wall-clock instant the writing skill captured this record.
    /// Seconds since the UNIX epoch.
    pub occurred_at_epoch_seconds: u64,

    /// Verdict the writing skill produced at this stage.
    pub outcome: WaveOutcome,

    /// Skill-supplied session identifier (`/test` "adversarial suite
    /// session-id", `/purple-team` "session-id", etc.).
    pub session_id: String,

    /// Stage of the wave ceremony pipeline this record attests to.
    pub stage: WaveStage,

    /// Identity of the wave this record belongs to.
    pub wave_id: WaveId,

    /// Name of the writing skill (`"/test"`, `"/purple-team"`,
    /// `"/user-acceptance"`, `"/closeout"`). Cross-checked against
    /// `stage` at the route layer.
    pub written_by: String,
}

impl WaveSessionRecord {
    /// Build a record. The domain layer does not read the clock or
    /// touch network state.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // The record genuinely has 9
    // fields and a builder shape would defeat the wire-clean intent.
    pub fn new(
        wave_id: WaveId,
        linear_issue: impl Into<String>,
        stage: WaveStage,
        session_id: impl Into<String>,
        outcome: WaveOutcome,
        evidence: impl Into<String>,
        gate_surfaces: HashSet<GateSurface>,
        written_by: impl Into<String>,
        occurred_at_epoch_seconds: u64,
    ) -> Self {
        Self {
            evidence: evidence.into(),
            gate_surfaces,
            linear_issue: linear_issue.into(),
            occurred_at_epoch_seconds,
            outcome,
            session_id: session_id.into(),
            stage,
            wave_id,
            written_by: written_by.into(),
        }
    }

    /// Canonical-JSON projection the kernel HMACs before append. Uses
    /// `serde_json::to_vec` against the lex-sorted struct layout, so
    /// the output is byte-stable across compilations and Rust
    /// versions (modulo a serde major bump, in which case the
    /// transparency-log version bumps too).
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if serialization fails (impossible
    /// for the current shape — all fields are `Serialize`). Surfaced
    /// rather than panicked so the route layer can return 500 instead
    /// of crashing the worker.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// SHA-256 idempotency key the transparency-log indexes on.
    /// Computed as `SHA-256(wave_id || "\x1F" || stage_wire_string ||
    /// "\x1F" || session_id)`. The `\x1F` (unit separator) is the
    /// canonical low-collision delimiter and matches the kernel's
    /// existing `idempotency_key` derivation in
    /// `crates/services/safety-kernel`.
    #[must_use]
    pub fn idempotency_key(
        wave_id: &WaveId,
        stage: WaveStage,
        session_id: &str,
    ) -> [u8; 32] {
        // Wire-form stage string mirrors what `serde` would emit. Pin
        // the mapping here so a future serde-rename does not silently
        // re-key existing rows.
        let stage_wire = match stage {
            WaveStage::Planned => "PLANNED",
            WaveStage::Decomposed => "DECOMPOSED",
            WaveStage::Tested => "TESTED",
            WaveStage::PurpleTeamed => "PURPLE_TEAMED",
            WaveStage::Accepted => "ACCEPTED",
            WaveStage::Closed => "CLOSED",
        };
        let mut h = Sha256::new();
        h.update(wave_id.as_str().as_bytes());
        h.update([0x1F]);
        h.update(stage_wire.as_bytes());
        h.update([0x1F]);
        h.update(session_id.as_bytes());
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Convenience: this record's own idempotency key. Used by the
    /// route layer to derive the storage adapter's `idempotency_key`
    /// without re-rolling the SHA-256 by hand.
    #[must_use]
    pub fn record_idempotency_key(&self) -> [u8; 32] {
        Self::idempotency_key(&self.wave_id, self.stage, &self.session_id)
    }
}

/// True iff a wave's chain of session records covers every required
/// stage.
///
/// Required stages always include [`WaveStage::Tested`],
/// [`WaveStage::Accepted`], and [`WaveStage::Closed`]. The chain MUST
/// additionally include [`WaveStage::PurpleTeamed`] when ANY record
/// in the chain carries a non-empty `gate_surfaces` (i.e. the wave
/// touched a gate surface at some point). This mirrors
/// [`super::context::WaveContext::requires_purple_team`] but operates
/// on the persisted chain instead of the in-flight context — the
/// transparency-log is the source of truth at audit time.
///
/// Pure-domain helper. The HTTP route wraps this in
/// `VerifyResponse.all_required_stages_present`.
#[must_use]
pub fn all_required_stages_present(records: &[WaveSessionRecord]) -> bool {
    let present: HashSet<WaveStage> = records.iter().map(|r| r.stage).collect();
    if !WaveStage::unconditionally_required()
        .iter()
        .all(|s| present.contains(s))
    {
        return false;
    }
    let any_gate_surface = records.iter().any(|r| !r.gate_surfaces.is_empty());
    if any_gate_surface && !present.contains(&WaveStage::PurpleTeamed) {
        return false;
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn rec(stage: WaveStage, gs: HashSet<GateSurface>) -> WaveSessionRecord {
        WaveSessionRecord::new(
            WaveId::new("wave-001"),
            "",
            stage,
            format!("sid-{stage:?}"),
            WaveOutcome::Pass,
            "evidence",
            gs,
            "/test",
            1_716_400_000,
        )
    }

    #[test]
    fn idempotency_key_is_stable_across_invocations() {
        let wid = WaveId::new("wave-42");
        let a = WaveSessionRecord::idempotency_key(&wid, WaveStage::Tested, "sid-x");
        let b = WaveSessionRecord::idempotency_key(&wid, WaveStage::Tested, "sid-x");
        assert_eq!(a, b);
    }

    #[test]
    fn idempotency_key_changes_per_field() {
        let wid = WaveId::new("wave-42");
        let base = WaveSessionRecord::idempotency_key(&wid, WaveStage::Tested, "sid-x");
        assert_ne!(
            base,
            WaveSessionRecord::idempotency_key(&wid, WaveStage::Closed, "sid-x")
        );
        assert_ne!(
            base,
            WaveSessionRecord::idempotency_key(&wid, WaveStage::Tested, "sid-y")
        );
        assert_ne!(
            base,
            WaveSessionRecord::idempotency_key(&WaveId::new("wave-43"), WaveStage::Tested, "sid-x")
        );
    }

    #[test]
    fn canonical_bytes_round_trip() {
        let r = rec(WaveStage::Tested, HashSet::new());
        let bytes = r.canonical_bytes().unwrap();
        let back: WaveSessionRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn canonical_bytes_byte_stable_across_calls() {
        let r = rec(WaveStage::Tested, HashSet::new());
        assert_eq!(r.canonical_bytes().unwrap(), r.canonical_bytes().unwrap());
    }

    #[test]
    fn all_required_present_with_purple_team() {
        let mut gs = HashSet::new();
        gs.insert(GateSurface::SafetyKernel);
        let chain = vec![
            rec(WaveStage::Tested, gs.clone()),
            rec(WaveStage::PurpleTeamed, gs.clone()),
            rec(WaveStage::Accepted, HashSet::new()),
            rec(WaveStage::Closed, HashSet::new()),
        ];
        assert!(all_required_stages_present(&chain));
    }

    #[test]
    fn all_required_present_without_purple_team_no_gate_surface() {
        let chain = vec![
            rec(WaveStage::Tested, HashSet::new()),
            rec(WaveStage::Accepted, HashSet::new()),
            rec(WaveStage::Closed, HashSet::new()),
        ];
        assert!(all_required_stages_present(&chain));
    }

    #[test]
    fn all_required_missing_purple_team_with_gate_surface() {
        let mut gs = HashSet::new();
        gs.insert(GateSurface::SafetyKernel);
        // Rule 8 fixture: gate surface present, no PurpleTeamed
        // record. The predicate MUST reject.
        let chain = vec![
            rec(WaveStage::Tested, gs),
            rec(WaveStage::Accepted, HashSet::new()),
            rec(WaveStage::Closed, HashSet::new()),
        ];
        assert!(!all_required_stages_present(&chain));
    }

    #[test]
    fn all_required_missing_tested() {
        let chain = vec![
            rec(WaveStage::Accepted, HashSet::new()),
            rec(WaveStage::Closed, HashSet::new()),
        ];
        assert!(!all_required_stages_present(&chain));
    }

    #[test]
    fn all_required_missing_closed() {
        let chain = vec![
            rec(WaveStage::Tested, HashSet::new()),
            rec(WaveStage::Accepted, HashSet::new()),
        ];
        assert!(!all_required_stages_present(&chain));
    }

    #[test]
    fn deny_unknown_fields_rejects_forged_extra() {
        // Rule 8 fixture — a wire payload with an extra field must
        // fail to deserialize so an attacker cannot smuggle metadata
        // past the kernel HMAC by hiding it in unknown fields.
        let bad = r#"{
            "evidence": "x",
            "gate_surfaces": [],
            "linear_issue": "",
            "occurred_at_epoch_seconds": 0,
            "outcome": "PASS",
            "session_id": "s",
            "stage": "TESTED",
            "wave_id": "w",
            "written_by": "/test",
            "smuggled_field": "boo"
        }"#;
        let r: Result<WaveSessionRecord, _> = serde_json::from_str(bad);
        assert!(r.is_err(), "unknown field must be rejected");
    }
}
