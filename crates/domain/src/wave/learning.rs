//! `WaveLearningRecord` — full implementation (internal-ref).
//!
//! Per internal-ref. The closeout transition emits a `WaveLearningRecord`
//! that feeds the nine memory lanes (`WorkingLane`, `EpisodicLane`,
//! `SemanticLane`, `BeliefLane`, `ConceptLane`, `ProceduralLane`,
//! `EvalLane`, `DistillateLane`, `LTPIndex`). This file defines the
//! complete, pure-data record type and all its sub-types.
//!
//! Design constraints (per internal-ref §"Pure data, no I/O"):
//!
//! - All fields are owned values.
//! - No references to live services.
//! - No async.
//! - No file or network I/O.
//! - No clock or RNG access — timestamps are passed in.
//!
//! The `AdversarialFinding.gate_rejected: bool` field is the critical
//! learning signal — `false` means a gate failed to reject a malicious
//! fixture, which is a high-value signal for downstream training.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::context::{
    AdversarialSessionId, PurpleTeamSessionId, UatOutcome, UatVerdict, WaveDomain, WaveId,
};

// ---------------------------------------------------------------------------
// WaveLearningRecord — root type
// ---------------------------------------------------------------------------

/// Lessons-learned record emitted at wave closeout.
///
/// Pure data — see module-level docs for the no-I/O contract. This is the
/// primary learning signal a `WaveLearningEmitter` would consume at wave
/// closeout — a planned consumer that is **not yet defined**: the learning-via-Wave
/// runtime path is deferred (see the crate README "Wave learning status" note and
/// internal-ref).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaveLearningRecord {
    /// The wave this record belongs to.
    pub wave_id: WaveId,
    /// Originating Linear issue (e.g. `"internal-ref"`).
    pub linear_issue: String,
    /// Domain this wave belonged to.
    pub domain: WaveDomain,
    /// One-paragraph goal summary, as written by the planner.
    pub goal_summary: String,
    /// Adversarial-suite session that produced the Tested transition.
    pub adversarial_session: AdversarialSessionId,
    /// Purple-team session that produced the `PurpleTeamed` transition.
    /// `None` is only valid when the wave had an empty `gate_surfaces`
    /// set and took the
    /// [`super::Wave::skip_purple_team_if_no_gate_surface`] branch.
    pub purple_team_session: Option<PurpleTeamSessionId>,
    /// Per-phase rollups for every phase that ran.
    pub phases_executed: Vec<WavePhaseRecord>,
    /// Aggregated verdicts across all gates that fired.
    pub gate_verdicts: GateVerdictSummary,
    /// Per-fixture results from the adversarial suite (`/test`).
    pub adversarial_findings: Vec<AdversarialFinding>,
    /// Per-finding results from the purple-team review (`/purple-team`).
    pub purple_team_findings: Vec<PurpleTeamFinding>,
    /// UAT verdicts, one row per acceptance criterion.
    pub uat_verdicts: Vec<UatVerdict>,
    /// Constraint-layer result for this wave.
    pub constraint_layer_result: ConstraintLayerResult,
    /// Final wave outcome — maps to FSRS feedback via
    /// [`WaveOutcome::to_fsrs_u8`].
    pub outcome: WaveOutcome,
    /// Wall-clock duration of the wave, in seconds.
    pub duration_seconds: u64,
    /// Closeout timestamp (seconds since UNIX epoch). Supplied by the
    /// adapter — the domain layer does not read the clock.
    pub closed_at_epoch: u64,
}

// ---------------------------------------------------------------------------
// Sub-types
// ---------------------------------------------------------------------------

/// One phase of the wave that actually ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WavePhaseRecord {
    /// Phase identifier (e.g. `"phase-1-build"`).
    pub phase_id: String,
    /// One-line summary of what the phase did.
    pub summary: String,
    /// Nano model IDs that participated in this phase.
    pub nano_model_ids: Vec<String>,
    /// Wall-clock duration for this phase, in seconds.
    pub duration_seconds: u64,
}

/// Severity classification for an adversarial finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdversarialSeverity {
    /// Cosmetic — gate response was correct but verbose.
    Low,
    /// Bug that did not affect gate decision.
    Medium,
    /// Gate produced incorrect verdict OR rejected a benign fixture.
    High,
    /// Gate failed to reject a malicious fixture (data plane breach).
    Critical,
}

/// One adversarial-suite fixture and its outcome.
///
/// `gate_rejected = false` on a malicious fixture is the canonical
/// high-value learning signal — it means the gate let something
/// through that it should have rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdversarialFinding {
    /// Stable identifier for the fixture (e.g. `"fix-001-malformed-json"`).
    pub fixture_id: String,
    /// Free-form description of the fixture.
    pub description: String,
    /// Gate id this fixture targeted (e.g. `"safety_kernel.token"`).
    pub gate_id: String,
    /// Did the gate reject this fixture?
    ///
    /// `true` = correct rejection (good outcome).
    /// `false` = gate failed to reject (high-value learning signal).
    pub gate_rejected: bool,
    /// Severity of the finding.
    pub severity: AdversarialSeverity,
    /// Nano model IDs implicated in producing or judging the fixture.
    pub responsible_model_ids: Vec<String>,
}

/// Verdict for a single purple-team finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PurpleTeamVerdict {
    /// Surface held up — no follow-up required.
    Pass,
    /// Bug or weakness, but not exploitable today.
    Finding,
    /// Exploitable today — triggers new nano model proposals downstream.
    Blocker,
}

/// One purple-team finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurpleTeamFinding {
    /// Stable finding identifier (e.g. `"pt-001-token-replay"`).
    pub finding_id: String,
    /// Surface the finding applies to (e.g. `"SafetyKernel"`,
    /// `"CogcoreLanes"`).
    pub surface: String,
    /// Verdict — only `Blocker` triggers new nano model proposals.
    pub verdict: PurpleTeamVerdict,
    /// Free-form description.
    pub description: String,
}

/// Aggregated gate verdicts across all gates that fired during the wave.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateVerdictSummary {
    /// Number of gate fires that returned PASS.
    pub passed: u32,
    /// Number of gate fires that returned a non-blocking finding.
    pub findings: u32,
    /// Number of gate fires that returned BLOCKER.
    pub blockers: u32,
    /// Gate ids that fired at least once.
    pub gate_ids_fired: Vec<String>,
}

/// Outcome of the Constraint Layer non-probabilistic check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintLayerResult {
    /// Did the Constraint Layer accept the wave's outputs?
    pub accepted: bool,
    /// Constraint ids that were evaluated.
    pub constraints_checked: Vec<String>,
    /// Constraint ids that REJECTED — empty iff `accepted = true`.
    pub constraints_violated: Vec<String>,
    /// Free-form note from the Constraint Layer.
    pub note: String,
}

/// Final wave outcome.
///
/// Maps to FSRS feedback per internal-ref: `Pass = 2`, `Partial = 1`,
/// `Fail = 0`. Use [`Self::to_fsrs_u8`] to get the FSRS code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WaveOutcome {
    /// All gates passed; wave is fully accepted.
    Pass,
    /// At least one non-blocker finding, but wave was allowed to close.
    Partial,
    /// Wave failed — closeout still emits a record so the system can
    /// learn from the failure.
    Fail,
}

impl WaveOutcome {
    /// FSRS feedback code: `Pass = 2`, `Partial = 1`, `Fail = 0`.
    ///
    /// Used downstream by the FSRS scheduler in the LTP index. The
    /// mapping is fixed by internal-ref §"Technical Notes".
    #[must_use]
    pub fn to_fsrs_u8(&self) -> u8 {
        match self {
            Self::Pass => 2,
            Self::Partial => 1,
            Self::Fail => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum characters for the [`WaveLearningRecord::to_ltp_summary`]
/// Markdown list-item line. Required by internal-ref AC5.
pub const LTP_SUMMARY_MAX_CHARS: usize = 200;

// ---------------------------------------------------------------------------
// WaveLearningRecord — methods
// ---------------------------------------------------------------------------

impl WaveLearningRecord {
    /// Construct a fully populated `WaveLearningRecord`.
    ///
    /// All arguments are passed explicitly — pure-data contract.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wave_id: WaveId,
        linear_issue: impl Into<String>,
        domain: WaveDomain,
        goal_summary: impl Into<String>,
        adversarial_session: AdversarialSessionId,
        purple_team_session: Option<PurpleTeamSessionId>,
        phases_executed: Vec<WavePhaseRecord>,
        gate_verdicts: GateVerdictSummary,
        adversarial_findings: Vec<AdversarialFinding>,
        purple_team_findings: Vec<PurpleTeamFinding>,
        uat_verdicts: Vec<UatVerdict>,
        constraint_layer_result: ConstraintLayerResult,
        outcome: WaveOutcome,
        duration_seconds: u64,
        closed_at_epoch: u64,
    ) -> Self {
        Self {
            wave_id,
            linear_issue: linear_issue.into(),
            domain,
            goal_summary: goal_summary.into(),
            adversarial_session,
            purple_team_session,
            phases_executed,
            gate_verdicts,
            adversarial_findings,
            purple_team_findings,
            uat_verdicts,
            constraint_layer_result,
            outcome,
            duration_seconds,
            closed_at_epoch,
        }
    }

    /// Deduplicated list of every nano model ID that participated in
    /// any phase of this wave.
    ///
    /// Order is preserved by first occurrence across phases; a
    /// `BTreeSet` is used internally only for fast "seen" lookup.
    #[must_use]
    pub fn all_nano_model_ids(&self) -> Vec<String> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut out: Vec<String> = Vec::new();
        for phase in &self.phases_executed {
            for id in &phase.nano_model_ids {
                if seen.insert(id.as_str()) {
                    out.push(id.clone());
                }
            }
        }
        out
    }

    /// Single Markdown list-item line summarizing this record for the
    /// LTP (long-term-policy) index.
    ///
    /// Output is **at most** [`LTP_SUMMARY_MAX_CHARS`] characters
    /// (200). Over-length input is truncated; the function never
    /// panics on input shape. Truncation is done at the byte boundary
    /// after coercion to ASCII-safe summary chars.
    ///
    /// Format:
    /// `- <wave-id> [<domain>] <outcome>: <goal> (gates p/f/b=N/N/N)`
    ///
    /// internal-ref (L) — newline sanitization (defense-in-depth):
    /// ``goal_summary`` is folded so every ASCII and Unicode line-break
    /// (``\n``, ``\r``, ``U+0085``, ``U+2028``, ``U+2029``, vertical
    /// tab, form feed) becomes a single space. Without this an attacker-
    /// controlled ``goal_summary`` containing ``"\nfree text\n"`` would
    /// span multiple Markdown list items in
    /// ``.synapse/memory/ltp_index.md``, smuggling whatever they chose
    /// into the LTP index as a separate entry. The Python parser at
    /// ``packages/rem/ltp.py::_sanitize_inline`` enforces the same
    /// invariant on the consumer side; the Rust side enforces it on
    /// the producer side so the on-disk file is always parser-safe.
    #[must_use]
    pub fn to_ltp_summary(&self) -> String {
        let outcome = match self.outcome {
            WaveOutcome::Pass => "PASS",
            WaveOutcome::Partial => "PARTIAL",
            WaveOutcome::Fail => "FAIL",
        };
        let domain = format!("{:?}", self.domain);
        let safe_goal = sanitize_inline(&self.goal_summary);
        let raw = format!(
            "- {} [{}] {}: {} (gates p/f/b={}/{}/{})",
            self.wave_id.as_str(),
            domain,
            outcome,
            safe_goal,
            self.gate_verdicts.passed,
            self.gate_verdicts.findings,
            self.gate_verdicts.blockers,
        );
        truncate_chars(&raw, LTP_SUMMARY_MAX_CHARS)
    }

    /// Canonical JSON representation.
    ///
    /// Uses `serde_json::to_string` which, because all `Vec` and
    /// scalar fields serialize in declared order and our types only
    /// use `Vec`/struct/scalar/enum (no `HashMap`), produces a
    /// deterministic byte sequence for a given record. If
    /// serialization fails (theoretically impossible for our
    /// schema), returns an empty JSON object string `{}` rather than
    /// panicking — the domain layer never panics on pure-data work.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

// ---------------------------------------------------------------------------
// Helpers (private)
// ---------------------------------------------------------------------------

/// Truncate `s` to at most `max_chars` *Unicode scalar values* (chars).
/// Returns an owned `String`. Pure; never panics.
fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    s.chars().take(max_chars).collect()
}

/// Replace every ASCII and Unicode line-break code point in `s` with
/// a single space. Used by [`WaveLearningRecord::to_ltp_summary`] to
/// prevent multi-line ``goal_summary`` values from corrupting the
/// Markdown LTP index. Pure; never panics.
///
/// Code points folded:
/// * U+000A `LF` (\n)
/// * U+000D `CR` (\r)
/// * U+000B `VT` (\v)
/// * U+000C `FF` (\f)
/// * U+0085 `NEL` (next line)
/// * U+2028 `LS` (line separator)
/// * U+2029 `PS` (paragraph separator)
fn sanitize_inline(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\n' | '\r' | '\u{0B}' | '\u{0C}' | '\u{85}' | '\u{2028}' | '\u{2029}' => ' ',
            other => other,
        })
        .collect()
}

/// Build a [`WaveLearningRecord`] from a closeout-ready [`super::Wave`]
/// payload plus the rollup fields supplied by the closeout adapter.
///
/// Kept here (private to the crate) so [`super::Wave::closeout`] can
/// produce a populated record without copying field-shuffling logic
/// inline. Pure — no I/O. The argument count mirrors
/// [`WaveLearningRecord::new`] minus the outcome (derived here).
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_from_closeout(
    wave_id: WaveId,
    linear_issue: String,
    domain: WaveDomain,
    goal_summary: String,
    adversarial_session: AdversarialSessionId,
    purple_team_session: Option<PurpleTeamSessionId>,
    phases_executed: Vec<WavePhaseRecord>,
    gate_verdicts: GateVerdictSummary,
    adversarial_findings: Vec<AdversarialFinding>,
    purple_team_findings: Vec<PurpleTeamFinding>,
    uat_verdicts: Vec<UatVerdict>,
    constraint_layer_result: ConstraintLayerResult,
    duration_seconds: u64,
    closed_at_epoch: u64,
) -> WaveLearningRecord {
    // Derive outcome from gate verdicts + purple-team blockers + UAT failures.
    let has_blocker = gate_verdicts.blockers > 0
        || purple_team_findings
            .iter()
            .any(|f| f.verdict == PurpleTeamVerdict::Blocker)
        || !constraint_layer_result.accepted;
    let has_uat_fail = uat_verdicts
        .iter()
        .any(|v| matches!(v.outcome, UatOutcome::Fail));
    let has_partial = gate_verdicts.findings > 0
        || uat_verdicts
            .iter()
            .any(|v| matches!(v.outcome, UatOutcome::Partial));
    let outcome = if has_blocker || has_uat_fail {
        WaveOutcome::Fail
    } else if has_partial {
        WaveOutcome::Partial
    } else {
        WaveOutcome::Pass
    };

    WaveLearningRecord::new(
        wave_id,
        linear_issue,
        domain,
        goal_summary,
        adversarial_session,
        purple_team_session,
        phases_executed,
        gate_verdicts,
        adversarial_findings,
        purple_team_findings,
        uat_verdicts,
        constraint_layer_result,
        outcome,
        duration_seconds,
        closed_at_epoch,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn cl_ok() -> ConstraintLayerResult {
        ConstraintLayerResult {
            accepted: true,
            constraints_checked: vec!["cdai.bounds".into(), "cdai.signed_output".into()],
            constraints_violated: vec![],
            note: "ok".into(),
        }
    }

    fn populated_record() -> WaveLearningRecord {
        WaveLearningRecord::new(
            WaveId::new("wave-2184-01"),
            "internal-ref",
            WaveDomain::Platform,
            "WaveLearningRecord full implementation".to_string(),
            AdversarialSessionId::new("adv-001"),
            Some(PurpleTeamSessionId::new("pt-001")),
            vec![
                WavePhaseRecord {
                    phase_id: "phase-1".into(),
                    summary: "scaffolding".into(),
                    nano_model_ids: vec!["nano.a".into(), "nano.b".into()],
                    duration_seconds: 120,
                },
                WavePhaseRecord {
                    phase_id: "phase-2".into(),
                    summary: "implement".into(),
                    nano_model_ids: vec!["nano.b".into(), "nano.c".into()],
                    duration_seconds: 600,
                },
            ],
            GateVerdictSummary {
                passed: 6,
                findings: 0,
                blockers: 0,
                gate_ids_fired: vec!["safety_kernel.token".into(), "constraint.cdai".into()],
            },
            vec![AdversarialFinding {
                fixture_id: "fix-1".into(),
                description: "malformed JSON".into(),
                gate_id: "safety_kernel.token".into(),
                gate_rejected: true,
                severity: AdversarialSeverity::Medium,
                responsible_model_ids: vec!["nano.a".into()],
            }],
            vec![PurpleTeamFinding {
                finding_id: "pt-1".into(),
                surface: "SafetyKernel".into(),
                verdict: PurpleTeamVerdict::Pass,
                description: "no exploit found".into(),
            }],
            vec![UatVerdict {
                criterion_id: "AC1".into(),
                outcome: UatOutcome::Pass,
                evidence: "compiles".into(),
            }],
            cl_ok(),
            WaveOutcome::Pass,
            720,
            1_716_400_000,
        )
    }

    #[test]
    fn outcome_to_fsrs_u8_matches_spec() {
        assert_eq!(WaveOutcome::Pass.to_fsrs_u8(), 2);
        assert_eq!(WaveOutcome::Partial.to_fsrs_u8(), 1);
        assert_eq!(WaveOutcome::Fail.to_fsrs_u8(), 0);
    }

    #[test]
    fn record_roundtrips_through_json() {
        let r = populated_record();
        let j = serde_json::to_string(&r).expect("serialize");
        let back: WaveLearningRecord = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(r, back);
    }

    #[test]
    fn record_canonical_json_is_stable() {
        let r = populated_record();
        let j1 = r.to_canonical_json();
        let j2 = r.to_canonical_json();
        assert_eq!(j1, j2);
        // And round-trips.
        let back: WaveLearningRecord = serde_json::from_str(&j1).expect("deserialize");
        assert_eq!(r, back);
    }

    #[test]
    fn all_nano_model_ids_dedups_across_phases() {
        let r = populated_record();
        let ids = r.all_nano_model_ids();
        assert_eq!(ids, vec!["nano.a", "nano.b", "nano.c"]);
    }

    #[test]
    fn all_nano_model_ids_on_empty_phases_returns_empty() {
        let mut r = populated_record();
        r.phases_executed.clear();
        assert!(r.all_nano_model_ids().is_empty());
    }

    #[test]
    fn ltp_summary_is_at_most_max_chars() {
        let r = populated_record();
        let s = r.to_ltp_summary();
        assert!(
            s.chars().count() <= LTP_SUMMARY_MAX_CHARS,
            "summary too long: {} chars",
            s.chars().count()
        );
        assert!(s.starts_with("- wave-2184-01 "));
    }

    #[test]
    fn ltp_summary_truncates_oversized_goal_without_panic() {
        let mut r = populated_record();
        r.goal_summary = "x".repeat(1_000);
        let s = r.to_ltp_summary();
        assert_eq!(s.chars().count(), LTP_SUMMARY_MAX_CHARS);
    }

    #[test]
    fn ltp_summary_sanitizes_newlines_ary_2189() {
        // internal-ref (L) defense-in-depth: ASCII + Unicode line breakers
        // in `goal_summary` must be folded to spaces so the Markdown LTP
        // index parser does not see two list items where the producer
        // intended one. Closes the deferred internal-ref G purple-team finding.
        let mut r = populated_record();
        r.goal_summary = "before\nafter\rmore\u{2028}then\u{2029}done\u{85}end".into();
        let s = r.to_ltp_summary();
        for bad in [
            '\n', '\r', '\u{2028}', '\u{2029}', '\u{85}', '\u{0B}', '\u{0C}',
        ] {
            assert!(
                !s.contains(bad),
                "to_ltp_summary leaked {:?} into output: {}",
                bad,
                s
            );
        }
        // The textual content survives (sans line-break code points).
        assert!(s.contains("before after more then done end"));
    }

    #[test]
    fn ltp_summary_preserves_unicode_round_trip() {
        let mut r = populated_record();
        r.goal_summary = "héllo — 世界".into();
        let j = r.to_canonical_json();
        let back: WaveLearningRecord = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(back.goal_summary, r.goal_summary);
        // Summary itself contains the unicode and stays under the cap.
        let s = r.to_ltp_summary();
        assert!(s.chars().count() <= LTP_SUMMARY_MAX_CHARS);
    }

    #[test]
    fn adversarial_finding_gate_rejected_false_serializes_explicitly() {
        // The critical learning signal: gate_rejected=false on a
        // malicious fixture must survive the round-trip.
        let f = AdversarialFinding {
            fixture_id: "fix-evil".into(),
            description: "crafted JSON that lies about gate_rejected".into(),
            gate_id: "safety_kernel.token".into(),
            gate_rejected: false,
            severity: AdversarialSeverity::Critical,
            responsible_model_ids: vec!["nano.attacker".into()],
        };
        let j = serde_json::to_string(&f).unwrap();
        assert!(j.contains("\"gate_rejected\":false"));
        let back: AdversarialFinding = serde_json::from_str(&j).unwrap();
        assert_eq!(f, back);
        assert!(!back.gate_rejected);
    }

    #[test]
    fn purple_team_verdict_roundtrips_all_variants() {
        for v in [
            PurpleTeamVerdict::Pass,
            PurpleTeamVerdict::Finding,
            PurpleTeamVerdict::Blocker,
        ] {
            let j = serde_json::to_string(&v).unwrap();
            let back: PurpleTeamVerdict = serde_json::from_str(&j).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn outcome_roundtrips_all_variants() {
        for o in [WaveOutcome::Pass, WaveOutcome::Partial, WaveOutcome::Fail] {
            let j = serde_json::to_string(&o).unwrap();
            let back: WaveOutcome = serde_json::from_str(&j).unwrap();
            assert_eq!(o, back);
        }
    }

    #[test]
    fn malformed_json_missing_required_fields_is_rejected() {
        // Missing `wave_id`, `outcome`, etc. — serde rejects.
        let bad = "{}";
        let parsed: Result<WaveLearningRecord, _> = serde_json::from_str(bad);
        assert!(parsed.is_err());
    }

    #[test]
    fn invalid_outcome_variant_is_rejected() {
        let bad = r#"{"outcome":"Bogus"}"#;
        let parsed: Result<WaveOutcome, _> = serde_json::from_str(bad);
        assert!(parsed.is_err());
    }

    #[test]
    fn empty_wave_id_round_trips_but_is_distinguishable() {
        // Domain layer does not enforce non-empty wave_id — the adapter
        // that mints it is responsible. We assert the type *carries*
        // the empty string faithfully so downstream code can detect it.
        let mut r = populated_record();
        r.wave_id = WaveId::new("");
        let j = serde_json::to_string(&r).unwrap();
        let back: WaveLearningRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back.wave_id.as_str(), "");
    }

    #[test]
    fn build_from_closeout_derives_pass_when_no_failures() {
        let r = build_from_closeout(
            WaveId::new("w"),
            "internal-ref".into(),
            WaveDomain::Platform,
            "g".into(),
            AdversarialSessionId::new("a"),
            Some(PurpleTeamSessionId::new("p")),
            vec![],
            GateVerdictSummary::default(),
            vec![],
            vec![],
            vec![],
            cl_ok(),
            0,
            0,
        );
        assert_eq!(r.outcome, WaveOutcome::Pass);
    }

    #[test]
    fn build_from_closeout_derives_partial_on_findings() {
        let gv = GateVerdictSummary {
            findings: 1,
            ..GateVerdictSummary::default()
        };
        let r = build_from_closeout(
            WaveId::new("w"),
            "internal-ref".into(),
            WaveDomain::Platform,
            "g".into(),
            AdversarialSessionId::new("a"),
            None,
            vec![],
            gv,
            vec![],
            vec![],
            vec![],
            cl_ok(),
            0,
            0,
        );
        assert_eq!(r.outcome, WaveOutcome::Partial);
    }

    #[test]
    fn build_from_closeout_derives_fail_on_blocker() {
        let gv = GateVerdictSummary {
            blockers: 1,
            ..GateVerdictSummary::default()
        };
        let r = build_from_closeout(
            WaveId::new("w"),
            "internal-ref".into(),
            WaveDomain::Platform,
            "g".into(),
            AdversarialSessionId::new("a"),
            None,
            vec![],
            gv,
            vec![],
            vec![],
            vec![],
            cl_ok(),
            0,
            0,
        );
        assert_eq!(r.outcome, WaveOutcome::Fail);
    }

    #[test]
    fn build_from_closeout_derives_fail_on_constraint_violation() {
        let cl_bad = ConstraintLayerResult {
            accepted: false,
            constraints_checked: vec!["cdai.bounds".into()],
            constraints_violated: vec!["cdai.bounds".into()],
            note: "out of bounds".into(),
        };
        let r = build_from_closeout(
            WaveId::new("w"),
            "internal-ref".into(),
            WaveDomain::Platform,
            "g".into(),
            AdversarialSessionId::new("a"),
            None,
            vec![],
            GateVerdictSummary::default(),
            vec![],
            vec![],
            vec![],
            cl_bad,
            0,
            0,
        );
        assert_eq!(r.outcome, WaveOutcome::Fail);
    }

    #[test]
    fn gate_verdict_summary_default_is_all_zero() {
        let gv = GateVerdictSummary::default();
        assert_eq!(gv.passed, 0);
        assert_eq!(gv.findings, 0);
        assert_eq!(gv.blockers, 0);
        assert!(gv.gate_ids_fired.is_empty());
    }
}
