//! Wave-pipeline stage enum + session-outcome.
//!
//!. A complementary surface to `Wave<S>` from
//! [`super::Wave`]: where `Wave<S>` is the *compile-time* witness that
//! drives the type-state of an in-flight wave, `WaveStage` is the
//! *wire-shape* tag the transparency-log persists per session record.
//! They must agree on the set of stages — the [`From`] impls below
//! pin the mapping at compile time.
//!
//! The transparency-log stores one [`WaveSessionRecord`] per (wave,
//! stage, session_id) tuple. A wave is "complete" only when records
//! exist for [`WaveStage::Tested`], [`WaveStage::Accepted`], and
//! [`WaveStage::Closed`] (plus [`WaveStage::PurpleTeamed`] if the wave
//! touched any gate surface).
//!
//! [`WaveSessionRecord`]: super::session_record::WaveSessionRecord

use serde::{Deserialize, Serialize};

/// Stage of the wave ceremony pipeline this session record attests to.
///
/// Ordering of variants is the canonical pipeline order — Planned →
/// Decomposed → Tested → PurpleTeamed → Accepted → Closed — so the
/// derived [`PartialOrd`]/[`Ord`] sort agrees with chronological order
/// for the verify-route response.
///
/// Wire form is `SCREAMING_SNAKE_CASE` so log scrapers and the Python
/// shadow library land on the same string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WaveStage {
    /// `/plan` produced a wave context but no role assignments yet.
    Planned,
    /// `/team` decomposed the wave into role assignments.
    Decomposed,
    /// `/test` ran the adversarial suite and signed a PASS record.
    Tested,
    /// `/purple-team` ran (mandatory when the wave touches a gate
    /// surface; otherwise skippable).
    PurpleTeamed,
    /// `/user-acceptance` re-derived per-AC evidence and produced
    /// verdicts.
    Accepted,
    /// `/closeout` signed the final rollup; the wave is terminal.
    Closed,
}

impl WaveStage {
    /// All variants, in canonical pipeline order. Stable across
    /// versions; new stages must be appended (never inserted) so the
    /// derived [`Ord`] keeps existing records sorting correctly.
    #[must_use]
    pub const fn all() -> &'static [WaveStage; 6] {
        &[
            WaveStage::Planned,
            WaveStage::Decomposed,
            WaveStage::Tested,
            WaveStage::PurpleTeamed,
            WaveStage::Accepted,
            WaveStage::Closed,
        ]
    }

    /// Stages that MUST be present in a complete wave regardless of
    /// gate-surface set. (`PurpleTeamed` is conditional and handled
    /// separately in
    /// [`super::session_record::all_required_stages_present`].)
    #[must_use]
    pub const fn unconditionally_required() -> &'static [WaveStage; 3] {
        &[WaveStage::Tested, WaveStage::Accepted, WaveStage::Closed]
    }
}

/// Per-session outcome attested by the writing skill.
///
/// A non-`Pass` outcome is still persisted — the ledger records the
/// fact that the stage ran. The closeout/gate decision is left to the
/// reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WaveOutcome {
    /// Stage completed and all gates green.
    Pass,
    /// Stage completed but at least one gate red.
    Fail,
    /// Stage completed with a known-and-waivered partial result.
    Partial,
    /// Stage was started but did not complete (process crash, timeout,
    /// etc.). Distinguishes a missing record (stage never ran) from
    /// a recorded incomplete run.
    NotTested,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn wire_form_is_screaming_snake_case() {
        let j = serde_json::to_string(&WaveStage::PurpleTeamed).unwrap();
        assert_eq!(j, "\"PURPLE_TEAMED\"");
        let j = serde_json::to_string(&WaveStage::Tested).unwrap();
        assert_eq!(j, "\"TESTED\"");
    }

    #[test]
    fn outcome_wire_form_is_screaming_snake_case() {
        let j = serde_json::to_string(&WaveOutcome::NotTested).unwrap();
        assert_eq!(j, "\"NOT_TESTED\"");
    }

    #[test]
    fn canonical_order_is_pipeline_order() {
        let mut stages = WaveStage::all().to_vec();
        stages.sort();
        assert_eq!(
            stages,
            vec![
                WaveStage::Planned,
                WaveStage::Decomposed,
                WaveStage::Tested,
                WaveStage::PurpleTeamed,
                WaveStage::Accepted,
                WaveStage::Closed,
            ]
        );
    }

    #[test]
    fn unknown_stage_string_rejected() {
        // Rule 8 adversarial fixture — a wire payload with a stage
        // outside the enum must fail to deserialize.
        let r: Result<WaveStage, _> = serde_json::from_str("\"FROBNICATED\"");
        assert!(r.is_err(), "unknown stage must be rejected");
    }
}
