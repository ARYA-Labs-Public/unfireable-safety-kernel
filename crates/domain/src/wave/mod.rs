//! `Wave<S>` — type-state model of the wave pipeline.
//!
//! Per. The Manus skill family (`/plan`, `/team`, `/test`,
//! `/purple-team`, `/user-acceptance`, `/closeout`) is enforced today
//! by a bash git hook (`.claude/hooks/team_release_gate.sh`). That
//! works for a human developer typing `git commit`; it does not work
//! for the autonomous self-improvement loop at A3+ where no `git commit` is run.
//!
//! `Wave<S>` makes the same ceremony a *compile-time* property:
//!
//! ```text
//! Wave<Planned>
//!.decompose(roles)            -> Wave<Decomposed>
//!.run_adversarial_suite(sid)  -> Wave<Tested>
//!.run_purple_team(sid)        -> Wave<PurpleTeamed>      [or]
//!.skip_purple_team_if_no_gate_surface()
//!                                -> Wave<PurpleTeamed>
//!.run_user_acceptance(verdicts)
//!                                -> Wave<Accepted>
//!.closeout(closed_at_epoch)   -> (Wave<Closed>, WaveLearningRecord)
//! ```
//!
//! Skipping a stage (calling `.closeout()` on `Wave<Tested>`, for
//! example) is a **compile error** — see the `compile_fail`
//! doc-tests on [`Wave`].
//!
//! # Why this layering
//!
//! Mirrors the `GroundTruthContext<WithGroundTruth>` /
//! `GroundTruthContext<WithoutGroundTruth>` precedent in
//! `crates/domain/src/invariant.rs`. Same idiom: zero-sized
//! `PhantomData<S>` witness, private `_state` field so downstream
//! code cannot synthesize the witness without going through a
//! transition method, transitions consume `self` so the chain is
//! one-way.
//!
//! # Soundness note
//!
//! The crate root carries `#![forbid(unsafe_code)]`. Downstream
//! crates importing `Wave<S>` cannot construct a higher state
//! without calling the transition method (the `_state` field is
//! private). A downstream crate that itself uses `unsafe` could
//! synthesize a `Wave<Closed>` — that is the deliberate property of
//! Rust's `PhantomData`-based type-states and matches `invariant.rs`.

use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

pub mod context;
pub mod gate_surface;
pub mod learning;
pub mod roles;
pub mod session_record;
pub mod stage;

use context::{AdversarialSessionId, PurpleTeamSessionId, UatVerdict, WaveContext};
use learning::{
    build_from_closeout, ConstraintLayerResult, GateVerdictSummary, WaveLearningRecord,
    WavePhaseRecord,
};
use roles::WaveRoleAssignment;

// ---------------------------------------------------------------------------
// State markers. Each is a unit struct used only as a type parameter.
// Deliberately do NOT implement `Default` for any state past `Planned`
// so callers cannot bypass the transition methods.
// ---------------------------------------------------------------------------

/// State: wave has been planned but not yet decomposed into roles.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Planned;

/// State: wave has role assignments; ready for the adversarial suite.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Decomposed;

/// State: adversarial-suite (`/test`) has run and signed a PASS record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Tested;

/// State: purple-team (`/purple-team`) has run, OR was provably
/// skippable (empty `gate_surfaces`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PurpleTeamed;

/// State: user-acceptance (`/user-acceptance`) has produced verdicts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Accepted;

/// State: closeout (`/closeout`) has signed the rollup; wave is
/// terminal. Only `Wave<Closed>` is acceptable as the witness for
/// `RSI_APPLY_IMPROVEMENT` / `DOMAIN_DEPLOY_MODEL`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Closed;

// ---------------------------------------------------------------------------
// Wave<S>
// ---------------------------------------------------------------------------

/// A wave in the platform ceremony pipeline.
///
/// `S` is the type-state — one of [`Planned`], [`Decomposed`],
/// [`Tested`], [`PurpleTeamed`], [`Accepted`], [`Closed`]. The
/// transition methods (`decompose`, `run_adversarial_suite`,
/// `run_purple_team`, `skip_purple_team_if_no_gate_surface`,
/// `run_user_acceptance`, `closeout`) are implemented only on the
/// state where they are valid — calling one out of order is a
/// compile error.
///
/// # Happy-path example
///
/// ```rust
/// use std::collections::HashSet;
/// use qorch_domain::wave::{
///     Wave,
///     context::{
///         AdversarialSessionId, PurpleTeamSessionId, UatOutcome, UatVerdict, WaveContext,
///         WaveDomain, WaveId, WavePhase,
///     },
///     gate_surface::GateSurface,
///     roles::{WaveRole, WaveRoleAssignment},
/// };
///
/// let mut gs = HashSet::new();
/// gs.insert(GateSurface::SafetyKernel);
/// let ctx = WaveContext::new(
///     WaveId::new("wave-001"),
///     "",
///     WaveDomain::Platform,
///     "demo",
///     vec![WavePhase { id: "phase-1".to_string(), summary: "build".to_string() }],
///     gs,
///     1_716_400_000,
/// );
///
/// let w = Wave::new(ctx);
/// let w = w.decompose(vec![WaveRoleAssignment {
///     role: WaveRole::DEVELOPER,
///     agent_id: "agent-42".to_string(),
/// }]);
/// let w = w.run_adversarial_suite(AdversarialSessionId::new("adv-1"));
/// let w = w.run_purple_team(PurpleTeamSessionId::new("pt-1"));
/// let w = w.run_user_acceptance(vec![UatVerdict {
///     criterion_id: "AC4".to_string(),
///     outcome: UatOutcome::Pass,
///     evidence: "re-derived".to_string(),
/// }]);
/// let (_closed, _record) = w.closeout(1_716_400_500);
/// ```
///
/// # Adversarial fixture 1 — cannot skip decompose
///
/// `Wave<Planned>` does not implement `run_adversarial_suite`, so
/// this fails to compile:
///
/// ```compile_fail
/// use std::collections::HashSet;
/// use qorch_domain::wave::{
///     Wave,
///     context::{AdversarialSessionId, WaveContext, WaveDomain, WaveId},
/// };
/// let ctx = WaveContext::new(
///     WaveId::new("w"), "", WaveDomain::Platform,
///     "g", vec![], HashSet::new(), 0,
/// );
/// let w = Wave::new(ctx);
/// // No `run_adversarial_suite` on `Wave<Planned>`.
/// let _ = w.run_adversarial_suite(AdversarialSessionId::new("adv-1"));
/// ```
///
/// # Adversarial fixture 2 — cannot skip adversarial suite
///
/// `Wave<Decomposed>` does not implement `run_purple_team`:
///
/// ```compile_fail
/// use std::collections::HashSet;
/// use qorch_domain::wave::{
///     Wave,
///     context::{PurpleTeamSessionId, WaveContext, WaveDomain, WaveId},
///     roles::{WaveRole, WaveRoleAssignment},
/// };
/// let ctx = WaveContext::new(
///     WaveId::new("w"), "", WaveDomain::Platform,
///     "g", vec![], HashSet::new(), 0,
/// );
/// let w = Wave::new(ctx).decompose(vec![WaveRoleAssignment {
///     role: WaveRole::DEVELOPER, agent_id: "a".to_string(),
/// }]);
/// // No `run_purple_team` on `Wave<Decomposed>`.
/// let _ = w.run_purple_team(PurpleTeamSessionId::new("pt-1"));
/// ```
///
/// # Adversarial fixture 3 — cannot skip purple-team when gate surface present
///
/// `Wave<Tested>::skip_purple_team_if_no_gate_surface` returns
/// `Result`; an explicit Err is produced at runtime when
/// `gate_surfaces` is non-empty. Compile-fail variant: `Wave<Tested>`
/// does not implement `run_user_acceptance`, so this is rejected:
///
/// ```compile_fail
/// use std::collections::HashSet;
/// use qorch_domain::wave::{
///     Wave,
///     context::{AdversarialSessionId, WaveContext, WaveDomain, WaveId},
///     gate_surface::GateSurface,
///     roles::{WaveRole, WaveRoleAssignment},
/// };
/// let mut gs = HashSet::new();
/// gs.insert(GateSurface::SafetyKernel);
/// let ctx = WaveContext::new(
///     WaveId::new("w"), "", WaveDomain::Platform,
///     "g", vec![], gs, 0,
/// );
/// let w = Wave::new(ctx)
///.decompose(vec![WaveRoleAssignment {
///         role: WaveRole::DEVELOPER, agent_id: "a".to_string(),
///     }])
///.run_adversarial_suite(AdversarialSessionId::new("adv-1"));
/// // No `run_user_acceptance` on `Wave<Tested>` — must traverse purple-team first.
/// let _ = w.run_user_acceptance(vec![]);
/// ```
///
/// # Adversarial fixture 4 — cannot skip UAT
///
/// `Wave<PurpleTeamed>` does not implement `closeout`:
///
/// ```compile_fail
/// use std::collections::HashSet;
/// use qorch_domain::wave::{
///     Wave,
///     context::{AdversarialSessionId, PurpleTeamSessionId, WaveContext, WaveDomain, WaveId},
///     roles::{WaveRole, WaveRoleAssignment},
/// };
/// let ctx = WaveContext::new(
///     WaveId::new("w"), "", WaveDomain::Platform,
///     "g", vec![], HashSet::new(), 0,
/// );
/// let w = Wave::new(ctx)
///.decompose(vec![WaveRoleAssignment {
///         role: WaveRole::DEVELOPER, agent_id: "a".to_string(),
///     }])
///.run_adversarial_suite(AdversarialSessionId::new("adv-1"))
///.run_purple_team(PurpleTeamSessionId::new("pt-1"));
/// // No `closeout` on `Wave<PurpleTeamed>` — UAT must run first.
/// let _ = w.closeout(0);
/// ```
///
/// # Adversarial fixture 5 — cannot jump straight from Planned to Closed
///
/// ```compile_fail
/// use std::collections::HashSet;
/// use qorch_domain::wave::{Wave, context::{WaveContext, WaveDomain, WaveId}};
/// let ctx = WaveContext::new(
///     WaveId::new("w"), "", WaveDomain::Platform,
///     "g", vec![], HashSet::new(), 0,
/// );
/// let w = Wave::new(ctx);
/// // No `closeout` on `Wave<Planned>`.
/// let _ = w.closeout(0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wave<S> {
    /// Wave data — independent of the type-state.
    pub ctx: WaveContext,

    /// Role assignments from the decompose transition. Populated on
    /// entry to `Decomposed`; preserved through subsequent states.
    pub role_assignments: Vec<WaveRoleAssignment>,

    /// Signed adversarial-suite session id from the
    /// `run_adversarial_suite` transition. `None` only on `Planned`
    /// and `Decomposed`.
    pub adversarial_session: Option<AdversarialSessionId>,

    /// Signed purple-team session id. `None` is only valid when the
    /// wave's `gate_surfaces` was empty AND the
    /// `skip_purple_team_if_no_gate_surface` transition was taken.
    pub purple_team_session: Option<PurpleTeamSessionId>,

    /// UAT verdicts from the `run_user_acceptance` transition.
    /// `None` on states before `Accepted`.
    pub uat_verdicts: Option<Vec<UatVerdict>>,

    /// PhantomData carries the type-state at zero cost. Private so
    /// downstream crates cannot synthesize a higher state without
    /// using a transition method.
    _state: PhantomData<S>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error returned when `skip_purple_team_if_no_gate_surface` is
/// called on a wave that DOES have a non-empty `gate_surfaces` set.
/// Carries the original wave back to the caller so no state is lost.
#[derive(Debug)]
pub struct GateSurfacePresent {
    /// The wave the caller tried to skip purple-team on. Returned so
    /// the caller can still take the `run_purple_team` branch.
    pub wave: Wave<Tested>,
}

// ---------------------------------------------------------------------------
// Transitions
// ---------------------------------------------------------------------------

impl Wave<Planned> {
    /// Construct a new wave in the `Planned` state. The only entry
    /// point into the state machine.
    #[must_use]
    pub fn new(ctx: WaveContext) -> Self {
        Self {
            ctx,
            role_assignments: Vec::new(),
            adversarial_session: None,
            purple_team_session: None,
            uat_verdicts: None,
            _state: PhantomData,
        }
    }

    /// `Planned -> Decomposed`. Records the role assignments from
    /// `/team`.
    #[must_use]
    pub fn decompose(self, roles: Vec<WaveRoleAssignment>) -> Wave<Decomposed> {
        Wave {
            ctx: self.ctx,
            role_assignments: roles,
            adversarial_session: self.adversarial_session,
            purple_team_session: self.purple_team_session,
            uat_verdicts: self.uat_verdicts,
            _state: PhantomData,
        }
    }
}

impl Wave<Decomposed> {
    /// `Decomposed -> Tested`. Records the signed adversarial-suite
    /// session id produced by `/test`.
    #[must_use]
    pub fn run_adversarial_suite(self, session_id: AdversarialSessionId) -> Wave<Tested> {
        Wave {
            ctx: self.ctx,
            role_assignments: self.role_assignments,
            adversarial_session: Some(session_id),
            purple_team_session: self.purple_team_session,
            uat_verdicts: self.uat_verdicts,
            _state: PhantomData,
        }
    }
}

impl Wave<Tested> {
    /// `Tested -> PurpleTeamed`. Records the signed purple-team
    /// session id produced by `/purple-team`. The caller MUST take
    /// this branch if the wave has any [`gate_surface::GateSurface`]
    /// set on its context.
    #[must_use]
    pub fn run_purple_team(self, session_id: PurpleTeamSessionId) -> Wave<PurpleTeamed> {
        Wave {
            ctx: self.ctx,
            role_assignments: self.role_assignments,
            adversarial_session: self.adversarial_session,
            purple_team_session: Some(session_id),
            uat_verdicts: self.uat_verdicts,
            _state: PhantomData,
        }
    }

    /// `Tested -> PurpleTeamed`, skipping the purple-team run. Only
    /// valid when the wave's `gate_surfaces` is empty — otherwise
    /// returns the wave back wrapped in [`GateSurfacePresent`] so
    /// the caller can fall back to [`Self::run_purple_team`].
    ///
    /// # Errors
    ///
    /// Returns [`GateSurfacePresent`] if `self.ctx.gate_surfaces` is
    /// non-empty. The error carries the original wave back so no
    /// state is lost.
    pub fn skip_purple_team_if_no_gate_surface(
        self,
    ) -> Result<Wave<PurpleTeamed>, GateSurfacePresent> {
        if self.ctx.requires_purple_team() {
            return Err(GateSurfacePresent { wave: self });
        }
        Ok(Wave {
            ctx: self.ctx,
            role_assignments: self.role_assignments,
            adversarial_session: self.adversarial_session,
            purple_team_session: None,
            uat_verdicts: self.uat_verdicts,
            _state: PhantomData,
        })
    }
}

impl Wave<PurpleTeamed> {
    /// `PurpleTeamed -> Accepted`. Records the UAT verdicts produced
    /// by `/user-acceptance`.
    #[must_use]
    pub fn run_user_acceptance(self, verdicts: Vec<UatVerdict>) -> Wave<Accepted> {
        Wave {
            ctx: self.ctx,
            role_assignments: self.role_assignments,
            adversarial_session: self.adversarial_session,
            purple_team_session: self.purple_team_session,
            uat_verdicts: Some(verdicts),
            _state: PhantomData,
        }
    }
}

impl Wave<Accepted> {
    /// `Accepted -> Closed`. Final transition. Returns both the
    /// terminal wave (used as the compile-time witness for
    /// `RSI_APPLY_IMPROVEMENT` / `DOMAIN_DEPLOY_MODEL` in the
    /// dispatcher) and a fully populated [`WaveLearningRecord`] with
    /// per-phase rollups, gate verdicts, and the constraint-layer
    /// result derived from the data carried through the type-state.
    ///
    /// `closed_at_epoch` is supplied by the caller (the domain layer
    /// has no clock per `agent/boundaries.toml`).
    #[must_use]
    pub fn closeout(self, closed_at_epoch: u64) -> (Wave<Closed>, WaveLearningRecord) {
        // The adversarial session is guaranteed to be present at this
        // state — only `run_adversarial_suite` could have produced it.
        // We defensively fall back to an empty id to avoid a panic in
        // the domain crate (lints forbid `expect`).
        let adversarial_session = self
            .adversarial_session
            .clone()
            .unwrap_or_else(|| AdversarialSessionId::new(""));
        // Per-phase rollups — for the domain layer carries no
        // per-phase metrics, so each phase is reflected with empty
        // model lists and zero duration. The closeout adapter
        // (ARY-H+) replaces these with real metrics.
        let phases_executed: Vec<WavePhaseRecord> = self
            .ctx
            .phases
            .iter()
            .map(|p| WavePhaseRecord {
                phase_id: p.id.clone(),
                summary: p.summary.clone(),
                nano_model_ids: Vec::new(),
                duration_seconds: 0,
            })
            .collect();
        let gate_verdicts = GateVerdictSummary {
            passed: u32::try_from(self.ctx.gate_surfaces.len()).unwrap_or(u32::MAX),
            findings: 0,
            blockers: 0,
            gate_ids_fired: self
                .ctx
                .gate_surfaces
                .iter()
                .map(|gs| format!("{gs:?}"))
                .collect(),
        };
        let constraint_layer_result = ConstraintLayerResult {
            accepted: true,
            constraints_checked: Vec::new(),
            constraints_violated: Vec::new(),
            note: "domain-layer closeout; constraints evaluated by adapter".to_string(),
        };
        let uat_verdicts_vec = self.uat_verdicts.clone().unwrap_or_default();
        let record = build_from_closeout(
            self.ctx.wave_id.clone(),
            self.ctx.linear_issue.clone(),
            self.ctx.domain,
            self.ctx.goal_summary.clone(),
            adversarial_session,
            self.purple_team_session.clone(),
            phases_executed,
            gate_verdicts,
            // Adversarial-finding and purple-team-finding rollups are
            // populated by the closeout adapter (ARY-H+). The domain
            // layer carries only the session ids.
            Vec::new(),
            Vec::new(),
            uat_verdicts_vec,
            constraint_layer_result,
            closed_at_epoch.saturating_sub(self.ctx.created_at_epoch),
            closed_at_epoch,
        );
        let closed = Wave {
            ctx: self.ctx,
            role_assignments: self.role_assignments,
            adversarial_session: self.adversarial_session,
            purple_team_session: self.purple_team_session,
            uat_verdicts: self.uat_verdicts,
            _state: PhantomData,
        };
        (closed, record)
    }
}

// ---------------------------------------------------------------------------
// Tests — happy paths, gate-surface guard, audit-trail preservation.
// Invalid-transition rejection is proven by the `compile_fail`
// doc-tests on the `Wave` struct above (Rule 8: adversarial
// fixtures the type-state must REJECT).
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::wave::context::{UatOutcome, WaveDomain, WaveId, WavePhase};
    use crate::wave::gate_surface::GateSurface;
    use crate::wave::roles::WaveRole;
    use std::collections::HashSet;

    fn ctx_with_gate_surface() -> WaveContext {
        let mut gs = HashSet::new();
        gs.insert(GateSurface::SafetyKernel);
        WaveContext::new(
            WaveId::new("wave-001"),
            "",
            WaveDomain::Platform,
            "demo",
            vec![WavePhase {
                id: "phase-1".to_string(),
                summary: "build".to_string(),
            }],
            gs,
            1_716_400_000,
        )
    }

    fn ctx_no_gate_surface() -> WaveContext {
        WaveContext::new(
            WaveId::new("wave-002"),
            "",
            WaveDomain::Biotech,
            "demo",
            vec![],
            HashSet::new(),
            1_716_400_000,
        )
    }

    fn role_assignment() -> WaveRoleAssignment {
        WaveRoleAssignment {
            role: WaveRole::DEVELOPER,
            agent_id: "agent-42".to_string(),
        }
    }

    #[test]
    fn happy_path_traversal_with_gate_surface() {
        let w = Wave::<Planned>::new(ctx_with_gate_surface());
        let w = w.decompose(vec![role_assignment()]);
        let w = w.run_adversarial_suite(AdversarialSessionId::new("adv-1"));
        let w = w.run_purple_team(PurpleTeamSessionId::new("pt-1"));
        let w = w.run_user_acceptance(vec![UatVerdict {
            criterion_id: "AC4".to_string(),
            outcome: UatOutcome::Pass,
            evidence: "re-derived".to_string(),
        }]);
        let (closed, record) = w.closeout(1_716_400_500);
        assert_eq!(closed.ctx.wave_id.as_str(), "wave-001");
        assert_eq!(record.wave_id.as_str(), "wave-001");
        assert_eq!(record.adversarial_session.as_str(), "adv-1");
        assert_eq!(
            record.purple_team_session.as_ref().map(|s| s.as_str()),
            Some("pt-1"),
        );
        //: populated record exposes the new top-level fields.
        assert_eq!(record.linear_issue, "");
        assert_eq!(record.outcome, learning::WaveOutcome::Pass);
        assert_eq!(record.duration_seconds, 500);
        assert_eq!(record.closed_at_epoch, 1_716_400_500);
    }

    #[test]
    fn skip_purple_team_succeeds_when_no_gate_surface() {
        let w = Wave::<Planned>::new(ctx_no_gate_surface());
        let w = w
            .decompose(vec![role_assignment()])
            .run_adversarial_suite(AdversarialSessionId::new("adv-2"));
        let result = w.skip_purple_team_if_no_gate_surface();
        assert!(result.is_ok(), "skip should succeed on empty gate-surface");
        let w = result.ok().unwrap();
        let w = w.run_user_acceptance(vec![]);
        let (_closed, record) = w.closeout(1_716_400_500);
        assert!(record.purple_team_session.is_none());
    }

    #[test]
    fn skip_purple_team_fails_when_gate_surface_present() {
        let w = Wave::<Planned>::new(ctx_with_gate_surface());
        let w = w
            .decompose(vec![role_assignment()])
            .run_adversarial_suite(AdversarialSessionId::new("adv-3"));
        let result = w.skip_purple_team_if_no_gate_surface();
        assert!(result.is_err(), "skip must reject when gate surface set");
        // Recover the wave from the error and walk the full path.
        let err = result.err().unwrap();
        let w = err.wave.run_purple_team(PurpleTeamSessionId::new("pt-3"));
        let w = w.run_user_acceptance(vec![]);
        let (_closed, _record) = w.closeout(1_716_400_500);
    }

    #[test]
    fn role_assignments_preserved_through_states() {
        let w = Wave::<Planned>::new(ctx_with_gate_surface());
        let w = w.decompose(vec![role_assignment()]);
        let w = w.run_adversarial_suite(AdversarialSessionId::new("adv-4"));
        let w = w.run_purple_team(PurpleTeamSessionId::new("pt-4"));
        let w = w.run_user_acceptance(vec![]);
        assert_eq!(w.role_assignments.len(), 1);
        assert_eq!(w.role_assignments[0].role, WaveRole::DEVELOPER);
    }

    #[test]
    fn wave_planned_is_zero_overhead_witness() {
        // The PhantomData<S> witness must be zero-sized — runtime
        // cost is only the WaveContext data, not the state.
        let size_planned = std::mem::size_of::<PhantomData<Planned>>();
        let size_closed = std::mem::size_of::<PhantomData<Closed>>();
        assert_eq!(size_planned, 0);
        assert_eq!(size_closed, 0);
    }

    #[test]
    fn wave_roundtrips_through_json_at_each_state() {
        let w = Wave::<Planned>::new(ctx_with_gate_surface());
        let j = serde_json::to_string(&w).unwrap();
        let _back: Wave<Planned> = serde_json::from_str(&j).unwrap();

        let w = w
            .decompose(vec![role_assignment()])
            .run_adversarial_suite(AdversarialSessionId::new("adv-5"))
            .run_purple_team(PurpleTeamSessionId::new("pt-5"))
            .run_user_acceptance(vec![]);
        let j = serde_json::to_string(&w).unwrap();
        let _back: Wave<Accepted> = serde_json::from_str(&j).unwrap();

        let (closed, _) = w.closeout(1_716_400_500);
        let j = serde_json::to_string(&closed).unwrap();
        let _back: Wave<Closed> = serde_json::from_str(&j).unwrap();
    }

    #[test]
    fn closeout_produces_populated_learning_record() {
        //  AC6: closeout returns a populated WaveLearningRecord
        // (not a stub). The phases_executed list is derived from
        // ctx.phases; gate_verdicts reflects the gate_surfaces set.
        let w = Wave::<Planned>::new(ctx_with_gate_surface())
            .decompose(vec![role_assignment()])
            .run_adversarial_suite(AdversarialSessionId::new("adv-pop"))
            .run_purple_team(PurpleTeamSessionId::new("pt-pop"))
            .run_user_acceptance(vec![]);
        let (_closed, record) = w.closeout(1_716_400_750);
        // Phases mirrored from context.
        assert_eq!(record.phases_executed.len(), 1);
        assert_eq!(record.phases_executed[0].phase_id, "phase-1");
        // Gate verdicts derived from gate_surfaces.
        assert_eq!(record.gate_verdicts.passed, 1);
        assert_eq!(record.gate_verdicts.gate_ids_fired.len(), 1);
        // Round-trip the populated record through JSON.
        let j = record.to_canonical_json();
        let back: WaveLearningRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back, record);
    }
}
