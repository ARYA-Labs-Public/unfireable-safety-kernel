//! Wave context — goal, phases, domain, gate surfaces, timestamps.
//!
//! Per. `WaveContext` is the data carried alongside the
//! type-state witness in `Wave<S>`. It is plain data — no behaviour
//! beyond constructors and accessors. State transitions are handled
//! by the [`super::Wave`] generic.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use super::gate_surface::GateSurface;

/// Stable identifier for a wave. Wrapped to keep wave-ids from being
/// confused with arbitrary strings at the call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WaveId(pub String);

impl WaveId {
    /// Wrap a raw string as a `WaveId`. The domain layer does not
    /// validate the schema — the adapter that mints the id is
    /// responsible.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the wrapped string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable identifier for an adversarial-suite session (from `/test`).
/// Wrapped so it cannot be confused with a purple-team or uat
/// session id at the type level.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AdversarialSessionId(pub String);

impl AdversarialSessionId {
    /// Wrap a raw string.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the wrapped string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable identifier for a purple-team session (from `/purple-team`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PurpleTeamSessionId(pub String);

impl PurpleTeamSessionId {
    /// Wrap a raw string.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the wrapped string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A single user-acceptance verdict — one row per acceptance criterion.
///
/// The domain layer carries only the verdict shape; evidence
/// re-derivation lives in the UAT skill (adapter layer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UatVerdict {
    /// Acceptance-criterion identifier (e.g. `"AC4"`).
    pub criterion_id: String,
    /// Outcome of the re-derivation.
    pub outcome: UatOutcome,
    /// Free-form evidence note (hash, replay output snippet, etc.).
    pub evidence: String,
}

/// Verdict for a single acceptance criterion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UatOutcome {
    /// Evidence re-derived; matches expectation.
    Pass,
    /// Evidence re-derived; does not match expectation.
    Fail,
    /// Partial match; explicit waiver required.
    Partial,
    /// Not attempted in this UAT session.
    NotTested,
}

/// The high-level domain a wave belongs to. Used by the dispatcher
/// to pick the right gate-surface defaults and the right tool
/// allow-lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WaveDomain {
    /// Biotech / pharma / life-sciences workloads.
    Biotech,
    /// Telco / SYNAPSE / SON / channel intent.
    Telco,
    /// Oil & gas.
    OilGas,
    /// Pharmaceutical manufacturing.
    PharmaManufacturing,
    /// Defense.
    Defense,
    /// Regulatory / FDA.
    Regulatory,
    /// Drug efficacy.
    DrugEfficacy,
    /// Infrastructure / platform — wave is not domain-specific (e.g.
    /// safety-kernel, dispatcher, MCP bridge changes).
    Platform,
}

/// One phase of a wave plan. A wave is a sequence of phases; each
/// phase has a description and a role responsible for executing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WavePhase {
    /// Short identifier (e.g. `"phase-1-build"`).
    pub id: String,
    /// One-line summary.
    pub summary: String,
}

/// The data side of a wave — independent of the type-state.
///
/// The `gate_surfaces` set may be populated explicitly by the
/// planner or computed from file paths via
/// [`super::gate_surface::detect_gate_surfaces`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WaveContext {
    /// Stable wave identifier.
    pub wave_id: WaveId,
    /// Originating Linear issue (e.g. `""`).
    pub linear_issue: String,
    /// Domain this wave belongs to.
    pub domain: WaveDomain,
    /// One-paragraph goal summary, as written by the planner.
    pub goal_summary: String,
    /// Ordered phases of the wave plan.
    pub phases: Vec<WavePhase>,
    /// Set of gate surfaces this wave touches. A non-empty set forces
    /// the wave through the purple-team transition; an empty set
    /// allows [`super::Wave::skip_purple_team_if_no_gate_surface`].
    pub gate_surfaces: HashSet<GateSurface>,
    /// Creation timestamp (seconds since UNIX epoch). The domain
    /// layer does not read the clock — the adapter that creates the
    /// context supplies this.
    pub created_at_epoch: u64,
}

impl WaveContext {
    /// Construct a `WaveContext`. All fields are passed explicitly —
    /// the domain layer has no clock and no env access.
    #[must_use]
    pub fn new(
        wave_id: WaveId,
        linear_issue: impl Into<String>,
        domain: WaveDomain,
        goal_summary: impl Into<String>,
        phases: Vec<WavePhase>,
        gate_surfaces: HashSet<GateSurface>,
        created_at_epoch: u64,
    ) -> Self {
        Self {
            wave_id,
            linear_issue: linear_issue.into(),
            domain,
            goal_summary: goal_summary.into(),
            phases,
            gate_surfaces,
            created_at_epoch,
        }
    }

    /// True iff this wave touches a gate surface (and therefore MUST
    /// go through the purple-team transition).
    #[must_use]
    pub fn requires_purple_team(&self) -> bool {
        !self.gate_surfaces.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn fixture() -> WaveContext {
        let mut gs = HashSet::new();
        gs.insert(GateSurface::SafetyKernel);
        WaveContext::new(
            WaveId::new("wave-001"),
            "",
            WaveDomain::Platform,
            "type-state wave model",
            vec![WavePhase {
                id: "phase-1".to_string(),
                summary: "build".to_string(),
            }],
            gs,
            1_716_400_000,
        )
    }

    #[test]
    fn requires_purple_team_when_gate_surface_present() {
        let ctx = fixture();
        assert!(ctx.requires_purple_team());
    }

    #[test]
    fn does_not_require_purple_team_when_empty() {
        let mut ctx = fixture();
        ctx.gate_surfaces.clear();
        assert!(!ctx.requires_purple_team());
    }

    #[test]
    fn context_roundtrips_through_json() {
        let ctx = fixture();
        let j = serde_json::to_string(&ctx).expect("serialize");
        let back: WaveContext = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(ctx, back);
    }

    #[test]
    fn wrapped_id_types_distinguish_at_compile_time() {
        let a = AdversarialSessionId::new("adv-1");
        let p = PurpleTeamSessionId::new("pt-1");
        // Both wrap String but are distinct nominal types — this
        // assertion exists so the compiler proves the wrapping is
        // not optimized away.
        assert_eq!(a.as_str(), "adv-1");
        assert_eq!(p.as_str(), "pt-1");
    }

    #[test]
    fn uat_verdict_roundtrips() {
        let v = UatVerdict {
            criterion_id: "AC4".to_string(),
            outcome: UatOutcome::Pass,
            evidence: "re-ran cargo test, hash matches".to_string(),
        };
        let j = serde_json::to_string(&v).expect("serialize");
        let back: UatVerdict = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(v, back);
    }
}
