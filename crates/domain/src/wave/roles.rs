//! Wave-role enumeration and per-role tool allow-lists.
//!
//! Per. Each role in the wave pipeline has a scoped tool
//! allow-list. The dispatcher consults this allow-list before
//! granting any role's invocation, so a wrong-role call is a
//! dispatch-level reject rather than a runtime debug-only check.
//!
//! Allow-lists are `&'static [&'static str]` — fixed at compile time,
//! no global mutable state, boundary-safe.

use serde::{Deserialize, Serialize};

/// A role in the wave pipeline. Each variant maps 1:1 to one of the
/// six Manus skills (`/plan`, `/team`, `/test`, `/purple-team`,
/// `/user-acceptance`, `/closeout`) plus `/release`.
///
/// `PLANNER` and `DECOMPOSER` are kept distinct because the planner
/// produces the goal-level decomposition (`/plan`) while the
/// decomposer assigns roles to phases (`/team`). They are often the
/// same agent, but the tool surface differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms, non_camel_case_types)]
pub enum WaveRole {
    /// `/plan` — produces the goal decomposition.
    PLANNER,
    /// `/team` — assigns roles to phases.
    DECOMPOSER,
    /// Writes the actual code under the plan.
    DEVELOPER,
    /// `/test` — builds the adversarial fixture suite.
    TESTER,
    /// `/purple-team` — adversarial review.
    PURPLE_TEAMER,
    /// `/user-acceptance` — re-derives evidence vs the acceptance criteria.
    UAT_REVIEWER,
    /// `/closeout` + release commit composition.
    RELEASER,
}

impl WaveRole {
    /// Tool allow-list for this role. Returned as a static slice so
    /// the dispatcher can do `allow_list.contains(&tool_name)`
    /// without allocating.
    ///
    /// Tool names use the orchestrator capability namespace (`aara.*`) plus
    /// the existing MCP tool names. The lists are intentionally
    /// minimal — adding a new tool to a role's allow-list is a
    /// reviewable change.
    #[must_use]
    pub const fn tool_allow_list(self) -> &'static [&'static str] {
        match self {
            Self::PLANNER => &["aara.plan", "aara.read_doc", "aara.search_code"],
            Self::DECOMPOSER => &["aara.team_decompose", "aara.role_assign", "aara.read_doc"],
            Self::DEVELOPER => &[
                "aara.edit_file",
                "aara.write_file",
                "aara.run_cargo",
                "aara.run_pytest",
                "aara.search_code",
                "aara.read_doc",
            ],
            Self::TESTER => &[
                "aara.run_cargo_test",
                "aara.run_pytest",
                "aara.write_fixture",
                "aara.sign_adversarial_record",
            ],
            Self::PURPLE_TEAMER => &[
                "aara.threat_model",
                "aara.run_attack",
                "aara.read_doc",
                "aara.sign_purple_team_record",
            ],
            Self::UAT_REVIEWER => &[
                "aara.read_acceptance_criteria",
                "aara.rederive_evidence",
                "aara.sign_uat_record",
            ],
            Self::RELEASER => &[
                "aara.compose_release_commit",
                "aara.sign_closeout_record",
                "aara.run_release_gate",
            ],
        }
    }

    /// Every role, in pipeline order. Useful for iteration over the
    /// full ceremony.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::PLANNER,
            Self::DECOMPOSER,
            Self::DEVELOPER,
            Self::TESTER,
            Self::PURPLE_TEAMER,
            Self::UAT_REVIEWER,
            Self::RELEASER,
        ]
    }
}

/// Assignment of a [`WaveRole`] to a phase of the wave plan. Carries
/// the agent identifier (free-form string — could be a Linear user
/// id, an agent-runtime handle, etc.) so the wave-context audit
/// trail records who did what.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WaveRoleAssignment {
    /// The role being assigned.
    pub role: WaveRole,
    /// Free-form identifier of the agent (human or AI) holding this
    /// role for the wave. Not validated by the domain layer; the
    /// adapter that creates the assignment is responsible for the
    /// schema.
    pub agent_id: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn every_role_has_a_non_empty_allow_list() {
        for role in WaveRole::all() {
            assert!(
                !role.tool_allow_list().is_empty(),
                "role {role:?} has empty allow-list",
            );
        }
    }

    #[test]
    fn developer_can_edit_files() {
        let allow = WaveRole::DEVELOPER.tool_allow_list();
        assert!(allow.contains(&"aara.edit_file"));
    }

    #[test]
    fn uat_reviewer_cannot_edit_files() {
        let allow = WaveRole::UAT_REVIEWER.tool_allow_list();
        assert!(!allow.contains(&"aara.edit_file"));
    }

    #[test]
    fn releaser_owns_release_gate() {
        let allow = WaveRole::RELEASER.tool_allow_list();
        assert!(allow.contains(&"aara.run_release_gate"));
        // Only the releaser may sign closeout records.
        for role in WaveRole::all() {
            if *role != WaveRole::RELEASER {
                assert!(
                    !role
                        .tool_allow_list()
                        .contains(&"aara.sign_closeout_record"),
                    "role {role:?} should not have closeout-signing capability",
                );
            }
        }
    }

    #[test]
    fn assignment_roundtrips_through_json() {
        let a = WaveRoleAssignment {
            role: WaveRole::DEVELOPER,
            agent_id: "agent-42".to_string(),
        };
        let j = serde_json::to_string(&a).expect("serialize");
        let back: WaveRoleAssignment = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(a, back);
    }

    #[test]
    fn role_count_pinned_at_seven() {
        // Pins the role count so we cannot silently add a role
        // without updating callers.
        assert_eq!(WaveRole::all().len(), 7);
    }
}
