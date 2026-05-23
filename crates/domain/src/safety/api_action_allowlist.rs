//! API-role action allowlist — port of
//! `packages/core/safety_kernel_routes.py::is_api_action_allowed`.
//!
//! Single source of truth for which `api`-caller-role actions the
//! Safety Kernel will mint authorize tokens for. Used by the HTTP
//! handler in step 4.2(2) (ADR-014 Slice 1 §4.2): when
//! `caller_role == "api"`, deny with `api_action_forbidden` if the
//! action is not in the allowlist.
//!
//! The action format is `METHOD:/path` (e.g. `POST:/api/v1/chat`); we
//! extract the path portion and prefix-match against the const list.
//! Equivalence harness (W3) MUST cover both allowed and disallowed
//! actions per ADR-014 Slice 1 §10 inconsistency note 5.
//!
//! **Last upstream sync**: `safety_kernel_routes.py` 2026-04-02 (the
//! "Last Updated" tag in the Python source). Any addition to the
//! Python list MUST be ported here in the same PR; CI parity check
//! lands with W3.

/// Prefix list — any action whose path component starts with one of
/// these strings is allowed for the `api` caller role. Mirrored from
/// `packages/core/safety_kernel_routes.py::API_ALLOWED_PREFIXES`.
pub const API_ALLOWED_PREFIXES: &[&str] = &[
    // AARA engine (single entry point)
    "/api/v1/aara-engine/",
    "/api/v1/aara/",
    "/api/v1/aara-orchestrator/",
    // Core capabilities
    "/api/v1/runs/",
    "/api/v1/experiments/",
    "/api/v1/compute/",
    "/api/v1/artifacts/",
    "/api/v1/analysis/",
    "/api/v1/context/",
    "/api/v1/data/",
    "/api/v1/nano/",
    "/api/v1/agents/",
    "/api/v1/domains/",
    "/api/v1/connectors/",
    "/api/v1/planner/",
    "/api/v1/workflows/",
    "/api/v1/chat/",
    "/api/v1/chat",
    "/api/v1/training/",
    "/api/v1/inference/",
    "/api/v1/queue/",
    "/api/v1/stream/",
    "/api/v1/ingest/",
    "/api/v1/ingest", // exact-path variant — POST /api/v1/ingest (no trailing slash)
    // Governance, compliance, safety
    "/api/v1/governance/",
    "/api/v1/compliance/",
    "/api/v1/safety/",
    "/api/v1/autonomous/",
    // RSI / improvement
    "/api/v1/rsi/",
    "/api/v1/hypothesis-evolution/",
    "/api/v1/problem-discovery/",
    // Knowledge and world model
    "/api/v1/world-model/",
    "/api/v1/semantic-kb/",
    "/api/v1/knowledge-base/",
    // Solvers
    "/api/v1/solvers/",
    "/api/v1/solvers",
    // Integrations and tools
    "/api/v1/integrations/",
    "/api/v1/code-tools/",
    "/api/v1/tool-discovery/",
    // Autonomy, HITL, graduation
    "/api/v1/autonomy/",
    "/api/v1/hitl/",
    "/api/v1/graduation/",
    // Auth and preferences (POST for login/token refresh)
    "/api/v1/auth/",
    "/api/v1/preferences/",
    // UI
    "/api/v1/ui-rsi/",
    // Telco vertical
    "/api/v1/telco/",
    // Vertical demos (built on demand; will move to runtime registration — see followup ticket)
    "/api/v1/panasonic/",        // Panasonic vertical
    "/api/v1/qcad/",             // D-Wave / quantum_computing (ARY-2063)
    "/api/v1/pulse/",            // D-Wave / quantum_computing (ARY-2063)
    "/api/v1/qec/",              // D-Wave / quantum_computing (ARY-2063)
    "/api/v1/wps/",              // Empulser / wireless_power_systems (ARY-2078)
    // Metrics and system
    "/api/v1/metrics/",
    "/api/v1/system/",
    "/api/v1/emergency/",
    // MCP (both API-prefixed and direct mount)
    "/api/v1/mcp/",
    "/mcp/",
    // AARA engine direct mount
    "/aara-engine/",
    // Demo builder REST endpoints and jobs
    "/api/v1/demo/",
    "/api/v1/demo_builder/",
    "/api/v1/jobs/",
    // GitHub integration
    "/api/v1/github/",
    // OAuth
    "/api/v1/oauth/",
    // Health (POST variants)
    "/api/v1/health",
    "/health",
    // Artifact governance (original allowlist)
    "artifact_promote",
    "artifact_rollback",
    "artifact_set_canary",
];

/// Checks whether an `api`-role action is in the allowlist.
///
/// The action string format is `METHOD:/path` (e.g. `POST:/api/v1/chat`).
/// We split on the first `:` and prefix-match the path portion. If no
/// colon is present, the whole string is treated as the path (matches
/// Python's behavior for the `artifact_*` short codes).
#[must_use]
pub fn is_api_action_allowed(action: &str) -> bool {
    let path = action.split_once(':').map_or(action, |(_, rest)| rest);
    let path = path.trim();
    API_ALLOWED_PREFIXES.iter().any(|p| path.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_aara_engine_post() {
        assert!(is_api_action_allowed("POST:/api/v1/aara-engine/invoke"));
    }

    #[test]
    fn allows_chat_exact_path_variant() {
        assert!(is_api_action_allowed("POST:/api/v1/chat"));
        assert!(is_api_action_allowed("POST:/api/v1/chat/sessions"));
    }

    #[test]
    fn allows_artifact_promote_no_method() {
        assert!(is_api_action_allowed("artifact_promote"));
    }

    #[test]
    fn rejects_unknown_path() {
        assert!(!is_api_action_allowed("POST:/api/v1/admin/dangerous"));
    }

    #[test]
    fn rejects_empty_action() {
        assert!(!is_api_action_allowed(""));
    }

    #[test]
    fn handles_action_without_colon() {
        // Treats the whole string as the path; "/health" matches.
        assert!(is_api_action_allowed("/health"));
    }
}
