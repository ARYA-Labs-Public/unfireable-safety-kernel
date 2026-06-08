//! API-role action allowlist — port of
//! `packages/core/safety_kernel_routes.py::is_api_action_allowed`.
//!
//! Single source of truth for which `api`-caller-role actions the
//! Safety Kernel will mint authorize tokens for. Used by the HTTP
//! handler in step 4.2(2) (): when
//! `caller_role == "api"`, deny with `api_action_forbidden` if the
//! action is not in the allowlist.
//!
//! The action format is `METHOD:/path` (e.g. `POST:/api/v1/chat`); we
//! extract the path portion and prefix-match against the const list.
//! Equivalence harness (W3) MUST cover both allowed and disallowed
//! actions
//!
//! **Last upstream sync**: `safety_kernel_routes.py` 2026-04-02 (the
//! "Last Updated" tag in the Python source). Any addition to the
//! Python list MUST be ported here in the same PR; CI parity check
//! lands with W3.

/// Prefix list — any action whose path component starts with one of
/// these strings is allowed for the `api` caller role. Mirrored from
/// `packages/core/safety_kernel_routes.py::API_ALLOWED_PREFIXES`.
pub const API_ALLOWED_PREFIXES: &[&str] = &[
    //  engine (single entry point)
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
    "/api/v1/ingest/", // bare collection-root POST /api/v1/ingest is covered by prefix_match
    // Governance, compliance, safety
    "/api/v1/governance/",
    "/api/v1/compliance/",
    "/api/v1/safety/",
    "/api/v1/autonomous/",
    //  / improvement
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
    "/api/v1/panasonic/", // Panasonic vertical
    "/api/v1/qcad/",
    "/api/v1/pulse/",
    "/api/v1/qec/",
    "/api/v1/wps/",    // Empulser / wireless_power_systems
    "/api/v1/models/", // per-model invocation surface (dwave-quantum/models.jsx primary path)
    // Metrics and system
    "/api/v1/metrics/",
    "/api/v1/system/",
    "/api/v1/emergency/",
    // MCP (both API-prefixed and direct mount)
    "/api/v1/mcp/",
    "/mcp/",
    //  engine direct mount
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
    API_ALLOWED_PREFIXES.iter().any(|p| prefix_match(path, p))
}

/// Match `path` against an allowlist `prefix`.
///
/// In addition to a normal prefix match, the EXACT collection root is admitted:
/// a slash-terminated entry like `/api/v1/runs/` also authorizes the bare
/// collection-root action `POST /api/v1/runs`. This admits ONLY the exact root
/// of an already-listed prefix — it never matches a sibling (`/api/v1/runsX`),
/// a shorter path (`/api/v1/run`), or any prefix not in the list, so the
/// allowlist's deny-by-default posture is unchanged. It also removes the need
/// for per-route "exact-path variant" duplicate entries (a no-slash twin next
/// to the slash-terminated prefix) that were previously hand-added.
#[must_use]
pub fn prefix_match(path: &str, prefix: &str) -> bool {
    path == prefix.trim_end_matches('/') || path.starts_with(prefix)
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

    // Collection-root matching: a slash-terminated prefix also authorizes its
    // exact bare root (e.g. /api/v1/runs/ admits POST /api/v1/runs), so the
    // create-collection POST is no longer rejected and no per-route no-slash
    // twin is needed.
    #[test]
    fn admits_collection_root_of_listed_prefix() {
        assert!(is_api_action_allowed("POST:/api/v1/runs")); // root of /api/v1/runs/
                                                             // Previously needed a dedicated no-slash entry; now covered generically.
        assert!(is_api_action_allowed("POST:/api/v1/ingest"));
        // Deeper paths under a listed prefix are unaffected.
        assert!(is_api_action_allowed("POST:/api/v1/runs/123/cancel"));
    }

    #[test]
    fn collection_root_does_not_widen_to_siblings_or_unlisted() {
        assert!(!is_api_action_allowed("POST:/api/v1/runsX")); // sibling
        assert!(!is_api_action_allowed("POST:/api/v1/run")); // shorter
        assert!(!is_api_action_allowed("POST:/api/v1/admin/dangerous")); // unlisted
        assert!(!is_api_action_allowed("POST:/api/v2/runs")); // wrong version
    }

    #[test]
    fn prefix_match_admits_only_exact_root() {
        assert!(prefix_match("/api/v1/runs", "/api/v1/runs/"));
        assert!(prefix_match("/api/v1/runs/9", "/api/v1/runs/"));
        assert!(!prefix_match("/api/v1/runsX", "/api/v1/runs/"));
        assert!(!prefix_match("/api/v1/run", "/api/v1/runs/"));
    }
}
