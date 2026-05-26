//! Gate-surface registry — auto-flag waves that touch safety-critical surfaces.
//!
//! Per. A "gate surface" is a code surface where a wave's
//! changes can affect the trust boundary of the system. If a wave
//! touches any gate surface, the type-state machine forces it through
//! `Wave<Tested>` → `Wave<PurpleTeamed>` (no skip allowed).
//!
//! Auto-detection from file paths is implemented as a pure mapping —
//! no I/O. The caller hands us paths it already collected from `git
//! diff --name-only` or equivalent; we return the set of surfaces
//! those paths touch.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A safety-critical surface in the codebase. A wave touching any of
/// these MUST traverse the purple-team transition before it can reach
/// `Wave<Accepted>`.
///
/// The variants mirror the gate-surface list in  §"Gate-Surface
/// Registry" exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GateSurface {
    /// Safety Kernel (`crates/safety-kernel`, `crates/domain/src/safety`,
    /// Rust HTTP service, Python policy sidecar). Token signing,
    /// authorization, audit.
    SafetyKernel,
    /// orchestrator dispatcher (`packages/aara/dispatch*`, `crates/application/src/dispatch`).
    /// Routes calls into capabilities; the trust boundary for tool
    /// invocation lives here.
    Dispatcher,
    /// MCP bridge (`packages/mcp/`, `crates/adapters/src/mcp/`).
    /// External tool surface; any change widens or narrows what
    /// untrusted callers can reach.
    McpBridge,
    /// Git hooks (`.claude/hooks/`, `.githooks/`). Pre-commit /
    /// pre-push gates that enforce the release ceremony.
    GitHooks,
    /// Transparency-log Merkle ledger (`crates/domain/src/transparency`,
    /// `crates/adapters/src/transparency/`). Append-only audit trail
    /// for signed outputs.
    TransparencyLog,
    /// Cogcore execution lanes (`packages/autonomy/cogcore/`,
    /// `crates/application/src/lanes/`). self-improvement proposal lifecycle and
    /// safety-kernel lane gating.
    CogcoreLanes,
}

impl GateSurface {
    /// Path prefixes (relative to the repo root, forward-slash form)
    /// that imply this surface is touched. Kept conservative — false
    /// positives are cheap (extra purple-team review) but false
    /// negatives bypass the gate.
    #[must_use]
    pub const fn path_prefixes(self) -> &'static [&'static str] {
        match self {
            Self::SafetyKernel => &[
                "crates/safety-kernel/",
                "crates/domain/src/safety",
                "python/safety_kernel/",
            ],
            Self::Dispatcher => &[
                "packages/aara/dispatch",
                "crates/application/src/dispatch",
            ],
            Self::McpBridge => &["packages/mcp/", "crates/adapters/src/mcp"],
            Self::GitHooks => &[".claude/hooks/", ".githooks/"],
            Self::TransparencyLog => &[
                "crates/domain/src/transparency",
                "crates/adapters/src/transparency",
            ],
            Self::CogcoreLanes => &[
                "packages/autonomy/cogcore/",
                "crates/application/src/lanes",
            ],
        }
    }

    /// Every surface, for path-scan iteration. Kept as a `const` slice
    /// so the boundary checker sees no `HashSet::iter` clock-style
    /// nondeterminism in domain code.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::SafetyKernel,
            Self::Dispatcher,
            Self::McpBridge,
            Self::GitHooks,
            Self::TransparencyLog,
            Self::CogcoreLanes,
        ]
    }
}

/// Scan a list of repo-relative paths (forward-slash form) and return
/// the set of gate surfaces those paths touch.
///
/// Matching is prefix-based against the canonical roots declared in
/// [`GateSurface::path_prefixes`]. Backslashes are normalized to
/// forward-slash so Windows-form paths still match.
///
/// # Examples
///
/// ```rust
/// use qorch_domain::wave::gate_surface::{detect_gate_surfaces, GateSurface};
///
/// let paths = ["crates/safety-kernel/src/token.rs", "README.md"];
/// let surfaces = detect_gate_surfaces(paths.iter().copied());
/// assert!(surfaces.contains(&GateSurface::SafetyKernel));
/// assert_eq!(surfaces.len(), 1);
/// ```
#[must_use]
pub fn detect_gate_surfaces<'a, I>(paths: I) -> HashSet<GateSurface>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out = HashSet::new();
    for raw in paths {
        let path = raw.replace('\\', "/");
        for surface in GateSurface::all() {
            for prefix in surface.path_prefixes() {
                if path.starts_with(prefix) {
                    out.insert(*surface);
                    break;
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn detects_safety_kernel_from_rust_path() {
        let surfaces = detect_gate_surfaces(["crates/safety-kernel/src/lib.rs"]);
        assert!(surfaces.contains(&GateSurface::SafetyKernel));
    }

    #[test]
    fn detects_safety_kernel_from_domain_subpath() {
        let surfaces = detect_gate_surfaces(["crates/domain/src/safety/token.rs"]);
        assert!(surfaces.contains(&GateSurface::SafetyKernel));
    }

    #[test]
    fn detects_dispatcher() {
        let surfaces = detect_gate_surfaces(["packages/aara/dispatcher.py"]);
        assert!(surfaces.contains(&GateSurface::Dispatcher));
    }

    #[test]
    fn detects_mcp_bridge() {
        let surfaces = detect_gate_surfaces(["packages/mcp/server.py"]);
        assert!(surfaces.contains(&GateSurface::McpBridge));
    }

    #[test]
    fn detects_git_hooks() {
        let surfaces = detect_gate_surfaces([".claude/hooks/team_release_gate.sh"]);
        assert!(surfaces.contains(&GateSurface::GitHooks));
    }

    #[test]
    fn detects_transparency_log() {
        let surfaces = detect_gate_surfaces(["crates/domain/src/transparency/merkle.rs"]);
        assert!(surfaces.contains(&GateSurface::TransparencyLog));
    }

    #[test]
    fn detects_cogcore_lanes() {
        let surfaces = detect_gate_surfaces(["packages/autonomy/cogcore/lane.py"]);
        assert!(surfaces.contains(&GateSurface::CogcoreLanes));
    }

    #[test]
    fn benign_paths_yield_empty_set() {
        let surfaces = detect_gate_surfaces(["README.md", "docs/architecture.md"]);
        assert!(surfaces.is_empty());
    }

    #[test]
    fn windows_style_paths_normalize() {
        let surfaces = detect_gate_surfaces(["crates\\safety-kernel\\src\\lib.rs"]);
        assert!(surfaces.contains(&GateSurface::SafetyKernel));
    }

    #[test]
    fn multi_surface_scan() {
        let paths = [
            "crates/safety-kernel/src/token.rs",
            ".claude/hooks/release.sh",
            "crates/adapters/src/transparency/witness.rs",
            "README.md",
        ];
        let surfaces = detect_gate_surfaces(paths.iter().copied());
        assert_eq!(surfaces.len(), 3);
        assert!(surfaces.contains(&GateSurface::SafetyKernel));
        assert!(surfaces.contains(&GateSurface::GitHooks));
        assert!(surfaces.contains(&GateSurface::TransparencyLog));
    }

    #[test]
    fn surface_roundtrips_through_json() {
        let s = GateSurface::SafetyKernel;
        let j = serde_json::to_string(&s).expect("serialize");
        let back: GateSurface = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(s, back);
    }

    #[test]
    fn all_lists_every_variant() {
        // If we add a variant and forget to update `all()`, this test
        // pins the count.
        assert_eq!(GateSurface::all().len(), 6);
    }
}
