//! Gate-surface registry — auto-flag waves that touch safety-critical surfaces.
//!
//! Per internal-ref. A "gate surface" is a code surface where a wave's
//! changes can affect the trust boundary of the system. If a wave
//! touches any gate surface, the type-state machine forces it through
//! `Wave<Tested>` → `Wave<PurpleTeamed>` (no skip allowed).
//!
//! Auto-detection from file paths is implemented as a pure mapping —
//! no I/O. The caller hands us paths it already collected from `git
//! diff --name-only` or equivalent; we return the set of surfaces
//! those paths touch.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A safety-critical surface in the codebase. A wave touching any of
/// these MUST traverse the purple-team transition before it can reach
/// `Wave<Accepted>`.
///
/// The variants mirror the gate-surface list in internal-ref §"Gate-Surface
/// Registry" exactly.
///
/// `PartialOrd`/`Ord` are derived (variant-declaration order) so the type can
/// live in a `BTreeSet`, which serializes in a deterministic, sorted order.
/// This matters for `WaveSessionRecord::canonical_bytes`: a `HashSet` would
/// serialize in per-process-random iteration order, so the append client and
/// the transparency-log service could HMAC byte-different canonicalizations of
/// the same record and disagree (`kernel_hmac_mismatch`) ~50% of the time for
/// records with ≥2 gate surfaces. `BTreeSet` removes that non-determinism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GateSurface {
    /// Safety Kernel (`crates/safety-kernel`, `crates/domain/src/safety`,
    /// Rust HTTP service, Python policy sidecar). Token signing,
    /// authorization, audit.
    SafetyKernel,
    /// Capability dispatcher (`crates/application/src/dispatch`).
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
    /// `crates/application/src/lanes/`). proposal lifecycle and
    /// safety-kernel lane gating.
    CogcoreLanes,
    /// Alembic migration chain (`alembic/`) and store modules
    /// (`packages/core/*_store.py`). The `qorch_certification_*`
    /// and `qorch_formal_verify_*` tables hold the durable evidence behind
    /// safety-level claims; a change that silently alters their shape
    /// can alter what "certified" means (internal-ref).
    ///
    /// Store modules are detected via suffix matching (`_store.py`) because
    /// prefix matching cannot express `packages/core/*_store.py` without
    /// matching all of `packages/core/`. Both authorities (alembic migrations
    /// and store modules) are now covered.
    ///
    /// This variant MUST remain last. `Ord` is derived from variant
    /// declaration order and feeds `BTreeSet` serialization, which feeds
    /// `WaveSessionRecord::canonical_bytes`, which feeds the kernel HMAC.
    /// Inserting a variant anywhere but the end would change the canonical
    /// bytes of every already-signed record carrying two or more surfaces,
    /// causing those records to stop verifying.
    PersistenceSchema,
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
            Self::Dispatcher => &["packages/aara/dispatch", "crates/application/src/dispatch"],
            Self::McpBridge => &["packages/mcp/", "crates/adapters/src/mcp"],
            Self::GitHooks => &[".claude/hooks/", ".githooks/"],
            Self::TransparencyLog => &[
                "crates/domain/src/transparency",
                "crates/adapters/src/transparency",
            ],
            Self::CogcoreLanes => &["packages/autonomy/cogcore/", "crates/application/src/lanes"],
            // Store modules (`packages/core/*_store.py`) are covered by suffix
            // matching in `path_suffixes`; adding `packages/core/` as a prefix
            // would flag most of the repo.
            Self::PersistenceSchema => &["alembic/"],
        }
    }

    /// Path suffixes (forward-slash form) that imply this surface is touched.
    /// Suffix matching is needed when a prefix cannot be made specific enough
    /// without causing excessive false positives. For example,
    /// `packages/core/*_store.py` cannot be expressed as a prefix without
    /// matching all of `packages/core/`, so `_store.py` is matched as a suffix
    /// instead. Kept conservative — false positives are cheap (extra
    /// purple-team review) but false negatives bypass the gate.
    #[must_use]
    pub const fn path_suffixes(self) -> &'static [&'static str] {
        match self {
            Self::SafetyKernel => &[],
            Self::Dispatcher => &[],
            Self::McpBridge => &[],
            Self::GitHooks => &[],
            Self::TransparencyLog => &[],
            Self::CogcoreLanes => &[],
            Self::PersistenceSchema => &["_store.py"],
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
            Self::PersistenceSchema,
        ]
    }

    /// The wire name of this surface: the string the Python side sends and the
    /// adapters map back to the domain value. It is the serde name (the variant
    /// name) — see the `wire_name_is_the_serde_name` test, which pins the two
    /// together for every variant in `all()`.
    ///
    /// This `match` is deliberately exhaustive with no `_` arm: adding a variant
    /// without a wire name is a compile error here, next to `path_prefixes`
    /// and `path_suffixes` which enforce the same thing. Adapters derive their
    /// string→surface lookup from `all()` + this method instead of keeping a
    /// parallel hand-written table that a new variant can silently miss
    /// (internal-ref).
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::SafetyKernel => "SafetyKernel",
            Self::Dispatcher => "Dispatcher",
            Self::McpBridge => "McpBridge",
            Self::GitHooks => "GitHooks",
            Self::TransparencyLog => "TransparencyLog",
            Self::CogcoreLanes => "CogcoreLanes",
            Self::PersistenceSchema => "PersistenceSchema",
        }
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
pub fn detect_gate_surfaces<'a, I>(paths: I) -> BTreeSet<GateSurface>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out = BTreeSet::new();
    for raw in paths {
        let path = raw.replace('\\', "/");
        for surface in GateSurface::all() {
            for prefix in surface.path_prefixes() {
                if path.starts_with(prefix) {
                    out.insert(*surface);
                    break;
                }
            }
            for suffix in surface.path_suffixes() {
                if path.ends_with(suffix) {
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
        assert_eq!(GateSurface::all().len(), 7);
    }

    #[test]
    fn appending_a_variant_does_not_reorder_the_existing_ones() {
        let pre_existing: BTreeSet<GateSurface> = [
            GateSurface::SafetyKernel,
            GateSurface::Dispatcher,
            GateSurface::McpBridge,
            GateSurface::GitHooks,
            GateSurface::TransparencyLog,
            GateSurface::CogcoreLanes,
        ]
        .iter()
        .copied()
        .collect();
        let ordered: Vec<GateSurface> = pre_existing.into_iter().collect();
        assert_eq!(
            ordered,
            vec![
                GateSurface::SafetyKernel,
                GateSurface::Dispatcher,
                GateSurface::McpBridge,
                GateSurface::GitHooks,
                GateSurface::TransparencyLog,
                GateSurface::CogcoreLanes,
            ]
        );
        assert!(GateSurface::PersistenceSchema > GateSurface::CogcoreLanes);
    }

    #[test]
    fn alembic_paths_are_detected_as_persistence_schema() {
        let surfaces =
            detect_gate_surfaces(["alembic/versions/012_red_team_campaigns.py", "README.md"]);
        assert!(surfaces.contains(&GateSurface::PersistenceSchema));
        assert_eq!(surfaces.len(), 1);
    }

    #[test]
    fn store_modules_are_detected_as_persistence_schema() {
        let surfaces = detect_gate_surfaces(["packages/core/red_team_store.py"]);
        assert!(surfaces.contains(&GateSurface::PersistenceSchema));
    }

    #[test]
    fn suffix_matching_does_not_widen_other_surfaces() {
        let surfaces = detect_gate_surfaces(["packages/core/red_team_store.py"]);
        assert_eq!(surfaces.len(), 1);
        assert!(surfaces.contains(&GateSurface::PersistenceSchema));
    }

    #[test]
    fn wire_name_is_the_serde_name() {
        // Locks the wire form to the JSON form for EVERY variant, driven by `all()`
        // rather than a literal list — a variant missing from either shows up here.
        for surface in GateSurface::all() {
            let json = serde_json::to_value(surface).expect("serialize");
            assert_eq!(json.as_str(), Some(surface.wire_name()), "{surface:?}");
        }
    }

    #[test]
    fn wire_names_are_unique() {
        let names: BTreeSet<&str> = GateSurface::all().iter().map(|s| s.wire_name()).collect();
        assert_eq!(names.len(), GateSurface::all().len());
    }
}
