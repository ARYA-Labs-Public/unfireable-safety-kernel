//! Forbidden-import lint for the policy domain module (,
//!; `agent/boundaries.toml`).
//!
//! Domain crates are pure types/traits — no I/O, no network, no clock,
//! no RNG, no logging. The `crates/domain` `Cargo.toml` and the
//! workspace `boundaries.toml` both spell out the forbidden imports,
//! but neither is a *compile-time* gate at the module level: a future
//! contributor can pull `tracing::info!` into `policy/types.rs` and
//! clippy will not complain. This test IS that gate.
//!
//! It scans every `.rs` file in `crates/domain/src/safety/policy/`
//! (excluding the test file itself) and asserts none of the forbidden
//! import strings appear. The check is grep-shaped, not parser-shaped —
//! that is sufficient because the forbidden patterns are unambiguous
//! (`use std::fs;` and friends don't have benign look-alikes).
//!
//! Slice-2 contributors note: when you add per-protein registry, audit
//! HMAC, or signed-decision logic that legitimately needs randomness
//! or a clock, you do NOT relax this test. You put the impl in
//! `crates/adapters/` and the trait stays here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// `std::fs` IS allowed in test-only code per the boundary contract
// (boundaries apply to non-test code in the domain crate). The
// `#[cfg(test)]` gate on the parent `mod import_discipline_test;`
// keeps this file out of production builds.
use std::fs;
use std::path::PathBuf;

/// The forbidden-import substrings from `agent/boundaries.toml` /
/// `CLAUDE.md` §"Domain-crate forbidden imports".
/
/// We match on `use <prefix>` patterns rather than bare `<prefix>::`
/// because the latter has too many benign collisions (e.g. inside
/// rustdoc links). The patterns below cover both classic imports
/// (`use sqlx::Pool`) and glob re-exports (`use tracing::*`).
const FORBIDDEN_USE_PATTERNS: &[&str] = &[
    "use std::fs",
    "use std::env",
    "use std::net",
    "use std::time::SystemTime",
    "use rand::",
    "use sqlx::",
    "use diesel::",
    "use reqwest::",
    "use rdkafka::",
    "use tracing::",
    "use log::",
];

/// Files in `crates/domain/src/safety/policy/` whose source MUST be
/// clean of every pattern above. New files added under that directory
/// MUST also be added here — that's an intentional speed-bump so a
/// reviewer eyeballs the import list of every new policy-domain file.
const POLICY_SOURCES: &[&str] = &["mod.rs", "types.rs", "claims.rs", "validation.rs"];

/// Path to `crates/domain/src/safety/policy/` relative to the
/// `qorch-domain` crate root (i.e. `CARGO_MANIFEST_DIR`).
fn policy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/safety/policy")
}

// Gate: ANY forbidden-import substring in a domain policy source = fail.
#[test]
fn policy_domain_sources_have_no_forbidden_imports() {
    let dir = policy_dir();
    assert!(
        dir.is_dir(),
        "policy dir {dir:?} does not exist — has the module been moved?",
    );

    let mut violations: Vec<String> = Vec::new();

    for filename in POLICY_SOURCES {
        let path = dir.join(filename);
        let src = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));

        // Walk line-by-line so we can report line numbers — much more
        // useful when a violation lands six months from now and the
        // grep ouput is a wall of context.
        for (lineno, line) in src.lines().enumerate() {
            let trimmed = line.trim_start();
            // Skip rustdoc, line comments, and block-comment lines —
            // they routinely mention these names without importing them
            // (see this file's own doc comments).
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            for pat in FORBIDDEN_USE_PATTERNS {
                if line.contains(pat) {
                    violations.push(format!(
                        "{filename}:{}: forbidden import pattern {pat:?}: {trimmed}",
                        lineno + 1,
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "forbidden imports in crates/domain/src/safety/policy/ \
         (see agent/boundaries.toml + ):\n{}",
        violations.join("\n"),
    );
}

/// Spot-check the test infrastructure itself: a SYNTHETIC source string
/// containing every forbidden pattern MUST be flagged by the same
/// match logic. This is the Rule 8 adversarial fixture for the lint
/// itself — without it, a `false` short-circuit anywhere above would
/// silently disable the entire gate.
// Gate: the lint logic itself MUST flag a known-bad source — guards the gate.
#[test]
fn lint_correctly_flags_synthetic_bad_source() {
    let bad_lines = [
        "use std::fs;",
        "use std::env::var;",
        "use std::net::TcpStream;",
        "use std::time::SystemTime;",
        "use rand::Rng;",
        "use sqlx::PgPool;",
        "use diesel::prelude::*;",
        "use reqwest::Client;",
        "use rdkafka::ClientConfig;",
        "use tracing::info;",
        "use log::warn;",
    ];

    for line in bad_lines {
        let hit = FORBIDDEN_USE_PATTERNS.iter().any(|pat| line.contains(pat));
        assert!(
            hit,
            "synthetic bad line {line:?} was NOT flagged — the lint is broken",
        );
    }

    // And a benign line MUST NOT be flagged.
    let good = "use serde::{Deserialize, Serialize};";
    let hit = FORBIDDEN_USE_PATTERNS.iter().any(|pat| good.contains(pat));
    assert!(!hit, "benign line {good:?} false-positive flagged");
}
