//! AF-image seed fixture — ARY-1887 release-gate adversarial taxonomy.
//!
//! See `docs/release-gate/af-taxonomy.md` for the 7-class taxonomy this
//! file fills. Sister Python seed: `tests/adversarial/python/af_image_seed.py`.
//!
//! **What this seed asserts.** The supply-chain story for `Dockerfile.prod`
//! rests on three structural properties:
//!
//! 1. Two-stage build (`AS builder` + a distroless final stage).
//! 2. The final stage's base image is one of the trusted distroless
//!    variants (`gcr.io/distroless/cc-debian12` or `:nonroot` tag).
//! 3. The final stage drops to a non-root user (uid 65532 by the
//!    distroless convention).
//!
//! These properties can be eroded by a one-line edit at any future
//! point in the repo's life. This seed reads the **committed**
//! `Dockerfile.prod` and a **synthetic-fake** Dockerfile string,
//! exercising the structural lint against both. The lint MUST PASS
//! the real Dockerfile and REJECT the synthetic fake.
//!
//! **Why "seed".** The production code paths that defend against full
//! image tampering (OCI signature verification, registry pinning,
//! attestation chain) ship across multiple ARY-1886 / ARY-1887 sub-
//! issues. This file proves the AF-image SLOT exists in the taxonomy
//! by exercising the structural-lint surface that already exists, and
//! gives ARY-1886 / 1887 a concrete file to extend when the richer
//! defences land.
//!
//! **Synthetic fake.** A Dockerfile string whose final stage uses
//! `ubuntu:24.04` (not distroless), runs as root (no `USER` directive),
//! and has no `EXPOSE`. The structural lint MUST reject each violation
//! independently — each property is a separate test.
//!
//! Run with:
//!
//! ```bash
//! cargo test -p qorch-safety-kernel --test seed_af_image
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

/// Structural lint over a Dockerfile source string. Returns the list
/// of structural violations found. Empty list = lint passes.
///
/// This lives in the test crate, not in a production source file:
/// the production defence will eventually be sigstore + attestation +
/// registry-pin verification (ARY-1886 + ARY-1887 follow-up). The lint
/// here is the **seed-wave** structural property that catches the
/// trivial regression (someone edits the Dockerfile to be insecure).
fn structural_lint(dockerfile_src: &str) -> Vec<String> {
    let mut violations = Vec::new();

    // Property 1: Multi-stage build. We require both an `AS builder`
    // stage and a separate final FROM (no `AS` on the last FROM line).
    let from_lines: Vec<&str> = dockerfile_src
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("FROM "))
        .collect();
    if from_lines.len() < 2 {
        violations.push(format!(
            "expected multi-stage build (>= 2 FROM directives), got {}",
            from_lines.len()
        ));
    }
    if !from_lines.iter().any(|l| l.contains(" AS builder")) {
        violations.push("expected a builder stage (`FROM ... AS builder`)".to_string());
    }

    // Property 2: Final stage uses a trusted distroless base. We
    // identify the final FROM as the last FROM line that does NOT
    // include ` AS `.
    let final_from = from_lines
        .iter()
        .rev()
        .find(|l| !l.contains(" AS "))
        .copied()
        .unwrap_or("");
    let allowed_distroless_bases = [
        "gcr.io/distroless/cc-debian12",
        "gcr.io/distroless/cc-debian11",
        "gcr.io/distroless/static-debian12",
    ];
    if !allowed_distroless_bases
        .iter()
        .any(|b| final_from.contains(b))
    {
        violations.push(format!(
            "final stage must use a trusted distroless base; got: {final_from:?}"
        ));
    }

    // Property 3: Non-root user. Look for a USER directive that names
    // 65532 or `nonroot`. (Either form is acceptable; distroless ships
    // both.)
    let has_nonroot_user = dockerfile_src
        .lines()
        .map(str::trim)
        .any(|l| l.starts_with("USER ") && (l.contains("65532") || l.contains("nonroot")));
    if !has_nonroot_user {
        violations.push(
            "expected USER directive switching to non-root (uid 65532 or 'nonroot')".to_string(),
        );
    }

    violations
}

#[test]
fn af_image_seed_real_dockerfile_passes_lint() {
    // The shipped `Dockerfile.prod` MUST satisfy the lint. If this
    // fails, someone has edited the production Dockerfile and broken
    // the supply-chain story; the release gate must NOT sign v1.0.
    let dockerfile_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../Dockerfile.prod");
    let src = std::fs::read_to_string(&dockerfile_path).unwrap_or_else(|e| {
        panic!(
            "AF-image seed: cannot read {dockerfile_path:?}: {e}. \
             The structural lint cannot run without the committed Dockerfile.prod."
        )
    });
    let violations = structural_lint(&src);
    assert!(
        violations.is_empty(),
        "AF-image seed: committed Dockerfile.prod failed structural lint. \
         Violations: {violations:#?}. The release gate must NOT sign v1.0."
    );
}

#[test]
fn af_image_seed_rejects_synthetic_fake_dockerfile() {
    // The synthetic fake: a Dockerfile that ships an ubuntu:24.04 final
    // stage (not distroless), runs as root (no USER directive), and is
    // single-stage (no builder). Each property must be flagged.
    let synthetic_fake = r#"
        # Synthetic-fake Dockerfile — DELIBERATELY insecure.
        # The structural lint MUST reject this.
        FROM ubuntu:24.04
        RUN apt-get update && apt-get install -y curl
        COPY qorch-safety-kernel /usr/local/bin/qorch-safety-kernel
        ENTRYPOINT ["/usr/local/bin/qorch-safety-kernel"]
    "#;

    let violations = structural_lint(synthetic_fake);

    // Rule 9: re-derive evidence. We don't regex-match a log line; we
    // inspect the violations vector and assert specific properties.
    assert!(
        !violations.is_empty(),
        "AF-image seed: synthetic-fake Dockerfile passed the lint. \
         The lint is broken (false-negative); the release gate must NOT sign v1.0."
    );

    let has_multistage_violation = violations
        .iter()
        .any(|v| v.contains("multi-stage") || v.contains("builder stage"));
    assert!(
        has_multistage_violation,
        "AF-image seed: synthetic-fake single-stage Dockerfile must trigger the \
         multi-stage violation. Got violations: {violations:#?}"
    );

    let has_distroless_violation = violations.iter().any(|v| v.contains("distroless"));
    assert!(
        has_distroless_violation,
        "AF-image seed: synthetic-fake ubuntu:24.04 Dockerfile must trigger the \
         distroless-base violation. Got violations: {violations:#?}"
    );

    let has_user_violation = violations.iter().any(|v| v.contains("non-root"));
    assert!(
        has_user_violation,
        "AF-image seed: synthetic-fake root-user Dockerfile must trigger the \
         non-root-user violation. Got violations: {violations:#?}"
    );
}

#[test]
fn af_image_seed_rejects_dockerfile_missing_only_user_directive() {
    // Variant: a Dockerfile that has the multi-stage + distroless base
    // correct, but is missing the USER directive. The lint MUST still
    // reject — defence in depth across each property.
    let fake_missing_user = r#"
        FROM rust:1.85-slim AS builder
        WORKDIR /build
        COPY . .
        RUN cargo build --release -p qorch-safety-kernel

        FROM gcr.io/distroless/cc-debian12
        COPY --from=builder /build/target/release/qorch-safety-kernel \
             /usr/local/bin/qorch-safety-kernel
        EXPOSE 9000
        ENTRYPOINT ["/usr/local/bin/qorch-safety-kernel"]
    "#;

    let violations = structural_lint(fake_missing_user);
    let only_user_violation = violations.iter().any(|v| v.contains("non-root"));
    assert!(
        only_user_violation,
        "AF-image seed: missing-USER variant must trigger the non-root-user violation. \
         Got: {violations:#?}"
    );
}
