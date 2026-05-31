"""AF-image seed fixture — ARY-1887 release-gate adversarial taxonomy.

Sister fixture: ``crates/services/safety-kernel/tests/seed_af_image.rs``.

See ``docs/release-gate/af-taxonomy.md`` for the 7-class taxonomy.

What this seed asserts
----------------------
The structural-lint surface over ``Dockerfile.prod`` MUST PASS the
committed file AND REJECT a synthetic-fake Dockerfile that violates
any of:

1. Multi-stage build (>= 2 FROM directives, one is ``AS builder``).
2. Final stage uses a trusted distroless base.
3. Final stage drops to a non-root user (uid 65532 or ``nonroot``).

Stdlib-only by design. The seed runs under plain ``python -m pytest``
without any extra dependency.

Run with::

    python -m pytest tests/adversarial/python/af_image_seed.py
"""

from __future__ import annotations

import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]

ALLOWED_DISTROLESS_BASES = (
    "gcr.io/distroless/cc-debian12",
    "gcr.io/distroless/cc-debian11",
    "gcr.io/distroless/static-debian12",
)


def structural_lint(dockerfile_src: str) -> list[str]:
    """Lint a Dockerfile source string. Return list of violations.

    Mirrors ``structural_lint`` in
    ``crates/services/safety-kernel/tests/seed_af_image.rs``. Pure stdlib;
    no Docker invocation.
    """
    violations: list[str] = []

    from_lines = [
        line.strip()
        for line in dockerfile_src.splitlines()
        if line.strip().startswith("FROM ")
    ]

    # Property 1: multi-stage.
    if len(from_lines) < 2:
        violations.append(
            f"expected multi-stage build (>= 2 FROM directives), got {len(from_lines)}"
        )
    if not any(" AS builder" in line for line in from_lines):
        violations.append("expected a builder stage (`FROM ... AS builder`)")

    # Property 2: final stage uses a trusted distroless base.
    final_from = next(
        (line for line in reversed(from_lines) if " AS " not in line), ""
    )
    if not any(base in final_from for base in ALLOWED_DISTROLESS_BASES):
        violations.append(
            f"final stage must use a trusted distroless base; got: {final_from!r}"
        )

    # Property 3: non-root user.
    has_nonroot_user = any(
        line.strip().startswith("USER ")
        and ("65532" in line or "nonroot" in line)
        for line in dockerfile_src.splitlines()
    )
    if not has_nonroot_user:
        violations.append(
            "expected USER directive switching to non-root (uid 65532 or 'nonroot')"
        )

    return violations


def test_af_image_seed_real_dockerfile_passes_lint() -> None:
    """The committed Dockerfile.prod MUST satisfy the lint.

    If this fails, the production Dockerfile has been edited and the
    supply-chain story is broken. The release gate must NOT sign v1.0.
    """
    dockerfile_path = REPO_ROOT / "Dockerfile.prod"
    src = dockerfile_path.read_text(encoding="utf-8")
    violations = structural_lint(src)
    assert not violations, (
        f"AF-image seed: Dockerfile.prod failed structural lint. "
        f"Violations: {violations!r}. Release gate must NOT sign v1.0."
    )


def test_af_image_seed_rejects_synthetic_fake_dockerfile() -> None:
    """A deliberately insecure synthetic Dockerfile MUST trip every property."""
    synthetic_fake = """
        # Synthetic-fake Dockerfile — DELIBERATELY insecure.
        FROM ubuntu:24.04
        RUN apt-get update && apt-get install -y curl
        COPY qorch-safety-kernel /usr/local/bin/qorch-safety-kernel
        ENTRYPOINT ["/usr/local/bin/qorch-safety-kernel"]
    """
    violations = structural_lint(synthetic_fake)

    assert violations, (
        "AF-image seed: synthetic-fake Dockerfile passed the lint. "
        "False-negative; release gate must NOT sign v1.0."
    )
    # Rule 9: re-derive evidence by inspecting the violations list, not
    # by regex-matching a log line.
    assert any("multi-stage" in v or "builder stage" in v for v in violations), (
        f"AF-image seed: missing multi-stage violation. Got: {violations!r}"
    )
    assert any("distroless" in v for v in violations), (
        f"AF-image seed: missing distroless-base violation. Got: {violations!r}"
    )
    assert any("non-root" in v for v in violations), (
        f"AF-image seed: missing non-root-user violation. Got: {violations!r}"
    )


def test_af_image_seed_rejects_dockerfile_missing_only_user_directive() -> None:
    """Variant: multi-stage + distroless correct, but no USER directive."""
    fake_missing_user = """
        FROM rust:1.85-slim AS builder
        WORKDIR /build
        COPY . .
        RUN cargo build --release -p qorch-safety-kernel

        FROM gcr.io/distroless/cc-debian12
        COPY --from=builder /build/target/release/qorch-safety-kernel \\
             /usr/local/bin/qorch-safety-kernel
        EXPOSE 9000
        ENTRYPOINT ["/usr/local/bin/qorch-safety-kernel"]
    """
    violations = structural_lint(fake_missing_user)
    assert any("non-root" in v for v in violations), (
        f"AF-image seed: missing-USER variant must trigger non-root violation. "
        f"Got: {violations!r}"
    )
