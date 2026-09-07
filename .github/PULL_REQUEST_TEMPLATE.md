<!--
Thanks for contributing to the Safety Kernel. Please read CONTRIBUTING.md
before opening. Keep PRs small and single-purpose — refactors and feature work
go in separate PRs. Security fixes do NOT go here; see SECURITY.md.
-->

## What this changes

<!-- One or two sentences. What problem does this solve? -->

Closes #<!-- issue number, if any -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (wire contract / behavior — bumps the major version)
- [ ] Docs / examples / tooling only

## Security-model impact

<!--
Changes to fail-closed semantics, signature schemes, the transparency log,
circuit-breaker invariants, deny-pattern tooling, or the OpenAPI contract
require a Discussion FIRST (CONTRIBUTING.md → Contribution Scope).
-->

- [ ] This PR does **not** touch the security model.
- [ ] This PR touches the security model, and it is backed by Discussion #<!-- number -->.

## Checklist

- [ ] Commits are **signed off** (`git commit -s`, Developer Certificate of Origin) — CI enforces this.
- [ ] One logical change; kept small.
- [ ] `cargo fmt --check` passes.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes.
- [ ] `cargo test --workspace` passes.
- [ ] For a **bug fix**: added a test that **fails before** this change and **passes after**.
- [ ] For behavior visible at the API / CLI / doc surface: docs updated in this PR.
- [ ] For a change to the revocation / fail-closed path: the relevant **Kani proofs** still verify (`just proofs`).
- [ ] For the Python defense crate: `pytest`, `ruff check .`, and `mypy .` pass.
- [ ] `CHANGELOG.md` updated (SemVer).

## How I tested this

<!-- Commands you ran and their result. "Green CI is required; we do not merge red." -->

## Notes for reviewers

<!-- Anything that will help review: design trade-offs, follow-ups, screenshots. -->
