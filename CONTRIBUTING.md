# Contributing to the Safety Kernel

Thank you for your interest in contributing. The Safety Kernel is a small
codebase that does one important thing — be a trustworthy authorization
seam — and we keep the bar for changes correspondingly high. Please read
this document end-to-end before opening a PR.

## Code of Conduct

This project is governed by the [Contributor Covenant](CODE_OF_CONDUCT.md).
By participating you agree to uphold it.

## Local Development Setup

You will need:

- Rust toolchain (stable, edition 2024). Pin via `rust-toolchain.toml` in the
  repo root.
- Python 3.11+ if you plan to work on the Python defense crate.
- `git` 2.40+.

Clone and verify the build:

```bash
git clone https://github.com/ARYA-Labs-Public/unfireable-safety-kernel.git
cd safety-kernel
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

If any of those fail on a clean checkout, that itself is a bug worth filing.

For the Python defense crate:

```bash
cd py-defense
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check .
mypy .
```

## Branching and Sign-off

- Branch from `main`. Name branches descriptively (`fix/circuit-breaker-half-open`,
  not `patch-1`).
- All commits **must be signed off** under the
  [Developer Certificate of Origin](https://developercertificate.org/) using
  `git commit -s`. Unsigned commits will be rejected by CI.
- For substantial contributions (new features, new client-language SDKs,
  changes to the OpenAPI contract) we also ask contributors to sign an
  Apache-2.0 Individual or Corporate CLA. We will reach out at PR time;
  this is a one-time process.

## Pull Request Guidelines

A good PR is:

- **Small.** One logical change per PR. Refactors and feature work go in
  separate PRs.
- **Tested.** Every behavior change carries a test. Bug fixes carry a test
  that fails before the fix and passes after.
- **Documented.** If you change behavior visible at the API, doc, or CLI
  surface, update the relevant doc file in the same PR.
- **Clean.** Run `cargo fmt`, `cargo clippy --all-targets -- -D warnings`,
  and (for Python) `ruff check . && mypy .` before pushing.

Open the PR against `main`. The CI matrix runs:

- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --check`
- OpenAPI spec lint
- Python defense crate tests + lint
- Example smoke tests (FastAPI, axum, nginx)

A green CI is required to merge. We do not merge with red CI.

## Coding Standards

### Rust

- Edition 2024.
- **No `unwrap()` or `expect()` in production code paths.** They are
  acceptable in tests and in `build.rs`-style scripts.
- Use structured error types (`thiserror` is fine). Return `Result<T, E>`
  from every fallible API.
- Use `tracing::` for logs (not `println!` or `log::`).
- Public APIs are documented with rustdoc comments. Cross-link to design
  docs in `docs/` where appropriate.

### Python (defense crate)

- Type-hint everything. `mypy --strict` is the bar.
- Async-first; do not block the event loop.
- Use `structlog` or `logging` with structured fields.

### OpenAPI

- The OpenAPI spec is the source of truth for the wire contract. Changes
  go through the process below.

## Contribution Scope

### In scope for community PRs

- Bug fixes against the kernel binary, client SDK, or defense crate.
- Documentation improvements.
- New `examples/` integrations (e.g. integration with a popular agent
  framework).
- New `templates/` starting points for adopters.
- Performance improvements with benchmarks demonstrating the gain.
- Additional client-language SDKs (Go, Node, Java, etc.) — please open a
  Discussion first so we can agree on the package shape.
- Test coverage improvements, including new adversarial fixtures.

### Out of scope — please open a Discussion first

The following require ARYA review before any code lands, because they
change the security properties of the kernel:

- Changes to the OpenAPI contract (`contracts/openapi/safety_kernel.yaml`).
- Changes to the security model — fail-closed semantics, signature
  schemes, transparency-log structure, circuit-breaker invariants.
- Modifications to any deny-pattern regex used in the build or release
  tooling.
- New dependencies that require runtime network egress.
- New dependencies that pull in a large transitive graph; we prefer a
  small, vendored, audited set.

Opening a Discussion is cheap and we are responsive. We will say yes to
many of these — we just want to do it deliberately.

## Asking Questions

Open a Discussion at
[https://github.com/ARYA-Labs-Public/unfireable-safety-kernel/discussions](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel/discussions).
"How do I integrate this with X?" is exactly the kind of question we
want to answer in public so the next person can find it.

## Security Issues

Do not file security issues here. See [SECURITY.md](SECURITY.md).

## Release Process

Releases follow [Semantic Versioning](https://semver.org/). Breaking changes
to the wire contract bump the major version. Release history is recorded in
`CHANGELOG.md`.

Thank you for contributing.
