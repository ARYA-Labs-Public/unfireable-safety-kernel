# Justfile — one-command setup & validation for the Unfireable Safety Kernel.
# Run `just <target>` from the repo root. See AGENTS.md for the full guide.
#
# Install just: https://github.com/casey/just  (cargo install just)

# Default: the pre-commit gate (fast checks + full tests).
default: check test

# ---- setup ----

# Install toolchain components + optional dev tools used by the lanes below.
setup:
	rustup component add rustfmt clippy
	@echo "optional: cargo install --locked cargo-deny jankurai   # for `just security` / `just audit`"
	@echo "optional (proofs): cargo install --locked kani-verifier && cargo kani setup"

# ---- fast gate ----

# Format check + lint + type-check the whole workspace. No tests.
check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -W warnings
	cargo check --workspace --all-targets

# ---- tests ----

# Full Rust workspace test suite + the Python defense library tests.
test: test-rust test-python

test-rust:
	cargo test --workspace --no-fail-fast

test-python:
	cd py-defense && python -m pip install -e ".[test]" --quiet && pytest safety_kernel_defense/tests/ -q

# Formal proofs over the fail-closed gate decision (requires Kani).
proofs:
	cargo kani -p qorch-domain \
	  --harness safety::client_state::kani_proofs::open_within_cooldown_always_refuses \
	  --harness safety::client_state::kani_proofs::open_permits_only_after_cooldown \
	  --harness safety::client_state::kani_proofs::half_open_with_probe_in_flight_refuses \
	  --harness safety::client_state::kani_proofs::permit_characterization_is_exhaustive

# ---- quality / security ----

# Jankurai repo-quality audit (advisory; never blocks locally).
audit:
	jankurai audit . --mode advisory --policy agent/audit-policy.toml \
	  --json agent/repo-score.json --md agent/repo-score.md

# Dependency policy (advisories + license/source bans from deny.toml).
security:
	cargo deny check
	@echo "secret scan runs in CI via gitleaks; for a local scan: gitleaks detect --source . --no-banner"

# ---- release helper ----

# Build the production kernel binary.
build-release:
	cargo build --release -p qorch-safety-kernel
