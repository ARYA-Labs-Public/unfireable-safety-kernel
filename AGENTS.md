# AGENTS.md — Unfireable Safety Kernel

Operating guide for AI agents and human contributors working in this
repository. Read this before making changes.

## What this repo is

A fail-closed, machine-checked authorization service for AI agents:
a separate Rust process that sits between an agent and every
consequential action. The agent's runtime is untrusted by construction.
See [`README.md`](README.md) for the full architecture and
[`docs/architecture.md`](docs/architecture.md) for the threat model.

## One-command lanes (`just`)

This repo uses [`just`](https://github.com/casey/just). From the repo root:

| Command | What it does |
|---------|--------------|
| `just setup` | Install the toolchain components + dev tools needed to build and validate |
| `just check` | Fast pre-commit gate: `fmt --check` + `clippy` + `cargo check --workspace` |
| `just test` | Full workspace test suite (`cargo test --workspace`) + Python `py-defense` tests |
| `just audit` | Jankurai repo-quality audit (advisory) |
| `just security` | Secret scan + dependency policy (`cargo-deny`) |
| `just` (default) | Runs `check` then `test` |

If you don't have `just`, the underlying commands are listed in the
[`Justfile`](Justfile) — run them directly.

## Build & test directly (no `just`)

```bash
# Build the kernel binary
cargo build --release -p qorch-safety-kernel

# Full workspace test suite (Rust)
cargo test --workspace

# A single crate (fast iteration on the domain types)
cargo test -p qorch-domain --lib

# Formal proofs (requires Kani: cargo install --locked kani-verifier && cargo kani setup)
cargo kani -p qorch-domain --harness safety::client_state::kani_proofs::open_within_cooldown_always_refuses

# Python defense library
cd py-defense && pip install -e ".[test]" && pytest safety_kernel_defense/tests/ -v
```

## Architecture you must respect

**Four defense-in-depth seams** sit on the only path between agent and
action: nginx `auth_request` → app middleware → dispatch hook → client
SDK circuit breaker → the kernel. Each denies independently on error.
Do not add a code path that lets an agent reach a consequential action
without passing every seam. See `README.md` § Architecture.

**Fail-closed is the invariant.** Unreachable → deny. Errored → deny.
Unparseable → deny. Bad signature → deny. The circuit-breaker decision
function `gate_decision` in `crates/domain/src/safety/client_state.rs`
is proven exhaustively by Kani (4 harnesses). If you touch it, the
proofs must stay green.

**Signing is externalized.** Every ALLOW appends an Ed25519-signed entry
to the transparency log under an operator key the kernel does not hold.
The sign/verify surface is `crates/domain/src/safety/token/`
(`canonical.rs` = byte-stable JSON + hashing, `sign.rs`, `verify.rs`).
The byte-stable JSON MUST match Python's
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
— changing it breaks cross-language signature equivalence. Treat this
module as a gate surface: any change needs equivalence tests + an
adversarial review confirming forged/tampered/expired tokens are still
rejected.

## Domain-crate import boundary (CI-enforced)

`crates/domain/` is pure types and traits — **no I/O**. The following
imports are forbidden anywhere under `crates/domain/` (full list in
[`agent/boundaries.toml`](agent/boundaries.toml)):

```
std::fs, std::env, std::net, std::time::SystemTime,
rand::, sqlx::, diesel::, reqwest::, rdkafka::, tracing::, log::
```

I/O belongs in `crates/adapters/`. Time and randomness enter the domain
through the `Clock` and nonce-source traits (test seams), never directly.

## Repository layout

| Path | Purpose |
|------|---------|
| `crates/domain/` | Pure types & traits (no I/O). Safety tokens, circuit-breaker state, transparency primitives. |
| `crates/application/` | Use-case orchestration over the domain. |
| `crates/adapters/` | I/O: client SDK, middleware, Postgres-backed transparency store. |
| `crates/services/safety-kernel/` | The kernel binary (axum + tokio). |
| `crates/services/transparency-log/` | Append-only Ed25519-signed audit log service. |
| `crates/services/safety-kernel-reconciler/` | Binary-attestation / drift-detection worker. |
| `contracts/openapi/safety_kernel.yaml` | API contract (single source of truth). |
| `py-defense/` | Python `safety_kernel_defense` library (audit hook, stdlib-only). |
| `examples/` | Reference integrations + adversarial test fixtures. |
| `agent/` | Machine-readable policy: `boundaries.toml` (import boundary), `audit-policy.toml` (Jankurai calibration). |

## Conventions

- **Rust**: `#![forbid(unsafe_code)]`. rustls only — `native-tls`/OpenSSL
  are banned via `deny.toml`. Keep `cargo fmt` clean and `clippy` warning-free.
- **GitHub Actions** are pinned to full commit SHAs (tag retained as a
  trailing comment). Renovate/Dependabot keeps pins current.
- **No secrets in source.** The only secret the kernel needs at boot is
  the operator *public* key. Private keys live in an HSM/KMS/air-gapped
  media outside the container.
- **Tests are the contract.** The adversarial fixtures under
  `crates/**/tests/` and `examples/testing/` encode what the gate must
  REJECT. A change that makes them pass by weakening an assertion is a
  regression, not a fix.

## Before you open a PR

Run `just check && just test` (or the direct equivalents). For changes
to the token/signing surface or the circuit breaker, also run
`cargo kani -p qorch-domain` and confirm the adversarial fixtures still
reject forged/tampered/expired inputs.
