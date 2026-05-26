# Safety Kernel

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status: early](https://img.shields.io/badge/status-early%20extraction-yellow)](#status)

A fail-closed authorization service for AI systems.

The Safety Kernel is the small, hardened gate that sits between every AI agent
and every consequential action the agent can take. If the kernel is unreachable,
calls are denied. If the kernel says DENY, calls are denied. If the kernel says
ALLOW, the call proceeds *and* an entry is appended to a tamper-evident
transparency log signed by an operator key the kernel itself does not hold.

It is designed to be:

- **Unfireable.** The kernel is a separate process. The agent cannot kill it,
  re-deploy it, or write to it. It can only call it.
- **Fail-closed.** Every seam — nginx, middleware, dispatch hook, client
  circuit breaker — denies on error.
- **Auditable.** Every allowed action is signed and logged. The operator key
  is generated and held outside the kernel; the kernel only verifies.
- **Language-neutral.** A single OpenAPI contract, one Rust reference
  binary, and a Python defense library for shops that aren't on Rust yet.

## Status

This repository is the **public extraction** of the safety-kernel architecture.

**What works today:**

- `contracts/openapi/safety_kernel.yaml` — the API contract (single source of truth)
- `crates/services/safety-kernel/` — the kernel binary (axum + tokio)
- `crates/services/transparency-log/` — append-only Ed25519-signed audit log
- `crates/services/safety-kernel-reconciler/` — background reconciliation worker
- `crates/domain/src/safety/` — pure types and traits (no I/O)
- `crates/adapters/safety_kernel_client/` — Rust client SDK with fail-closed circuit breaker
- `crates/adapters/transparency_store/` — Postgres-backed transparency log storage
- `py-defense/` — Python `safety_kernel_defense` library (audit hook + subprocess propagation, stdlib-only)
- `examples/` — reference integrations (FastAPI middleware, axum tower::Layer, nginx auth_request, mock kernel + adversarial fixtures, reference Python + Rust apps)
- `docs/` — architecture, integration guides, deployment, OpenAPI pointer

**What's not here yet:**

- Crate is **not** on [crates.io](https://crates.io) yet. Build from source (instructions below).
- Python package is **not** on PyPI yet. Install from this repo's `py-defense/` directory.
- The workspace's `crates/domain/Cargo.toml` manifest is not present in this initial extraction; the source is, but you may need to author the manifest for an end-to-end `cargo build --workspace`. This is being tracked for the v1.0 cut.
- No prebuilt Docker images on Docker Hub yet — see [`docs/deployment/docker.md`](docs/deployment/docker.md) for the Dockerfile pattern.

## Why a separate service?

Authorization checks inside the agent's own process can be removed by the
agent — accidentally, through a refactor, or deliberately, through prompt
injection. Authorization checks in a separate process that the agent cannot
write to cannot be removed by the agent. That is the property the kernel
exists to deliver.

## Architecture

```
   Agent / API client
        │
        ▼
   nginx auth_request   ← coarse network-layer gate
        │
        ▼
   App middleware       ← app-layer gate (FastAPI / axum)
        │
        ▼
   Dispatch hook        ← per-tool gate (defense-in-depth)
        │
        ▼
   Client SDK           ← circuit breaker, fail-closed on Unavailable
        │
        ▼
   Safety Kernel  ←→  Transparency log (Ed25519, append-only)
```

Four defense seams, each independently denying on error. See
[`docs/architecture.md`](docs/architecture.md) for the full design.

## Quickstart (build from source)

```bash
# 1. Clone
git clone https://github.com/ARYA-Labs-PBC/safety-kernel.git
cd safety-kernel

# 2. Generate an operator Ed25519 keypair (one-time)
openssl genpkey -algorithm Ed25519 -out operator.key
openssl pkey -in operator.key -pubout -outform DER \
  | tail -c 32 | xxd -p -c 64 > operator.pub.hex

# 3. Build the kernel (per-crate; the workspace manifest is partial in this cut)
cargo build --release -p qorch-safety-kernel

# 4. Run
./target/release/qorch-safety-kernel \
  --operator-pubkey "$(cat operator.pub.hex)" \
  --bind 127.0.0.1:9000

# 5. Smoke test
curl -fsS http://localhost:9000/health
```

For a working integration in ~10 minutes, see
[`docs/integration/getting-started.md`](docs/integration/getting-started.md).

For Python adopters, install the audit-hook library directly from this repo:

```bash
pip install ./py-defense
```

See [`docs/integration/python-fastapi.md`](docs/integration/python-fastapi.md)
for the FastAPI middleware integration.

## What's in this repo

| Path | Purpose |
|---|---|
| `crates/services/safety-kernel/` | The kernel binary (axum + tokio) |
| `crates/services/transparency-log/` | Append-only signed audit log service |
| `crates/services/safety-kernel-reconciler/` | Reconciliation worker |
| `crates/domain/src/safety/` | Pure types & traits (no I/O) |
| `crates/adapters/safety_kernel_client/` | Rust client SDK + circuit breaker |
| `crates/adapters/transparency_store/` | Postgres-backed log storage |
| `contracts/openapi/safety_kernel.yaml` | API contract (source of truth) |
| `py-defense/` | Python defense library (FastAPI middleware + audit hook) |
| `examples/middleware/` | FastAPI, gRPC, nginx, dispatch-hook examples |
| `examples/observability/` | Prometheus metrics + Grafana dashboard |
| `examples/policy/` | Three-tier policy DSL example |
| `examples/reference_app/` + `examples/reference_app_rs/` | End-to-end reference apps (Python + Rust) |
| `examples/testing/` | Mock kernel + adversarial test fixtures |
| `docs/` | Architecture, integration guides, deployment, API |

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — design overview, defense seams, transparency log, threat model
- [`docs/integration/getting-started.md`](docs/integration/getting-started.md) — 10-minute walkthrough
- [`docs/integration/python-fastapi.md`](docs/integration/python-fastapi.md) — FastAPI middleware
- [`docs/integration/rust-axum.md`](docs/integration/rust-axum.md) — axum `tower::Layer`
- [`docs/integration/nginx.md`](docs/integration/nginx.md) — nginx `auth_request` gate
- [`docs/integration/circuit-breaker.md`](docs/integration/circuit-breaker.md) — fail-closed client pattern
- [`docs/deployment/docker.md`](docs/deployment/docker.md) — Dockerfile + compose
- [`docs/api/openapi.md`](docs/api/openapi.md) — API spec navigation

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Security

Report security issues privately to **security@aryalabs.io**. Please do not
open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md) for
the full policy.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, sign-off
requirements, and contribution scope. See
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for the community standards.
