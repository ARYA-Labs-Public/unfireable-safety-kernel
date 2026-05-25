# Safety Kernel

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Crate](https://img.shields.io/badge/crate-qorch--safety--kernel-orange)](https://crates.io/crates/qorch-safety-kernel)

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
  circuit breaker — denies on error. A missing seam is a configuration bug
  the wiring checklist catches before production.
- **Auditable.** Every allowed action is signed and logged. The operator key
  is generated and held outside the kernel; the kernel only verifies.
- **Language-neutral.** A single OpenAPI contract, one Rust reference
  binary, and a Python defense crate for shops that aren't on Rust yet.

## Why a separate service?

Authorization checks inside the agent's own process can be removed by the
agent — accidentally, through a refactor, or deliberately, through prompt
injection. Authorization checks in a separate process that the agent cannot
write to cannot be removed by the agent. That is the property the kernel
exists to deliver.

## Quickstart

```bash
cargo install qorch-safety-kernel
qorch-safety-kernel --operator-pubkey <hex> --bind 127.0.0.1:9000
curl -fsS http://localhost:9000/health
```

For a working integration in ~10 minutes, see
[`docs/integration/getting-started.md`](docs/integration/getting-started.md).

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

See [`docs/architecture.md`](docs/architecture.md) for the full design.

## What's in this repo

| Path | Purpose |
|---|---|
| `crates/services/safety-kernel/` | The kernel binary (axum + tokio) |
| `crates/services/transparency-log/` | Append-only signed audit log service |
| `crates/services/safety-kernel-reconciler/` | Reconciliation worker |
| `crates/domain/src/safety/` | Pure types & traits (no I/O) |
| `crates/adapters/safety_kernel_client/` | Rust client SDK + circuit breaker |
| `contracts/openapi/safety_kernel.yaml` | Single-source-of-truth API contract |
| `py-defense/` | Python defense crate (FastAPI middleware + audit hook) |
| `examples/` | Reference integrations: FastAPI, axum, nginx |
| `templates/` | Starter templates for new integrations |
| `cli/` | `safety-kernel scaffold` + `safety-kernel validate` |
| `docs/` | Architecture, integration guides, deployment, security |

## Status

This is the **public reference implementation** of the Safety Kernel
architecture. The kernel binary and Rust client SDK are production-quality.
The Python defense crate, CLI, and deployment artifacts are reference
implementations intended as starting points.

We use this kernel in production at ARYA Labs. We ship the *same* code
publicly that we run internally, attested by sigstore-style transparency
log entries — so adopters can verify they are running the same defense
we ship.

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
