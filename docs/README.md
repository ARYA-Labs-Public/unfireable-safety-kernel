# Documentation

This directory is the entry point for safety-kernel adopters.

## Start here

- **[`architecture.md`](architecture.md)** — the design in one read.
  What the kernel is, why it's a separate process, how the four defense
  seams compose, what the transparency log signs, what's in/out of scope.

- **[`integration/getting-started.md`](integration/getting-started.md)** —
  a working integration in about 10 minutes. Build the kernel from source,
  generate an operator keypair, wire a sample app, verify fail-closed
  behavior, and inspect the transparency log.

## Integration guides

Pick the one that matches your stack:

| Guide | When to read |
|---|---|
| [`integration/python-fastapi.md`](integration/python-fastapi.md) | You have a FastAPI app and want middleware-level enforcement |
| [`integration/rust-axum.md`](integration/rust-axum.md) | You have an axum service and want a `tower::Layer` |
| [`integration/nginx.md`](integration/nginx.md) | You want network-edge enforcement via `auth_request` |
| [`integration/circuit-breaker.md`](integration/circuit-breaker.md) | You're writing a client and need the fail-closed pattern right |

Each guide is self-contained but cross-references
[`architecture.md`](architecture.md) for the underlying design.

## Operations

- **[`deployment/docker.md`](deployment/docker.md)** — multi-stage
  distroless Dockerfile, `docker run` invocation, compose snippet for
  kernel + transparency log + sample app, hardening checklist
  (read-only rootfs, drop-all-caps, non-root user, distroless base).

## API reference

- **[`api/openapi.md`](api/openapi.md)** — pointer to the OpenAPI spec
  at [`contracts/openapi/safety_kernel.yaml`](../contracts/openapi/safety_kernel.yaml),
  endpoint summary table, client-generation notes, versioning policy,
  and notes on signed-response semantics.

## See also

- Top-level [`README.md`](../README.md) — project overview + quickstart
- [`SECURITY.md`](../SECURITY.md) — vulnerability disclosure policy
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — development setup + DCO
- [`CHANGELOG.md`](../CHANGELOG.md) — release history
