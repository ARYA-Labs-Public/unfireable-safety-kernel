# Docker deployment

This page covers running the Safety Kernel as a container — building the
image, launching it standalone, wiring it into a compose stack with a
transparency log and a sample app, and the hardening flags that make the
container worth the trouble.

The kernel is a single static binary. There is no Python runtime, no
virtualenv, and no shell in the final image.

## Reference Dockerfile

Two-stage build: Rust toolchain in the builder stage, distroless in the
runtime stage. The final image carries the binary and nothing else.

```dockerfile
# Stage 1 — build
FROM rust:1.85-slim AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p qorch-safety-kernel

# Stage 2 — runtime
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /build/target/release/qorch-safety-kernel \
     /usr/local/bin/qorch-safety-kernel

# Non-root, unprivileged uid (distroless `nonroot` user).
USER 65532:65532
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/qorch-safety-kernel"]
```

Build:

```bash
docker build -t qorch-safety-kernel:1.0.0 .
```

Target image size is ≤ 60 MB. There is no `sh`, no package manager, and
no writable filesystem in the final image — `docker exec ... sh` will
fail, which is the point.

## Required environment

The kernel reads its configuration from env vars (no CLI flags, no
config file). Four are required at boot; the kernel exits with
`Error: missing <VAR>` if any are absent:

| Env var | Value shape | Purpose |
|---|---|---|
| `QORCH_KERNEL_SIGNING_KEY_B64` | base64url-encoded 32 bytes | Kernel's Ed25519 signing key. Generate with `python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode())"`. **base64url, not base64** — the kernel rejects `/` and `+`. |
| `QORCH_KERNEL_AUDIT_PEPPER_B64` | base64url-encoded 32 bytes | HMAC pepper for audit log entries. Same encoding rule. |
| `QORCH_KERNEL_API_KEY_WORKER` | opaque string | API key for worker-role callers. |
| `QORCH_KERNEL_API_KEY_API` | opaque string | API key for API-role callers. |

Optional, with sensible defaults:

| Env var | Default | Purpose |
|---|---|---|
| `QORCH_ENV` | `dev` | Set to `prod` to refuse any startup without all secrets present and TLS configured. |
| `QORCH_KERNEL_LISTEN_ADDR` | `127.0.0.1:9000` | Bind address; set to `0.0.0.0:9000` inside containers. |
| `QORCH_KERNEL_TRANSPARENCY_LOG_URL` | unset | URL of the transparency-log sidecar; if unset, transparency entries are not emitted (dev only). |
| `QORCH_KERNEL_API_KEY_OPERATOR` | required in `prod` | Operator-role API key. Production refuses to start without this. |

See [`crates/services/safety-kernel/src/settings.rs`](../../crates/services/safety-kernel/src/settings.rs) for the complete env-var contract.

## Standalone `docker run`

```bash
# Generate boot secrets (dev-only — do NOT reuse for real workloads).
SIGNING_KEY=$(python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode())")
AUDIT_PEPPER=$(python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode())")

docker run --rm \
  --name qorch-safety-kernel \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --user 65532:65532 \
  -p 9000:9000 \
  -e QORCH_ENV=dev \
  -e QORCH_KERNEL_LISTEN_ADDR=0.0.0.0:9000 \
  -e QORCH_KERNEL_SIGNING_KEY_B64="$SIGNING_KEY" \
  -e QORCH_KERNEL_AUDIT_PEPPER_B64="$AUDIT_PEPPER" \
  -e QORCH_KERNEL_API_KEY_WORKER=dev-worker-key \
  -e QORCH_KERNEL_API_KEY_API=dev-api-key \
  ghcr.io/arya-labs-pbc/unfireable-safety-kernel:edge
```

Notes:

- `--read-only` is safe — the kernel does not write to its own filesystem. The transparency log lives in a separate service with its own volume.
- No container-internal `--health-cmd`. The final image is distroless: no shell, no `wget`, no `curl`. Use the orchestrator's TCP probe (`tcpSocket: { port: 9000 }` in Kubernetes; compose `depends_on: service_started` without health gating; ECS task definition's `healthCheck` with a container-internal binary the operator embeds themselves). See the smoke-test guide at [`smoke-test.md`](./smoke-test.md) for the canonical post-pull verification.
- The four required `QORCH_KERNEL_*` env vars above must be set. The kernel exits early with `Error: missing <VAR>` if any are missing.

## Compose: kernel + transparency log + sample app

A complete reference compose file ships at [`deployment/docker-compose.prod.yml`](../../deployment/docker-compose.prod.yml). Use it directly:

```bash
# Generate boot secrets, export, then bring up the stack.
export QORCH_KERNEL_SIGNING_KEY_B64=$(python3 -c \
  "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode())")
export QORCH_KERNEL_AUDIT_PEPPER_B64=$(python3 -c \
  "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode())")
export QORCH_KERNEL_API_KEY_WORKER=$(openssl rand -hex 16)
export QORCH_KERNEL_API_KEY_API=$(openssl rand -hex 16)

docker compose -f deployment/docker-compose.prod.yml up -d
```

The `tlog-data` named volume in the compose file is the only piece of mutable state in the stack. Snapshot it the same way you snapshot any append-only audit store.

## Health probes

The kernel exposes `GET /health`. It returns `200 {"ok": true, ...}` if
the process is up and reachable. Recommended probe settings:

| Probe | Interval | Timeout | Failure threshold |
|---|---|---|---|
| Liveness | 10 s | 2 s | 3 |
| Readiness | 5 s | 2 s | 2 |

A failing health probe should cause the orchestrator to mark the
container unhealthy. **Callers must continue to fail-closed (deny) if
the kernel is unreachable** — health probes are an operator signal, not
a substitute for client-side circuit breaking.

## Hardening checklist

The kernel is a gate. A compromised kernel container is worse than no
container at all, because callers trust its signatures. Apply every
control on this list before exposing the kernel to traffic.

- **Read-only root filesystem** (`--read-only` / `read_only: true`).
- **Drop all Linux capabilities** (`--cap-drop=ALL` / `cap_drop: [ALL]`).
  The kernel needs none.
- **No new privileges** (`--security-opt=no-new-privileges`).
- **Non-root user** — the distroless `nonroot` image runs as
  uid 65532. Do not override to root.
- **No shell in the final image** — use a distroless base. If you need
  to debug, run a separate diagnostic container, do not add a shell to
  the kernel image.
- **Pin the image digest** in production (`@sha256:...`), not just the
  tag. Tags are mutable.
- **Verify the image signature** against the project's published
  release-signing key before pulling into production.
- **Egress allowlist** — the kernel should only need to reach the
  transparency log. Block everything else at the network layer.
