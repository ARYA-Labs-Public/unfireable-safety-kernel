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

## Standalone `docker run`

```bash
docker run --rm \
  --name qorch-safety-kernel \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --user 65532:65532 \
  -p 9000:9000 \
  -e KERNEL_OPERATOR_PUBKEY="$(cat operator.pub)" \
  -e KERNEL_BIND="0.0.0.0:9000" \
  --health-cmd='wget -qO- http://127.0.0.1:9000/health || exit 1' \
  --health-interval=10s \
  --health-timeout=2s \
  --health-retries=3 \
  qorch-safety-kernel:1.0.0
```

Notes:

- `--read-only` is safe — the kernel does not write to its own filesystem.
  The transparency log lives in a separate service with its own volume.
- The operator public key is the only secret the kernel needs at boot.
  It is a public key; the matching private key is held outside the
  container (HSM, KMS, or air-gapped media).

## Compose: kernel + transparency log + sample app

```yaml
# docker-compose.yml
services:
  safety-kernel:
    image: qorch-safety-kernel:1.0.0
    read_only: true
    user: "65532:65532"
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges
    environment:
      KERNEL_BIND: "0.0.0.0:9000"
      KERNEL_OPERATOR_PUBKEY: "${OPERATOR_PUBKEY}"
      KERNEL_TLOG_URL: "http://transparency-log:9100"
    ports:
      - "9000:9000"
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:9000/health"]
      interval: 10s
      timeout: 2s
      retries: 3
    depends_on:
      transparency-log:
        condition: service_healthy

  transparency-log:
    image: qorch-transparency-log:1.0.0
    read_only: true
    user: "65532:65532"
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges
    environment:
      TLOG_BIND: "0.0.0.0:9100"
      TLOG_DATA_DIR: "/var/lib/tlog"
    volumes:
      # The log MUST persist across restarts. The kernel binary need not.
      - tlog-data:/var/lib/tlog
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:9100/health"]
      interval: 10s
      timeout: 2s
      retries: 3

  sample-app:
    image: my-app:latest
    environment:
      SAFETY_KERNEL_URL: "http://safety-kernel:9000"
      SAFETY_KERNEL_PUBKEY: "${KERNEL_PUBKEY}"
    depends_on:
      safety-kernel:
        condition: service_healthy

volumes:
  tlog-data:
```

The `tlog-data` named volume is the only piece of mutable state in the
stack. Snapshot it the same way you snapshot any append-only audit
store.

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
