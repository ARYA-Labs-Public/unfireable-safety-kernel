# Image smoke test

A two-minute end-to-end check that the published kernel image at
`ghcr.io/arya-labs-pbc/unfireable-safety-kernel:edge` pulls, boots
with the documented hardening flags, and answers a `/health` probe
with a 200.

Run this any time you cut a new image (release tag, `:edge` refresh),
before announcing the image to consumers, or as part of a deployment
runbook to confirm the registry is reachable from your cluster's
egress.

## Prerequisites

- `docker` and `curl` on the operator workstation.
- Internet egress to `ghcr.io` and `gcr.io` (the latter for the
  distroless base image; pulled transitively).
- Free TCP port `9099` on the host (used here to avoid colliding with
  any existing kernel deployment on `9000`).
- `python3` on the operator workstation (for base64url encoding —
  the kernel does not accept standard base64).

The image has no shell, no `wget`, no `curl`. Everything below runs
against the kernel from the host, not from inside the container.

## Steps

```bash
# 1. Generate kernel boot secrets — base64url-encoded 32-byte values.
#    NOT base64 (the kernel rejects '/' and '+'). These are dev-only
#    smoke-test values; do NOT reuse for any deployment that touches
#    real workloads.
SIGNING_KEY=$(python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode())")
AUDIT_PEPPER=$(python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode())")

# 2. Pull the published image (no GHCR login needed for public pulls).
docker pull ghcr.io/arya-labs-pbc/unfireable-safety-kernel:edge

# 3. Start the kernel with the canonical hardening flags.
docker run --rm -d --name safety-kernel-smoke \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --user 65532:65532 -p 9099:9000 \
  -e QORCH_ENV=dev \
  -e QORCH_KERNEL_LISTEN_ADDR=0.0.0.0:9000 \
  -e QORCH_KERNEL_SIGNING_KEY_B64="$SIGNING_KEY" \
  -e QORCH_KERNEL_AUDIT_PEPPER_B64="$AUDIT_PEPPER" \
  -e QORCH_KERNEL_API_KEY_WORKER=dev-worker-key \
  -e QORCH_KERNEL_API_KEY_API=dev-api-key \
  ghcr.io/arya-labs-pbc/unfireable-safety-kernel:edge

# 4. Give it ~3 seconds to bind, then probe `/health`.
sleep 3
curl -fsS http://localhost:9099/health

# Expected:
#   {"ok":true,"version":"...","uptime_s":3.x}

# 5. Tear down.
docker rm -f safety-kernel-smoke
```

## Pass criteria

- `docker pull` reports the digest matches the multi-arch manifest
  for `:edge`.
- The container starts and stays `Up` after the 3-second sleep
  (`docker ps -a --filter "name=safety-kernel-smoke"`).
- `curl ... /health` returns HTTP 200 with `{"ok": true, "version": "...", "uptime_s": ...}`.

## Fail-mode diagnosis

| Symptom | Likely cause |
|---|---|
| `Error: missing QORCH_KERNEL_SIGNING_KEY_B64` | The boot secrets weren't passed in. Re-export `$SIGNING_KEY` and `$AUDIT_PEPPER` and retry. |
| `Error: base64url decode failed` | The signing key or audit pepper was encoded as standard base64 (with `+` or `/`). Use base64url (see step 1). |
| Container exits in < 1 second, no logs | The image is broken for the host architecture. Re-pull and verify `docker image inspect` shows a matching architecture. |
| `curl: (7) Failed to connect to localhost port 9099` | The kernel did not bind. Inspect `docker logs safety-kernel-smoke` for the actual error — typically a missing required env var or an invalid base64url value. |
| `{"ok": false}` | The kernel started but reports degraded health. Inspect `docker logs` for the degradation reason. |

## What this smoke test does NOT cover

This is a **boot** smoke test. It does not exercise:

- The `/authorize` decision path (needs a calling client + a signed token).
- The transparency log (needs the t-log service running too — see
  [`deployment/docker-compose.prod.yml`](../../deployment/docker-compose.prod.yml)).
- TLS termination, mutual TLS, or the nginx auth-request gate.
- The fail-closed circuit breaker behaviour from the SDK side.

Each of those has its own integration suite under `crates/services/safety-kernel/tests/` (Rust) and `examples/testing/` (Python).

## CI / automation hook

This procedure is automatable end-to-end. A `make smoke-test` target
or a GitHub Actions workflow can run the same steps against the
just-published `:edge` image as a post-publish gate. The
`scripts/audit_adversarial_coverage.sh` job runs **on** every PR;
the image smoke test runs **after** every publish.
