# FastAPI integration

How to wire the Python defense crate's middleware into a FastAPI app so
every request to a gated route is authorized by the Safety Kernel before
it reaches your handler.

This is **seam 2 of four** — see
[architecture.md § four defense seams](../architecture.md#the-four-defense-seams) for the full picture.

## Install

The middleware needs a few runtime deps (async transport + signature
verification), so install the `fastapi` extra:

```bash
pip install "safety-kernel-defense[fastapi]"
```

The `[fastapi]` extra pulls `fastapi`, `starlette`, `httpx`, and
`cryptography`. The **core** package (the Layer-1 audit hook) stays
stdlib-only — `pip install safety-kernel-defense` with no extra keeps that
surface dependency-free; the extra is only required for the middleware and
the revoke client. `import safety_kernel_defense` does not pull the extra
deps until you actually touch `SafetyKernelMiddleware` / `RevokeClient`.

## Wire the middleware

```python
import os

from fastapi import FastAPI
from safety_kernel_defense import SafetyKernelMiddleware

app = FastAPI()

app.add_middleware(
    SafetyKernelMiddleware,
    kernel_url="http://localhost:9000",
    worker_api_key=os.environ["KERNEL_WORKER_KEY"],
    operator_pubkey_hex=os.environ["KERNEL_OPERATOR_PUBKEY"],
    # Defaults shown — see "Tunables" below
    request_timeout_s=0.5,
    circuit_breaker_failure_threshold=3,
    circuit_breaker_open_duration_s=10.0,
    gated_path_prefixes=("/api/v1/write/", "/api/v1/execute/"),
)
```

For each gated request the middleware POSTs to
`{kernel_url}/kernel/v1/authorize` with the worker key in the `x-api-key`
header and a body of `{action, run_id, subject, params_fingerprint}`. It
derives:

- `run_id` / `subject` from the `x-run-id` / `x-subject` request headers
  (missing `x-run-id` → a fresh per-request UUID; missing `x-subject` →
  `"anonymous"`);
- `action` as `http.<method>:<path>` (e.g. `http.post:/api/v1/write/thing`);
- `params_fingerprint` as the SHA-256 of the canonical JSON of
  `{"method", "path", "query"}`.

**About `operator_pubkey_hex`.** This is the 32-byte raw Ed25519 public key
(64 hex chars) the middleware uses to verify the signature on every `ALLOW`
token. The token is `<payload_b64>.<sig_b64>` and the signature is over the
ASCII bytes of `payload_b64`; the middleware reproduces exactly that check.
Feed it the public key that corresponds to whatever key signs the kernel's
decision tokens — retrieve it from the kernel's `GET /kernel/v1/public_key`
(that endpoint returns `public_key_b64`; convert base64 → hex). See the
note in [`getting-started.md`](getting-started.md#the-operator_pubkey_hex-value)
on how this maps to the kernel's signing-key configuration.

Order matters: install the middleware **before** any router that
mounts a gated path, and **after** anything that resolves the caller
identity (authentication, request-id propagation). The middleware
reads `x-run-id` and `x-subject` from the request headers; if your
auth layer sets those on `request.state`, adapt with a thin shim
middleware.

## Tunables

| Argument | Default | Notes |
|---|---|---|
| `kernel_url` | required | Reach the kernel via service DNS, not a load-balanced public URL. |
| `worker_api_key` | required | Read from a secrets manager; never hardcode. |
| `operator_pubkey_hex` | required | Used to verify Ed25519 signatures on `ALLOW` decisions. |
| `request_timeout_s` | `0.5` | Hard cap on a single authorize call. The kernel is on the hot path; keep this tight. |
| `circuit_breaker_failure_threshold` | `3` | Consecutive failures before the breaker opens. See [`circuit-breaker.md`](circuit-breaker.md). |
| `circuit_breaker_open_duration_s` | `10.0` | Seconds the breaker stays open before probing. |
| `gated_path_prefixes` | required | Tuple of path prefixes that require authorization. Everything else passes through. |

## Error responses (fail-closed)

When the middleware denies a request it returns ONE JSON shape:

```json
{"error_code": "kernel_unavailable", "detail": "…", "fail_closed": true}
```

| `error_code` | HTTP | When |
|---|---|---|
| `kernel_unavailable` | 503 | Kernel unreachable, timed out, returned a non-decision status (401 / 5xx / an unparseable or non-`ok` 200), **or** the circuit breaker is open (denied with no network call). |
| `policy_denied` | 403 | Kernel returned an authoritative DENY (403). |
| `signature_invalid` | 503 | Kernel returned an `ALLOW`, but the token was malformed, its Ed25519 signature failed verification against `operator_pubkey_hex`, or its bound expiry had passed. |

This is the full fail-closed decision table. A gated request only reaches
your handler on a 200 `ALLOW` **whose signature verifies**. Every other
outcome is a deny, and `fail_closed` is always `true` on a deny body.

The circuit breaker mirrors the Rust client SDK: an authoritative answer
(ALLOW or DENY) keeps it closed; a transport error, timeout, non-decision
status, or bad signature is a failure. `circuit_breaker_failure_threshold`
consecutive failures open it for `circuit_breaker_open_duration_s`, after
which a single half-open probe decides whether to close. **An open breaker
denies (503 `kernel_unavailable`) without calling the kernel — it never
fails open.**

## Per-route opt-out

Some routes legitimately do not need a gate — `/health`, `/metrics`,
static assets. The simplest opt-out is to keep them outside
`gated_path_prefixes`. For finer control, register an opt-out matcher:

```python
def is_opted_out(request) -> bool:
    return request.url.path in {"/health", "/metrics", "/readyz"}

app.add_middleware(
    SafetyKernelMiddleware,
    kernel_url="http://localhost:9000",
    worker_api_key=os.environ["KERNEL_WORKER_KEY"],
    operator_pubkey_hex=os.environ["KERNEL_OPERATOR_PUBKEY"],
    gated_path_prefixes=("/api/v1/write/", "/api/v1/execute/"),
    opt_out=is_opted_out,
)
```

Opt-outs are a **policy decision** — review the list during every
security audit. A new "harmless" exemption is the most common path to
a missing gate.

## Verify it works

The single most important property is **fail-closed when the kernel is
unreachable**. Test it explicitly:

```python
from fastapi.testclient import TestClient

def test_denies_when_kernel_unreachable():
    # Point the middleware at an address that will refuse connections
    app = FastAPI()
    app.add_middleware(
        SafetyKernelMiddleware,
        kernel_url="http://127.0.0.1:1",  # connection refused
        worker_api_key="test",
        operator_pubkey_hex="00" * 32,
        gated_path_prefixes=("/api/v1/",),
        request_timeout_s=0.1,
    )

    @app.post("/api/v1/write/thing")
    def thing():
        return {"ok": True}

    client = TestClient(app)
    r = client.post("/api/v1/write/thing")
    assert r.status_code == 503
    assert r.json()["error_code"] == "kernel_unavailable"
```

If this test passes when you set `kernel_url` to a refusing address
and fails when you set it to a reachable kernel returning `ALLOW`,
your fail-closed contract is intact. If the test ever returns 200 with
an unreachable kernel, the wiring is broken — fix before shipping.

For end-to-end verification with a real kernel, see
[`getting-started.md`](getting-started.md).

## Reaper / revoke-client SDK

The same package ships `RevokeClient`, a small async client for the
kernel's coercive-shutdown surface (`/kernel/v1/revoke/*`). The kernel is
the decider: it mints signed `RevokeCompute` / restore decisions; an
out-of-band supervisor (the "reaper") pulls, verifies, and executes them
from outside the agent's failure domain. `RevokeClient` is the integrator
surface for both roles.

```python
from safety_kernel_defense import RevokeClient, InstanceTarget

target = InstanceTarget(project="my-proj", zone="us-central1-a", instance="agent-vm-1")

# Operator role — mint a signed kill decision (Phase 1 mints vm_stop only).
async with RevokeClient(kernel_url="https://kernel.internal:9000",
                        api_key=os.environ["KERNEL_OPERATOR_KEY"]) as op:
    decision = await op.mint_revoke(
        target=target, tier="vm_stop", trigger="operator_emergency_stop",
    )
    # decision -> {"ok": True, "run_id": ..., "token": ..., "token_sha256": ..., "claims": {...}}

# Reaper role — pull the pending signed decision(s), execute, then ack.
async with RevokeClient(kernel_url="https://kernel.internal:9000",
                        api_key=os.environ["KERNEL_REAPER_KEY"]) as reaper:
    pending = await reaper.pull_pending("agent-vm-1")   # [] on an empty queue (204)
    for _token in pending:
        # ... verify the token signature yourself, then execute the stop ...
        await reaper.ack(run_id=decision["run_id"], outcome="stopped")

# Operator role — mint a signed restore (un-kill).
async with RevokeClient(kernel_url="https://kernel.internal:9000",
                        api_key=os.environ["KERNEL_OPERATOR_KEY"]) as op:
    await op.restore(target=target, reason="incident resolved")
```

| Method | Endpoint | Role |
|---|---|---|
| `mint_revoke(target, tier, trigger, reason=None)` | `POST /kernel/v1/revoke/compute` | operator |
| `pull_pending(instance)` | `GET /kernel/v1/revoke/pending` | reaper (or operator) |
| `ack(run_id, outcome)` | `POST /kernel/v1/revoke/ack` | reaper (or operator) |
| `restore(target, reason=None)` | `POST /kernel/v1/revoke/restore` | operator |

Supply the API key whose role each call needs; the kernel enforces the
role from the key. **Fail-closed:** every method raises on failure and
never returns a false success — a transport error / timeout raises
`KernelUnavailable`, and a non-success HTTP status (401 / 403 / 422 / 503)
raises `RevokeError` (carrying `.status`, `.error_code`, `.reason`). A
supervisor never believes a kill was minted, pulled, or acked when it was
not.
