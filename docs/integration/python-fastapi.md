# FastAPI integration

How to wire the Python defense crate's middleware into a FastAPI app so
every request to a gated route is authorized by the Safety Kernel before
it reaches your handler.

This is **seam 2 of four** — see
[architecture.md § four defense seams](../architecture.md#the-four-defense-seams) for the full picture.

## Install

```bash
pip install safety-kernel-defense
```

The package is stdlib-only at runtime apart from `httpx` for async
transport, and pulls FastAPI/Starlette as soft dependencies.

## Wire the middleware

```python
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
