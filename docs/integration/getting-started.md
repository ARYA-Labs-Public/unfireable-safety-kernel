# Getting started

A ~10-minute walkthrough that takes you from a clean machine to a running
Safety Kernel, a smoke-tested authorize call, a working FastAPI
integration, and a verified fail-closed behavior when the kernel is
killed.

## Prerequisites

- **Rust 1.75 or newer.** Install via [rustup](https://rustup.rs/):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  rustc --version  # should print 1.75.0 or later
  ```

- **An Ed25519 operator keypair.** The kernel does not generate or hold
  the operator key — you do. Generate one with `openssl`:
  ```bash
  # Generate a private key (keep this secret; this is your operator key)
  openssl genpkey -algorithm ed25519 -out operator.key

  # Derive the public key (this is what the kernel will be told to trust)
  openssl pkey -in operator.key -pubout -outform DER \
    | tail -c 32 \
    | xxd -p -c 256 \
    > operator.pub.hex

  cat operator.pub.hex
  # 64 hex characters representing the raw 32-byte Ed25519 public key
  ```

  Keep `operator.key` in a secure location — a hardware security module,
  a cloud KMS, or at minimum an offline encrypted backup. The kernel
  itself never sees this file. You will only ever feed it the public
  key, never the private key.

- **`curl`** and **`jq`** for the smoke tests.

## Install

```bash
cargo install qorch-safety-kernel
qorch-safety-kernel --version
```

The install pulls the published crate, builds it locally, and places
the `qorch-safety-kernel` binary in `~/.cargo/bin/`. Confirm
`~/.cargo/bin` is on your `PATH`.

## Run

Start the kernel bound to localhost, telling it which operator public
key to trust:

```bash
qorch-safety-kernel \
  --operator-pubkey "$(cat operator.pub.hex)" \
  --bind 127.0.0.1:9000
```

The kernel logs its startup banner, the public-key fingerprint it just
loaded, and `listening on 127.0.0.1:9000`. Leave it running in this
terminal; the rest of the walkthrough uses a second terminal.

## Smoke test

In a second terminal, verify the kernel is up and responding:

```bash
curl -fsS http://127.0.0.1:9000/health | jq
```

Expected response:

```json
{
  "ok": true,
  "version": "1.0.0",
  "uptime_s": 4.21
}
```

Now request an authorization for a sample action:

```bash
curl -fsS http://127.0.0.1:9000/kernel/v1/authorize \
  -H 'content-type: application/json' \
  -H "x-api-key: $KERNEL_WORKER_API_KEY" \
  -d '{
    "action": "example.read_report",
    "run_id": "smoke-test-001",
    "subject": "smoke-test-worker",
    "params_fingerprint": "0000000000000000000000000000000000000000000000000000000000000000"
  }' | jq
```

Expected response (truncated):

```json
{
  "ok": true,
  "token": "eyJ...<compact Ed25519-signed JWT>...",
  "token_sha256": "a1b2c3...",
  "claims": {
    "action": "example.read_report",
    "run_id": "smoke-test-001",
    "subject": "smoke-test-worker",
    "exp": 1700000000
  }
}
```

The `token` field is the short-lived signed authorization. Your
application code passes it along when it actually invokes the protected
action — see the dispatch-hook integration in
[architecture.md § four defense seams](../architecture.md#the-four-defense-seams).

## Add the FastAPI middleware

For a Python application, install the reference middleware:

```bash
pip install qorch-safety-kernel-py
```

Wire it into a FastAPI app:

```python
from fastapi import FastAPI
from qorch_safety_kernel_py import SafetyKernelMiddleware

app = FastAPI()
app.add_middleware(
    SafetyKernelMiddleware,
    kernel_url="http://127.0.0.1:9000",
    api_key=os.environ["KERNEL_WORKER_API_KEY"],
    fail_closed=True,  # never set this to False in production
)

@app.post("/do-thing")
async def do_thing():
    # Reaching this handler means the kernel said ALLOW.
    return {"status": "done"}
```

The middleware checks every request against the kernel before any
handler runs. The full reference (configuration knobs, exception
hierarchy, testing helpers) is in
[`python-fastapi.md`](python-fastapi.md).

## Verify fail-closed behavior

This is the most important test. The kernel's whole job is to deny when
it cannot make a definite decision — confirm that yourself.

With the FastAPI app running and the kernel running, a request to
`/do-thing` returns `200`. Now kill the kernel (Ctrl+C in the first
terminal) and retry:

```bash
curl -i -X POST http://127.0.0.1:8000/do-thing
```

Expected response:

```
HTTP/1.1 503 Service Unavailable
content-type: application/json

{"error":"safety_kernel_unreachable","fail_closed":true}
```

If you see a `200` here, the integration is **not** fail-closed. Stop,
re-read the middleware configuration, and confirm `fail_closed=True` is
set and no exception handler is swallowing the `KernelUnavailable`
error.

Restart the kernel and the call recovers automatically — no need to
restart the app.

## Verify a successful call lands in the transparency log

Make one more successful call, then query the log:

```bash
curl -fsS http://127.0.0.1:9000/log/v1/entries?limit=5 | jq
```

You should see the most recent decisions, each with:

- `entry_id` — monotonically increasing
- `action`, `run_id`, `subject` — matching what you authorized
- `signature` — Ed25519 signature over the entry
- `prev_hash` — chain pointer to the previous entry

The log is append-only and externally verifiable; see
[`reconciler-and-transparency-log.md`](reconciler-and-transparency-log.md)
for the verifier walkthrough.

## Common pitfalls

- **Clock skew.** Decision tokens carry a 5-minute expiration. If the
  agent host and the kernel host disagree on the wall clock by more
  than a few seconds, the agent will reject freshly-minted tokens as
  "already expired" (or, worse, as "issued in the future"). Run NTP on
  both hosts.

- **Missing operator pubkey.** Forgetting `--operator-pubkey` makes the
  kernel refuse to start. This is intentional: a kernel with no pinned
  operator key has no anchor of trust and would be worse than no
  kernel at all.

- **Setting `fail_closed=False`.** The middleware accepts this flag for
  local development and testing. **Never set it to `False` in
  production.** A kernel running with fail-open middleware in front of
  it provides exactly zero of the kernel's stated guarantees.

- **API key reuse across roles.** The kernel distinguishes worker, API,
  and operator roles by pre-shared key. Using the worker key from the
  middleware *and* from the operator approval workflow collapses two
  trust domains into one. Provision a distinct key per role.

- **Kernel behind a permissive proxy.** If you front the kernel with a
  proxy that returns cached `200`s on errors, you have replaced
  fail-closed with fail-open. The kernel must reach the caller's
  middleware with its real status code on every request.

## Next steps

- [architecture.md § four defense seams](../architecture.md#the-four-defense-seams)
  — wiring the dispatch hook (seam 3) and the nginx `auth_request`
  gate (seam 1).
- [`reconciler-and-transparency-log.md`](reconciler-and-transparency-log.md)
  — verifying log entries from outside the kernel.
- [`../security/threat-model.md`](../security/threat-model.md) — the
  full threat model the kernel is designed against.
