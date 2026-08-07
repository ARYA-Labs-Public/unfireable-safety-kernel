# Getting started

A ~10-minute walkthrough that takes you from a clean machine to a running
Safety Kernel, a smoke-tested authorize call, a working FastAPI
integration, and a verified fail-closed behavior when the kernel is
killed.

## Prerequisites

- **Rust 1.85 or newer.** Install via [rustup](https://rustup.rs/):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  rustc --version  # should print 1.85.0 or later
  ```

- **Kernel boot secrets.** The kernel is configured entirely by
  environment variables — there is no CLI flag parser and no config file.
  Two secrets are required in every environment, and they are
  **base64url-encoded 32 bytes** (base64url, not standard base64 — the
  kernel rejects `/` and `+`):

  ```bash
  # The kernel's Ed25519 signing key (used to sign decision tokens).
  export QORCH_KERNEL_SIGNING_KEY_B64=$(python3 -c \
    "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode())")

  # HMAC pepper for audit-log entries.
  export QORCH_KERNEL_AUDIT_PEPPER_B64=$(python3 -c \
    "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode())")
  ```

  Keep these in a secret manager for anything beyond a local smoke test.
  In production (`QORCH_ENV=prod`) the kernel refuses `KERNEL_KEY_BACKEND=env`
  and fetches the seed from a managed backend instead — see
  [`../deployment/key-management.md`](../deployment/key-management.md).

- **Per-role API keys.** The kernel distinguishes caller roles by
  pre-shared key: `QORCH_KERNEL_API_KEY_WORKER` and
  `QORCH_KERNEL_API_KEY_API` are required to boot;
  `QORCH_KERNEL_API_KEY_OPERATOR` is required only when `QORCH_ENV=prod`.
  For this walkthrough:

  ```bash
  export QORCH_KERNEL_API_KEY_WORKER=dev-worker-key
  export QORCH_KERNEL_API_KEY_API=dev-api-key
  ```

- **`curl`** and **`jq`** for the smoke tests.

## Install

The crate is not on crates.io yet. Build from this repo:

```bash
git clone https://github.com/ARYA-Labs-Public/unfireable-safety-kernel.git
cd safety-kernel
cargo build --release -p qorch-safety-kernel
```

The resulting binary lives at `target/release/qorch-safety-kernel`.
Copy it to a directory on your `PATH` if you prefer:

```bash
install -m 0755 target/release/qorch-safety-kernel ~/.local/bin/
```

(Prefer a container? The published image runs the same binary — see
[`../deployment/docker.md`](../deployment/docker.md).)

## Run

The kernel takes **no CLI flags** — it reads everything from the
environment. With the four env vars from the prerequisites exported
(`QORCH_KERNEL_SIGNING_KEY_B64`, `QORCH_KERNEL_AUDIT_PEPPER_B64`,
`QORCH_KERNEL_API_KEY_WORKER`, `QORCH_KERNEL_API_KEY_API`), start it
bound to localhost:

```bash
QORCH_ENV=dev \
QORCH_KERNEL_LISTEN_ADDR=127.0.0.1:9000 \
  ./target/release/qorch-safety-kernel
```

The kernel logs its startup banner and begins listening on
`127.0.0.1:9000`. If any required secret is missing it exits immediately
with `Error: missing <VAR>` — that fail-fast is intentional: a kernel with
no signing key has no anchor of trust. Leave it running in this terminal;
the rest of the walkthrough uses a second terminal.

The full env-var contract is in
[`crates/services/safety-kernel/src/settings.rs`](../../crates/services/safety-kernel/src/settings.rs);
[`../deployment/docker.md`](../deployment/docker.md) summarizes the common
ones.

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
  -H "x-api-key: $QORCH_KERNEL_API_KEY_WORKER" \
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

For a Python application, install the reference middleware (the `fastapi`
extra pulls the transport + signature-verification deps):

```bash
pip install "safety-kernel-defense[fastapi]"
```

Wire it into a FastAPI app:

```python
import os

from fastapi import FastAPI
from safety_kernel_defense import SafetyKernelMiddleware

app = FastAPI()
app.add_middleware(
    SafetyKernelMiddleware,
    kernel_url="http://127.0.0.1:9000",
    worker_api_key=os.environ["QORCH_KERNEL_API_KEY_WORKER"],
    operator_pubkey_hex=os.environ["KERNEL_TOKEN_PUBKEY_HEX"],
    gated_path_prefixes=("/api/v1/write/", "/api/v1/execute/"),
)

@app.post("/api/v1/write/do-thing")
async def do_thing():
    # Reaching this handler means the kernel said ALLOW and its signature
    # verified against operator_pubkey_hex.
    return {"status": "done"}
```

Only requests whose path starts with a `gated_path_prefixes` entry are
authorized; everything else passes through. There is **no `fail_closed`
flag** — the middleware is unconditionally fail-closed (an unreachable
kernel, a bad signature, or an open circuit breaker all deny). The full
reference (all tunables, the exact error shape, per-route opt-out, the
circuit breaker, and the revoke-client SDK) is in
[`python-fastapi.md`](python-fastapi.md).

### The `operator_pubkey_hex` value

`operator_pubkey_hex` is the 32-byte raw Ed25519 public key (64 hex chars)
the middleware uses to verify the signature on every `ALLOW` token. Fetch
the key that the kernel signs decision tokens with from its public-key
endpoint and convert base64 → hex:

```bash
export KERNEL_TOKEN_PUBKEY_HEX=$(curl -fsS http://127.0.0.1:9000/kernel/v1/public_key \
  | jq -r .public_key_b64 | base64 -d | xxd -p -c 256)
```

> **Naming caveat (flagged, not invented).** The middleware parameter is
> named `operator_pubkey_hex`, but the kernel signs `/kernel/v1/authorize`
> decision tokens with its **own** signing key
> (`QORCH_KERNEL_SIGNING_KEY_B64`) — the one surfaced by
> `GET /kernel/v1/public_key`. There is **no separate operator-public-key
> env var** in the kernel's settings
> (`crates/services/safety-kernel/src/settings.rs`); the only operator-scoped
> setting is the operator *API key* (`QORCH_KERNEL_API_KEY_OPERATOR`,
> required in prod). So in the reference deployment, feed
> `operator_pubkey_hex` the kernel's own token-verification public key
> (above). If your deployment has a distinct operator key sign decision
> tokens, feed that key's hex instead. This mapping is not fully pinned by
> the current kernel code and may be tightened in a later release.

## Verify fail-closed behavior

This is the most important test. The kernel's whole job is to deny when
it cannot make a definite decision — confirm that yourself.

With the FastAPI app running and the kernel running, a request to
`/api/v1/write/do-thing` returns `200`. Now kill the kernel (Ctrl+C in the
first terminal) and retry:

```bash
curl -i -X POST http://127.0.0.1:8000/api/v1/write/do-thing
```

Expected response:

```
HTTP/1.1 503 Service Unavailable
content-type: application/json

{"error_code":"kernel_unavailable","detail":"...","fail_closed":true}
```

If you see a `200` here, the integration is **not** fail-closed. Stop and
confirm the path is actually inside `gated_path_prefixes` and that no
exception handler is swallowing the middleware's 503. The middleware has
no fail-open mode to misconfigure — an unreachable kernel always denies.

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
[`architecture.md` § transparency log](../architecture.md#transparency-log)
for how entries are verified against the operator public key.

## Common pitfalls

- **Clock skew.** Decision tokens carry a 5-minute expiration. If the
  agent host and the kernel host disagree on the wall clock by more
  than a few seconds, the agent will reject freshly-minted tokens as
  "already expired" (or, worse, as "issued in the future"). Run NTP on
  both hosts.

- **Missing boot secrets.** Forgetting `QORCH_KERNEL_SIGNING_KEY_B64` (or
  any required var) makes the kernel exit immediately with
  `Error: missing <VAR>`. This is intentional: a kernel with no signing
  key has no anchor of trust and would be worse than no kernel at all.

- **Standard base64 for the key/pepper.** `QORCH_KERNEL_SIGNING_KEY_B64`
  and `QORCH_KERNEL_AUDIT_PEPPER_B64` are **base64url** — the kernel
  rejects `/` and `+`. Generate them with the `urlsafe_b64encode` snippet
  in the prerequisites, not plain `base64`.

- **Wrong `operator_pubkey_hex`.** If the hex you pin does not match the
  key the kernel signs tokens with, every `ALLOW` fails signature
  verification and the middleware returns `503 signature_invalid`. Pull it
  from `GET /kernel/v1/public_key` (see "The `operator_pubkey_hex` value"
  above) rather than typing it by hand.

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
- [`architecture.md` § transparency log](../architecture.md#transparency-log)
  — verifying log entries from outside the kernel.
- **The paper, § 2** — the full threat model the kernel is designed
  against (see the [README](../../README.md#paper) for the arXiv reference).
