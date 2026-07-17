# safety-kernel-client

Python binding for the [Unfireable Safety Kernel](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel)
Rust primitives, built with PyO3. The public surface is the **real Rust code**,
compiled — not a Python reimplementation.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel/blob/main/LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)

## What this exposes

- **`params_fingerprint(params: dict) -> str`** — the canonical
  `sha256_hex(stable_json(params))` fingerprint the kernel recomputes
  server-side to bind a token to its exact params. Byte-identical to the Rust
  `qorch_domain::safety::token::params_fingerprint`.
- **`PinnedKeyVerifier`** — the **offline** Ed25519 receipt verifier. Verify a
  kernel authorization token against a pinned public key with **no network
  call**. Every verification failure (bad signature, expiry, missing claim,
  wrong audience) raises `ValueError` — treat a raise as a hard refusal
  (fail-closed).
- **`SafetyKernelClient`** — the signature-verifying, circuit-broken HTTP
  client. `authorize(...)` performs `POST /kernel/v1/authorize`, verifies the
  returned token against the pinned key, and is **fail-closed**: ALLOW returns
  a dict, DENY raises `PermissionError`, and an unreachable kernel / open
  circuit breaker / bad signature raises `ConnectionError`. A raise is never an
  ALLOW.

## Quickstart

```bash
pip install safety-kernel-client
```

```python
from safety_kernel_client import params_fingerprint, PinnedKeyVerifier, SafetyKernelClient

fp = params_fingerprint({"action": "deploy", "target": "prod-1"})

# Offline receipt verification (no network):
verifier = PinnedKeyVerifier(pinned_pubkey_bytes)  # 32-byte Ed25519 public key
claims = verifier.verify(token, now_epoch_seconds)  # raises on ANY failure
# claims -> {"token": ..., "claims": {...}, "signature_b64": ...}

# Live authorization (fail-closed):
client = SafetyKernelClient(
    "https://kernel.local:9443", api_key, pinned_pubkey_bytes, timeout_ms=2000
)
decision = client.authorize("deploy", fp, run_id="run-1", subject="worker")
# ALLOW -> {"decision": "allow", "token", "claims", "signature_b64"}
# DENY  -> raises PermissionError; unreachable/bad-signature -> raises ConnectionError
```

## Build from source

```bash
pip install maturin
maturin develop            # from crates/adapters/safety_kernel_py/
```

The wheel is `abi3-py310` — one binary spans CPython 3.10+.

## License

Apache-2.0 — see [LICENSE](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel/blob/main/LICENSE).
