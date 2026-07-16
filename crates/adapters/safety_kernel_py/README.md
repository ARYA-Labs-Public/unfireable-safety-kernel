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

## Quickstart

```bash
pip install safety-kernel-client
```

```python
from safety_kernel_client import params_fingerprint, PinnedKeyVerifier

fp = params_fingerprint({"action": "deploy", "target": "prod-1"})

verifier = PinnedKeyVerifier(pinned_pubkey_bytes)  # 32-byte Ed25519 public key
claims = verifier.verify(token, now_epoch_seconds)  # raises on ANY failure
# claims -> {"token": ..., "claims": {...}, "signature_b64": ...}
```

## Build from source

```bash
pip install maturin
maturin develop            # from crates/adapters/safety_kernel_py/
```

The wheel is `abi3-py310` — one binary spans CPython 3.10+.

## License

Apache-2.0 — see [LICENSE](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel/blob/main/LICENSE).
