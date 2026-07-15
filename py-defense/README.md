# safety-kernel-defense

Python audit-hook + FastAPI middleware reference for the
[safety-kernel](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel)
authorization service.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel/blob/main/LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)

The Layer-1 in-process defender for Python applications calling the
safety-kernel. Stdlib-only at runtime — no `httpx`, `requests`, or
`fastapi` runtime dependencies. Designed to be loaded as early as
possible in the interpreter's lifecycle so the audit-event seam
catches import / exec / compile events before any application code
runs.

## What this does

- **`install_audit_hook(...)`** — registers a `sys.addaudithook`
  callback that forwards `import`, `exec`, and `compile` audit events
  to the kernel's `/policy/module/authorize` endpoint. Fail-closed
  by default: if the kernel is unreachable, the audit event is denied
  and the calling action (typically an `import`) raises.
- **`wrap_subprocess(...)` / `wrap_multiprocessing(...)`** — wrap
  `subprocess.Popen` and `multiprocessing.Process` so child processes
  inherit the kernel configuration via environment variables.
- **Canonical event fingerprinting** — bit-identical to the kernel's
  Rust `params_fingerprint` (SHA-256 over a canonicalized JSON of the
  event tuple). The mock kernel in the source tree verifies this
  contract.

## Quickstart

```bash
pip install safety-kernel-defense
```

```python
from safety_kernel_defense import install_audit_hook

install_audit_hook(
    kernel_url="https://your-kernel-host:9443",
    worker_api_key=os.environ["KERNEL_API_KEY"],
    caller_subject="my-app-1.2.3",
    caller_run_id="run-abc",
    timeout_seconds=2.0,
)

# From this point on, any `import some_module` triggers an audit
# event POST to the kernel. The kernel either allows the import or
# raises ImportError(__cause__=PolicyDenied(...)).
```

## Configuration

| Argument | Type | Default | Notes |
|---|---|---|---|
| `kernel_url` | `str` | — | base URL of the kernel (e.g. `https://kernel.local:9443`) |
| `worker_api_key` | `str` | — | per-caller API key |
| `caller_subject` | `str` | — | identifier reported on every audit event |
| `caller_run_id` | `str` | — | run-scoped correlation id |
| `timeout_seconds` | `float` | `2.0` | per-event HTTP budget |
| `fail_closed_on_unreachable` | `bool` | `True` | deny on kernel-unavailable; set `False` only with explicit operator approval |
| `audited_event_kinds` | `tuple[str, ...]` | `("import", "exec", "compile")` | which `sys.audit` events to forward |
| `event_metadata_max_bytes` | `int` | `8192` | cap on per-event metadata payload |

## Kill-switch

Set `ARYA_AUDIT_HOOK_DISABLED=1` to no-op the install. The hook never
arms; the kernel records a `hook_install_violation` chain entry (when
reachable) so the operator has an audit trail of the disablement. Use
only for emergency operational scenarios.

## FastAPI middleware

For HTTP-request-level enforcement (rather than per-import), see
the FastAPI middleware reference in the safety-kernel repo's
`examples/middleware/fastapi_safety_middleware.py` and the
[python-fastapi integration guide](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel/blob/main/docs/integration/python-fastapi.md).

## Architecture

The audit hook is one of four defense seams. See
[`docs/architecture.md`](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel/blob/main/docs/architecture.md)
in the upstream repo for the full design.

```
   Agent / API client
        │
        ▼
   nginx auth_request   ← coarse network-layer gate
        │
        ▼
   App middleware       ← app-layer gate (FastAPI / axum)
        │
        ▼
   Dispatch hook        ← per-tool gate (defense-in-depth)
        │
        ▼
   Client SDK           ← circuit breaker, fail-closed on Unavailable
        │
        ▼
   Safety Kernel  ←→  Transparency log (Ed25519, append-only)
```

This package implements the **Dispatch hook** and **Client SDK** layers
(plus the audit-hook variant that catches import events).

## Testing

The package ships with an in-process mock kernel (stdlib HTTP server)
so you can run the test suite locally without a live kernel:

```bash
pip install safety-kernel-defense[test]
pytest safety_kernel_defense/tests/
```

## Publishing (maintainers)

Releases are published to [PyPI](https://pypi.org/project/safety-kernel-defense/)
by the `publish-pypi.yml` GitHub Actions workflow using **Trusted Publishing**
(OIDC) — no API token is stored in the repo.

**One-time PyPI setup** (before the first release): on PyPI, add a *pending
publisher* for project `safety-kernel-defense` bound to
owner `ARYA-Labs-Public`, repository `unfireable-safety-kernel`,
workflow `publish-pypi.yml`, environment `pypi`
(PyPI → *Your projects* → *Publishing* → *Add a pending publisher*).

**To cut a release:**

1. Bump `version` in `py-defense/pyproject.toml` (and `__version__` in
   `safety_kernel_defense/__init__.py`).
2. Publish a GitHub Release with tag `pydefense-v<version>` (e.g.
   `pydefense-v0.1.0`). The workflow builds, runs `twine check --strict`,
   asserts the tag matches the package version, and publishes.

A dry run to TestPyPI is available via *Run workflow* → target `testpypi`
(requires a matching TestPyPI pending publisher + a `testpypi` environment).

## Security

Report security issues privately to
**security@aryalabs.io**. See the upstream
[SECURITY.md](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel/blob/main/SECURITY.md)
for the full policy.

## License

Apache-2.0 — see
[LICENSE](https://github.com/ARYA-Labs-Public/unfireable-safety-kernel/blob/main/LICENSE)
in the upstream repo.
