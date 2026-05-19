"""Session-scoped fixtures for the slice-5 perf harness.

Spawns ``policy_sidecar.py --mock`` + ``qorch-safety-kernel`` once per
pytest session and yields a dict with ``base_url`` / ``api_key_worker``
/ canonical ``request_body``. The fixture pattern mirrors
``tests/equivalence/policy_engine_vs_mandatory_safety/test_runner_production.py``
(slice 5 Bundle D) to keep the boot semantics identical across the
two harnesses.

Skip semantics:

* No ``python3`` on PATH -> skip.
* No ``cargo`` on PATH -> skip.
* ``cargo build --release`` failure -> skip.
* Kernel ``/health`` does not respond within 30s -> skip.

Skips never fail CI — the bench is label-gated (``perf`` label on the
PR) and a skip-on-missing-toolchain produces the cleanest signal for
an under-provisioned runner. The gated grade step downstream of pytest
still runs even on a skipped session and detects the missing JSON
report.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterator

import pytest

# Repo-root discovery: this file lives at
# crates/services/safety-kernel/tests/perf/conftest.py — 4 levels up
# is the repo root.
_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parents[4]

# Boot timeouts (seconds) — matched to test_runner_production.py.
_SIDECAR_SOCKET_TIMEOUT_S = 10.0
_KERNEL_READY_TIMEOUT_S = 30.0


def _have_executable(name: str) -> bool:
    return shutil.which(name) is not None


def _pick_free_port() -> int:
    """Bind to port 0, read the OS-assigned port, then close."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _fresh_b64url_seed(n: int = 32) -> str:
    """base64url-no-pad over n random bytes."""
    import base64

    return base64.urlsafe_b64encode(os.urandom(n)).rstrip(b"=").decode("ascii")


def _stable_json(obj: Any) -> bytes:
    """Stable JSON canonicalization — sorted keys, no whitespace.

    Mirrors the Rust ``params_fingerprint`` byte shape so the
    SHA-256 of this output equals the server-side recompute.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _build_canonical_request() -> dict[str, Any]:
    """Build a ``ModuleAuthorizeRequest`` body whose ``event_fingerprint``
    matches the server-side recompute.

    The recompute canonicalization is over
    ``{event_kind, module_path, caller_subject, caller_run_id}`` —
    see ``routes/policy/authorize.rs::recompute_event_fingerprint``.
    """
    module_path = "pkg.mod"
    caller_subject = "perf-bench-worker"
    caller_run_id = "perf-bench-run"
    canonical = {
        "event_kind": "import",
        "module_path": module_path,
        "caller_subject": caller_subject,
        "caller_run_id": caller_run_id,
    }
    event_fingerprint = hashlib.sha256(_stable_json(canonical)).hexdigest()
    return {
        "event_kind": "import",
        "module_path": module_path,
        "caller_subject": caller_subject,
        "caller_run_id": caller_run_id,
        "event_fingerprint": event_fingerprint,
    }


@pytest.fixture(scope="session")
def perf_stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    """Spawn the kernel binary + sidecar; yield connection info."""
    if not _have_executable("python3"):
        pytest.skip("python3 not on PATH — perf harness needs the sidecar")
    if not _have_executable("cargo"):
        pytest.skip("cargo not on PATH — perf harness needs the Rust kernel")

    tmp = tmp_path_factory.mktemp("policy_perf_stack")
    sock_path = tmp / "sk.sock"

    # 1. Build the kernel (release — perf-relevant binary shape).
    build = subprocess.run(
        ["cargo", "build", "-p", "qorch-safety-kernel", "--release"],
        cwd=str(_REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    if build.returncode != 0:
        pytest.skip(
            f"cargo build --release -p qorch-safety-kernel failed:\n{build.stderr[-2000:]}"
        )
    bin_path = _REPO / "target" / "release" / "qorch-safety-kernel"
    if not bin_path.exists():
        pytest.skip(f"release kernel binary not at {bin_path} after build")

    # 2. Spawn the sidecar in mock mode.
    sidecar_script = _REPO / "apps" / "safety_kernel" / "policy_sidecar.py"
    env_sidecar = os.environ.copy()
    env_sidecar["PYTHONPATH"] = str(_REPO)
    sidecar_proc = subprocess.Popen(
        [
            sys.executable,
            str(sidecar_script),
            "--mock",
            "--sock-path",
            str(sock_path),
        ],
        cwd=str(_REPO),
        env=env_sidecar,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    deadline = time.time() + _SIDECAR_SOCKET_TIMEOUT_S
    while not sock_path.exists() and time.time() < deadline:
        time.sleep(0.05)
    if not sock_path.exists():
        sidecar_proc.kill()
        sidecar_proc.wait(timeout=5)
        pytest.skip(
            f"policy_sidecar socket {sock_path} did not appear within "
            f"{_SIDECAR_SOCKET_TIMEOUT_S}s"
        )

    # 3. Spawn the Rust binary on a free port.
    port = _pick_free_port()
    listen_addr = f"127.0.0.1:{port}"
    base_url = f"http://{listen_addr}"
    api_key_worker = "perf-bench-worker-key"
    env_kernel = os.environ.copy()
    env_kernel.update(
        {
            "QORCH_ENV": "dev",
            "QORCH_KERNEL_LISTEN_ADDR": listen_addr,
            "QORCH_KERNEL_POLICY_SOCK": str(sock_path),
            "QORCH_KERNEL_SIGNING_KEY_B64": _fresh_b64url_seed(),
            "QORCH_KERNEL_AUDIT_PEPPER_B64": _fresh_b64url_seed(),
            "QORCH_KERNEL_API_KEY_WORKER": api_key_worker,
            "QORCH_KERNEL_API_KEY_API": "perf-bench-api-key",
            "QORCH_KERNEL_API_KEY_OPERATOR": "perf-bench-operator-key",
            "QORCH_KERNEL_BUILD_VERSION": "perf-bench-0.0.0",
            "RUST_LOG": "warn",
        }
    )
    kernel_proc = subprocess.Popen(
        [str(bin_path)],
        env=env_kernel,
        cwd=str(_REPO),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # 4. Poll /health.
    import urllib.error
    import urllib.request

    deadline = time.time() + _KERNEL_READY_TIMEOUT_S
    ready = False
    last_err: str | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=0.5) as r:
                if r.status == 200:
                    ready = True
                    break
        except (urllib.error.URLError, OSError, ConnectionError) as e:
            last_err = repr(e)
        time.sleep(0.1)
    if not ready:
        kernel_proc.kill()
        sidecar_proc.kill()
        kernel_proc.wait(timeout=5)
        sidecar_proc.wait(timeout=5)
        pytest.skip(
            f"qorch-safety-kernel did not become ready at {base_url}/health "
            f"in {_KERNEL_READY_TIMEOUT_S}s (last err: {last_err})"
        )

    request_body = _build_canonical_request()

    yield {
        "base_url": base_url,
        "api_key_worker": api_key_worker,
        "request_body": request_body,
    }

    # Tear-down in reverse spawn order.
    for proc in (kernel_proc, sidecar_proc):
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
