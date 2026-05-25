"""Tests for :func:`_warm_stdlib_deps` (the architecture overview re-entrancy
mitigation).

The hook's HTTP call goes through :mod:`urllib.request`, which lazily
imports :mod:`http.client`, :mod:`ssl`, :mod:`socket`. If any of those
imports fire on the FIRST kernel call, the re-entrancy guard catches
it but only after the modules have already loaded INSIDE the guarded
path (i.e. unauthorized). The warm-up moves those imports BEFORE
``sys.addaudithook`` arms.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

import importlib

from safety_kernel_defense import install_audit_hook
from safety_kernel_defense.install_audit_hook import _warm_stdlib_deps

# Bypass __init__.py's function shadowing of the module name.
_install_mod = importlib.import_module("safety_kernel_defense.install_audit_hook")


def test_warm_stdlib_deps_loads_urllib_transitive_closure() -> None:
    """After :func:`_warm_stdlib_deps`, every module the hook's HTTP
    call needs is in :data:`sys.modules`."""
    _warm_stdlib_deps()
    required = [
        "http.client",
        "socket",
        "ssl",
        "urllib.parse",
        "urllib.response",
        "urllib.request",
    ]
    for mod in required:
        assert mod in sys.modules, f"warm-up failed: {mod} not in sys.modules"


def test_install_calls_warm_up_before_addaudithook(
    mock_kernel: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``install_audit_hook`` must call ``_warm_stdlib_deps`` BEFORE
    ``sys.addaudithook``. We monkey-patch both, record the call
    order, and assert.
    """
    order: list[str] = []
    install_mod = _install_mod

    real_warm = install_mod._warm_stdlib_deps
    real_addaudit = sys.addaudithook

    def tracer_warm() -> None:
        order.append("warm")
        real_warm()

    def tracer_addaudit(cb: Any) -> None:
        order.append("addaudithook")
        real_addaudit(cb)

    monkeypatch.setattr(install_mod, "_warm_stdlib_deps", tracer_warm)
    monkeypatch.setattr(sys, "addaudithook", tracer_addaudit)

    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        timeout_seconds=2.0,
    )

    assert order == ["warm", "addaudithook"], (
        f"warm-up must precede addaudithook; got order={order}"
    )


def test_warm_idempotent() -> None:
    """Calling :func:`_warm_stdlib_deps` twice does not raise."""
    _warm_stdlib_deps()
    _warm_stdlib_deps()  # second call must be a no-op.


def test_kill_switch_skips_warm_up(
    mock_kernel: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """the architecture overview: when the kill switch is active, the hook never
    arms — so we MUST NOT spend the warm-up cost either. Verify by
    monkey-patching ``_warm_stdlib_deps`` to record invocations."""
    monkeypatch.setenv("ARYA_AUDIT_HOOK_DISABLED", "1")
    install_mod = _install_mod

    warm_calls = {"count": 0}
    real_warm = install_mod._warm_stdlib_deps

    def tracer_warm() -> None:
        warm_calls["count"] += 1
        real_warm()

    monkeypatch.setattr(install_mod, "_warm_stdlib_deps", tracer_warm)

    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
    )
    assert warm_calls["count"] == 0, (
        "kill-switch path must skip the warm-up to keep its cost zero"
    )
