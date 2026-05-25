"""Test fixtures for ``safety_kernel_defense``.

Per the architecture overview: one MockKernel per test, OS-assigned port, fresh
``tmp_path`` already supplied by pytest. We also reset the
:mod:`safety_kernel_defense.install_audit_hook` module-level state
between tests since the hook is a process-singleton — every test
gets a clean slate.
"""

from __future__ import annotations

import os
import sys
from typing import Iterator

import pytest

# Ensure the package under test resolves before any 3rd-party plugin.
_PKG_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

import importlib  # noqa: E402

_install_mod = importlib.import_module("safety_kernel_defense.install_audit_hook")
from safety_kernel_defense.tests._mock_kernel import MockKernel  # noqa: E402


def _reset_hook_state() -> None:
    """Reset the module-level hook state — the hook is a singleton."""
    _install_mod._installed.config = None
    _install_mod._installed.armed = False
    # Best-effort: also clear any lingering thread-local guard.
    try:
        _install_mod._state.in_hook = False
    except AttributeError:
        pass


@pytest.fixture
def mock_kernel() -> Iterator[MockKernel]:
    """Yield a fresh MockKernel; tear down on test exit."""
    kernel = MockKernel()
    kernel.start()
    try:
        yield kernel
    finally:
        kernel.stop()


@pytest.fixture(autouse=True)
def _reset_hook_between_tests() -> Iterator[None]:
    """Auto-applied to every test: clean hook state before AND after.

    Note: we cannot remove a Python audit hook (PEP 578 / the architecture overview
    note 1). The reset clears ``_installed`` so a fresh
    :func:`install_audit_hook` call rearms cleanly. Stale audit hooks
    from earlier tests fire against ``_installed.config = None`` which
    is the fail-CLOSED-on-import path; we suppress this by also
    flipping the hook's reentrancy flag during reset.
    """
    _reset_hook_state()
    # Suppress any stray kill-switch leak across tests.
    os.environ.pop("ARYA_AUDIT_HOOK_DISABLED", None)
    yield
    _reset_hook_state()
    os.environ.pop("ARYA_AUDIT_HOOK_DISABLED", None)
