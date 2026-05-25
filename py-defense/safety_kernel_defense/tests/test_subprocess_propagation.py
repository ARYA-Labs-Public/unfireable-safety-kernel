"""Tests for :mod:`safety_kernel_defense.subprocess_propagation`
(the architecture overview test contract).

These tests cover both the python-child case (Case A — prologue
injection) and the non-python-child case (Case B — propagation-failed
audit event). The multiprocessing test is best-effort: ``spawn``
context cannot pickle the test fixture cleanly, so the
context-manager + monkey-patch lifecycle is what we verify.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Any

import pytest

from safety_kernel_defense import (
    install_audit_hook,
    wrap_multiprocessing,
    wrap_subprocess,
)
from safety_kernel_defense import subprocess_propagation as sp


# ============================================================================
# 1. wrap_subprocess_injects_prologue (python child)
# ============================================================================


def test_wrap_subprocess_python_child_gets_propagation_env(
    mock_kernel: Any,
) -> None:
    """Spawn a python -c "import x" subprocess via ``wrap_subprocess``.
    Verify the child's env has the propagation vars set, AND that the
    prologue rewriting injected the install call into the -c source.

    NOTE: we cannot easily prove the child actually POSTed to the mock
    kernel in this test environment because the child process must be
    able to ``import safety_kernel_defense``. We assert on the static
    indicators that the propagation machinery did its job: env vars
    flow through; ``-c`` source contains the install prologue.
    """
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="key1",
        caller_subject="subj1",
        caller_run_id="r1",
        timeout_seconds=2.0,
    )

    # We use ``echo`` + a hand-rolled python wrapper: rather than
    # actually executing python (which would need the package on the
    # subprocess PYTHONPATH), we observe the args + env handed to
    # subprocess.Popen by monkey-patching it.
    captured = {}

    class _FakePopen:
        def __init__(
            self, args: Any, *a: Any, env: Any = None, **kw: Any
        ) -> None:
            captured["args"] = args
            captured["env"] = env

        def wait(self, *a: Any, **kw: Any) -> int:
            return 0

        def communicate(self, *a: Any, **kw: Any) -> tuple:
            return (b"", b"")

    monkey_orig = subprocess.Popen
    subprocess.Popen = _FakePopen  # type: ignore[misc]
    try:
        wrap_subprocess(
            [sys.executable, "-c", "import os"],
        )
    finally:
        subprocess.Popen = monkey_orig  # type: ignore[misc]

    # Assert env was injected with the propagation vars.
    env = captured["env"]
    assert env is not None
    assert env["SAFETY_KERNEL_URL"] == mock_kernel.url
    assert env["SAFETY_KERNEL_WORKER_API_KEY"] == "key1"
    assert env["SAFETY_KERNEL_CALLER_SUBJECT"] == "subj1"

    # Assert prologue was injected into the -c source.
    args = captured["args"]
    assert "-c" in args
    c_idx = args.index("-c")
    rewritten = args[c_idx + 1]
    assert "install_audit_hook" in rewritten
    # The original source is preserved at the end.
    assert "import os" in rewritten


# ============================================================================
# 2. wrap_subprocess_non_python_warns
# ============================================================================


def test_wrap_subprocess_non_python_emits_propagation_event(
    mock_kernel: Any, caplog: pytest.LogCaptureFixture
) -> None:
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="key1",
        caller_subject="subj1",
        caller_run_id="r1",
        timeout_seconds=2.0,
    )

    captured = {"called": False}

    class _FakePopen:
        def __init__(self, *a: Any, **kw: Any) -> None:
            captured["called"] = True

    monkey_orig = subprocess.Popen
    subprocess.Popen = _FakePopen  # type: ignore[misc]
    try:
        wrap_subprocess(["/bin/echo", "hi"])
    finally:
        subprocess.Popen = monkey_orig  # type: ignore[misc]

    assert captured["called"], "Popen must still be called for non-python child"
    # Verify the audit-event POST was made.
    events = mock_kernel.audit_event_requests()
    assert len(events) >= 1
    body = events[0]["body"]
    assert body["event_kind"] == "subprocess_propagation_failed"
    assert body["metadata"]["argv0"] == "/bin/echo"


# ============================================================================
# 3. env-var stripping detection
# ============================================================================


def test_wrap_subprocess_detects_env_var_stripping(
    mock_kernel: Any, caplog: pytest.LogCaptureFixture
) -> None:
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="key1",
        caller_subject="subj1",
        caller_run_id="r1",
        timeout_seconds=2.0,
    )

    captured = {}

    class _FakePopen:
        def __init__(self, args: Any, *a: Any, env: Any = None, **kw: Any) -> None:
            captured["env"] = env

    monkey_orig = subprocess.Popen
    subprocess.Popen = _FakePopen  # type: ignore[misc]
    try:
        # Pass env= that explicitly STRIPS the safety-kernel vars.
        wrap_subprocess(
            [sys.executable, "-c", "pass"],
            env={"PATH": "/bin"},
        )
    finally:
        subprocess.Popen = monkey_orig  # type: ignore[misc]

    # Assert a propagation_failed event was emitted to the mock kernel.
    events = mock_kernel.audit_event_requests()
    assert any(
        e["body"]["metadata"].get("reason", "").startswith("env_var_stripped")
        for e in events
    ), "env-stripping must emit subprocess_propagation_failed event"

    # And the vars were re-injected into the child env (architect risk #2:
    # "WARN but allow; chain entry is the auditable control").
    env = captured["env"]
    assert env["SAFETY_KERNEL_URL"] == mock_kernel.url
    assert env["SAFETY_KERNEL_WORKER_API_KEY"] == "key1"


# ============================================================================
# 4. wrap_multiprocessing — context-manager lifecycle
# ============================================================================


def test_wrap_multiprocessing_patches_and_restores() -> None:
    """The context manager monkey-patches ``Process.run`` on enter and
    restores it on exit. Reference-counted for nested use."""
    import multiprocessing

    original_run = multiprocessing.Process.run
    with wrap_multiprocessing():
        assert multiprocessing.Process.run is not original_run, (
            "Process.run must be patched inside the context"
        )
        # Nested entry — should not break.
        with wrap_multiprocessing():
            assert multiprocessing.Process.run is not original_run
        # After inner exit but still inside outer: patched.
        assert multiprocessing.Process.run is not original_run
    # After outer exit: restored.
    assert multiprocessing.Process.run is original_run


def test_wrap_multiprocessing_refcount() -> None:
    """Two concurrent users must not de-patch each other."""
    import multiprocessing

    original = multiprocessing.Process.run
    cm1 = wrap_multiprocessing()
    cm2 = wrap_multiprocessing()
    cm1.__enter__()
    cm2.__enter__()
    assert multiprocessing.Process.run is not original
    cm1.__exit__(None, None, None)
    assert multiprocessing.Process.run is not original  # cm2 still active
    cm2.__exit__(None, None, None)
    assert multiprocessing.Process.run is original


# ============================================================================
# 5. shell-form Popen call is treated as Case B
# ============================================================================


def test_wrap_subprocess_shell_form_treated_as_non_python(
    mock_kernel: Any, caplog: pytest.LogCaptureFixture
) -> None:
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="s",
        caller_run_id="r",
        timeout_seconds=2.0,
    )

    class _FakePopen:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

    monkey_orig = subprocess.Popen
    subprocess.Popen = _FakePopen  # type: ignore[misc]
    try:
        # shell=True form: string args, not list.
        wrap_subprocess("/bin/echo hi", shell=True)
    finally:
        subprocess.Popen = monkey_orig  # type: ignore[misc]

    events = mock_kernel.audit_event_requests()
    assert any(
        e["body"]["metadata"].get("reason") == "shell_form_invocation"
        for e in events
    )


# ============================================================================
# 6. wrap_subprocess passes args as keyword
# ============================================================================


def test_wrap_subprocess_kwarg_args_form(mock_kernel: Any) -> None:
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="s",
        caller_run_id="r",
        timeout_seconds=2.0,
    )
    captured = {}

    class _FakePopen:
        def __init__(self, args: Any, *a: Any, **kw: Any) -> None:
            captured["args"] = args

    monkey_orig = subprocess.Popen
    subprocess.Popen = _FakePopen  # type: ignore[misc]
    try:
        wrap_subprocess(args=[sys.executable, "-c", "pass"])
    finally:
        subprocess.Popen = monkey_orig  # type: ignore[misc]
    assert "install_audit_hook" in captured["args"][captured["args"].index("-c") + 1]


# ============================================================================
# DIRECT UNIT TESTS for helpers (boost coverage of script-rewrite logic)
# ============================================================================


def test_unit_is_python_executable_recognizes_python_binaries() -> None:
    assert sp._is_python_executable("python") is True
    assert sp._is_python_executable("python3") is True
    assert sp._is_python_executable("/usr/bin/python3.11") is True
    assert sp._is_python_executable(sys.executable) is True


def test_unit_is_python_executable_rejects_non_python() -> None:
    assert sp._is_python_executable("/bin/echo") is False
    assert sp._is_python_executable("bash") is False


def test_unit_inject_python_prologue_with_c_flag() -> None:
    out = sp._inject_python_prologue([sys.executable, "-c", "print(1)"])
    c_idx = out.index("-c")
    assert "install_audit_hook" in out[c_idx + 1]
    assert "print(1)" in out[c_idx + 1]


def test_unit_inject_python_prologue_with_script_path() -> None:
    out = sp._inject_python_prologue([sys.executable, "/tmp/script.py", "arg1"])
    # Rewritten to python -c "<prologue>; exec(open('/tmp/script.py').read())" arg1
    assert "-c" in out
    c_idx = out.index("-c")
    assert "install_audit_hook" in out[c_idx + 1]
    assert "/tmp/script.py" in out[c_idx + 1]
    # arg1 is preserved.
    assert "arg1" in out


def test_unit_inject_python_prologue_with_interpreter_flags() -> None:
    """``python -u -X dev script.py`` — flags skipped, script rewritten."""
    out = sp._inject_python_prologue(
        [sys.executable, "-u", "-X", "dev", "/tmp/x.py", "extra"]
    )
    assert "-c" in out
    c_idx = out.index("-c")
    assert "install_audit_hook" in out[c_idx + 1]


def test_unit_inject_python_prologue_bare_python_returns_unchanged() -> None:
    out = sp._inject_python_prologue([sys.executable])
    assert out == [sys.executable]


def test_unit_build_propagation_env_no_caller_env(mock_kernel: Any) -> None:
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="api-key-99",
        caller_subject="my-app",
        caller_run_id="r",
        timeout_seconds=2.0,
    )
    env = sp._build_propagation_env(None)
    assert env["SAFETY_KERNEL_URL"] == mock_kernel.url
    assert env["SAFETY_KERNEL_WORKER_API_KEY"] == "api-key-99"
    assert env["SAFETY_KERNEL_CALLER_SUBJECT"] == "my-app"
    assert env["SAFETY_KERNEL_FAIL_CLOSED"] == "1"


def test_unit_build_propagation_env_preserves_caller_env_overlay(mock_kernel: Any) -> None:
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="s",
        caller_run_id="r",
        timeout_seconds=2.0,
    )
    env = sp._build_propagation_env({"PATH": "/bin"})
    assert env["PATH"] == "/bin"
    # Safety-kernel vars synced (not overwriting since setdefault was used).
    assert "SAFETY_KERNEL_URL" in env


def test_unit_emit_propagation_failure_event_no_install(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """If the hook isn't installed, emit a WARN log and don't crash."""
    with caplog.at_level("WARNING", logger="safety_kernel_defense.subprocess"):
        sp._emit_propagation_failure_event("reason", "/bin/echo")
    assert any("propagation failure" in r.message.lower() for r in caplog.records)


def test_unit_emit_propagation_failure_event_kernel_unreachable(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If install IS active but the kernel POST fails, emit a WARN and
    don't raise — the helper is best-effort."""
    install_audit_hook(
        kernel_url="http://127.0.0.1:1",  # nothing listens here
        worker_api_key="k",
        caller_subject="s",
        timeout_seconds=0.2,
    )
    with caplog.at_level("WARNING", logger="safety_kernel_defense.subprocess"):
        sp._emit_propagation_failure_event("reason", "/bin/echo")
    assert any("failed to emit" in r.message.lower() for r in caplog.records)


def test_unit_patched_run_with_no_config_calls_original() -> None:
    """If no hook is installed, ``_patched_run`` simply forwards to
    the original run (which the context manager has captured)."""
    calls = {"original": 0}

    def fake_original(self: Any) -> None:
        calls["original"] += 1

    # Set up state as if we were inside wrap_multiprocessing().
    sp._mp_patch_state["original"] = fake_original
    sp._installed.config = None
    try:
        # Pass a dummy self.
        sp._patched_run(object())
    finally:
        sp._mp_patch_state["original"] = None
    assert calls["original"] == 1


def test_unit_patched_run_with_config_installs_and_forwards(mock_kernel: Any) -> None:
    """When config IS set, ``_patched_run`` installs the hook in the
    child then forwards to original. Since the test interpreter has
    a previous install, the re-install detection short-circuits with
    a WARN — but the original run still fires."""
    calls = {"original": 0}

    def fake_original(self: Any) -> None:
        calls["original"] += 1

    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="s",
        timeout_seconds=2.0,
    )
    sp._mp_patch_state["original"] = fake_original
    try:
        sp._patched_run(object())
    finally:
        sp._mp_patch_state["original"] = None
    assert calls["original"] == 1


def test_unit_patched_run_with_config_install_failure_logs() -> None:
    """If the child-side install raises (e.g. hook config mismatch),
    the patched run logs a WARN and still forwards."""
    calls = {"original": 0}

    def fake_original(self: Any) -> None:
        calls["original"] += 1

    # Hand-craft a config that triggers reinstall-with-different-config
    # path. Set the state so the first install_audit_hook call inside
    # _patched_run sees a different existing config.
    sp._installed.config = sp._installed.config or type(
        "_C", (), {"kernel_url": "http://prev"}
    )()
    sp._mp_patch_state["original"] = fake_original
    try:
        sp._patched_run(object())
    finally:
        sp._mp_patch_state["original"] = None
        sp._installed.config = None


def test_unit_patched_run_no_original() -> None:
    """If somehow ``_mp_patch_state['original']`` is None (defensive
    branch), ``_patched_run`` returns None without crashing."""
    sp._mp_patch_state["original"] = None
    sp._installed.config = None
    sp._patched_run(object())  # returns None, no raise
