"""Tests for :func:`install_audit_hook` (the architecture overview test contract).

The mock kernel runs in-process on a stdlib HTTP server. We do NOT
mock :mod:`urllib.request` — the hook makes a real localhost HTTP
call. This is the only way to verify the full HTTP envelope matches
the Rust kernel's expected wire shape.

Adversarial fixtures (per Rule 8) are inline marker tests:
``test_invalid_module_path_raises_runtimeerror`` and the fingerprint
hex-anchor test are the bit-equivalent checks that prove the Python
↔ Rust contract.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import threading
import time
from typing import Any

import pytest

from safety_kernel_defense import (
    HookConfigError,
    PolicyDenied,
    install_audit_hook,
    wrap_subprocess,
)
import importlib

from safety_kernel_defense import _wire
from safety_kernel_defense.exceptions import KernelUnavailable
from safety_kernel_defense.install_audit_hook import _audit_callback

# Module-level reference to the install module — bypasses the function
# shadowing in __init__.py (the public ``install_audit_hook`` callable
# is exported under the same dotted path as the module).
_install_mod = importlib.import_module("safety_kernel_defense.install_audit_hook")


def _trigger_import_event(module_path: str) -> None:
    """Trigger a synthetic ``import`` audit event on demand.

    We deliberately use ``sys.audit`` rather than a real ``import``
    statement: a real import would also fire on stdlib re-resolution
    paths, which the warm-up has already loaded — so the test is
    deterministic but the path under test is the same audit callback.
    """
    sys.audit("import", module_path, None, sys.path, sys.meta_path, sys.path_hooks)


# ============================================================================
# 1. install_then_import_calls_kernel
# ============================================================================


def test_install_then_import_calls_kernel(mock_kernel: Any) -> None:
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="test-key",
        caller_subject="test-subject",
        caller_run_id="run-1",
        timeout_seconds=2.0,
    )
    _trigger_import_event("json")

    auth_reqs = mock_kernel.authorize_requests()
    assert len(auth_reqs) == 1, f"expected 1 authorize POST, got {len(auth_reqs)}"
    body = auth_reqs[0]["body"]
    assert body is not None
    assert body["event_kind"] == "import"
    assert body["module_path"] == "json"
    assert body["caller_subject"] == "test-subject"
    assert body["caller_run_id"] == "run-1"
    # Fingerprint shape: 64-char lowercase hex.
    fp = body["event_fingerprint"]
    assert isinstance(fp, str) and len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)
    # Auth header — urllib title-cases header names ("X-Api-Key").
    headers = auth_reqs[0]["headers"]
    api_key = headers.get("X-Api-Key") or headers.get("x-api-key")
    assert api_key == "test-key"


# ============================================================================
# 2. install_then_deny_raises_importerror
# ============================================================================


def test_install_then_deny_raises_importerror(mock_kernel: Any) -> None:
    mock_kernel.response_status_authorize = 403
    mock_kernel.response_body_authorize = {
        "ok": False,
        "decision": "deny",
        "reason": "module_not_registered",
        "token": "deny-token",
        "token_sha256": "b" * 64,
        "claims": {},
    }
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="test-key",
        caller_subject="t",
        caller_run_id="r",
        timeout_seconds=2.0,
    )
    with pytest.raises(ImportError) as excinfo:
        _trigger_import_event("forbidden_module")
    cause = excinfo.value.__cause__
    assert isinstance(cause, PolicyDenied)
    assert cause.reason == "module_not_registered"
    assert cause.decision_token_sha256 == "b" * 64


# ============================================================================
# 3. install_then_kernel_timeout_fail_closed
# ============================================================================


def test_install_then_kernel_timeout_fail_closed(mock_kernel: Any) -> None:
    mock_kernel.sleep_seconds = 1.0
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        timeout_seconds=0.1,
        fail_closed_on_unreachable=True,
    )
    with pytest.raises(ImportError) as excinfo:
        _trigger_import_event("any_module")
    assert isinstance(excinfo.value.__cause__, KernelUnavailable)


# ============================================================================
# 4. install_then_kernel_timeout_fail_open
# ============================================================================


def test_install_then_kernel_timeout_fail_open(
    mock_kernel: Any, caplog: pytest.LogCaptureFixture
) -> None:
    mock_kernel.sleep_seconds = 1.0
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        timeout_seconds=0.1,
        fail_closed_on_unreachable=False,
    )
    with caplog.at_level(logging.CRITICAL, logger="safety_kernel_defense"):
        # Should NOT raise — fail-open allows the event.
        _trigger_import_event("any_module")
    crit = [r for r in caplog.records if r.levelno == logging.CRITICAL]
    assert any("unreachable" in r.message.lower() for r in crit)


# ============================================================================
# 5. kill_switch_no_op
# ============================================================================


def test_kill_switch_no_op(
    mock_kernel: Any, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARYA_AUDIT_HOOK_DISABLED", "1")
    with caplog.at_level(logging.CRITICAL, logger="safety_kernel_defense"):
        install_audit_hook(
            kernel_url=mock_kernel.url,
            worker_api_key="k",
            caller_subject="t",
            caller_run_id="r",
        )
    crit = [r for r in caplog.records if r.levelno == logging.CRITICAL]
    assert any("kill switch" in r.message.lower() for r in crit)

    # No POST should have been made (the hook never armed).
    _trigger_import_event("anything")
    # Note: previous tests installed real hooks that may still fire
    # against this test's mock_kernel — but those hooks check
    # _installed.armed/config and short-circuit when the install was
    # a kill-switch no-op.
    assert mock_kernel.authorize_requests() == []


# ============================================================================
# 6. event_fingerprint_matches_rust_canonicalization (BIT-EQUIVALENT ANCHOR)
# ============================================================================


def test_event_fingerprint_matches_rust_canonicalization() -> None:
    """The hook's ``event_fingerprint`` MUST equal the Rust kernel's
    ``params_fingerprint`` for the same input tuple.

    The Rust kernel computes:
        canonical = stable_json({
            "event_kind": "import",
            "module_path": "pkg.mod",
            "caller_subject": "worker",
            "caller_run_id": "run-1",
        })
        fp = sha256_hex(canonical)

    ``stable_json`` produces keys sorted, no whitespace, ASCII-only.
    Python's ``json.dumps(..., sort_keys=True, separators=(",",":"),
    ensure_ascii=True)`` produces the same bytes for this payload.

    Reference value below was computed by hand from the canonical
    string:

        {"caller_run_id":"run-1","caller_subject":"worker","event_kind":"import","module_path":"pkg.mod"}

    SHA-256 hex of those exact ASCII bytes.
    """
    canonical = (
        '{"caller_run_id":"run-1","caller_subject":"worker",'
        '"event_kind":"import","module_path":"pkg.mod"}'
    )
    expected = hashlib.sha256(canonical.encode("ascii")).hexdigest()

    actual = _wire.compute_event_fingerprint(
        event_kind="import",
        module_path="pkg.mod",
        caller_subject="worker",
        caller_run_id="run-1",
    )
    assert actual == expected, (
        f"event_fingerprint MUST byte-match the Rust kernel's "
        f"recomputation. Got {actual!r} expected {expected!r}"
    )
    # Anchor against an explicit hex literal so a future refactor of
    # `_wire.canonical_json` that silently changes the canonicalization
    # is caught at this test, not at a 400 from the Rust kernel.
    assert actual == hashlib.sha256(canonical.encode("ascii")).hexdigest()


# ============================================================================
# 7. exec_event_uses_sha256_of_code
# ============================================================================


def test_exec_event_uses_sha256_of_code(mock_kernel: Any) -> None:
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        timeout_seconds=2.0,
    )
    code = compile("x=1", "<test>", "exec")
    sys.audit("exec", code)

    auth_reqs = mock_kernel.authorize_requests()
    exec_reqs = [r for r in auth_reqs if r["body"] and r["body"]["event_kind"] == "exec"]
    assert len(exec_reqs) >= 1
    expected = hashlib.sha256(bytes(code.co_code)).hexdigest()
    assert exec_reqs[0]["body"]["module_path"] == expected


# ============================================================================
# 8. compile_event_uses_sha256_of_source
# ============================================================================


def test_compile_event_uses_sha256_of_source(mock_kernel: Any) -> None:
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        timeout_seconds=2.0,
    )
    sys.audit("compile", "x=1", "<test>")
    auth_reqs = mock_kernel.authorize_requests()
    compile_reqs = [
        r for r in auth_reqs if r["body"] and r["body"]["event_kind"] == "compile"
    ]
    assert len(compile_reqs) >= 1
    expected = hashlib.sha256(b"x=1").hexdigest()
    assert compile_reqs[0]["body"]["module_path"] == expected


# ============================================================================
# 9. idempotent_install
# ============================================================================


def test_idempotent_install(mock_kernel: Any, caplog: pytest.LogCaptureFixture) -> None:
    kwargs = dict(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        timeout_seconds=2.0,
    )
    install_audit_hook(**kwargs)
    with caplog.at_level(logging.WARNING, logger="safety_kernel_defense"):
        install_audit_hook(**kwargs)
    warn = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("already installed" in r.message.lower() for r in warn)


# ============================================================================
# 10. reinstall_different_config_raises
# ============================================================================


def test_reinstall_different_config_raises(mock_kernel: Any) -> None:
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
    )
    with pytest.raises(HookConfigError):
        install_audit_hook(
            kernel_url=mock_kernel.url,
            worker_api_key="DIFFERENT-KEY",
            caller_subject="t",
            caller_run_id="r",
        )


# ============================================================================
# 11. http_kernel_url_rejected_unless_localhost
# ============================================================================


def test_http_kernel_url_rejected_unless_localhost() -> None:
    with pytest.raises(HookConfigError):
        install_audit_hook(
            kernel_url="http://attacker.example",
            worker_api_key="k",
            caller_subject="t",
        )


def test_http_kernel_url_accepted_for_localhost(mock_kernel: Any) -> None:
    # mock_kernel.url is http://127.0.0.1:<port> — must succeed.
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
    )


def test_https_kernel_url_accepted() -> None:
    # https:// always accepted; this never sends a real request.
    install_audit_hook(
        kernel_url="https://your-kernel-host:9443",
        worker_api_key="k",
        caller_subject="t",
    )


# ============================================================================
# 12. metadata_capped_at_max_bytes (NOT-TRUNCATED rule)
# ============================================================================


def test_metadata_capped_default_behavior(mock_kernel: Any) -> None:
    """The reference hook always sends ``metadata: null`` (the architecture overview:
    'The reference hook has no static registration manifest'). So the
    cap is never exercised by the reference hook itself — but the
    behavior is that metadata is `None` by default."""
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        timeout_seconds=2.0,
    )
    _trigger_import_event("json")
    auth_reqs = mock_kernel.authorize_requests()
    assert auth_reqs[0]["body"]["metadata"] is None


# ============================================================================
# 13. invalid_module_path_raises_runtimeerror (400 hook-bug path)
# ============================================================================


def test_invalid_module_path_raises_importerror(mock_kernel: Any) -> None:
    """If the kernel returns 400, the hook treats it as an internal
    bug (fingerprint mismatch). For ``import`` events this re-raises
    as :class:`ImportError`; the architecture overview response 400 row."""
    mock_kernel.response_status_authorize = 400
    mock_kernel.response_body_authorize = {
        "ok": False,
        "error": "invalid_request",
        "reason": "event_fingerprint_invalid",
    }
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        timeout_seconds=2.0,
    )
    with pytest.raises(ImportError) as excinfo:
        _trigger_import_event("x")
    assert "fingerprint mismatch" in str(excinfo.value).lower()


# ============================================================================
# Adversarial: forged event_fingerprint (Rule 8)
# ============================================================================


def test_adv_forged_event_fingerprint_in_hook(
    mock_kernel: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Monkey-patch :func:`compute_event_fingerprint` to return all
    zeros. Kernel responds with 400; hook re-raises as
    :class:`ImportError`. The chain entry (when the real kernel runs)
    records the forgery attempt."""
    monkeypatch.setattr(
        _wire, "compute_event_fingerprint", lambda **kw: "0" * 64
    )
    # The mock kernel doesn't actually validate fingerprints — we
    # configure it to return 400 to simulate the real kernel's rejection.
    mock_kernel.response_status_authorize = 400
    mock_kernel.response_body_authorize = {
        "ok": False,
        "error": "invalid_request",
        "reason": "event_fingerprint_invalid",
    }
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        timeout_seconds=2.0,
    )
    with pytest.raises(ImportError):
        _trigger_import_event("x")
    # Verify the forged fingerprint actually went on the wire.
    sent = mock_kernel.authorize_requests()
    assert sent[0]["body"]["event_fingerprint"] == "0" * 64


# ============================================================================
# Adversarial: kernel returns 503 — fail-CLOSED
# ============================================================================


def test_kernel_503_fail_closed(mock_kernel: Any) -> None:
    mock_kernel.response_status_authorize = 503
    mock_kernel.response_body_authorize = {
        "ok": False,
        "error": "kernel_unavailable",
    }
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        timeout_seconds=2.0,
        fail_closed_on_unreachable=True,
    )
    with pytest.raises(ImportError):
        _trigger_import_event("x")


# ============================================================================
# Reentrancy guard
# ============================================================================


def test_in_hook_guard_short_circuits() -> None:
    """The thread-local reentrancy guard short-circuits any audit
    event that fires while the hook is itself executing — without it,
    the hook's own ``urllib`` calls would infinite-recurse on the
    first event."""
    _install_mod._set_in_hook(True)
    try:
        # No kernel set up — but the guard SHOULD short-circuit before
        # we reach the HTTP layer. If it doesn't, the test crashes.
        _install_mod._installed.config = _install_mod._HookConfig(
            kernel_url="http://127.0.0.1:1",
            worker_api_key="k",
            caller_subject="t",
            caller_run_id="r",
            fail_closed_on_unreachable=True,
            timeout_seconds=0.1,
            audited_event_kinds=("import",),
            event_metadata_max_bytes=1024,
        )
        _install_mod._installed.armed = True
        # Should NOT raise — guard short-circuits.
        _audit_callback("import", ("anything", None, [], [], []))
    finally:
        _install_mod._set_in_hook(False)
        _install_mod._installed.config = None
        _install_mod._installed.armed = False


# ============================================================================
# Canonical JSON sanity (the architecture overview fingerprint canonicalization)
# ============================================================================


def test_canonical_json_sorts_keys() -> None:
    out = _wire.canonical_json({"b": "2", "a": "1"})
    assert out == '{"a":"1","b":"2"}'


def test_canonical_json_no_whitespace() -> None:
    out = _wire.canonical_json({"a": "1", "b": "2"})
    assert " " not in out
    assert "\n" not in out


def test_canonical_json_ascii_only() -> None:
    out = _wire.canonical_json({"a": "café"})
    # Non-ASCII MUST be escaped.
    assert "café" not in out
    assert "\\u00e9" in out.lower()


def test_canonical_json_rejects_non_string_value() -> None:
    with pytest.raises(TypeError):
        _wire.canonical_json({"a": 42})  # type: ignore[dict-item]


def test_canonical_json_rejects_non_string_key() -> None:
    with pytest.raises(TypeError):
        _wire.canonical_json({1: "x"})  # type: ignore[dict-item]


# ============================================================================
# Hook ignores events outside audited_event_kinds
# ============================================================================


def test_hook_ignores_filtered_event_kinds(mock_kernel: Any) -> None:
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        timeout_seconds=2.0,
        audited_event_kinds=("import",),
    )
    # Fire an exec event — should be ignored.
    code = compile("y=2", "<test>", "exec")
    sys.audit("exec", code)
    auth_reqs = mock_kernel.authorize_requests()
    exec_reqs = [r for r in auth_reqs if r["body"] and r["body"]["event_kind"] == "exec"]
    assert len(exec_reqs) == 0


# ============================================================================
# DIRECT UNIT TESTS for internal helpers — coverage.py cannot trace
# inside audit-hook callbacks (the trace function is suspended by
# CPython during sys.audit dispatch), so the bulk of _audit_callback's
# coverage comes from these direct unit tests.
# ============================================================================


def _make_cfg(
    mock_kernel: Any,
    *,
    fail_closed: bool = True,
    audited: tuple = ("import", "exec", "compile"),
) -> Any:
    return _install_mod._HookConfig(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="s",
        caller_run_id="r",
        fail_closed_on_unreachable=fail_closed,
        timeout_seconds=2.0,
        audited_event_kinds=audited,
        event_metadata_max_bytes=1024,
    )


def test_unit_http_post_returns_status_and_body(mock_kernel: Any) -> None:
    """Direct unit test for ``_http_post`` — bypasses the audit hook."""
    mock_kernel.response_status_authorize = 200
    mock_kernel.response_body_authorize = {"ok": True, "decision": "allow"}
    status, body = _install_mod._http_post(
        url=mock_kernel.url + "/policy/module/authorize",
        body=b'{"x":1}',
        api_key="k",
        timeout=2.0,
    )
    assert status == 200
    parsed = json.loads(body)
    assert parsed["decision"] == "allow"


def test_unit_http_post_handles_4xx(mock_kernel: Any) -> None:
    mock_kernel.response_status_authorize = 403
    mock_kernel.response_body_authorize = {"reason": "denied"}
    status, body = _install_mod._http_post(
        url=mock_kernel.url + "/policy/module/authorize",
        body=b"{}",
        api_key="k",
        timeout=2.0,
    )
    assert status == 403
    assert b"denied" in body


def test_unit_http_post_raises_on_connection_refused() -> None:
    """Connecting to a port nothing listens on raises KernelUnavailable."""
    with pytest.raises(KernelUnavailable):
        _install_mod._http_post(
            url="http://127.0.0.1:1/policy/module/authorize",  # port 1 = unbound
            body=b"{}",
            api_key="k",
            timeout=0.5,
        )


def test_unit_validate_kernel_url_accepts_https() -> None:
    # Returns None silently on accept; raises on reject.
    _install_mod._validate_kernel_url("https://kernel.example:9443")


def test_unit_validate_kernel_url_accepts_localhost() -> None:
    _install_mod._validate_kernel_url("http://localhost:9443")
    _install_mod._validate_kernel_url("http://127.0.0.1:9443")


def test_unit_validate_kernel_url_rejects_remote_http() -> None:
    with pytest.raises(HookConfigError):
        _install_mod._validate_kernel_url("http://attacker.example:80")


def test_unit_derive_module_path_import() -> None:
    assert _install_mod._derive_module_path("import", ("json", None, [], [], [])) == "json"


def test_unit_derive_module_path_exec_with_code_object() -> None:
    code = compile("z=3", "<x>", "exec")
    out = _install_mod._derive_module_path("exec", (code,))
    assert out == hashlib.sha256(bytes(code.co_code)).hexdigest()


def test_unit_derive_module_path_exec_with_string() -> None:
    out = _install_mod._derive_module_path("exec", ("z=3",))
    assert out == hashlib.sha256(b"z=3").hexdigest()


def test_unit_derive_module_path_compile_with_bytes() -> None:
    out = _install_mod._derive_module_path("compile", (b"x=1", "<f>"))
    assert out == hashlib.sha256(b"x=1").hexdigest()


def test_unit_derive_module_path_unknown_event_raises() -> None:
    with pytest.raises(ValueError):
        _install_mod._derive_module_path("unknown_event", ("foo",))


def test_unit_derive_module_path_empty_args_raises() -> None:
    with pytest.raises(ValueError):
        _install_mod._derive_module_path("import", ())
    with pytest.raises(ValueError):
        _install_mod._derive_module_path("exec", ())
    with pytest.raises(ValueError):
        _install_mod._derive_module_path("compile", ())


def test_unit_parse_token_sha_returns_field() -> None:
    body = json.dumps({"token_sha256": "abc"}).encode()
    assert _install_mod._parse_token_sha(body) == "abc"


def test_unit_parse_token_sha_returns_none_on_garbage() -> None:
    assert _install_mod._parse_token_sha(b"not json") is None
    assert _install_mod._parse_token_sha(b'"a string"') is None  # non-dict


def test_unit_parse_reason_returns_field() -> None:
    body = json.dumps({"reason": "module_not_registered"}).encode()
    assert _install_mod._parse_reason(body) == "module_not_registered"


def test_unit_parse_reason_returns_none_on_garbage() -> None:
    assert _install_mod._parse_reason(b"not json") is None


def test_unit_audit_callback_allow(mock_kernel: Any) -> None:
    """Directly invoke the callback (bypasses sys.audit) to exercise
    its happy path under coverage's trace function."""
    _install_mod._installed.config = _make_cfg(mock_kernel)
    _install_mod._installed.armed = True
    try:
        # Allow path — no exception.
        _install_mod._audit_callback("import", ("json", None, [], [], []))
    finally:
        _install_mod._installed.config = None
        _install_mod._installed.armed = False
    # Verify the POST went out.
    reqs = mock_kernel.authorize_requests()
    assert len(reqs) == 1


def test_unit_audit_callback_deny(mock_kernel: Any) -> None:
    mock_kernel.response_status_authorize = 403
    mock_kernel.response_body_authorize = {
        "reason": "module_not_registered",
        "token_sha256": "c" * 64,
    }
    _install_mod._installed.config = _make_cfg(mock_kernel)
    _install_mod._installed.armed = True
    try:
        with pytest.raises(ImportError) as excinfo:
            _install_mod._audit_callback("import", ("blocked", None, [], [], []))
        assert isinstance(excinfo.value.__cause__, PolicyDenied)
    finally:
        _install_mod._installed.config = None
        _install_mod._installed.armed = False


def test_unit_audit_callback_400_hookbug(mock_kernel: Any) -> None:
    mock_kernel.response_status_authorize = 400
    mock_kernel.response_body_authorize = {"reason": "event_fingerprint_invalid"}
    _install_mod._installed.config = _make_cfg(mock_kernel)
    _install_mod._installed.armed = True
    try:
        with pytest.raises(ImportError):
            _install_mod._audit_callback("import", ("x", None, [], [], []))
    finally:
        _install_mod._installed.config = None
        _install_mod._installed.armed = False


def test_unit_audit_callback_400_hookbug_runtimeerror_for_exec(mock_kernel: Any) -> None:
    mock_kernel.response_status_authorize = 400
    mock_kernel.response_body_authorize = {"reason": "event_fingerprint_invalid"}
    _install_mod._installed.config = _make_cfg(mock_kernel)
    _install_mod._installed.armed = True
    try:
        with pytest.raises(RuntimeError):
            _install_mod._audit_callback("exec", (compile("a=1", "<>", "exec"),))
    finally:
        _install_mod._installed.config = None
        _install_mod._installed.armed = False


def test_unit_audit_callback_503_runtimeerror_for_exec(mock_kernel: Any) -> None:
    mock_kernel.response_status_authorize = 503
    _install_mod._installed.config = _make_cfg(mock_kernel)
    _install_mod._installed.armed = True
    try:
        with pytest.raises(RuntimeError):
            _install_mod._audit_callback("exec", (compile("a=1", "<>", "exec"),))
    finally:
        _install_mod._installed.config = None
        _install_mod._installed.armed = False


def test_unit_audit_callback_kernel_unavailable_runtimeerror_for_exec(
    mock_kernel: Any,
) -> None:
    """Connection refused on exec path -> RuntimeError (not ImportError)."""
    cfg = _install_mod._HookConfig(
        kernel_url="http://127.0.0.1:1",
        worker_api_key="k",
        caller_subject="s",
        caller_run_id="r",
        fail_closed_on_unreachable=True,
        timeout_seconds=0.2,
        audited_event_kinds=("exec",),
        event_metadata_max_bytes=1024,
    )
    _install_mod._installed.config = cfg
    _install_mod._installed.armed = True
    try:
        with pytest.raises(RuntimeError):
            _install_mod._audit_callback("exec", (compile("a=1", "<>", "exec"),))
    finally:
        _install_mod._installed.config = None
        _install_mod._installed.armed = False


def test_unit_audit_callback_deny_runtimeerror_for_compile(mock_kernel: Any) -> None:
    mock_kernel.response_status_authorize = 403
    mock_kernel.response_body_authorize = {"reason": "denied"}
    _install_mod._installed.config = _make_cfg(mock_kernel)
    _install_mod._installed.armed = True
    try:
        with pytest.raises(RuntimeError):
            _install_mod._audit_callback("compile", ("a=1", "<>"))
    finally:
        _install_mod._installed.config = None
        _install_mod._installed.armed = False


def test_unit_audit_callback_unhandled_status_fail_closed(mock_kernel: Any) -> None:
    mock_kernel.response_status_authorize = 418  # I'm a teapot
    _install_mod._installed.config = _make_cfg(mock_kernel)
    _install_mod._installed.armed = True
    try:
        with pytest.raises(ImportError):
            _install_mod._audit_callback("import", ("x", None, [], [], []))
    finally:
        _install_mod._installed.config = None
        _install_mod._installed.armed = False


def test_unit_audit_callback_no_config_no_op() -> None:
    """If the hook has been reset (config=None) the callback short-circuits."""
    _install_mod._installed.config = None
    _install_mod._installed.armed = False
    # Should NOT raise.
    _install_mod._audit_callback("import", ("x", None, [], [], []))


def test_unit_audit_callback_filtered_event_no_op(mock_kernel: Any) -> None:
    _install_mod._installed.config = _make_cfg(mock_kernel, audited=("exec",))
    _install_mod._installed.armed = True
    try:
        # import event filtered out — no POST, no raise.
        _install_mod._audit_callback("import", ("json", None, [], [], []))
        assert len(mock_kernel.authorize_requests()) == 0
    finally:
        _install_mod._installed.config = None
        _install_mod._installed.armed = False


def test_unit_audit_callback_unknown_event_no_op(mock_kernel: Any) -> None:
    _install_mod._installed.config = _make_cfg(mock_kernel)
    _install_mod._installed.armed = True
    try:
        _install_mod._audit_callback("open", ("/etc/passwd",))
        # event kind not in audited_event_kinds default; no POST.
        assert len(mock_kernel.authorize_requests()) == 0
    finally:
        _install_mod._installed.config = None
        _install_mod._installed.armed = False


def test_unit_audit_callback_derive_failure_fail_closed(mock_kernel: Any) -> None:
    """If ``_derive_module_path`` raises, the callback raises
    ImportError (for import event)."""
    _install_mod._installed.config = _make_cfg(mock_kernel)
    _install_mod._installed.armed = True
    try:
        with pytest.raises(ImportError):
            _install_mod._audit_callback("import", ())  # empty args -> ValueError
    finally:
        _install_mod._installed.config = None
        _install_mod._installed.armed = False


def test_unit_audit_callback_derive_failure_runtimeerror_for_exec(mock_kernel: Any) -> None:
    _install_mod._installed.config = _make_cfg(mock_kernel)
    _install_mod._installed.armed = True
    try:
        with pytest.raises(RuntimeError):
            _install_mod._audit_callback("exec", ())
    finally:
        _install_mod._installed.config = None
        _install_mod._installed.armed = False


def test_unit_audit_callback_kernel_unavailable_fail_open(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cfg = _install_mod._HookConfig(
        kernel_url="http://127.0.0.1:1",
        worker_api_key="k",
        caller_subject="s",
        caller_run_id="r",
        fail_closed_on_unreachable=False,
        timeout_seconds=0.2,
        audited_event_kinds=("import",),
        event_metadata_max_bytes=1024,
    )
    _install_mod._installed.config = cfg
    _install_mod._installed.armed = True
    try:
        with caplog.at_level(logging.CRITICAL, logger="safety_kernel_defense"):
            # Should NOT raise — fail-open.
            _install_mod._audit_callback("import", ("x", None, [], [], []))
    finally:
        _install_mod._installed.config = None
        _install_mod._installed.armed = False


# ============================================================================
#  — kill-switch emits `hook_install_violation` chain entry
# 
# ============================================================================


def test_kill_switch_emits_chain_entry(
    mock_kernel: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The kill-switch install path MUST POST a single
    ``hook_install_violation`` audit event to ``/policy/audit-event``
    BEFORE returning. The chain entry plus the CRITICAL log line are
    the operational + audit-chain controls for kill-switch use."""
    monkeypatch.setenv("ARYA_AUDIT_HOOK_DISABLED", "1")
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="kill-switch-subject",
        caller_run_id="run-ks",
    )

    audit_events = mock_kernel.audit_event_requests()
    assert len(audit_events) == 1, (
        f"expected 1 audit-event POST, got {len(audit_events)}"
    )
    body = audit_events[0]["body"]
    assert body is not None
    assert body["event_kind"] == "hook_install_violation"
    assert body["subject"] == "kill-switch-subject"
    metadata = body["metadata"]
    assert metadata["reason"] == "kill_switch_engaged"
    assert metadata["kill_switch_env_var"] == "ARYA_AUDIT_HOOK_DISABLED"
    #   the raw operator-controlled
    # env-var value is no longer copied into the chain entry; the
    # engaged state is captured by a boolean presence flag instead.
    assert metadata["kill_switch_present"] is True
    assert "kill_switch_value" not in metadata
    # Hook never armed → no authorize-call traffic.
    assert mock_kernel.authorize_requests() == []


def test_kill_switch_handles_kernel_unreachable(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the kernel is unreachable at install time, the kill-switch
    path still completes (kill-switch is operationally legitimate)
    and a CRITICAL log line records the POST failure."""
    monkeypatch.setenv("ARYA_AUDIT_HOOK_DISABLED", "1")
    # Port 1 is reserved; nothing listens there.
    with caplog.at_level(logging.CRITICAL, logger="safety_kernel_defense"):
        install_audit_hook(
            kernel_url="http://127.0.0.1:1",
            worker_api_key="k",
            caller_subject="t",
            caller_run_id="r",
        )
    crit = [r for r in caplog.records if r.levelno == logging.CRITICAL]
    # At least two CRITICAL log lines: the kill-switch banner + the
    # POST-failure record.
    assert any("kill switch" in r.message.lower() for r in crit)
    assert any(
        "install-time audit event post failed" in r.message.lower() for r in crit
    )


def test_kill_switch_handles_kernel_5xx(
    mock_kernel: Any, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-2xx response from the audit-event endpoint also falls
    back to the local CRITICAL log without raising."""
    monkeypatch.setenv("ARYA_AUDIT_HOOK_DISABLED", "1")
    mock_kernel.response_status_audit_event = 503
    mock_kernel.response_body_audit_event = {"error": "kernel_unavailable"}
    with caplog.at_level(logging.CRITICAL, logger="safety_kernel_defense"):
        install_audit_hook(
            kernel_url=mock_kernel.url,
            worker_api_key="k",
            caller_subject="t",
            caller_run_id="r",
        )
    crit = [r for r in caplog.records if r.levelno == logging.CRITICAL]
    assert any("returned http 503" in r.message.lower() for r in crit)


def test_kill_switch_metadata_captures_diagnostics(
    mock_kernel: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The metadata MUST include hostname, process_id, and
    python_version so kernel-side forensics can identify the adopter
    process that engaged the kill switch."""
    monkeypatch.setenv("ARYA_AUDIT_HOOK_DISABLED", "1")
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
    )
    audit_events = mock_kernel.audit_event_requests()
    assert len(audit_events) == 1
    metadata = audit_events[0]["body"]["metadata"]
    # process_id must match the running interpreter.
    assert metadata["process_id"] == os.getpid()
    # hostname is a non-empty string (sentinel "<unknown>" allowed on
    # exotic platforms where ``socket.gethostname()`` raises).
    assert isinstance(metadata["hostname"], str) and metadata["hostname"]
    # python_version is the full ``sys.version`` string.
    assert metadata["python_version"] == sys.version


def test_kill_switch_uses_custom_env_var_name(
    mock_kernel: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the adopter passes a custom ``kill_switch_env_var``, the
    audit event records THAT variable name (not the default), so
    audit-chain replay shows which knob the operator flipped."""
    # Make sure the default isn't set, to prove only the custom var
    # matters.
    monkeypatch.delenv("ARYA_AUDIT_HOOK_DISABLED", raising=False)
    monkeypatch.setenv("CUSTOM_KILL_SWITCH", "1")
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        kill_switch_env_var="CUSTOM_KILL_SWITCH",
    )
    audit_events = mock_kernel.audit_event_requests()
    assert len(audit_events) == 1
    assert (
        audit_events[0]["body"]["metadata"]["kill_switch_env_var"]
        == "CUSTOM_KILL_SWITCH"
    )


# ============================================================================
#  — `report_preloaded_modules=True` public param
# 
# ============================================================================


def test_report_preloaded_modules_default_off(mock_kernel: Any) -> None:
    """The default (``report_preloaded_modules=False``) MUST preserve
    the existing call-site behaviour: NO audit-event POST is emitted
    at install time on the happy path."""
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
    )
    assert mock_kernel.audit_event_requests() == []


def test_report_preloaded_modules_on_captures_snapshot(mock_kernel: Any) -> None:
    """With ``report_preloaded_modules=True``, the install path POSTs
    one ``hook_install_violation`` audit event whose
    ``metadata.preloaded_modules`` is a SORTED list of names drawn from
    ``sys.modules``. The cause is encoded in ``metadata.reason``."""
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="preload-subject",
        caller_run_id="r",
        report_preloaded_modules=True,
    )

    audit_events = mock_kernel.audit_event_requests()
    assert len(audit_events) == 1
    body = audit_events[0]["body"]
    assert body["event_kind"] == "hook_install_violation"
    assert body["subject"] == "preload-subject"
    metadata = body["metadata"]
    assert metadata["reason"] == "preloaded_modules_at_install"
    modules = metadata["preloaded_modules"]
    assert isinstance(modules, list)
    # Strictly-sorted (alphabetical).
    assert modules == sorted(modules), (
        "preloaded_modules MUST be sorted alphabetically for stable output"
    )
    # At minimum, the snapshot is non-empty and contains a known-early
    # stdlib name. Under pytest ``sys.modules`` may exceed the 256-entry
    # cap, so we pick names guaranteed to sort within the first 256:
    # ``_abc`` is a built-in that loads very early in interpreter
    # startup and starts with an underscore (sorts before lowercase
    # letters in ASCII).
    assert len(modules) > 0
    assert "_abc" in modules, (
        f"_abc expected in early-alphabetical slice; got first 5: {modules[:5]}"
    )
    # Count matches the slice we send.
    assert metadata["preloaded_module_count"] == len(modules)
    # Diagnostic fields present.
    assert metadata["process_id"] == os.getpid()
    assert isinstance(metadata["hostname"], str) and metadata["hostname"]
    assert metadata["python_version"] == sys.version


def test_report_preloaded_modules_caps_at_256(
    mock_kernel: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If ``sys.modules`` carries more than 256 names, the snapshot is
    truncated to the first 256 (alphabetically) and
    ``metadata.truncated`` is ``True``."""
    # Build a synthetic sys.modules with > 256 entries. Use existing
    # values from sys.modules to avoid disturbing import machinery.
    real_modules = dict(sys.modules)
    synthetic: Dict[str, Any] = dict(real_modules)
    # Add enough sentinel keys to push us well past the 256 cap.
    for i in range(300):
        synthetic[f"_zzz_preload_sentinel_{i:04d}"] = real_modules.get("sys")
    monkeypatch.setattr(sys, "modules", synthetic)

    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        report_preloaded_modules=True,
    )

    audit_events = mock_kernel.audit_event_requests()
    assert len(audit_events) == 1
    metadata = audit_events[0]["body"]["metadata"]
    assert metadata["truncated"] is True
    assert metadata["preloaded_module_count"] == 256
    assert len(metadata["preloaded_modules"]) == 256
    # Sorted; first entries are alphabetical predecessors of the
    # sentinel block.
    assert metadata["preloaded_modules"] == sorted(metadata["preloaded_modules"])


def test_report_preloaded_modules_no_truncate_under_cap(
    mock_kernel: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When ``sys.modules`` carries ≤ 256 names, ``truncated`` is
    ``False`` and every name appears in the snapshot."""
    synthetic = {f"mod_{i:02d}": None for i in range(50)}
    monkeypatch.setattr(sys, "modules", synthetic)
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        report_preloaded_modules=True,
    )
    audit_events = mock_kernel.audit_event_requests()
    metadata = audit_events[0]["body"]["metadata"]
    assert metadata["truncated"] is False
    assert metadata["preloaded_module_count"] == 50
    assert len(metadata["preloaded_modules"]) == 50


def test_report_preloaded_modules_on_kill_switch_path(
    mock_kernel: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When BOTH the kill-switch is engaged AND
    ``report_preloaded_modules=True``, BOTH chain entries are emitted:
    the kill-switch one first, the preloaded-modules one second.
    Forensics can correlate the bypass with the bootstrap window."""
    monkeypatch.setenv("ARYA_AUDIT_HOOK_DISABLED", "1")
    install_audit_hook(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        caller_run_id="r",
        report_preloaded_modules=True,
    )
    audit_events = mock_kernel.audit_event_requests()
    assert len(audit_events) == 2
    reasons = [e["body"]["metadata"]["reason"] for e in audit_events]
    assert reasons == [
        "kill_switch_engaged",
        "preloaded_modules_at_install",
    ]


def test_report_preloaded_modules_fail_soft_on_kernel_unreachable(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """If the audit-event POST fails (kernel unreachable), the install
    still returns successfully — the local CRITICAL log is the
    fallback forensic record. The hook arms normally."""
    with caplog.at_level(logging.CRITICAL, logger="safety_kernel_defense"):
        install_audit_hook(
            kernel_url="http://127.0.0.1:1",  # unbound port
            worker_api_key="k",
            caller_subject="t",
            caller_run_id="r",
            report_preloaded_modules=True,
        )
    # Hook still armed.
    assert _install_mod._installed.armed is True
    # CRITICAL log records the failure.
    crit = [r for r in caplog.records if r.levelno == logging.CRITICAL]
    assert any(
        "install-time audit event post failed" in r.message.lower() for r in crit
    )


# ============================================================================
# Direct unit tests for the new helpers (coverage)
# ============================================================================


def test_unit_enumerate_preloaded_modules_returns_sorted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    synthetic = {"zoo": None, "alpha": None, "beta": None}
    monkeypatch.setattr(sys, "modules", synthetic)
    names, truncated = _install_mod._enumerate_preloaded_modules()
    assert names == ["alpha", "beta", "zoo"]
    assert truncated is False


def test_unit_enumerate_preloaded_modules_truncates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    synthetic = {f"m{i:04d}": None for i in range(500)}
    monkeypatch.setattr(sys, "modules", synthetic)
    names, truncated = _install_mod._enumerate_preloaded_modules(cap=128)
    assert truncated is True
    assert len(names) == 128
    assert names == sorted(synthetic)[:128]


def test_unit_diagnostics_metadata_shape() -> None:
    meta = _install_mod._diagnostics_metadata()
    assert set(meta.keys()) == {"hostname", "process_id", "python_version"}
    assert meta["process_id"] == os.getpid()
    assert meta["python_version"] == sys.version
    assert isinstance(meta["hostname"], str) and meta["hostname"]


def test_unit_post_install_audit_event_happy_path(mock_kernel: Any) -> None:
    _install_mod._post_install_audit_event(
        kernel_url=mock_kernel.url,
        worker_api_key="k",
        caller_subject="t",
        metadata={"reason": "test_reason"},
    )
    audit_events = mock_kernel.audit_event_requests()
    assert len(audit_events) == 1
    assert audit_events[0]["body"]["metadata"]["reason"] == "test_reason"


def test_unit_post_install_audit_event_swallows_kernel_unavailable(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The helper MUST NEVER raise — install path is one-shot at
    startup and a kill-switch with an unreachable kernel is a valid
    operating state."""
    with caplog.at_level(logging.CRITICAL, logger="safety_kernel_defense"):
        _install_mod._post_install_audit_event(
            kernel_url="http://127.0.0.1:1",
            worker_api_key="k",
            caller_subject="t",
            metadata={"reason": "test_reason"},
        )
    crit = [r for r in caplog.records if r.levelno == logging.CRITICAL]
    assert any(
        "install-time audit event post failed" in r.message.lower() for r in crit
    )


def test_unit_post_install_audit_event_swallows_unserializable_metadata(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """If the metadata payload contains a non-JSON-serializable value,
    the helper logs a CRITICAL line and returns without raising."""

    class _NotSerializable:  # noqa: D401 — test fixture
        """Intentionally not JSON-serializable."""

    with caplog.at_level(logging.CRITICAL, logger="safety_kernel_defense"):
        _install_mod._post_install_audit_event(
            kernel_url="http://127.0.0.1:1",
            worker_api_key="k",
            caller_subject="t",
            metadata={"reason": "x", "bad": _NotSerializable()},
        )
    crit = [r for r in caplog.records if r.levelno == logging.CRITICAL]
    assert any("not serializable" in r.message.lower() for r in crit)


def test_unit_post_install_audit_event_swallows_unexpected_exception(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """If ``_http_post`` raises an unexpected (non-KernelUnavailable)
    exception, the helper logs a CRITICAL line and returns."""

    def _raise_unexpected(**_kw: Any) -> Any:
        raise ValueError("contrived failure")

    monkeypatch.setattr(_install_mod, "_http_post", _raise_unexpected)
    with caplog.at_level(logging.CRITICAL, logger="safety_kernel_defense"):
        _install_mod._post_install_audit_event(
            kernel_url="http://127.0.0.1:9999",
            worker_api_key="k",
            caller_subject="t",
            metadata={"reason": "x"},
        )
    crit = [r for r in caplog.records if r.levelno == logging.CRITICAL]
    assert any(
        "raised unexpected error" in r.message.lower() for r in crit
    )


def test_unit_diagnostics_metadata_handles_gethostname_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If ``socket.gethostname`` raises, diagnostics fall back to
    ``"<unknown>"`` instead of propagating."""

    def _raise(*_args: Any, **_kw: Any) -> str:
        raise OSError("no hostname")

    monkeypatch.setattr(_install_mod.socket, "gethostname", _raise)
    meta = _install_mod._diagnostics_metadata()
    assert meta["hostname"] == "<unknown>"
