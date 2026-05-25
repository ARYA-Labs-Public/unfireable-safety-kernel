"""Install the safety-kernel audit hook.

The hook subscribes to CPython's audit-event fan-out via
:func:`sys.addaudithook` and forwards ``import``/``exec``/``compile``
events to the kernel's ``/policy/module/authorize`` endpoint.
See ``docs/architecture.md`` for the architecture overview.

Key invariants
--------------

* **Stdlib-only**. ``urllib.request`` is the HTTP client; no
  ``httpx``/``requests`` deps.
* **Eager stdlib warm-up**. ``_warm_stdlib_deps()`` runs BEFORE
  ``sys.addaudithook`` arms so the first kernel call does not
  trigger nested import events from inside the hook.
* **Thread-local reentrancy guard**. ``_state.in_hook`` short-circuits
  to allow during any audit event that fires while the hook is
  itself executing.
* **Fail-CLOSED default**. Timeout / connection error raises
  :class:`KernelUnavailable` which CPython surfaces as
  :class:`ImportError` / :class:`RuntimeError`.
* **Idempotent re-install**. Same kwargs → WARN + no-op. Different
  kwargs → :class:`HookConfigError`.

The hook is ~80 lines of real logic (install + callback + helpers);
the rest is docstrings and module-level state.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
import threading
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from . import _wire
from .exceptions import HookConfigError, KernelUnavailable, PolicyDenied

__all__ = ["install_audit_hook"]

_LOGGER = logging.getLogger("safety_kernel_defense")

# Kill-switch env var — when set to "1", install_audit_hook() is a
# no-op (the hook never arms). The CRITICAL log line is the operational
# alert; the audit-event POST (when reachable) is the chain entry.
_DEFAULT_KILL_SWITCH_ENV_VAR = "ARYA_AUDIT_HOOK_DISABLED"

# Cap on the `preloaded_modules` list shipped in the install-time
# `hook_install_violation` audit event (see the architecture overview). Caps oversized
# `sys.modules` snapshots to keep audit-event payloads bounded.
_PRELOADED_MODULES_CAP = 256

# Per-event HTTP timeout for the install-time `/policy/audit-event`
# POSTs (kill-switch + preloaded-modules snapshot). The install path
# fires AT MOST twice per interpreter; this is not a hot loop, so a
# generous 2-second budget is acceptable.
# The integration overview mandates the timeout here, not the
# per-event hot-path `cfg.timeout_seconds`.
_INSTALL_TIME_AUDIT_EVENT_TIMEOUT_S = 2.0


@dataclass(frozen=True)
class _HookConfig:
    """Frozen configuration captured at install time."""

    kernel_url: str
    worker_api_key: str
    caller_subject: str
    caller_run_id: str
    fail_closed_on_unreachable: bool
    timeout_seconds: float
    audited_event_kinds: Tuple[str, ...]
    event_metadata_max_bytes: int


# Module-level state for the (singleton) hook. The hook is installed
# at most once per interpreter; idempotent re-install with the same
# config is a WARN-and-no-op (the architecture overview, test #9).
_state = threading.local()


class _InstalledState:
    """Aggregated state for the installed hook.

    Held at module scope (not in ``_state``) because re-install
    detection needs to see the prior config from any thread, not just
    the thread that called ``install_audit_hook``.

    Attributes:
        config: the captured ``_HookConfig`` from the most recent
            install attempt (kill-switch path included).
        armed: ``True`` iff ``sys.addaudithook`` was called for this
            config — i.e. the callback should forward events to the
            kernel. ``False`` for kill-switch installs (config is
            captured for re-install detection but no audit callback
            was registered).
    """

    config: Optional[_HookConfig] = None
    armed: bool = False


_installed = _InstalledState()


def _warm_stdlib_deps() -> None:
    """Eagerly import every stdlib module the hook's HTTP call needs.

    the architecture overview "Re-entrancy and bootstrap of the hook itself" — without
    this warm-up the first kernel call triggers an audit-event recursion
    on ``http.client``/``ssl``/``socket`` etc., which the thread-local
    guard mitigates but only after the modules have already been
    loaded inside the guarded path (i.e. not authorized).
    """
    # The imports below are NOT dead code despite linters' best
    # efforts. They populate ``sys.modules`` so the audit callback's
    # urlopen call does not trigger nested ``import`` events.
    import http.client  # noqa: F401
    import socket  # noqa: F401
    import ssl  # noqa: F401
    import urllib.parse  # noqa: F401
    import urllib.response  # noqa: F401


def _in_hook_guard() -> bool:
    """Return True if we are already inside a hook callback."""
    return getattr(_state, "in_hook", False)


def _set_in_hook(value: bool) -> None:
    _state.in_hook = value


def _http_post(url: str, body: bytes, api_key: str, timeout: float) -> Tuple[int, bytes]:
    """Synchronous POST. Returns ``(status, body_bytes)``.

    Raises :class:`KernelUnavailable` on connection / timeout error;
    DOES NOT raise on 4xx/5xx — caller branches on status.
    """
    req = urllib.request.Request(
        url=url,
        data=body,
        method="POST",
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as exc:  # 4xx/5xx with body
        try:
            body_bytes = exc.read()
        except Exception:  # noqa: BLE001 — best-effort read
            body_bytes = b""
        return exc.code, body_bytes
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise KernelUnavailable(str(exc)) from exc


def _post_install_audit_event(
    *,
    kernel_url: str,
    worker_api_key: str,
    caller_subject: str,
    metadata: Dict[str, Any],
    timeout: float = _INSTALL_TIME_AUDIT_EVENT_TIMEOUT_S,
) -> None:
    """Best-effort POST of a ``hook_install_violation`` audit event.

    Used by the install-time chain-entry emitters (kill-switch path
     preloaded-modules snapshot ). On any failure
    (kernel unreachable, timeout, non-2xx, malformed response), this
    helper logs a CRITICAL line with the JSON-serialized metadata and
    returns ``None`` — it NEVER raises. The local log is the fallback
    forensic record per the architecture overview: "kill-switch use is
    operationally legitimate; chain entry + log line is the audit, not
    a hard fail."

    The wire `event_kind` is the closed-enum variant
    `hook_install_violation` (the only Rust ``AuditEventKind`` variant
    that fits both the kill-switch and preloaded-modules use cases
    see ``the kernel's AuditEventKind enum``).
    The cause discriminator lives in ``metadata.reason``.
    """
    payload = {
        "event_kind": "hook_install_violation",
        "subject": caller_subject,
        "metadata": metadata,
    }
    try:
        body = json.dumps(payload).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _LOGGER.critical(
            "install-time audit event payload not serializable "
            "(reason=%s, error=%s); local-only forensic record kept",
            metadata.get("reason"),
            exc,
        )
        return

    url = kernel_url + "/policy/audit-event"
    try:
        status, _resp_body = _http_post(
            url=url,
            body=body,
            api_key=worker_api_key,
            timeout=timeout,
        )
    except KernelUnavailable as exc:
        _LOGGER.critical(
            "install-time audit event POST failed (kernel unreachable: %s); "
            "metadata=%s",
            exc.detail if hasattr(exc, "detail") else exc,
            json.dumps(metadata, sort_keys=True, default=str),
        )
        return
    except Exception as exc:  # noqa: BLE001 — install path must never raise
        _LOGGER.critical(
            "install-time audit event POST raised unexpected error: %s; "
            "metadata=%s",
            exc,
            json.dumps(metadata, sort_keys=True, default=str),
        )
        return

    if status < 200 or status >= 300:
        _LOGGER.critical(
            "install-time audit event POST returned HTTP %d; "
            "kernel did not record chain entry. metadata=%s",
            status,
            json.dumps(metadata, sort_keys=True, default=str),
        )


def _diagnostics_metadata() -> Dict[str, Any]:
    """Common diagnostic fields included in both install-time audit
    events (see the architecture overview, also row 4).

    Captures the hostname, process id, and Python version so the
    kernel-side chain entry can identify which adopter process emitted
    the install-time event. ``socket.gethostname`` is best-effort
    fall back to ``"<unknown>"`` on platforms where it raises.
    """
    try:
        host = socket.gethostname()
    except Exception:  # noqa: BLE001
        host = "<unknown>"
    return {
        "hostname": host,
        "process_id": os.getpid(),
        "python_version": sys.version,
    }


def _enumerate_preloaded_modules(cap: int = _PRELOADED_MODULES_CAP) -> Tuple[List[str], bool]:
    """Return (sorted module names, truncated_flag).

    Snapshots ``sys.modules`` keys at install time per the architecture overview
    §3/§5/§8 row 12. The list is sorted alphabetically for stable
    output across runs; if ``len(sys.modules) > cap``, the first ``cap``
    names (alphabetically) are returned and the truncated flag is set.

    A snapshot copy is taken first so the sort is deterministic
    regardless of concurrent imports racing with our enumeration
    Python's dict iteration is undefined under concurrent mutation
    but ``list(sys.modules)`` returns a consistent snapshot.
    """
    snapshot = list(sys.modules)
    total = len(snapshot)
    snapshot.sort()
    truncated = total > cap
    return snapshot[:cap], truncated


def _validate_kernel_url(url: str) -> None:
    """the architecture overview: plain-http rejected unless localhost/loopback."""
    if url.startswith("https://"):
        return
    if url.startswith("http://"):
        # localhost / 127.0.0.1 / [::1] forms.
        rest = url[len("http://"):]
        host_part = rest.split("/", 1)[0].split(":", 1)[0]
        if host_part in ("127.0.0.1", "localhost", "[::1]", "::1"):
            return
    raise HookConfigError(
        f"kernel_url must be https:// or http://localhost; got {url!r}"
    )


def _audit_callback(event: str, args: Tuple) -> None:
    """The actual ``sys.addaudithook`` callback.

    CPython contract: raising from this callback ABORTS the underlying
    operation. Returning ``None`` allows it. We map kernel DENY to
    raise; ALLOW / unhandled events to return.
    """
    cfg = _installed.config
    if cfg is None or not _installed.armed:
        # Hook fired but the install is not (or no longer) armed.
        # Either the install was reset (test fixtures do this), the
        # install was a kill-switch no-op (cfg set but armed=False
        # cannot happen via the public API — kill-switch armed=True
        # is documented), or this is the brief window between
        # _installed.config being set and _installed.armed becoming
        # True during install (handled by ordering). In every case,
        # short-circuit to allow — the install is not currently
        # responsible for this event.
        return

    # Re-entrancy guard: any audit event from inside our own callback
    # short-circuits to allow. the architecture overview.
    if _in_hook_guard():
        return

    # Filter to the kinds we forward.
    if event not in cfg.audited_event_kinds:
        return

    # Build the module_path per the architecture overview "Mapping CPython event tuple".
    try:
        module_path = _derive_module_path(event, args)
    except Exception as exc:  # noqa: BLE001 — defensive
        _LOGGER.warning("derive_module_path failed for %s: %s", event, exc)
        # the architecture overview response 400 handling: hook bug → fail-CLOSED.
        if event == "import":
            raise ImportError(f"safety-kernel hook internal error: {exc}") from exc
        raise RuntimeError(f"safety-kernel hook internal error: {exc}") from exc

    fingerprint = _wire.compute_event_fingerprint(
        event_kind=event,
        module_path=module_path,
        caller_subject=cfg.caller_subject,
        caller_run_id=cfg.caller_run_id,
    )

    payload = {
        "event_kind": event,
        "module_path": module_path,
        "caller_subject": cfg.caller_subject,
        "caller_run_id": cfg.caller_run_id,
        "event_fingerprint": fingerprint,
        "expected_required_patterns": None,
        "metadata": None,
    }
    body = json.dumps(payload).encode("utf-8")

    _set_in_hook(True)
    try:
        status, response_body = _http_post(
            url=cfg.kernel_url + "/policy/module/authorize",
            body=body,
            api_key=cfg.worker_api_key,
            timeout=cfg.timeout_seconds,
        )
    except KernelUnavailable as exc:
        if cfg.fail_closed_on_unreachable:
            if event == "import":
                raise ImportError(f"safety-kernel unreachable: {exc.detail}") from exc
            raise RuntimeError(f"safety-kernel unreachable: {exc.detail}") from exc
        # Fail-OPEN: CRITICAL log per the architecture overview (rate-limit deferred
        # to slice 5b — first WARN per event is acceptable in slice 3).
        _LOGGER.critical(
            "safety-kernel unreachable; allowing %s of %s (fail-open)",
            event,
            module_path,
        )
        return
    finally:
        _set_in_hook(False)

    if status == 200:
        return  # ALLOW
    if status == 403:
        token_sha = _parse_token_sha(response_body)
        reason = _parse_reason(response_body) or "policy_denied"
        denied = PolicyDenied(reason, decision_token_sha256=token_sha)
        if event == "import":
            raise ImportError(f"policy denied: {reason}") from denied
        raise RuntimeError(f"policy denied: {reason}") from denied
    if status == 400:
        # the architecture overview: 400 is a HOOK BUG (fingerprint mismatch). Fail-CLOSED.
        if event == "import":
            raise ImportError("audit hook fingerprint mismatch — internal bug")
        raise RuntimeError("audit hook fingerprint mismatch — internal bug")
    # Any other status: fail-CLOSED.
    if event == "import":
        raise ImportError(f"policy decision failed: HTTP {status}")
    raise RuntimeError(f"policy decision failed: HTTP {status}")


def _derive_module_path(event: str, args: Tuple) -> str:
    """Map CPython audit event args to the wire ``module_path``."""
    import hashlib  # already warmed

    if event == "import":
        if not args:
            raise ValueError("import audit event with empty args")
        return str(args[0])
    if event == "exec":
        if not args:
            raise ValueError("exec audit event with empty args")
        code_obj = args[0]
        # code_obj may be a string (from compile-then-exec at the
        # source level) or a code object (from compiled bytecode).
        if isinstance(code_obj, str):
            data = code_obj.encode("utf-8")
        elif hasattr(code_obj, "co_code"):
            data = bytes(code_obj.co_code)
        else:
            data = repr(code_obj).encode("utf-8")
        return hashlib.sha256(data).hexdigest()
    if event == "compile":
        if not args:
            raise ValueError("compile audit event with empty args")
        src = args[0]
        if isinstance(src, bytes):
            data = src
        else:
            data = str(src).encode("utf-8")
        return hashlib.sha256(data).hexdigest()
    raise ValueError(f"unknown audit event kind: {event}")


def _parse_token_sha(body: bytes) -> Optional[str]:
    try:
        parsed = json.loads(body)
    except Exception:  # noqa: BLE001
        return None
    val = parsed.get("token_sha256") if isinstance(parsed, dict) else None
    return val if isinstance(val, str) else None


def _parse_reason(body: bytes) -> Optional[str]:
    try:
        parsed = json.loads(body)
    except Exception:  # noqa: BLE001
        return None
    val = parsed.get("reason") if isinstance(parsed, dict) else None
    return val if isinstance(val, str) else None


def install_audit_hook(
    *,
    kernel_url: str,
    worker_api_key: str,
    caller_subject: str,
    caller_run_id: Optional[str] = None,
    fail_closed_on_unreachable: bool = True,
    timeout_seconds: float = 0.5,
    kill_switch_env_var: str = _DEFAULT_KILL_SWITCH_ENV_VAR,
    audited_event_kinds: Tuple[str, ...] = ("import", "exec", "compile"),
    event_metadata_max_bytes: int = 1024,
    report_preloaded_modules: bool = False,
) -> None:
    """Install the safety-kernel audit hook on the current interpreter.

    the architecture overview. Idempotent same-config; ``HookConfigError`` on
    differing config. Kill-switch (``ARYA_AUDIT_HOOK_DISABLED=1``) is
    checked AT INSTALL TIME and produces a CRITICAL log + a
    ``hook_install_violation`` chain entry.

    When ``report_preloaded_modules`` is ``True``, a second
    ``hook_install_violation`` chain entry is posted carrying a
    snapshot of ``sys.modules`` keys at install time. This narrows the
    bootstrap window's forensic blind spot per the architecture overview §5
    row 2.

    See :mod:`safety_kernel_defense` package docstring + the bootstrap
    doc at ``safety_kernel_oss/docs/integration/python-audit-hook.md``.

    Args:
        kernel_url: base URL, e.g. ``https://your-kernel-host:9443``.
            Trailing path is appended by the hook
            (``/policy/module/authorize``).
        worker_api_key: worker-role API key sent on every kernel call.
        caller_subject: adopter app identity bound into every authorize
            request.
        caller_run_id: run id; default is a per-install
            :func:`uuid.uuid4().hex`.
        fail_closed_on_unreachable: ``True`` (default) → raise on
            timeout / connection error. ``False`` → log CRITICAL and
            allow.
        timeout_seconds: per-event HTTP timeout. Clamped to
            ``[0.05, 5.0]``.
        kill_switch_env_var: env var name; when set to ``"1"`` the
            hook is a no-op at install time.   also
            posts a ``hook_install_violation`` audit event with
            ``metadata.reason="kill_switch_engaged"`` so the chain
            records the bypass.
        audited_event_kinds: subset of ``("import", "exec", "compile")``.
        event_metadata_max_bytes: cap for any future metadata payload.
        report_preloaded_modules: when ``True``, emit a
            ``hook_install_violation`` audit event at install time
            carrying a sorted snapshot of ``sys.modules`` keys
            (capped at 256). Default ``False`` — preserves the
            existing call-site behaviour for adopters that haven't
            opted in.  / the architecture overview §3 / §5 / §8 row 12.

    Raises:
        HookConfigError: if config validation fails (e.g. plain-http
            URL to non-loopback host, or re-install with different
            config).
    """
    if caller_run_id is None:
        caller_run_id = uuid.uuid4().hex
    timeout_seconds = max(0.05, min(5.0, float(timeout_seconds)))
    cfg = _HookConfig(
        kernel_url=kernel_url.rstrip("/"),
        worker_api_key=worker_api_key,
        caller_subject=caller_subject,
        caller_run_id=caller_run_id,
        fail_closed_on_unreachable=fail_closed_on_unreachable,
        timeout_seconds=timeout_seconds,
        audited_event_kinds=tuple(audited_event_kinds),
        event_metadata_max_bytes=event_metadata_max_bytes,
    )

    _validate_kernel_url(cfg.kernel_url)

    # Idempotency: same config → WARN + no-op. Different → raise.
    if _installed.armed:
        if _installed.config == cfg:
            _LOGGER.warning(
                "safety-kernel audit hook already installed with same "
                "config — second install_audit_hook() call is a no-op"
            )
            return
        raise HookConfigError(
            "audit hook already installed with different config; "
            "re-install with the same config or restart the process"
        )

    # Kill-switch check: install-time CRITICAL log + no-op +
    # `hook_install_violation` chain entry.
    kill_switch_value = os.environ.get(kill_switch_env_var)
    if kill_switch_value == "1":
        _LOGGER.critical(
            "audit hook installation suppressed by kill switch "
            "%s=1 — emergency bypass active",
            kill_switch_env_var,
        )
        # Record config for re-install detection but leave armed=False
        # so any audit-callback (re)registrations from prior installs
        # in this interpreter (in tests, or via the design's
        # idempotent-install path) see armed=False and short-circuit.
        _installed.config = cfg
        _installed.armed = False

        #  best-effort `hook_install_violation` chain entry.
        # The kernel-side chain records the bypass; failure here falls
        # back to the CRITICAL log emitted above + the helper's own
        # CRITICAL log on POST failure. NEVER raises — kill-switch is
        # operationally legitimate even if the kernel is unreachable.
        #   do NOT copy the raw
        # operator-controlled env-var value into the audit chain entry.
        # The branch is only reached when ``kill_switch_value == "1"``,
        # so the engaged state is fully captured by a boolean presence
        # flag; recording the raw string risks leaking operator-supplied
        # content into the signed/append-only chain (hygiene, not a
        # soundness issue).
        kill_switch_metadata: Dict[str, Any] = {
            "reason": "kill_switch_engaged",
            "kill_switch_env_var": kill_switch_env_var,
            "kill_switch_present": True,
        }
        kill_switch_metadata.update(_diagnostics_metadata())
        _post_install_audit_event(
            kernel_url=cfg.kernel_url,
            worker_api_key=cfg.worker_api_key,
            caller_subject=cfg.caller_subject,
            metadata=kill_switch_metadata,
        )

        #  preloaded-modules snapshot is opt-in even on the
        # kill-switch path. The chain entry is still useful: forensics
        # may want to see what loaded before the bypass took effect.
        if report_preloaded_modules:
            _emit_preloaded_modules_audit_event(cfg)
        return

    # Eager warm-up BEFORE arming. the architecture overview re-entrancy mitigation.
    _warm_stdlib_deps()

    # Commit config before arming so the callback sees it on first fire.
    _installed.config = cfg
    sys.addaudithook(_audit_callback)
    _installed.armed = True
    _LOGGER.info(
        "safety-kernel audit hook armed (subject=%s run=%s)",
        cfg.caller_subject,
        cfg.caller_run_id,
    )

    #  post-arm preloaded-modules snapshot. Default off so the
    # existing call-site behaviour is unchanged. When opted in, the
    # chain entry catalogues which modules loaded into ``sys.modules``
    # BEFORE the hook armed (the bootstrap-window forensic record per
    # the architecture overview §5 row 2). Best-effort: POST failures fall
    # back to a CRITICAL log line via ``_post_install_audit_event``.
    if report_preloaded_modules:
        _emit_preloaded_modules_audit_event(cfg)


def _emit_preloaded_modules_audit_event(cfg: _HookConfig) -> None:
    """Build and POST the preloaded-modules audit event.

    Snapshots ``sys.modules`` keys, caps at ``_PRELOADED_MODULES_CAP``,
    sorts alphabetically, then POSTs a ``hook_install_violation``
    audit event with ``metadata.reason="preloaded_modules_at_install"``.
    Fail-soft — never raises.
    """
    modules, truncated = _enumerate_preloaded_modules()
    metadata: Dict[str, Any] = {
        "reason": "preloaded_modules_at_install",
        "preloaded_module_count": len(modules),
        "preloaded_modules": modules,
        "truncated": truncated,
    }
    metadata.update(_diagnostics_metadata())
    _post_install_audit_event(
        kernel_url=cfg.kernel_url,
        worker_api_key=cfg.worker_api_key,
        caller_subject=cfg.caller_subject,
        metadata=metadata,
    )
