"""Subprocess propagation helpers (see the architecture overview).

``sys.addaudithook`` registrations do not survive ``fork()`` cleanly
and do not survive ``spawn()`` at all. These helpers re-arm the hook
in child processes via:

* :func:`wrap_subprocess` — drop-in replacement for
  :class:`subprocess.Popen` that injects a Python prologue calling
  :func:`install_audit_hook` in the child.
* :func:`wrap_multiprocessing` — context manager that monkey-patches
  :class:`multiprocessing.Process.run` so the hook installs before the
  user target executes.

Configuration is propagated to the child via env vars:

``SAFETY_KERNEL_URL`` / ``SAFETY_KERNEL_WORKER_API_KEY`` /
``SAFETY_KERNEL_CALLER_SUBJECT`` / ``SAFETY_KERNEL_FAIL_CLOSED`` /
``ARYA_AUDIT_HOOK_DISABLED`` (kill-switch inherited automatically).

**Env-var stripping detection (architect risk #2)**: adopters that
pass ``env=`` to :class:`subprocess.Popen` MUST include the safety-kernel
vars or the child silently spawns without the hook. The wrap helpers
detect this case, emit a CRITICAL log + ``subprocess_propagation_failed``
audit-event POST to the kernel, then ALLOW the spawn (the chain entry
is the auditable control).
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Iterable, Iterator, List, Optional, Sequence

from .install_audit_hook import _installed

__all__ = [
    "wrap_subprocess",
    "wrap_multiprocessing",
]

_LOGGER = logging.getLogger("safety_kernel_defense.subprocess")

# Env-var names — the architecture overview "Configuration propagation via env vars".
_ENV_KERNEL_URL = "SAFETY_KERNEL_URL"
_ENV_WORKER_API_KEY = "SAFETY_KERNEL_WORKER_API_KEY"
_ENV_CALLER_SUBJECT = "SAFETY_KERNEL_CALLER_SUBJECT"
_ENV_FAIL_CLOSED = "SAFETY_KERNEL_FAIL_CLOSED"

# The 4 env vars that MUST flow to the child for the hook to arm.
_REQUIRED_PROPAGATION_VARS = (
    _ENV_KERNEL_URL,
    _ENV_WORKER_API_KEY,
    _ENV_CALLER_SUBJECT,
)


def _is_python_executable(arg0: str) -> bool:
    """Heuristic: does ``arg0`` invoke a Python interpreter?"""
    base = os.path.basename(arg0)
    if base.startswith("python"):
        return True
    return arg0 == sys.executable


def _build_propagation_env(base_env: Optional[dict]) -> dict:
    """Build the child env: start from parent ``os.environ`` then
    overlay caller-supplied ``env=``, but ALWAYS preserve the
    safety-kernel vars from the parent's environment (so an adopter
    that passes ``env={"PATH": "/bin"}`` does not strip the hook
    config). the architecture overview — env-var propagation is unconditional.
    """
    if base_env is None:
        # Use the parent's environment unchanged + ensure our vars
        # are present. (They will already be present in the parent
        # process — the parent's install_audit_hook exported them
        # implicitly via os.environ. But if for some reason the
        # parent did NOT export them, we sync from the hook config.)
        new_env = dict(os.environ)
    else:
        # Caller-supplied env: start from it.
        new_env = dict(base_env)

    # Sync from the live config — wins over any stale env values.
    cfg = _installed.config
    if cfg is not None:
        new_env.setdefault(_ENV_KERNEL_URL, cfg.kernel_url)
        new_env.setdefault(_ENV_WORKER_API_KEY, cfg.worker_api_key)
        new_env.setdefault(_ENV_CALLER_SUBJECT, cfg.caller_subject)
        new_env.setdefault(
            _ENV_FAIL_CLOSED,
            "1" if cfg.fail_closed_on_unreachable else "0",
        )

    return new_env


def _emit_propagation_failure_event(reason: str, argv0: str) -> None:
    """Best-effort POST of a ``subprocess_propagation_failed`` audit event.

    Per the architecture overview Case B and risk #2: this is the auditable control
    for spawn paths that cannot be intercepted. Never raises; failure
    to emit is logged but does not block the parent.
    """
    cfg = _installed.config
    if cfg is None:
        _LOGGER.warning("propagation failure but hook not installed: %s", argv0)
        return
    payload = {
        "event_kind": "subprocess_propagation_failed",
        "subject": cfg.caller_subject,
        "metadata": {
            "argv0": argv0,
            "reason": reason,
        },
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=cfg.kernel_url + "/policy/audit-event",
        data=body,
        method="POST",
        headers={
            "content-type": "application/json",
            "x-api-key": cfg.worker_api_key,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout_seconds) as _resp:
            pass
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        _LOGGER.warning(
            "failed to emit subprocess_propagation_failed event: %s", exc
        )


def _inject_python_prologue(args: Sequence[Any]) -> List[Any]:
    """the architecture overview Case A: rewrite a python invocation to install
    the hook before user code runs.

    Returns a NEW args list — the caller's input is not mutated.
    """
    args_list = list(args)
    if len(args_list) < 2:
        return args_list  # bare ``python`` with no script — let it through

    # Find the "-c <source>" form or treat as "python script.py..." form.
    prologue = (
        "import safety_kernel_defense as _skd, os as _os; "
        "_skd.install_audit_hook("
        f"kernel_url=_os.environ['{_ENV_KERNEL_URL}'], "
        f"worker_api_key=_os.environ['{_ENV_WORKER_API_KEY}'], "
        f"caller_subject=_os.environ['{_ENV_CALLER_SUBJECT}'], "
        "fail_closed_on_unreachable="
        f"_os.environ.get('{_ENV_FAIL_CLOSED}', '1') != '0',"
        ")"
    )

    if "-c" in args_list[1:]:
        idx = args_list.index("-c")
        if idx + 1 < len(args_list):
            original = args_list[idx + 1]
            args_list[idx + 1] = f"{prologue}; {original}"
            return args_list

    # python script.py [args...] — rewrite to python -c "<prologue>; exec(open(script).read())" [args...]
    script_idx = 1
    # Skip leading interpreter flags like -u, -X..., -O, etc.
    while script_idx < len(args_list) and isinstance(args_list[script_idx], str) and args_list[script_idx].startswith("-"):
        # Some flags take an argument (e.g. -X dev). We can't perfectly
        # parse the Python CLI here — for the slice-3 reference, we
        # conservatively skip only single-arg flags and rely on -c
        # form for complex cases.
        if args_list[script_idx] in ("-X", "-W"):
            script_idx += 2
        else:
            script_idx += 1
    if script_idx >= len(args_list):
        return args_list
    script = args_list[script_idx]
    if not isinstance(script, str):
        return args_list
    new_args: List[Any] = list(args_list[:script_idx])
    new_args.extend([
        "-c",
        f"{prologue}; exec(open({script!r}).read())",
    ])
    new_args.extend(args_list[script_idx + 1 :])
    return new_args


def wrap_subprocess(*popen_args: Any, **popen_kwargs: Any) -> subprocess.Popen:
    """Drop-in replacement for :class:`subprocess.Popen` (see the architecture overview).

    Case A (child is python): rewrites the args list to inject a
    prologue that calls :func:`install_audit_hook` before user code.

    Case B (child is not python): logs WARN, emits a
    ``subprocess_propagation_failed`` audit event to the kernel, and
    spawns the child unchanged.

    Env-var stripping detection: if ``env=`` is supplied without the
    required safety-kernel vars, we re-inject them from the parent
    hook's config. If the parent has no hook config (i.e. wrap was
    called before install_audit_hook), we WARN.

    Returns the live :class:`subprocess.Popen` object — the caller is
    responsible for ``wait()`` / ``communicate()`` as with normal
    ``Popen``.
    """
    # Extract args (positional or keyword).
    if popen_args:
        args = popen_args[0]
        popen_args = popen_args[1:]
    else:
        args = popen_kwargs.pop("args")

    if isinstance(args, (str, bytes)):
        # Shell-form invocation; treat as Case B (we can't safely rewrite).
        argv0 = str(args).split(maxsplit=1)[0] if args else ""
        _LOGGER.warning(
            "wrap_subprocess: shell-form Popen call cannot inject "
            "hook prologue (argv0=%s) — emitting propagation event",
            argv0,
        )
        _emit_propagation_failure_event("shell_form_invocation", argv0)
        return subprocess.Popen(*((args,) + popen_args), **popen_kwargs)

    args = list(args)
    argv0 = str(args[0]) if args else ""

    # Detect env-var stripping. If the caller passed env= and our
    # required vars are missing, log + audit-event but PRESERVE the
    # vars in the merged env (architect risk #2).
    caller_env = popen_kwargs.get("env")
    if caller_env is not None:
        missing = [v for v in _REQUIRED_PROPAGATION_VARS if v not in caller_env]
        if missing:
            _LOGGER.critical(
                "wrap_subprocess: caller env= stripped safety-kernel vars %s "
                "for argv0=%s — re-injecting from hook config",
                missing,
                argv0,
            )
            _emit_propagation_failure_event(
                "env_var_stripped:" + ",".join(missing),
                argv0,
            )

    if _is_python_executable(argv0):
        args = _inject_python_prologue(args)
    else:
        _LOGGER.warning(
            "wrap_subprocess: non-python child argv0=%s; cannot intercept "
            "imports — emitting propagation event and allowing spawn",
            argv0,
        )
        _emit_propagation_failure_event("non_python_child", argv0)

    popen_kwargs["env"] = _build_propagation_env(caller_env)
    return subprocess.Popen(args, *popen_args, **popen_kwargs)


# Multiprocessing patch — monkey-patches Process.run via a context
# manager. Ref-counted so two concurrent users do not de-patch each
# other (see the architecture overview).

_mp_patch_lock = __import__("threading").Lock()
_mp_patch_state = {"count": 0, "original": None}


def _patched_run(self: Any) -> Any:
    """Replacement for ``multiprocessing.Process.run`` that installs
    the hook in the child before invoking the original ``run``.
    """
    cfg = _installed.config
    if cfg is not None:
        from .install_audit_hook import install_audit_hook

        try:
            install_audit_hook(
                kernel_url=cfg.kernel_url,
                worker_api_key=cfg.worker_api_key,
                caller_subject=cfg.caller_subject,
                caller_run_id=None,  # fresh run id per child
                fail_closed_on_unreachable=cfg.fail_closed_on_unreachable,
                timeout_seconds=cfg.timeout_seconds,
                audited_event_kinds=cfg.audited_event_kinds,
                event_metadata_max_bytes=cfg.event_metadata_max_bytes,
            )
        except Exception as exc:  # noqa: BLE001 — best-effort install
            _LOGGER.warning(
                "wrap_multiprocessing: child-side install failed: %s", exc
            )
    original = _mp_patch_state["original"]
    if original is not None:
        return original(self)
    return None


@contextlib.contextmanager
def wrap_multiprocessing() -> Iterator[None]:
    """Context manager: patch :class:`multiprocessing.Process.run` so
    children install the hook before executing the user target.

    Reference-counted: nested or concurrent uses are safe. The patch
    is removed when the outermost ``with`` block exits.
    """
    import multiprocessing  # imported lazily — many adopters never use mp.

    with _mp_patch_lock:
        if _mp_patch_state["count"] == 0:
            _mp_patch_state["original"] = multiprocessing.Process.run
            multiprocessing.Process.run = _patched_run  # type: ignore[assignment]
        _mp_patch_state["count"] += 1

    try:
        yield
    finally:
        with _mp_patch_lock:
            _mp_patch_state["count"] -= 1
            if _mp_patch_state["count"] == 0:
                original = _mp_patch_state["original"]
                if original is not None:
                    multiprocessing.Process.run = original  # type: ignore[assignment]
                _mp_patch_state["original"] = None


# Suppress unused-import warning on Iterable
_ = Iterable  # type: ignore[assignment]
