"""``safety_kernel_defense`` — Python audit-hook reference for the
safety-kernel

The Layer-1 in-process defender. Subscribes to CPython's audit-event
fan-out via :func:`sys.addaudithook` and forwards
``import``/``exec``/``compile`` events to the Rust kernel's
``/policy/module/authorize`` endpoint. Replaces the legacy
in-process ``the in-process defender`` defender by moving
the policy decisions out-of-process to the Rust kernel.

Quickstart::

    from safety_kernel_defense import install_audit_hook

    install_audit_hook(
        kernel_url="https://your-kernel-host:9443",
        worker_api_key="<from env>",
        caller_subject="my-app-1.2.3",
    )

The hook is stdlib-only (uses :mod:`urllib.request` for the kernel
HTTP call). See ``safety_kernel_oss/docs/integration/python-audit-hook.md``
for the bootstrap-ordering caveat (CPython audit hooks are NOT
retroactive — install BEFORE any untrusted code loads).

Architect spec: ``docs/architecture.md``.
Threat model: ``docs/safety_kernel/threat_model_caller_bypass.md``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .exceptions import (
    HookConfigError,
    KernelUnavailable,
    PolicyDenied,
    RevokeError,
    SignatureInvalid,
)
from .install_audit_hook import install_audit_hook
from .subprocess_propagation import wrap_multiprocessing, wrap_subprocess

if TYPE_CHECKING:  # import for type-checkers only — no runtime dependency pull
    from .middleware import SafetyKernelMiddleware
    from .revoke_client import InstanceTarget, RevokeClient

__all__ = [
    "install_audit_hook",
    "wrap_subprocess",
    "wrap_multiprocessing",
    "PolicyDenied",
    "KernelUnavailable",
    "HookConfigError",
    "SignatureInvalid",
    "RevokeError",
    # FastAPI-extra surface — importing these pulls the [fastapi] deps.
    "SafetyKernelMiddleware",
    "RevokeClient",
    "InstanceTarget",
]

# Package version — kept here so the hook can report it as part of
# the optional metadata payload (the architecture overview "metadata" default).
__version__ = "0.2.0"

# The core audit hook is stdlib-only. The FastAPI middleware + revoke
# client depend on the `[fastapi]` extra (httpx / starlette / cryptography),
# so they are imported LAZILY here (PEP 562) — `import safety_kernel_defense`
# stays stdlib-only, and the extra deps are only required when a caller
# actually touches `SafetyKernelMiddleware` / `RevokeClient`.
_LAZY = {
    "SafetyKernelMiddleware": ".middleware",
    "RevokeClient": ".revoke_client",
    "InstanceTarget": ".revoke_client",
}


def __getattr__(name: str) -> Any:
    """Lazily import the FastAPI-extra surface on first attribute access."""
    module_path = _LAZY.get(name)
    if module_path is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    module = importlib.import_module(module_path, __name__)
    return getattr(module, name)
