"""Per-tool dispatch hook decorator (, seam #3 of 4).

Use this when a single function is the choke point for a sensitive
operation — typical for LangChain tools, MCP handlers, and any
agentic dispatch layer. The decorator gates the call through the
Safety Kernel and ENFORCES that the kernel's signed claim matches the
caller's declared action (defends against tool-confusion attacks).

Usage::

    from examples.middleware import safety_gate
    from packages.safety.client import SafetyKernelClient

    client = SafetyKernelClient(api_key=...)

    @safety_gate(client=client, action="rsi.apply_proposal", subject="worker")
    def apply_proposal(proposal_id: str) -> dict:
        #... actually apply the proposal...
        return {"status": "applied"}

    apply_proposal("p-123")  # → consults kernel first; raises on deny

If the kernel approves, the decorated function runs as normal. The
``KernelPolicyDecision`` (with the signed token) is exposed via
``safety_gate.last_decision()`` for downstream signing.
"""

from __future__ import annotations

import functools
import hashlib
import json
import uuid
from collections.abc import Callable
from typing import Any, TypeVar

from packages.core.safety_tokens import params_fingerprint
from packages.safety.client import KernelClientError, SafetyKernelClient

from examples.observability.kernel_call_metrics import (
    instrument_authorize,
    record_bypass_attempt,
)

__all__ = ["safety_gate", "ToolConfusionError"]

T = TypeVar("T")


class ToolConfusionError(KernelClientError):
    """The kernel signed a token whose ``claims.action`` did NOT match
    the action the caller declared at decoration time.

    Mirrors the AC16 ``WRONG_TOOL_TOKEN`` fixture's rejection contract.
    Always a REJECTION — the caller MUST treat this as fail-closed.
    """


def safety_gate(
    *,
    client: SafetyKernelClient,
    action: str,
    subject: str = "worker",
    fingerprint_args: bool = True,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator factory.

    Args:
        client: The :class:`SafetyKernelClient` to consult.
        action: The action string passed to the kernel and verified
            against the response token's ``claims.action`` field.
            Must be on the kernel's allowlist.
        subject: The subject string ("worker"/"api"/"operator").
        fingerprint_args: When True, the decorator hashes the call's
            ``(args, kwargs)`` into the ``params_fingerprint``. This
            binds the kernel's signed token to this exact invocation
            — preventing token reuse across different argument shapes.
    """

    def _decorate(fn: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(fn)
        def _wrapped(*args: Any, **kwargs: Any) -> T:
            params_fp = (
                _fingerprint_call(args, kwargs)
                if fingerprint_args
                else "0" * 64
            )
            run_id = f"dispatch-{action}-{uuid.uuid4().hex[:12]}"
            try:
                with instrument_authorize(action=action) as record:
                    decision = client.authorize(
                        action=action,
                        params_fingerprint=params_fp,
                        run_id=run_id,
                        subject=subject,
                    )
                    record(decision)
            except KernelClientError:
                record_bypass_attempt("dispatch")
                raise

            if not decision.allowed:
                # Kernel refused — propagate as a KernelClientError.
                raise KernelClientError(
                    f"safety_gate: kernel denied action {action!r}: {decision.reason}"
                )

            # Tool-confusion defence: the kernel's signed claims MUST
            # report the SAME action we asked for. If not, the token
            # was issued for something else — reject.
            claims = (decision.metadata or {}).get("claims") or {}
            signed_action = str(claims.get("action") or "")
            if signed_action and signed_action != action:
                record_bypass_attempt("dispatch")
                raise ToolConfusionError(
                    f"safety_gate: kernel signed action={signed_action!r} but "
                    f"caller asked for action={action!r} — tool-confusion attempt rejected."
                )

            # Expose the decision on the wrapper for downstream code.
            _wrapped.last_decision = decision  # type: ignore[attr-defined]
            return fn(*args, **kwargs)

        _wrapped.last_decision = None  # type: ignore[attr-defined]
        return _wrapped

    return _decorate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fingerprint_call(args: tuple[Any,...], kwargs: dict[str, Any]) -> str:
    """Stable SHA-256 hex of the call's positional + keyword arguments.

    Uses :func:`packages.core.safety_tokens.params_fingerprint` so the
    fingerprint format matches the kernel's canonical hash.
    """
    canonical = {
        "args": [_safe(repr(a)) for a in args],
        "kwargs": {str(k): _safe(repr(v)) for k, v in sorted(kwargs.items())},
    }
    return params_fingerprint(canonical)


def _safe(value: str) -> str:
    """Truncate over-long args so the fingerprint payload stays bounded."""
    return value[:512]
