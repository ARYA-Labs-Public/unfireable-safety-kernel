"""Per-handler structural-defense decorator (, ).

Companion to :mod:`examples.middleware.fastapi_safety_middleware`. The
FastAPI middleware authorizes a request and stashes the
:class:`KernelPolicyDecision` on ``request.state.safety_decision``. If
some operator wires the middleware incorrectly (typo on
``app.add_middleware``, route attached to a sub-app that lacks the
middleware, or the middleware is removed by a misguided refactor), the
GATED handlers would silently accept the request because nothing on the
handler itself checks that a Safety Kernel decision is present.

This decorator closes that gap. It is the Python analogue of the
Rust-side ``request.extensions().get::<SafetyToken>()`` check —
*structural* defence-in-depth that refuses the request if the
middleware did not run, even if all four enforcement seams in
``docs/integration/enforcement-seams.md`` were misconfigured.

Usage::

    from examples.middleware import require_safety_token

    @fastapi_app.post("/api/v1/rsi/apply")
    @require_safety_token
    async def _rsi_apply(request: Request) -> dict[str, Any]:
        ...

The decorator MUST be applied to **every** GATED route handler in the
reference app (and in operator deployments). It costs one ``getattr``
per request; the safety it buys is worth that cost.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar

__all__ = ["require_safety_token", "MissingSafetyTokenError"]

T = TypeVar("T")


class MissingSafetyTokenError(RuntimeError):
    """The handler ran without a Safety Kernel decision on ``request.state``.

    Raised by :func:`require_safety_token` and converted into a 403 by
    FastAPI's exception handlers. The fact that this error reached the
    handler indicates the FastAPI middleware was NOT installed (or was
    misconfigured) — the request should be refused regardless.
    """


def require_safety_token(fn: Callable[..., T]) -> Callable[..., T]:
    """Refuse the request if the SafetyMiddleware did not run.

    Looks for ``request.state.safety_decision`` (set by
    :class:`SafetyMiddleware` after a successful kernel authorize). If
    missing, raises :class:`fastapi.HTTPException` with status 403 and
    ``missing_safety_token`` detail.

    The decorator is async-aware: if the wrapped function is a
    coroutine, the wrapper itself is a coroutine and awaits the inner
    call. Otherwise the wrapper is synchronous.

    Args:
        fn: The route handler. MUST accept a ``request`` argument
            (positional or keyword) — the convention for FastAPI route
            handlers that need access to the request state.

    Returns:
        The wrapped handler.

    Raises:
        fastapi.HTTPException(403): when ``request.state.safety_decision``
            is missing — i.e. the middleware did not run.
    """
    # Local import: keeps the module importable in non-FastAPI
    # contexts (the gRPC interceptor module also lives in this package).
    try:
        from fastapi import HTTPException
    except ImportError:  # pragma: no cover — fastapi is a hard dep of the ref app
        HTTPException = RuntimeError  # type: ignore[misc,assignment]

    import asyncio

    is_coroutine = asyncio.iscoroutinefunction(fn)

    def _extract_request(args: tuple[Any,...], kwargs: dict[str, Any]) -> Any:
        """Find the ``Request`` (or ``WebSocket``) argument in the call.

        FastAPI passes the request as a positional argument when the
        parameter is annotated as ``Request``. Operators may also bind
        it by keyword name (``request=``). We look both ways.
        """
        req = kwargs.get("request") or kwargs.get("req")
        if req is not None:
            return req
        # Fall back to the first positional arg that has a ``.state``
        # attribute (duck-typing — matches both Request and WebSocket).
        for a in args:
            if hasattr(a, "state"):
                return a
        return None

    def _check(request: Any) -> None:
        """Raise if request.state lacks the safety_decision marker."""
        decision = getattr(getattr(request, "state", None), "safety_decision", None)
        if decision is None:
            # We do NOT include any kernel detail in the response body —
            # the absence of the decision is enough to refuse, and we
            # do not want to leak internal-state info to a caller that
            # bypassed the middleware.
            raise HTTPException(status_code=403, detail="missing_safety_token")

    if is_coroutine:

        @functools.wraps(fn)
        async def _async_wrapper(*args: Any, **kwargs: Any) -> T:
            request = _extract_request(args, kwargs)
            if request is None:
                # Handler signature is unusual — refuse rather than
                # silently allow. Documents the contract: every guarded
                # handler MUST accept the request object.
                raise HTTPException(
                    status_code=403,
                    detail="missing_safety_token",
                )
            _check(request)
            return await fn(*args, **kwargs)  # type: ignore[misc]

        return _async_wrapper  # type: ignore[return-value]

    @functools.wraps(fn)
    def _sync_wrapper(*args: Any, **kwargs: Any) -> T:
        request = _extract_request(args, kwargs)
        if request is None:
            raise HTTPException(
                status_code=403,
                detail="missing_safety_token",
            )
        _check(request)
        return fn(*args, **kwargs)

    return _sync_wrapper
