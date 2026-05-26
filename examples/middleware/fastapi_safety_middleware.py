"""FastAPI Safety Kernel middleware (, seam #2 of 4).

Drop-in :class:`BaseHTTPMiddleware` that consults the Safety Kernel
once per request. The policy classifies each route into one of three
tiers (``UNRESTRICTED`` / ``SUPERVISED`` / ``GATED``) — only
``GATED`` and ``SUPERVISED`` routes actually hit the kernel.

Failure semantics:

* ``GATED`` + kernel deny       → 403 Forbidden
* ``GATED`` + kernel unreachable → 503 Service Unavailable
* ``GATED`` + signature failed   → 503 Service Unavailable
* ``SUPERVISED`` + any failure   → request continues, audit warning emitted
* ``UNRESTRICTED``               → no kernel call, no audit

Usage::

    from fastapi import FastAPI
    from examples.middleware import install_safety_middleware
    from examples.policy import DEFAULT_POLICY
    from packages.safety.client import SafetyKernelClient

    app = FastAPI()
    install_safety_middleware(
        app,
        client=SafetyKernelClient(api_key=os.environ["QORCH_KERNEL_API_KEY_WORKER"]),
        policy=DEFAULT_POLICY,
        subject="api",
    )

WebSocket coverage
-----------------------------

``BaseHTTPMiddleware`` does NOT cover WebSocket upgrades. Starlette
only dispatches HTTP scopes through it; WebSocket scopes flow straight
to the route handler. To gate WebSocket upgrades through the kernel,
use the :func:`websocket_safety_dependency` FastAPI ``Depends``::

    from fastapi import Depends, WebSocket
    from examples.middleware import (
        WebSocketSafetyDependency, websocket_safety_dependency
    )

    ws_gate = WebSocketSafetyDependency(
        client=safety_client,
        policy=safety_policy,
        subject="api",
    )

    @app.websocket("/ws/rsi/feed")
    async def _rsi_feed(
        websocket: WebSocket,
        token = Depends(ws_gate),
    ) -> None:
        # gate has already authorized; missing/denied → 1008 close
        ...

The dependency authorizes the upgrade against the kernel. On deny it
calls :meth:`WebSocket.close` with code 1008 (Policy Violation) and
raises :class:`fastapi.WebSocketException`. See
``docs/integration/enforcement-seams.md`` § WebSocket gating.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from typing import Any

from packages.core.safety_tokens import params_fingerprint
from packages.safety.client import (
    KernelClientError,
    KernelDecisionError,
    SafetyKernelClient,
)

from examples.observability.kernel_call_metrics import (
    instrument_authorize,
    record_bypass_attempt,
)
from examples.policy.default_policy import PolicyTier, SafetyPolicy

__all__ = [
    "SafetyMiddleware",
    "WebSocketSafetyDependency",
    "install_safety_middleware",
    "websocket_safety_dependency",
]


# Header callers can set to provide an explicit run id. Defaults are
# generated per-request if absent.
_RUN_ID_HEADER = "x-arya-run-id"
_SUBJECT_HEADER = "x-arya-subject"


def install_safety_middleware(
    app: Any,
    *,
    client: SafetyKernelClient,
    policy: SafetyPolicy,
    subject: str = "api",
) -> None:
    """Convenience helper — wires the middleware and stashes the client
    on ``app.state`` so route handlers can introspect the audit trail.

    Equivalent to::

        app.state.safety_client = client
        app.state.safety_policy = policy
        app.add_middleware(SafetyMiddleware, client=client, policy=policy, subject=subject)
    """
    app.state.safety_client = client
    app.state.safety_policy = policy
    app.add_middleware(
        SafetyMiddleware, client=client, policy=policy, default_subject=subject
    )


try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.types import ASGIApp
    from starlette.websockets import WebSocket

    _STARLETTE_AVAILABLE = True
except ImportError:  # pragma: no cover — starlette is a hard dep of fastapi
    _STARLETTE_AVAILABLE = False
    BaseHTTPMiddleware = object  # type: ignore[misc,assignment]
    WebSocket = Any  # type: ignore[misc,assignment]


class SafetyMiddleware(BaseHTTPMiddleware):
    """Starlette/FastAPI middleware that gates every request through
    the Safety Kernel per the configured :class:`SafetyPolicy`.

    Args:
        app: The downstream ASGI app.
        client: The :class:`SafetyKernelClient` instance.
        policy: The :class:`SafetyPolicy` rule list.
        default_subject: Default subject string when the
            ``x-arya-subject`` header is absent. Typically ``"api"`` or
            ``"worker"``.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        client: SafetyKernelClient,
        policy: SafetyPolicy,
        default_subject: str = "api",
    ) -> None:
        if not _STARLETTE_AVAILABLE:  # pragma: no cover
            raise RuntimeError(
                "SafetyMiddleware requires starlette/fastapi to be installed."
            )
        super().__init__(app)
        self._client = client
        self._policy = policy
        self._default_subject = default_subject

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        path = request.url.path
        method = request.method.upper()
        tier, action = self._policy.classify(path=path, method=method)

        if tier == PolicyTier.UNRESTRICTED:
            return await call_next(request)

        # Compute the params fingerprint over the request shape — for
        # GET we use {path, query}; for write methods we include the
        # body. Both fingerprints are SHA-256 hex so the kernel can
        # bind the signed token to this exact request.
        params_fp = await self._compute_params_fingerprint(request)
        run_id = request.headers.get(_RUN_ID_HEADER) or self._generate_run_id(path, method)
        subject = request.headers.get(_SUBJECT_HEADER) or self._default_subject

        try:
            with instrument_authorize(action=action) as record:
                decision = self._client.authorize(
                    action=action,
                    params_fingerprint=params_fp,
                    run_id=run_id,
                    subject=subject,
                )
                record(decision)
        except KernelDecisionError as exc:
            # Kernel unreachable (transport / 5xx / breaker open).
            if tier == PolicyTier.GATED:
                return self._unavailable_response(action=action, reason=str(exc))
            # Supervised tier — fail open with audit warning.
            request.state.safety_warning = f"supervised_kernel_unavailable:{exc}"
            return await call_next(request)
        except KernelClientError as exc:
            # Decode / transport drift / verification failure → always
            # fail-closed (even on supervised) because these signal a
            # contract bug or potential tampering.
            return self._unavailable_response(action=action, reason=str(exc))

        if not decision.allowed:
            # 403 — the kernel REFUSED.
            return JSONResponse(
                status_code=403,
                content={
                    "error": "forbidden",
                    "reason": decision.reason,
                    "action": action,
                },
            )

        # Stash decision metadata on request.state so handlers can
        # introspect the token (e.g. to forward to downstream services).
        request.state.safety_decision = decision
        request.state.safety_action = action
        return await call_next(request)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _compute_params_fingerprint(self, request: Request) -> str:
        """Stable SHA-256 fingerprint of the request shape.

        For GET / DELETE we hash ``{path, query}``. For write methods
        (POST / PUT / PATCH) we additionally include the request body
        — but we read it lazily and stash it back on the request so the
        downstream handler still sees it.
        """
        components: dict[str, Any] = {
            "path": request.url.path,
            "method": request.method.upper(),
            "query": dict(request.query_params),
        }
        if request.method.upper() in {"POST", "PUT", "PATCH"}:
            try:
                body_bytes = await request.body()
            except Exception:  # noqa: BLE001
                body_bytes = b""
            # Stash body so the inner handler can re-read it.
            request._body = body_bytes  # type: ignore[attr-defined]
            components["body_sha256"] = hashlib.sha256(body_bytes).hexdigest()
        return params_fingerprint(components)

    @staticmethod
    def _generate_run_id(path: str, method: str) -> str:
        """Per-request run id when the caller didn't supply one.

        Includes a short uuid suffix so two identical requests still
        produce distinct run ids and the kernel's replay-protection
        does not block the second one.
        """
        return f"req-{method.lower()}-{path.strip('/').replace('/', '-') or 'root'}-{uuid.uuid4().hex[:12]}"

    @staticmethod
    def _unavailable_response(*, action: str, reason: str) -> JSONResponse:
        record_bypass_attempt("circuit_breaker")
        return JSONResponse(
            status_code=503,
            content={
                "error": "service_unavailable",
                "reason": "safety_kernel_unavailable",
                "detail": reason,
                "action": action,
            },
        )


# ---------------------------------------------------------------------------
# WebSocket gating
# ---------------------------------------------------------------------------
#
# Starlette's :class:`BaseHTTPMiddleware` only handles ``http`` ASGI
# scopes; WebSocket upgrades flow straight to the route handler. The
# class + helper below provide a FastAPI ``Depends`` that gates a
# WebSocket upgrade through the Safety Kernel before the application
# code accepts the socket.


class WebSocketSafetyDependency:
    """FastAPI ``Depends``-compatible WebSocket authorization gate.

    Authenticates the upgrade request against the Safety Kernel using
    the same :class:`SafetyPolicy` that governs HTTP routes. The
    dependency is constructed once per app (binding it to the client
    and policy) and used per-route as ``Depends(dependency_instance)``.

    Args:
        client: :class:`SafetyKernelClient` to consult.
        policy: :class:`SafetyPolicy` mapping path → tier + action.
            The same instance the HTTP middleware uses is recommended
            (single source of truth for the route taxonomy).
        subject: Default subject string ("api"/"worker"/"operator").
        token_query_param: Name of the query parameter (or first
            header) that carries the caller's run-id / correlation
            token. The dependency does NOT itself validate caller
            identity — that should be done by an outer mTLS / cookie
            layer; this dependency consults the kernel for the upgrade
            *action*.

    Failure modes:
        * Kernel deny → ``WebSocket.close(code=1008)`` then raise
          :class:`fastapi.WebSocketException(code=1008,...)`.
        * Kernel unreachable → same; we fail-closed (consistent with
          HTTP GATED tier semantics).
        * Policy is UNRESTRICTED for the path → no kernel call, the
          dependency returns ``None`` and the handler proceeds.
        * Policy is SUPERVISED → kernel called; failure is logged but
          the socket is still accepted (audit-only). This matches the
          HTTP supervised tier — keep parity to avoid operator
          confusion.
    """

    def __init__(
        self,
        *,
        client: SafetyKernelClient,
        policy: SafetyPolicy,
        subject: str = "api",
        token_query_param: str = "x-arya-run-id",
    ) -> None:
        self._client = client
        self._policy = policy
        self._subject = subject
        self._token_query_param = token_query_param

    async def __call__(self, websocket: WebSocket) -> Any:
        return await websocket_safety_dependency(
            websocket,
            client=self._client,
            policy=self._policy,
            subject=self._subject,
            token_query_param=self._token_query_param,
        )


async def websocket_safety_dependency(
    websocket: WebSocket,
    *,
    client: SafetyKernelClient,
    policy: SafetyPolicy,
    subject: str = "api",
    token_query_param: str = "x-arya-run-id",
) -> Any:
    """Authorize a WebSocket upgrade through the Safety Kernel.

    Works as a standalone ``Depends`` callable when partial-applied via
    :class:`WebSocketSafetyDependency` (preferred — captures the
    client/policy at app-build time). Can also be called directly when
    the operator wants per-route configuration.

    Returns the :class:`KernelPolicyDecision` on allow (so the handler
    can introspect the signed token) or ``None`` for UNRESTRICTED
    routes.

    Raises:
        :class:`fastapi.WebSocketException(code=1008)` on deny /
        unreachable (GATED tier). The socket is closed with code 1008
        (Policy Violation) before the exception propagates.
    """
    # Local imports — keeps non-FastAPI consumers of this module from
    # paying for FastAPI/Starlette import at module load.
    try:
        from fastapi import WebSocketException
    except ImportError:  # pragma: no cover
        WebSocketException = RuntimeError  # type: ignore[misc,assignment]

    path = str(getattr(getattr(websocket, "url", None), "path", "") or "")
    # Treat ws upgrade as a "GET" for policy classification (the HTTP
    # method on the upgrade is always GET per RFC 6455 §1.3).
    tier, action = policy.classify(path=path, method="GET")

    if tier == PolicyTier.UNRESTRICTED:
        return None

    # Build a stable fingerprint from the upgrade URL + the caller's
    # correlation token (if present in either the query string or the
    # initial connect headers).
    query = dict(getattr(websocket, "query_params", {}) or {})
    headers = dict(getattr(websocket, "headers", {}) or {})
    run_id_raw = query.get(token_query_param) or headers.get(token_query_param)
    run_id = str(run_id_raw) if run_id_raw else f"ws-{action}-{uuid.uuid4().hex[:12]}"
    components = {
        "path": path,
        "method": "GET",
        "query": query,
        "upgrade": "websocket",
    }
    params_fp = params_fingerprint(components)

    try:
        with instrument_authorize(action=action) as record:
            decision = client.authorize(
                action=action,
                params_fingerprint=params_fp,
                run_id=run_id,
                subject=subject,
            )
            record(decision)
    except KernelDecisionError as exc:
        if tier == PolicyTier.GATED:
            # WebSocketException causes FastAPI to close with the given
            # code; we MUST NOT close manually first (Starlette refuses a
            # second close on the same socket).
            record_bypass_attempt("websocket")
            raise WebSocketException(
                code=1008, reason=f"safety_kernel_unavailable: {exc}"
            )
        # SUPERVISED — accept the socket; the caller can introspect the audit trail.
        return None
    except KernelClientError as exc:
        # Transport / verification failure — always fail-closed.
        record_bypass_attempt("websocket")
        raise WebSocketException(
            code=1008, reason=f"safety_kernel_unavailable: {exc}"
        )

    if not decision.allowed:
        record_bypass_attempt("websocket")
        raise WebSocketException(code=1008, reason=decision.reason or "kernel_denied")

    return decision
