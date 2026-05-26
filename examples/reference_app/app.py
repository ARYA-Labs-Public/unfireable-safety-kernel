"""Reference FastAPI app for the Safety Kernel.

Demonstrates all three policy tiers in one process:

* ``GET  /healthz`` → UNRESTRICTED — no kernel call
* ``GET  /api/v1/status`` → SUPERVISED — kernel called, fail-open
* ``POST /api/v1/rsi/apply`` → GATED — kernel called, fail-closed

Also exposes a ``POST /auth-check`` sidecar that nginx can call via
``auth_request`` — see ``examples/middleware/nginx_policy.conf``.

Run with::

    uvicorn examples.reference_app.app:app --port 8080
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from examples.middleware import install_safety_middleware
from examples.middleware.handler_guard import require_safety_token
from examples.policy import policy
from examples.policy.default_policy import PolicyTier
from packages.core.safety_tokens import params_fingerprint
from packages.safety.client import (
    KernelClientError,
    PinnedKeyVerifier,
    SafetyKernelClient,
)

__all__ = ["app", "build_app"]


def build_app(
    *,
    client: SafetyKernelClient | None = None,
    api_key: str | None = None,
    pinned_verifier: PinnedKeyVerifier | None = None,
    base_url: str | None = None,
) -> FastAPI:
    """Build the reference app.

    Defaults to a :class:`SafetyKernelClient` pointing at
    ``$QORCH_KERNEL_URL`` (or the mock kernel — see ``docker-compose.yml``).
    """
    fastapi_app = FastAPI(title="ARYA Safety Kernel reference app")
    safety_policy = (
        policy()
        .unrestricted("GET", r"^/healthz$")
        .unrestricted("GET", r"^/metrics$")
        .unrestricted("GET", r"^/docs")
        .unrestricted("GET", r"^/openapi\.json$")
        .unrestricted("POST", r"^/auth-check$")  # nginx sidecar — gated externally
        .supervised(
            "GET",
            r"^/api/v1/status$",
            action="api.read.status",
        )
        .gated(
            "POST",
            r"^/api/v1/rsi/apply$",
            action="rsi.apply_proposal",
        )
        .gated(
            "POST",
            r"^/api/v1/rsi/rollback$",
            action="rsi.rollback",
        )
        .build()
    )

    if client is None:
        client = SafetyKernelClient(
            base_url=base_url or os.environ.get("QORCH_KERNEL_URL", "http://localhost:9001"),
            api_key=api_key or os.environ.get("QORCH_KERNEL_API_KEY_WORKER", ""),
            pinned_verifier=pinned_verifier,
        )

    install_safety_middleware(
        fastapi_app, client=client, policy=safety_policy, subject="api"
    )

    # ----------------------------------------------------------------
    # Routes
    # ----------------------------------------------------------------

    @fastapi_app.get("/healthz")
    def _healthz() -> dict[str, str]:
        return {"status": "ok"}

    @fastapi_app.get("/api/v1/status")
    def _status(request: Request) -> dict[str, Any]:
        warning = getattr(request.state, "safety_warning", None)
        return {
            "status": "ok",
            "tier": "SUPERVISED",
            "safety_warning": warning,
        }

    @fastapi_app.post("/api/v1/rsi/apply")
    @require_safety_token
    async def _rsi_apply(request: Request) -> dict[str, Any]:
        decision = getattr(request.state, "safety_decision", None)
        body = await request.json() if int(request.headers.get("content-length", 0) or 0) else {}
        return {
            "status": "applied",
            "proposal_id": str(body.get("proposal_id", "unknown")),
            "token_sha256": (decision.metadata or {}).get("token_sha256") if decision else None,
        }

    @fastapi_app.post("/api/v1/rsi/rollback")
    @require_safety_token
    async def _rsi_rollback(request: Request) -> dict[str, Any]:
        decision = getattr(request.state, "safety_decision", None)
        return {
            "status": "rolled_back",
            "token_sha256": (decision.metadata or {}).get("token_sha256") if decision else None,
        }

    # ----------------------------------------------------------------
    # /auth-check — nginx auth_request sidecar
    # ----------------------------------------------------------------

    @fastapi_app.post("/auth-check")
    async def _auth_check(request: Request) -> Response:
        """Nginx ``auth_request`` sidecar — see nginx_policy.conf.

        Calls the kernel with the original request's method + URI as
        the params fingerprint input. Returns 200 (allow), 403 (deny),
        or 503 (unavailable). On allow, surfaces the signed kernel
        metadata via ``X-Kernel-*`` response headers so nginx can
        forward them to the upstream.
        """
        original_uri = request.headers.get("x-original-uri", "")
        original_method = request.headers.get("x-original-method", "GET")
        tier, action = safety_policy.classify(path=original_uri.split("?")[0], method=original_method)
        if tier == PolicyTier.UNRESTRICTED:
            return Response(status_code=204)

        params_fp = params_fingerprint(
            {"path": original_uri, "method": original_method.upper()}
        )
        run_id = f"nginx-{original_method.lower()}-{params_fp[:12]}"
        try:
            decision = client.authorize(
                action=action,
                params_fingerprint=params_fp,
                run_id=run_id,
                subject="api",
            )
        except KernelClientError as exc:
            return JSONResponse(
                status_code=503,
                content={
                    "error": "service_unavailable",
                    "reason": "safety_kernel_unavailable",
                    "detail": str(exc),
                },
            )
        if not decision.allowed:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "forbidden",
                    "reason": decision.reason,
                },
            )

        resp = Response(status_code=204)
        token_sha256_str = str((decision.metadata or {}).get("token_sha256") or "")
        resp.headers["X-Kernel-Decision"] = "allow"
        resp.headers["X-Kernel-Action"] = action
        resp.headers["X-Kernel-Run-Id"] = run_id
        if token_sha256_str:
            resp.headers["X-Kernel-Token-Sha256"] = token_sha256_str
        return resp

    return fastapi_app


# Default app instance for `uvicorn examples.reference_app.app:app`.
app = build_app()
