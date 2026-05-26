"""Drop-in mock Safety Kernel for local dev + test.

A minimal FastAPI app exposing the three endpoints the
:class:`SafetyKernelClient` consumes:

* ``POST /kernel/v1/authorize`` — returns an Ed25519-signed token on
  allow, or 403 on deny.
* ``GET  /kernel/v1/health`` — always 200.
* ``GET  /kernel/v1/public_key`` — returns the mock signing key as
  base64url-no-pad + sha256 fingerprint.

The mock holds a private signing key (generated once at startup) so
the issued tokens verify against the bundled fingerprint. The action
allowlist and deny rules are configurable via :class:`MockKernelConfig`.

This is NOT a production kernel. It exists so the reference app can
run end-to-end in CI without the full Rust kernel container.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from packages.core.safety_tokens import (
    KERNEL_AUTHORIZE_AUD,
    ed25519_public_key_b64,
    ed25519_public_key_fingerprint,
    sign_kernel_token,
    token_sha256,
)

__all__ = ["MockKernelConfig", "build_mock_kernel_app"]


@dataclass
class MockKernelConfig:
    """Behaviour knobs for the mock kernel.

    Args:
        allowed_actions: Set of action strings the kernel will ALLOW.
            Any other action receives a 403 with reason
            ``action_denylist``.
        token_ttl_s: Lifetime of issued tokens in seconds.
        api_keys: Set of API keys the kernel will accept on the
            ``x-api-key`` header. An empty set disables auth.
        replay_cache: Optional shared set of (run_id,
            params_fingerprint) tuples for replay-rejection tests.
            When set and a duplicate request arrives, the kernel
            responds with 403 ``replay_detected``.
        force_unavailable: When True every authorize call returns 503
            — used by the kernel-stopped fixture.
    """

    allowed_actions: frozenset[str] = frozenset(
        {
            "rsi.apply_proposal",
            "rsi.rollback",
            "api.read.status",
            "api.admin",
            "test.adversarial.action_a",
            "test.adversarial.action_b",
        }
    )
    token_ttl_s: float = 300.0
    api_keys: frozenset[str] = frozenset()
    replay_cache: set[tuple[str, str]] = field(default_factory=set)
    force_unavailable: bool = False


def build_mock_kernel_app(
    config: MockKernelConfig | None = None,
    *,
    signing_key: Ed25519PrivateKey | None = None,
) -> Any:
    """Build a FastAPI app that mimics the real Rust kernel.

    Returns the FastAPI instance and exposes the signing key + pinned
    public key via ``app.state`` so test fixtures can construct a
    matching :class:`PinnedKeyVerifier`.
    """
    from fastapi import FastAPI, Header, HTTPException, Request

    cfg = config or MockKernelConfig()
    priv = signing_key or Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_b64 = ed25519_public_key_b64(pub)
    pub_fp = ed25519_public_key_fingerprint(pub)

    app = FastAPI(title="MockSafetyKernel")
    app.state.signing_key = priv
    app.state.public_key_b64 = pub_b64
    app.state.public_key_fingerprint = pub_fp
    app.state.config = cfg

    started_at = time.time()

    @app.get("/kernel/v1/health")
    def _health() -> dict[str, Any]:
        return {
            "ok": True,
            "uptime_s": time.time() - started_at,
            "version": "mock-ary1889-",
        }

    @app.get("/kernel/v1/public_key")
    def _public_key() -> dict[str, Any]:
        return {
            "algorithm": "Ed25519",
            "ok": True,
            "public_key_b64": pub_b64,
            "public_key_fingerprint": pub_fp,
        }

    @app.post("/kernel/v1/authorize")
    async def _authorize(
        request: Request,
        x_api_key: str | None = Header(default=None, alias="x-api-key"),
    ) -> Any:
        if cfg.force_unavailable:
            raise HTTPException(status_code=503, detail="kernel unavailable (mock)")

        if cfg.api_keys and (not x_api_key or x_api_key not in cfg.api_keys):
            return _deny(403, "missing_or_invalid_api_key")

        body = await request.json()
        action = str(body.get("action", ""))
        params_fp = str(body.get("params_fingerprint", ""))
        run_id = str(body.get("run_id", ""))
        subject = str(body.get("subject", ""))

        if not action or not params_fp or not run_id or not subject:
            return _deny(403, "missing_required_field")

        if action not in cfg.allowed_actions:
            return _deny(403, "action_denylist")

        replay_key = (run_id, params_fp)
        if replay_key in cfg.replay_cache:
            return _deny(403, "replay_detected")
        cfg.replay_cache.add(replay_key)

        now = time.time()
        claims = {
            "action": action,
            "run_id": run_id,
            "subject": subject,
            "params_fingerprint": params_fp,
            "issued_at": now,
            "expires_at": now + cfg.token_ttl_s,
            "nonce": uuid4().hex[:22],
            "aud": KERNEL_AUTHORIZE_AUD,
        }
        token = sign_kernel_token(claims=claims, private_key=priv)
        return {
            "ok": True,
            "token": token,
            "token_sha256": token_sha256(token),
            "claims": claims,
        }

    return app


def _deny(status: int, reason: str) -> Any:
    """Build a 403 deny response in the new Rust kernel shape."""
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=status,
        content={"ok": False, "error": "denied", "reason": reason},
    )
