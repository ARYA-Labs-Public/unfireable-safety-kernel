"""``SafetyKernelMiddleware`` — Layer-2 FastAPI/Starlette request gate.

Seam 2 of the four defense seams: every request whose path starts with a
gated prefix is authorized by the Safety Kernel *before* it reaches the
handler. The whole point of this file is to be **fail-closed** — if the
middleware cannot obtain a fresh, cryptographically-verified ``ALLOW``
from the kernel, the request is denied, never let through.

Decision table (as implemented — see the module tests for each row):

===========================================  ======  =====================  ===============
Condition                                    HTTP    ``error_code``         breaker
===========================================  ======  =====================  ===============
path not gated, or ``opt_out`` returns True  (pass)  —                      untouched
breaker OPEN (cooldown not elapsed)          503     ``kernel_unavailable`` (no network call)
connect refused / timeout / transport error  503     ``kernel_unavailable`` failure
kernel 200 + ALLOW + signature VERIFIES      (pass)  —                      success
kernel 200 but body unparseable / not ok     503     ``kernel_unavailable`` failure
kernel 200 + token but signature INVALID     503     ``signature_invalid``  failure
kernel 403 (deny / role-forbidden)           403     ``policy_denied``      success (reachable)
kernel other non-2xx (401 / 5xx / …)         503     ``kernel_unavailable`` failure
===========================================  ======  =====================  ===============

"success"/"failure" above is the *circuit-breaker* outcome, mirroring the
Rust client SDK (``crates/adapters/safety_kernel_client``): an authoritative
kernel answer (ALLOW or DENY) keeps the breaker closed; anything that
denies us a trustworthy answer (transport, timeout, malformed reply, bad
signature) is a failure. ``failure_threshold`` consecutive failures open
the breaker for ``open_duration_s``; then a single half-open probe decides
whether to close again. An OPEN breaker denies (503) with no network call —
it never fails open.

Token verification is grounded in the kernel's on-wire token format
(``crates/domain/src/safety/token/{sign,verify}.rs``): a compact token is
``<payload_b64>.<sig_b64>`` where the Ed25519 signature is computed over the
**ASCII bytes of ``payload_b64``** (the base64url-no-pad JSON payload), NOT
the raw JSON. We reproduce exactly that verification with
``cryptography``'s ``Ed25519PublicKey.verify``.

Runtime deps (``fastapi``/``starlette``/``httpx``/``cryptography``) ship as
the ``[fastapi]`` extra — the core audit-hook package stays stdlib-only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from . import _wire
from .exceptions import KernelUnavailable, SignatureInvalid

__all__ = ["SafetyKernelMiddleware"]

_LOGGER = logging.getLogger("safety_kernel_defense.middleware")

# Standardized fail-closed error codes. ONE shape, reconciled across both
# integration docs: {"error_code": <code>, "detail": <msg>, "fail_closed": true}.
_CODE_UNAVAILABLE = "kernel_unavailable"
_CODE_DENIED = "policy_denied"
_CODE_SIGNATURE = "signature_invalid"

# Clock skew leeway (seconds) applied to the token's ``expires_at`` claim
# when it is present. Matches the spirit of the Rust verifier's ``leeway_s``.
_EXP_LEEWAY_S = 60.0


class _CircuitBreaker:
    """Minimal fail-closed breaker mirroring the Rust client SDK.

    States: CLOSED → (``failure_threshold`` consecutive failures) → OPEN →
    (``open_duration_s`` elapsed) → HALF_OPEN → (probe success) → CLOSED, or
    (probe failure) → OPEN. While OPEN and inside the cooldown window,
    :meth:`allow_call` returns ``False`` so the caller denies WITHOUT a
    network call. Exactly one probe is permitted in HALF_OPEN.

    The middleware runs on an asyncio event loop; state mutations are cheap
    and non-awaiting, so a plain object (no lock) is race-free within a
    single loop. ``time.monotonic`` drives the cooldown so a wall-clock
    step never reopens or prematurely closes the breaker.
    """

    _CLOSED = "closed"
    _OPEN = "open"
    _HALF_OPEN = "half_open"

    def __init__(self, *, failure_threshold: int, open_duration_s: float) -> None:
        self._failure_threshold = max(1, int(failure_threshold))
        self._open_duration_s = max(0.0, float(open_duration_s))
        self._state = self._CLOSED
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self._probe_in_flight = False

    @property
    def state(self) -> str:
        return self._state

    def allow_call(self) -> bool:
        """Return True if an outbound authorize call is permitted now.

        Fail-closed: an OPEN breaker whose cooldown has not elapsed returns
        ``False`` (deny, no call). When the cooldown has elapsed it flips to
        HALF_OPEN and permits exactly one probe.
        """
        now = time.monotonic()
        if self._state == self._CLOSED:
            return True
        if self._state == self._OPEN:
            opened = self._opened_at if self._opened_at is not None else now
            if now - opened >= self._open_duration_s:
                # Cooldown elapsed → half-open single probe.
                self._state = self._HALF_OPEN
                self._probe_in_flight = True
                return True
            return False
        # HALF_OPEN: exactly one probe in flight.
        if self._probe_in_flight:
            return False
        self._probe_in_flight = True
        return True

    def record_success(self) -> None:
        """Authoritative kernel answer observed → close the breaker."""
        self._consecutive_failures = 0
        self._probe_in_flight = False
        self._state = self._CLOSED
        self._opened_at = None

    def record_failure(self) -> None:
        """Untrustworthy outcome observed → may trip the breaker OPEN."""
        self._consecutive_failures += 1
        was_probe = self._probe_in_flight
        self._probe_in_flight = False
        if self._state == self._HALF_OPEN and was_probe:
            # A failed probe re-opens immediately.
            self._open()
            return
        if self._state == self._CLOSED and self._consecutive_failures >= self._failure_threshold:
            self._open()

    def _open(self) -> None:
        self._state = self._OPEN
        self._opened_at = time.monotonic()


class SafetyKernelMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that gates requests behind a Safety Kernel authorize.

    See the module docstring for the full fail-closed decision table. Wire
    it with ``app.add_middleware(SafetyKernelMiddleware, ...)``.

    Args:
        app: the ASGI app (supplied by Starlette's ``add_middleware``).
        kernel_url: base URL of the kernel, e.g. ``http://localhost:9000``.
            The middleware POSTs to ``{kernel_url}/kernel/v1/authorize``.
        worker_api_key: worker-role key sent as ``x-api-key`` on every
            authorize call. Read from a secrets manager; never hardcode.
        operator_pubkey_hex: 32-byte raw Ed25519 public key, hex-encoded
            (64 hex chars), used to verify the signature on ALLOW tokens.
        request_timeout_s: hard cap on a single authorize call. The kernel
            is on the hot path — keep this tight (default 0.5s).
        circuit_breaker_failure_threshold: consecutive failures before the
            breaker opens (default 3).
        circuit_breaker_open_duration_s: seconds the breaker stays open
            before a single half-open probe (default 10.0).
        gated_path_prefixes: tuple of path prefixes that REQUIRE
            authorization. Everything else passes through untouched.
        opt_out: optional ``callable(request) -> bool``; when it returns
            ``True`` for a request, that request bypasses the gate even if
            its path matches a gated prefix. Opt-outs are a policy decision.

    Raises:
        ValueError: if ``operator_pubkey_hex`` is not a 64-char hex string
            decoding to 32 bytes, or ``gated_path_prefixes`` is empty. A
            malformed pin is a configuration error, caught at wiring time
            rather than silently degrading verification.
    """

    def __init__(
        self,
        app: Any,
        *,
        kernel_url: str,
        worker_api_key: str,
        operator_pubkey_hex: str,
        request_timeout_s: float = 0.5,
        circuit_breaker_failure_threshold: int = 3,
        circuit_breaker_open_duration_s: float = 10.0,
        gated_path_prefixes: tuple[str, ...],
        opt_out: Callable[[Request], bool] | None = None,
    ) -> None:
        super().__init__(app)
        self._kernel_url = kernel_url.rstrip("/")
        self._worker_api_key = worker_api_key
        self._public_key = self._load_public_key(operator_pubkey_hex)
        self._timeout = httpx.Timeout(float(request_timeout_s))
        self._gated_prefixes = tuple(gated_path_prefixes)
        if not self._gated_prefixes:
            raise ValueError("gated_path_prefixes must be a non-empty tuple")
        self._opt_out = opt_out
        self._breaker = _CircuitBreaker(
            failure_threshold=circuit_breaker_failure_threshold,
            open_duration_s=circuit_breaker_open_duration_s,
        )
        # Lazily-created shared async client (bound to the running loop on
        # first use). Reused across requests to avoid per-request setup.
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------ setup
    @staticmethod
    def _load_public_key(operator_pubkey_hex: str) -> Ed25519PublicKey:
        """Parse a 32-byte raw Ed25519 public key from hex.

        Fail-fast on a malformed pin: verification with no valid key would
        be worse than none at all.
        """
        try:
            raw = bytes.fromhex(operator_pubkey_hex.strip())
        except ValueError as exc:
            raise ValueError(
                "operator_pubkey_hex must be hex-encoded (64 chars → 32 bytes)"
            ) from exc
        if len(raw) != 32:
            raise ValueError(
                f"operator_pubkey_hex must decode to 32 bytes; got {len(raw)}"
            )
        return Ed25519PublicKey.from_public_bytes(raw)

    # --------------------------------------------------------------- dispatch
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Gate the request. See the module-level decision table."""
        path = request.url.path
        if not self._is_gated(path) or self._is_opted_out(request):
            return await call_next(request)

        # Breaker OPEN → deny immediately, no network call.
        if not self._breaker.allow_call():
            return self._deny(
                503,
                _CODE_UNAVAILABLE,
                "circuit breaker open — kernel treated as unavailable",
            )

        try:
            status, body = await self._authorize(request)
        except KernelUnavailable as exc:
            self._breaker.record_failure()
            return self._deny(503, _CODE_UNAVAILABLE, str(exc))

        if status == 200:
            try:
                self._verify_allow(body)
            except SignatureInvalid as exc:
                # Reachable kernel, but we cannot trust the reply.
                self._breaker.record_failure()
                return self._deny(503, _CODE_SIGNATURE, str(exc))
            except KernelUnavailable as exc:
                # 200 with an unparseable / non-ALLOW body — no trustworthy
                # decision, so treat as unavailable (fail-closed).
                self._breaker.record_failure()
                return self._deny(503, _CODE_UNAVAILABLE, str(exc))
            self._breaker.record_success()
            return await call_next(request)

        if status == 403:
            # Authoritative DENY (policy / role forbidden). Kernel reachable.
            self._breaker.record_success()
            return self._deny(403, _CODE_DENIED, "safety kernel denied the action")

        # Any other status (401, 5xx, unexpected 2xx≠200): no trustworthy
        # ALLOW → fail-closed as unavailable.
        self._breaker.record_failure()
        return self._deny(503, _CODE_UNAVAILABLE, f"kernel returned HTTP {status}")

    # ------------------------------------------------------------- authorize
    async def _authorize(self, request: Request) -> tuple[int, bytes]:
        """POST the authorize request. Returns ``(status, body_bytes)``.

        Raises :class:`KernelUnavailable` on any transport error / timeout —
        the caller maps that to 503.
        """
        method = request.method
        path = request.url.path
        query = request.url.query or ""

        # Identity comes from documented request headers; sensible
        # fail-closed defaults keep the required fields non-empty.
        run_id = request.headers.get("x-run-id") or uuid.uuid4().hex
        subject = request.headers.get("x-subject") or "anonymous"
        # Documented action scheme: http.<method>:<path>.
        action = f"http.{method.lower()}:{path}"
        params_fingerprint = self._params_fingerprint(method, path, query)

        payload = {
            "action": action,
            "run_id": run_id,
            "subject": subject,
            "params_fingerprint": params_fingerprint,
        }
        client = self._get_client()
        try:
            resp = await client.post(
                self._kernel_url + "/kernel/v1/authorize",
                content=json.dumps(payload).encode("utf-8"),
                headers={
                    "content-type": "application/json",
                    "x-api-key": self._worker_api_key,
                },
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise KernelUnavailable(str(exc)) from exc
        return resp.status_code, resp.content

    @staticmethod
    def _params_fingerprint(method: str, path: str, query: str) -> str:
        """SHA-256 over the canonical JSON of the request's gated params.

        Reuses ``_wire.canonical_json`` (the byte-stable, sorted-key,
        ASCII, whitespace-free encoder) so the fingerprint is reproducible.
        The fingerprinted payload is documented: the request method, path,
        and raw query string — all strings, as ``canonical_json`` requires.
        """
        fp_payload = {"method": method, "path": path, "query": query}
        canonical = _wire.canonical_json(fp_payload)
        return hashlib.sha256(canonical.encode("ascii")).hexdigest()

    # ---------------------------------------------------------- verification
    def _verify_allow(self, body: bytes) -> None:
        """Verify a 200 body is a genuine, unexpired ALLOW.

        Raises :class:`SignatureInvalid` if the token is malformed, its
        signature does not verify against the pinned public key, or its
        bound ``expires_at`` claim (when present) is in the past. Raises
        :class:`KernelUnavailable` if the body is not a usable ALLOW
        envelope (unparseable / ``ok`` not true / no token).
        """
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError) as exc:
            raise KernelUnavailable(f"unparseable authorize response: {exc}") from exc
        if not isinstance(parsed, dict) or parsed.get("ok") is not True:
            raise KernelUnavailable("authorize response not an ok=true envelope")
        token = parsed.get("token")
        if not isinstance(token, str) or not token:
            raise KernelUnavailable("authorize response missing token")

        # Token format (crates/domain/src/safety/token): <payload_b64>.<sig_b64>,
        # signature computed over the ASCII bytes of payload_b64.
        parts = token.split(".")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise SignatureInvalid("malformed_token")
        payload_b64, sig_b64 = parts[0], parts[1]
        try:
            signature = _b64url_decode(sig_b64)
        except (ValueError, TypeError) as exc:
            raise SignatureInvalid("malformed_token") from exc
        try:
            self._public_key.verify(signature, payload_b64.encode("ascii"))
        except InvalidSignature as exc:
            raise SignatureInvalid("bad_signature") from exc

        # Signature is good. Best-effort expiry enforcement: if the signed
        # payload binds ``expires_at``, an expired token is not a valid
        # ALLOW even though its signature verifies.
        self._reject_if_expired(payload_b64)

    @staticmethod
    def _reject_if_expired(payload_b64: str) -> None:
        try:
            payload_json = _b64url_decode(payload_b64)
            claims = json.loads(payload_json)
        except (ValueError, TypeError):
            # Signature already verified; if we cannot re-read the payload
            # we do not additionally reject on expiry (the signature is the
            # binding integrity check).
            return
        if not isinstance(claims, dict):
            return
        exp = claims.get("expires_at")
        if isinstance(exp, (int, float)) and not isinstance(exp, bool):
            if time.time() - _EXP_LEEWAY_S > float(exp):
                raise SignatureInvalid("token_expired")

    # -------------------------------------------------------------- helpers
    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    def _is_gated(self, path: str) -> bool:
        return any(path.startswith(prefix) for prefix in self._gated_prefixes)

    def _is_opted_out(self, request: Request) -> bool:
        if self._opt_out is None:
            return False
        try:
            return bool(self._opt_out(request))
        except Exception:  # noqa: BLE001 — a broken matcher must NOT fail open.
            _LOGGER.warning("opt_out matcher raised; treating request as NOT opted out")
            return False

    @staticmethod
    def _deny(status: int, error_code: str, detail: str) -> JSONResponse:
        return JSONResponse(
            status_code=status,
            content={"error_code": error_code, "detail": detail, "fail_closed": True},
        )


def _b64url_decode(data: str) -> bytes:
    """Decode base64url, tolerating missing ``=`` padding (no-pad tokens)."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)
