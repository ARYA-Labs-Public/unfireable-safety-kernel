"""``RevokeClient`` — async SDK for the kernel's ``/kernel/v1/revoke/*``
coercive-shutdown surface.

The kernel is the *decider*: it mints signed ``RevokeCompute`` / restore
decisions; an out-of-band supervisor (the "reaper") pulls, verifies, and
executes them from outside the agent's failure domain. This client is the
integrator surface for both roles — the operator minting/restoring, and
the supervisor pulling/acking.

Four methods, one per endpoint in the OpenAPI contract
(``contracts/openapi/safety_kernel.yaml``):

* :meth:`mint_revoke`  → ``POST /kernel/v1/revoke/compute`` (operator role)
* :meth:`pull_pending` → ``GET  /kernel/v1/revoke/pending`` (reaper role)
* :meth:`ack`          → ``POST /kernel/v1/revoke/ack``     (reaper role)
* :meth:`restore`      → ``POST /kernel/v1/revoke/restore`` (operator role)

Fail-closed: every method raises on failure and NEVER returns a partial or
false-success object. Transport errors / timeouts raise
:class:`KernelUnavailable`; a documented non-success HTTP status raises
:class:`RevokeError`. A supervisor must never believe a kill was minted,
pulled, or acked when it was not.

Role note: the caller supplies the API key with the role each call needs
(``operator`` for mint/restore, ``reaper`` or ``operator`` for
pending/ack). The kernel enforces the role from the key; this client does
not second-guess it.

Ships in the ``[fastapi]`` extra (uses ``httpx``); the core audit-hook
package stays stdlib-only.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from .exceptions import KernelUnavailable, RevokeError

__all__ = ["RevokeClient", "InstanceTarget"]

# Tiers the caller may request. Phase 1 mints ``vm_stop`` only; the kernel
# rejects the finer rungs with 422. Kept here so a caller-side typo fails
# before a network round-trip.
_VALID_TIERS = ("sigterm", "sigkill", "cgroup_kill", "vm_stop")
_VALID_TRIGGERS = ("operator_emergency_stop", "rogue_determination")


def InstanceTarget(*, project: str, zone: str, instance: str) -> dict[str, str]:  # noqa: N802
    """Build an ``InstanceTarget`` body fragment.

    A thin, validated constructor for the ``{project, zone, instance}``
    coordinate the revoke endpoints require. Returned as a plain dict so it
    drops straight into a request body. All three fields are required and
    must be non-empty (matches the OpenAPI ``minLength: 1`` on each).
    """
    for name, val in (("project", project), ("zone", zone), ("instance", instance)):
        if not isinstance(val, str) or not val:
            raise ValueError(f"InstanceTarget.{name} must be a non-empty string")
    return {"project": project, "zone": zone, "instance": instance}


class RevokeClient:
    """Async client for the kernel coercive-shutdown endpoints.

    Args:
        kernel_url: base URL of the kernel, e.g. ``https://kernel.internal:9000``.
        api_key: role-appropriate ``x-api-key`` sent on every call (operator
            for mint/restore; reaper or operator for pending/ack).
        request_timeout_s: hard per-call timeout (default 5.0s — these are
            control-plane calls, not the request hot path).
    """

    def __init__(
        self,
        *,
        kernel_url: str,
        api_key: str,
        request_timeout_s: float = 5.0,
    ) -> None:
        self._kernel_url = kernel_url.rstrip("/")
        self._api_key = api_key
        self._timeout = httpx.Timeout(float(request_timeout_s))
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------- lifecycle
    async def aclose(self) -> None:
        """Close the underlying HTTP client, if one was opened."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> RevokeClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    # --------------------------------------------------------------- mint
    async def mint_revoke(
        self,
        *,
        target: dict[str, str],
        tier: str = "vm_stop",
        trigger: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Mint a signed coercive-shutdown (kill) decision (operator role).

        ``POST /kernel/v1/revoke/compute``. Returns the parsed
        ``SignedRevokeResponse`` (``{ok, run_id, token, token_sha256,
        claims}``) on 200. Raises :class:`RevokeError` on 401/403/422/503,
        :class:`KernelUnavailable` on transport failure.
        """
        if tier not in _VALID_TIERS:
            raise ValueError(f"tier must be one of {_VALID_TIERS}; got {tier!r}")
        if trigger not in _VALID_TRIGGERS:
            raise ValueError(f"trigger must be one of {_VALID_TRIGGERS}; got {trigger!r}")
        body: dict[str, Any] = {"target": target, "tier": tier, "trigger": trigger}
        if reason is not None:
            body["reason"] = reason
        return await self._post_json("/kernel/v1/revoke/compute", body, expect=(200,))

    # ------------------------------------------------------------- pending
    async def pull_pending(self, instance: str) -> list[str]:
        """Pull pending signed decision(s) for an instance (reaper role).

        ``GET /kernel/v1/revoke/pending?instance=…``. Returns the list of
        already-signed opaque token strings (``pending``) on 200, or an
        empty list on 204 No Content (empty queue). Raises
        :class:`RevokeError` on any other status, :class:`KernelUnavailable`
        on transport failure.
        """
        if not instance:
            raise ValueError("instance must be a non-empty string")
        client = self._get_client()
        try:
            resp = await client.get(
                self._kernel_url + "/kernel/v1/revoke/pending",
                params={"instance": instance},
                headers={"x-api-key": self._api_key},
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise KernelUnavailable(str(exc)) from exc

        if resp.status_code == 204:
            return []
        if resp.status_code != 200:
            raise self._error_for(resp)
        parsed = self._parse_ok_envelope(resp)
        pending = parsed.get("pending")
        if not isinstance(pending, list):
            raise RevokeError(200, error_code="malformed_pending_response")
        return [t for t in pending if isinstance(t, str)]

    # ----------------------------------------------------------------- ack
    async def ack(self, *, run_id: str, outcome: str) -> dict[str, Any]:
        """Acknowledge execution of a pending decision (reaper role).

        ``POST /kernel/v1/revoke/ack``. Returns the parsed
        ``RevokeAckResponse`` (``{ok, run_id, cleared}``) on 200. Raises
        :class:`RevokeError` / :class:`KernelUnavailable` on failure.
        """
        if not run_id:
            raise ValueError("run_id must be a non-empty string")
        if not outcome:
            raise ValueError("outcome must be a non-empty string")
        body = {"run_id": run_id, "outcome": outcome}
        return await self._post_json("/kernel/v1/revoke/ack", body, expect=(200,))

    # ------------------------------------------------------------- restore
    async def restore(
        self,
        *,
        target: dict[str, str],
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Mint a signed restore (un-kill) decision (operator role).

        ``POST /kernel/v1/revoke/restore``. Returns the parsed
        ``SignedRevokeResponse`` on 200. Raises :class:`RevokeError` /
        :class:`KernelUnavailable` on failure.
        """
        body: dict[str, Any] = {"target": target}
        if reason is not None:
            body["reason"] = reason
        return await self._post_json("/kernel/v1/revoke/restore", body, expect=(200,))

    # -------------------------------------------------------------- helpers
    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def _post_json(
        self,
        path: str,
        body: dict[str, Any],
        *,
        expect: tuple[int, ...],
    ) -> dict[str, Any]:
        client = self._get_client()
        try:
            resp = await client.post(
                self._kernel_url + path,
                content=json.dumps(body).encode("utf-8"),
                headers={"content-type": "application/json", "x-api-key": self._api_key},
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise KernelUnavailable(str(exc)) from exc
        if resp.status_code not in expect:
            raise self._error_for(resp)
        return self._parse_ok_envelope(resp)

    @staticmethod
    def _parse_ok_envelope(resp: httpx.Response) -> dict[str, Any]:
        """Parse a success body; fail-closed if it is not an ``ok`` object.

        A 200 that does not decode to ``{"ok": true, ...}`` is NOT a real
        success — raising here keeps a garbled reply from masquerading as a
        signed decision.
        """
        try:
            parsed = resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise RevokeError(
                resp.status_code, error_code="unparseable_response"
            ) from exc
        if not isinstance(parsed, dict) or parsed.get("ok") is not True:
            raise RevokeError(resp.status_code, error_code="not_ok_envelope")
        return parsed

    @staticmethod
    def _error_for(resp: httpx.Response) -> RevokeError:
        """Build a :class:`RevokeError` from a non-success response body."""
        error_code: str | None = None
        reason: str | None = None
        try:
            parsed = resp.json()
            if isinstance(parsed, dict):
                ec = parsed.get("error")
                rs = parsed.get("reason")
                error_code = ec if isinstance(ec, str) else None
                reason = rs if isinstance(rs, str) else None
        except (ValueError, json.JSONDecodeError):
            pass
        return RevokeError(resp.status_code, error_code=error_code, reason=reason)
