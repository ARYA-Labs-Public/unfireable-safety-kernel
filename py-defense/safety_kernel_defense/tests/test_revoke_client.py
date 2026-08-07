"""Tests for :class:`RevokeClient` against the in-process mock kernel.

Each of the four endpoints is exercised for both success AND failure. The
failure cases assert the client RAISES (fail-closed) rather than returning
a partial / false-success object. Only dummy test keys are used.
"""

from __future__ import annotations

import asyncio

import pytest

from safety_kernel_defense import InstanceTarget, RevokeClient
from safety_kernel_defense.exceptions import KernelUnavailable, RevokeError
from safety_kernel_defense.tests._mock_kernel import MockKernel

# Dummy operator/reaper key — a test literal, not a secret.
_OP_KEY = "test-operator-key"

_TARGET = InstanceTarget(project="proj", zone="zone-a", instance="agent-vm-1")


def _run(coro):
    return asyncio.run(coro)


def _client(mock: MockKernel | None) -> RevokeClient:
    url = mock.url if mock is not None else "http://127.0.0.1:1"
    return RevokeClient(kernel_url=url, api_key=_OP_KEY, request_timeout_s=0.5)


# ------------------------------------------------------------------- mint
def test_mint_revoke_success(mock_kernel: MockKernel) -> None:
    async def go() -> None:
        client = _client(mock_kernel)
        try:
            resp = await client.mint_revoke(
                target=_TARGET, tier="vm_stop", trigger="operator_emergency_stop"
            )
        finally:
            await client.aclose()
        assert resp["ok"] is True
        assert resp["run_id"].startswith("revoke-")
        assert "token" in resp and resp["token"]

    _run(go())
    reqs = mock_kernel.requests_to("/kernel/v1/revoke/compute")
    assert len(reqs) == 1
    assert reqs[0]["body"]["tier"] == "vm_stop"


def test_mint_revoke_error_raises(mock_kernel: MockKernel) -> None:
    mock_kernel.revoke_compute_status = 503  # revoke_not_recorded

    async def go() -> None:
        client = _client(mock_kernel)
        try:
            with pytest.raises(RevokeError) as ei:
                await client.mint_revoke(
                    target=_TARGET, tier="vm_stop", trigger="rogue_determination"
                )
            assert ei.value.status == 503
        finally:
            await client.aclose()

    _run(go())


def test_mint_revoke_bad_tier_rejected_locally(mock_kernel: MockKernel) -> None:
    async def go() -> None:
        client = _client(mock_kernel)
        try:
            with pytest.raises(ValueError):
                await client.mint_revoke(
                    target=_TARGET, tier="nope", trigger="operator_emergency_stop"
                )
        finally:
            await client.aclose()

    _run(go())
    # A locally-rejected tier must never hit the wire.
    assert mock_kernel.requests_to("/kernel/v1/revoke/compute") == []


# ---------------------------------------------------------------- pending
def test_pull_pending_returns_tokens(mock_kernel: MockKernel) -> None:
    mock_kernel.pending_tokens = ["tok-a", "tok-b"]

    async def go() -> list[str]:
        client = _client(mock_kernel)
        try:
            return await client.pull_pending("agent-vm-1")
        finally:
            await client.aclose()

    assert _run(go()) == ["tok-a", "tok-b"]


def test_pull_pending_empty_queue_returns_empty_list(mock_kernel: MockKernel) -> None:
    mock_kernel.pending_tokens = None  # → 204 No Content

    async def go() -> list[str]:
        client = _client(mock_kernel)
        try:
            return await client.pull_pending("agent-vm-1")
        finally:
            await client.aclose()

    assert _run(go()) == []


def test_pull_pending_error_raises(mock_kernel: MockKernel) -> None:
    mock_kernel.revoke_pending_status = 500

    async def go() -> None:
        client = _client(mock_kernel)
        try:
            with pytest.raises(RevokeError):
                await client.pull_pending("agent-vm-1")
        finally:
            await client.aclose()

    _run(go())


# -------------------------------------------------------------------- ack
def test_ack_success(mock_kernel: MockKernel) -> None:
    mock_kernel.revoke_ack_cleared = True

    async def go() -> dict:
        client = _client(mock_kernel)
        try:
            return await client.ack(run_id="revoke-123", outcome="stopped")
        finally:
            await client.aclose()

    resp = _run(go())
    assert resp["ok"] is True
    assert resp["cleared"] is True
    assert resp["run_id"] == "revoke-123"


def test_ack_error_raises(mock_kernel: MockKernel) -> None:
    mock_kernel.revoke_ack_status = 422

    async def go() -> None:
        client = _client(mock_kernel)
        try:
            with pytest.raises(RevokeError):
                await client.ack(run_id="revoke-123", outcome="stopped")
        finally:
            await client.aclose()

    _run(go())


# ---------------------------------------------------------------- restore
def test_restore_success(mock_kernel: MockKernel) -> None:
    async def go() -> dict:
        client = _client(mock_kernel)
        try:
            return await client.restore(target=_TARGET, reason="incident resolved")
        finally:
            await client.aclose()

    resp = _run(go())
    assert resp["ok"] is True
    assert resp["run_id"].startswith("restore-")


def test_restore_error_raises(mock_kernel: MockKernel) -> None:
    mock_kernel.revoke_restore_status = 503

    async def go() -> None:
        client = _client(mock_kernel)
        try:
            with pytest.raises(RevokeError):
                await client.restore(target=_TARGET)
        finally:
            await client.aclose()

    _run(go())


# ------------------------------------------------------ transport failure
def test_transport_failure_raises_kernel_unavailable() -> None:
    """Unreachable kernel → KernelUnavailable, never a false success."""

    async def go() -> None:
        client = _client(None)  # points at a refusing address
        try:
            with pytest.raises(KernelUnavailable):
                await client.ack(run_id="r", outcome="stopped")
        finally:
            await client.aclose()

    _run(go())


# ------------------------------------------------------ target validation
def test_instance_target_requires_all_fields() -> None:
    with pytest.raises(ValueError):
        InstanceTarget(project="", zone="z", instance="i")
