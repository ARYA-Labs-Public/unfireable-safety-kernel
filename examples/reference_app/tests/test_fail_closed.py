"""Fail-closed acceptance test — kernel down → every GATED route returns 503.

Mirrors the Rust track's ``examples/reference_app_rs/tests/fail_closed.rs``
suite (AC14). The test does NOT need an actual kernel container running
— we configure the mock kernel with ``force_unavailable=True`` to
simulate the kernel-stopped state.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from examples.reference_app.app import build_app
from examples.testing.mock_kernel import MockKernelConfig, build_mock_kernel_app
from packages.safety.client import PinnedKeyVerifier, SafetyKernelClient


@pytest.fixture
def kernel_app_and_client():
    """Build a mock kernel + a matching pinned-key verifier."""
    mock_cfg = MockKernelConfig()
    kernel_app = build_mock_kernel_app(mock_cfg)
    pub_b64 = kernel_app.state.public_key_b64
    verifier = PinnedKeyVerifier(pub_b64)
    return kernel_app, mock_cfg, verifier


def test_unrestricted_route_always_200(kernel_app_and_client) -> None:
    """``/healthz`` is UNRESTRICTED — must return 200 even with no kernel."""
    _, _, verifier = kernel_app_and_client

    # Build the app with a client pointing at a dead URL — the
    # UNRESTRICTED route must NOT be affected.
    client = SafetyKernelClient(
        base_url="http://127.0.0.1:1",  # dead port
        api_key="x",
        pinned_verifier=verifier,
        timeout_s=0.2,
    )
    app = build_app(client=client)
    with TestClient(app) as tc:
        resp = tc.get("/healthz")
    assert resp.status_code == 200


def test_gated_route_returns_503_when_kernel_down(kernel_app_and_client) -> None:
    """``POST /api/v1/rsi/apply`` is GATED — kernel down → 503, never allow."""
    _, _, verifier = kernel_app_and_client

    client = SafetyKernelClient(
        base_url="http://127.0.0.1:1",  # dead port
        api_key="x",
        pinned_verifier=verifier,
        timeout_s=0.2,
    )
    app = build_app(client=client)
    with TestClient(app) as tc:
        resp = tc.post("/api/v1/rsi/apply", json={"proposal_id": "p-1"})

    assert resp.status_code == 503, (
        f"AC14 fail-closed: GATED route must return 503 when kernel is down; "
        f"got {resp.status_code} body={resp.text!r}"
    )
    body = resp.json()
    assert body.get("error") == "service_unavailable"


def test_gated_route_503_never_returns_allow_body(kernel_app_and_client) -> None:
    """Critical invariant: under NO circumstances may a kernel-down state
    produce a 2xx response for a GATED route."""
    _, _, verifier = kernel_app_and_client
    client = SafetyKernelClient(
        base_url="http://127.0.0.1:1",
        api_key="x",
        pinned_verifier=verifier,
        timeout_s=0.2,
    )
    app = build_app(client=client)
    with TestClient(app) as tc:
        for _ in range(5):
            resp = tc.post("/api/v1/rsi/apply", json={"proposal_id": "x"})
            assert resp.status_code >= 500, (
                "FAIL-CLOSED VIOLATION: kernel down produced a "
                f"2xx response. status={resp.status_code} body={resp.text!r}"
            )
