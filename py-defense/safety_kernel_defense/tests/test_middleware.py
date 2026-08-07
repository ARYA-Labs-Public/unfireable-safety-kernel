"""Tests for :class:`SafetyKernelMiddleware`.

Every row of the fail-closed decision table (see the middleware module
docstring) is exercised here against the in-process mock kernel. Only
dummy test keys are used — never a real secret.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from safety_kernel_defense import SafetyKernelMiddleware
from safety_kernel_defense.tests._mock_kernel import MockKernel

# Dummy worker key — a test literal, not a secret.
_WORKER_KEY = "test-worker-key"
_GATED = ("/api/v1/write/", "/api/v1/execute/")


def _make_app(mock: MockKernel | None, **overrides) -> FastAPI:
    """Build a FastAPI app wired with the middleware + one gated route."""
    app = FastAPI()
    kwargs = {
        "kernel_url": mock.url if mock is not None else "http://127.0.0.1:1",
        "worker_api_key": _WORKER_KEY,
        "operator_pubkey_hex": mock.public_key_hex if mock is not None else "00" * 32,
        "gated_path_prefixes": _GATED,
    }
    kwargs.update(overrides)
    app.add_middleware(SafetyKernelMiddleware, **kwargs)

    @app.post("/api/v1/write/thing")
    def write_thing() -> dict:
        return {"ok": True, "handler": "ran"}

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "handler": "health"}

    return app


# ---------------------------------------------------------------- row: 503
def test_denies_when_kernel_unreachable() -> None:
    """The exact fail-closed test from python-fastapi.md."""
    app = _make_app(None, request_timeout_s=0.1, gated_path_prefixes=("/api/v1/",))
    client = TestClient(app, raise_server_exceptions=False)
    r = client.post("/api/v1/write/thing")
    assert r.status_code == 503
    body = r.json()
    assert body["error_code"] == "kernel_unavailable"
    assert body["fail_closed"] is True


# ---------------------------------------------------------------- row: 200
def test_allow_lets_handler_run(mock_kernel: MockKernel) -> None:
    mock_kernel.authorize_decision = "allow"
    app = _make_app(mock_kernel)
    client = TestClient(app)
    r = client.post("/api/v1/write/thing")
    assert r.status_code == 200
    assert r.json()["handler"] == "ran"
    # The middleware actually called the kernel.
    assert len(mock_kernel.requests_to("/kernel/v1/authorize")) == 1


# ---------------------------------------------------------------- row: 403
def test_deny_returns_403(mock_kernel: MockKernel) -> None:
    mock_kernel.authorize_decision = "deny"
    app = _make_app(mock_kernel)
    client = TestClient(app, raise_server_exceptions=False)
    r = client.post("/api/v1/write/thing")
    assert r.status_code == 403
    assert r.json()["error_code"] == "policy_denied"


# --------------------------------------------------- row: bad signature 503
def test_tampered_signature_returns_503(mock_kernel: MockKernel) -> None:
    mock_kernel.authorize_decision = "allow"
    mock_kernel.tamper_authorize_signature = True
    app = _make_app(mock_kernel)
    client = TestClient(app, raise_server_exceptions=False)
    r = client.post("/api/v1/write/thing")
    assert r.status_code == 503
    assert r.json()["error_code"] == "signature_invalid"


def test_wrong_pubkey_returns_503(mock_kernel: MockKernel) -> None:
    """A valid signature but the WRONG pinned key must still fail closed."""
    mock_kernel.authorize_decision = "allow"
    # Pin an unrelated (all-ones) key the mock did not sign with.
    app = _make_app(mock_kernel, operator_pubkey_hex="11" * 32)
    client = TestClient(app, raise_server_exceptions=False)
    r = client.post("/api/v1/write/thing")
    assert r.status_code == 503
    assert r.json()["error_code"] == "signature_invalid"


# ------------------------------------------------------------ row: opt-out
def test_opt_out_bypasses_gate(mock_kernel: MockKernel) -> None:
    # Kernel would DENY, but the opt-out matcher bypasses the gate entirely.
    mock_kernel.authorize_decision = "deny"

    def opt_out(request) -> bool:
        return request.url.path == "/api/v1/write/thing"

    app = _make_app(mock_kernel, opt_out=opt_out)
    client = TestClient(app)
    r = client.post("/api/v1/write/thing")
    assert r.status_code == 200
    assert r.json()["handler"] == "ran"
    # No authorize call was made — the request bypassed the gate.
    assert mock_kernel.requests_to("/kernel/v1/authorize") == []


# --------------------------------------------------------- row: non-gated
def test_non_gated_path_bypasses(mock_kernel: MockKernel) -> None:
    mock_kernel.authorize_decision = "deny"  # would deny if it were gated
    app = _make_app(mock_kernel)
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["handler"] == "health"
    assert mock_kernel.requests_to("/kernel/v1/authorize") == []


# ---------------------------------------------------- row: breaker OPEN 503
def test_circuit_breaker_opens_after_threshold(mock_kernel: MockKernel) -> None:
    # Force every authorize call to fail (HTTP 500) → breaker trips after 3.
    mock_kernel.authorize_http_status = 500
    app = _make_app(
        mock_kernel,
        circuit_breaker_failure_threshold=3,
        circuit_breaker_open_duration_s=30.0,
    )
    client = TestClient(app, raise_server_exceptions=False)

    # First three requests each reach the kernel and fail closed (503).
    for _ in range(3):
        r = client.post("/api/v1/write/thing")
        assert r.status_code == 503
        assert r.json()["error_code"] == "kernel_unavailable"
    assert len(mock_kernel.requests_to("/kernel/v1/authorize")) == 3

    # Breaker is now OPEN: the next request is denied WITHOUT a network call.
    r = client.post("/api/v1/write/thing")
    assert r.status_code == 503
    assert r.json()["error_code"] == "kernel_unavailable"
    # Still 3 — no new authorize call was made while the breaker was open.
    assert len(mock_kernel.requests_to("/kernel/v1/authorize")) == 3


# ------------------------------------------------------- config validation
def test_bad_pubkey_hex_rejected_at_construction() -> None:
    import pytest

    async def _app(scope, receive, send) -> None:  # minimal ASGI app
        raise AssertionError("should not be reached")

    with pytest.raises(ValueError):
        SafetyKernelMiddleware(
            _app,
            kernel_url="http://127.0.0.1:9000",
            worker_api_key=_WORKER_KEY,
            operator_pubkey_hex="not-hex",
            gated_path_prefixes=_GATED,
        )


def test_empty_gated_prefixes_rejected() -> None:
    import pytest

    async def _app(scope, receive, send) -> None:
        raise AssertionError("should not be reached")

    with pytest.raises(ValueError):
        SafetyKernelMiddleware(
            _app,
            kernel_url="http://127.0.0.1:9000",
            worker_api_key=_WORKER_KEY,
            operator_pubkey_hex="00" * 32,
            gated_path_prefixes=(),
        )
