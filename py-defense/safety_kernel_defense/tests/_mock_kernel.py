"""Stdlib-only mock kernel for the audit-hook tests.

the architecture overview: ``http.server.HTTPServer`` + ``BaseHTTPRequestHandler``
running in a thread. Per-test instance with OS-assigned port. Records
every request so tests can assert on what the hook sent.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _b64url_nopad(data: bytes) -> str:
    """base64url-encode without padding (kernel token envelope)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _stable_json(obj: Any) -> str:
    """Byte-stable JSON — sorted keys, no whitespace (matches the kernel)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class MockKernel:
    """A test fixture wrapping a tiny HTTP server.

    Attributes that tests set BEFORE making requests:

    * ``response_status_authorize`` (int) — HTTP status to return for
      ``POST /policy/module/authorize``.
    * ``response_body_authorize`` (dict | None) — JSON body to return.
    * ``sleep_seconds`` (float) — sleep before responding (for timeout
      tests).
    * ``response_status_audit_event`` (int) — HTTP status for
      ``POST /policy/audit-event``.

    Attributes the tests READ after the hook has run:

    * ``received_requests`` (list[dict]) — every POST seen, with
      ``path``, ``headers``, ``body`` (parsed JSON or None).
    """

    def __init__(self) -> None:
        self.response_status_authorize: int = 200
        self.response_body_authorize: dict[str, Any] | None = {
            "ok": True,
            "decision": "allow",
            "token": "<test-token>",
            "token_sha256": "a" * 64,
            "claims": {},
            "reason": None,
        }
        self.response_status_audit_event: int = 202
        self.response_body_audit_event: dict[str, Any] | None = {
            "ok": True,
            "audit_kind": "policy_audit_event",
            "ts_unix_ms": 0,
        }
        self.sleep_seconds: float = 0.0
        self.received_requests: list[dict[str, Any]] = []
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        # ---- Ed25519 signing (for /kernel/v1/authorize + /revoke/*) ----
        # A per-instance keypair; tests hand the middleware / verifier the
        # matching `public_key_hex`. Never a real key.
        self._signing_key = Ed25519PrivateKey.generate()

        # ---- /kernel/v1/authorize knobs ----
        # "allow" → 200 signed ALLOW token; "deny" → 403.
        self.authorize_decision: str = "allow"
        # When True, corrupt the ALLOW token's signature so verification
        # fails (exercises the fail-closed signature_invalid → 503 path).
        self.tamper_authorize_signature: bool = False
        # Override the authorize HTTP status directly (e.g. 500) regardless
        # of decision — used to drive the circuit breaker to OPEN.
        self.authorize_http_status: int | None = None

        # ---- /kernel/v1/revoke/* knobs ----
        self.revoke_compute_status: int = 200
        self.revoke_restore_status: int = 200
        self.revoke_ack_status: int = 200
        self.revoke_ack_cleared: bool = True
        # None → 204 No Content (empty queue). A list → 200 with `pending`.
        self.pending_tokens: list[str] | None = None
        self.revoke_pending_status: int = 200

    # ------------------------------------------------------------------ start
    def start(self) -> None:
        """Bind to 127.0.0.1:0 (OS-assigned port) and serve in a thread."""
        kernel = self

        class _Handler(BaseHTTPRequestHandler):
            # Silence per-request stderr noise.
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

            def _record(self, raw: bytes, parsed: Any) -> None:
                with kernel._lock:
                    kernel.received_requests.append(
                        {
                            "path": self.path,
                            "headers": dict(self.headers),
                            "body": parsed,
                            "raw_body": raw,
                        }
                    )

            def do_GET(self) -> None:  # noqa: N802 — stdlib API
                self._record(b"", None)
                if kernel.sleep_seconds > 0:
                    time.sleep(kernel.sleep_seconds)
                split = urllib.parse.urlsplit(self.path)
                if split.path == "/kernel/v1/revoke/pending":
                    status, body = kernel._pending_response()
                    self._send(status, body)
                    return
                self._send(404, {"error": "not_found"})

            def do_POST(self) -> None:  # noqa: N802 — stdlib API
                length = int(self.headers.get("content-length", "0") or "0")
                raw = self.rfile.read(length) if length else b""
                try:
                    parsed = json.loads(raw) if raw else None
                except Exception:  # noqa: BLE001
                    parsed = None
                self._record(raw, parsed)

                if kernel.sleep_seconds > 0:
                    time.sleep(kernel.sleep_seconds)

                if self.path == "/policy/module/authorize":
                    status = kernel.response_status_authorize
                    body = kernel.response_body_authorize
                elif self.path == "/policy/audit-event":
                    status = kernel.response_status_audit_event
                    body = kernel.response_body_audit_event
                elif self.path == "/kernel/v1/authorize":
                    status, body = kernel._authorize_response(parsed)
                elif self.path == "/kernel/v1/revoke/compute":
                    status, body = kernel._revoke_mint_response(parsed, kind="revoke")
                elif self.path == "/kernel/v1/revoke/restore":
                    status, body = kernel._revoke_mint_response(parsed, kind="restore")
                elif self.path == "/kernel/v1/revoke/ack":
                    status, body = kernel._revoke_ack_response(parsed)
                else:
                    status = 404
                    body = {"error": "not_found"}
                self._send(status, body)

            def _send(self, status: int, body: Any) -> None:
                if status == 204 or body is None:
                    self.send_response(status)
                    self.send_header("content-length", "0")
                    self.end_headers()
                    return
                self.send_response(status)
                self.send_header("content-type", "application/json")
                payload = json.dumps(body).encode("utf-8")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._server = HTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    # ------------------------------------------------------------------- stop
    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    # ------------------------------------------------------------------- url
    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("MockKernel not started")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    # --------------------------------------------------------------- helpers
    def requests_to(self, path: str) -> list[dict[str, Any]]:
        """Return every received POST to a specific path."""
        return [r for r in self.received_requests if r["path"] == path]

    def authorize_requests(self) -> list[dict[str, Any]]:
        return self.requests_to("/policy/module/authorize")

    def audit_event_requests(self) -> list[dict[str, Any]]:
        return self.requests_to("/policy/audit-event")

    def reset(self) -> None:
        with self._lock:
            self.received_requests.clear()

    # ------------------------------------------------------------ signing
    @property
    def public_key_hex(self) -> str:
        """Raw 32-byte Ed25519 public key, hex-encoded (what the
        middleware / verifier is configured to trust)."""
        from cryptography.hazmat.primitives import serialization

        raw = self._signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    def _sign_token(self, claims: dict[str, Any], *, tamper: bool = False) -> tuple[str, str]:
        """Mint a compact ``<payload_b64>.<sig_b64>`` token over ``claims``.

        Mirrors the kernel token format: the signature is over the ASCII
        bytes of ``payload_b64`` (NOT the raw JSON). When ``tamper`` is
        set, one signature byte is flipped so verification fails.
        """
        payload_b64 = _b64url_nopad(_stable_json(claims).encode("utf-8"))
        sig = self._signing_key.sign(payload_b64.encode("ascii"))
        if tamper:
            sig = bytes([sig[0] ^ 0x01]) + sig[1:]
        token = f"{payload_b64}.{_b64url_nopad(sig)}"
        token_sha = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return token, token_sha

    # --------------------------------------------------- response builders
    def _authorize_response(self, req: Any) -> tuple[int, Any]:
        """Build a ``/kernel/v1/authorize`` response per the configured knobs."""
        if self.authorize_http_status is not None:
            return self.authorize_http_status, {"ok": False, "error": "forced_status"}
        if self.authorize_decision == "deny":
            return 403, {"ok": False, "error": "policy_denied", "reason": "denied_by_mock"}

        now = int(time.time())
        pf = ""
        if isinstance(req, dict) and isinstance(req.get("params_fingerprint"), str):
            pf = req["params_fingerprint"]
        claims = {
            "action": (req or {}).get("action", "http.get:/") if isinstance(req, dict) else "x",
            "run_id": (req or {}).get("run_id", "run") if isinstance(req, dict) else "run",
            "subject": (req or {}).get("subject", "subj") if isinstance(req, dict) else "subj",
            "params_fingerprint": pf,
            "issued_at": now,
            "expires_at": now + 3600,
            "nonce": "n-" + str(now),
        }
        token, token_sha = self._sign_token(
            claims, tamper=self.tamper_authorize_signature
        )
        return 200, {"ok": True, "token": token, "token_sha256": token_sha, "claims": claims}

    def _revoke_mint_response(self, req: Any, *, kind: str) -> tuple[int, Any]:
        """Build a signed ``/revoke/compute`` or ``/revoke/restore`` response."""
        status = self.revoke_compute_status if kind == "revoke" else self.revoke_restore_status
        if status != 200:
            return status, {"ok": False, "error": "revoke_not_recorded"}
        now = int(time.time())
        run_id = f"{kind}-{now}"
        target = req.get("target") if isinstance(req, dict) else None
        claims = {
            "action": f"compute.{kind}",
            "run_id": run_id,
            "target": target,
            "issued_at": now,
            "expires_at": now + 120,
            "nonce": "rn-" + str(now),
        }
        token, token_sha = self._sign_token(claims)
        return 200, {
            "ok": True,
            "run_id": run_id,
            "token": token,
            "token_sha256": token_sha,
            "claims": claims,
        }

    def _revoke_ack_response(self, req: Any) -> tuple[int, Any]:
        if self.revoke_ack_status != 200:
            return self.revoke_ack_status, {"ok": False, "error": "ack_failed"}
        run_id = req.get("run_id") if isinstance(req, dict) else None
        return 200, {"ok": True, "run_id": run_id, "cleared": self.revoke_ack_cleared}

    def _pending_response(self) -> tuple[int, Any]:
        if self.revoke_pending_status != 200:
            return self.revoke_pending_status, {"ok": False, "error": "pending_failed"}
        if self.pending_tokens is None:
            return 204, None
        return 200, {"ok": True, "pending": list(self.pending_tokens)}
