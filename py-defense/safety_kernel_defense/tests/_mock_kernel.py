"""Stdlib-only mock kernel for the audit-hook tests.

the architecture overview: ``http.server.HTTPServer`` + ``BaseHTTPRequestHandler``
running in a thread. Per-test instance with OS-assigned port. Records
every request so tests can assert on what the hook sent.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple


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
        self.response_body_authorize: Optional[Dict[str, Any]] = {
            "ok": True,
            "decision": "allow",
            "token": "<test-token>",
            "token_sha256": "a" * 64,
            "claims": {},
            "reason": None,
        }
        self.response_status_audit_event: int = 202
        self.response_body_audit_event: Optional[Dict[str, Any]] = {
            "ok": True,
            "audit_kind": "policy_audit_event",
            "ts_unix_ms": 0,
        }
        self.sleep_seconds: float = 0.0
        self.received_requests: List[Dict[str, Any]] = []
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ start
    def start(self) -> None:
        """Bind to 127.0.0.1:0 (OS-assigned port) and serve in a thread."""
        kernel = self

        class _Handler(BaseHTTPRequestHandler):
            # Silence per-request stderr noise.
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

            def do_POST(self) -> None:  # noqa: N802 — stdlib API
                length = int(self.headers.get("content-length", "0") or "0")
                raw = self.rfile.read(length) if length else b""
                try:
                    parsed = json.loads(raw) if raw else None
                except Exception:  # noqa: BLE001
                    parsed = None
                with kernel._lock:
                    kernel.received_requests.append(
                        {
                            "path": self.path,
                            "headers": dict(self.headers),
                            "body": parsed,
                            "raw_body": raw,
                        }
                    )

                if kernel.sleep_seconds > 0:
                    time.sleep(kernel.sleep_seconds)

                if self.path == "/policy/module/authorize":
                    status = kernel.response_status_authorize
                    body = kernel.response_body_authorize
                elif self.path == "/policy/audit-event":
                    status = kernel.response_status_audit_event
                    body = kernel.response_body_audit_event
                else:
                    status = 404
                    body = {"error": "not_found"}
                self._send(status, body)

            def _send(self, status: int, body: Any) -> None:
                self.send_response(status)
                self.send_header("content-type", "application/json")
                payload = json.dumps(body if body is not None else {}).encode("utf-8")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._server = HTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
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
    def requests_to(self, path: str) -> List[Dict[str, Any]]:
        """Return every received POST to a specific path."""
        return [r for r in self.received_requests if r["path"] == path]

    def authorize_requests(self) -> List[Dict[str, Any]]:
        return self.requests_to("/policy/module/authorize")

    def audit_event_requests(self) -> List[Dict[str, Any]]:
        return self.requests_to("/policy/audit-event")

    def reset(self) -> None:
        with self._lock:
            self.received_requests.clear()
