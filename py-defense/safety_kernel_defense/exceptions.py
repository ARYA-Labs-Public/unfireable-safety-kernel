"""Exception types raised by the safety-kernel audit-hook reference.

Per the architecture overview, the audit hook raises three exception classes. The choice of base
classes is deliberate:

* ``PolicyDenied`` inherits from :class:`PermissionError` so that
  generic exception handlers that catch :class:`PermissionError` (a
  common pattern in adopter code) catch policy denials without
  needing to know about safety-kernel internals. The audit hook
  re-raises this as :class:`ImportError` / :class:`RuntimeError` at
  the CPython audit-callback boundary depending on event kind; the
  original ``PolicyDenied`` is available via ``__cause__``.

* ``KernelUnavailable`` inherits from :class:`ConnectionError`. The
  hook re-raises this at the callback boundary the same way as
  ``PolicyDenied``. The base class lets adopter retry-on-network
  handlers naturally cover the kernel-unreachable case.

* ``HookConfigError`` inherits from :class:`RuntimeError`. Raised
  only at install time when the configuration is malformed
  (incompatible re-install, http:// to a non-localhost URL, etc.).
  Never raised from inside the audit callback.

None of these exceptions are serializable across processes — they
are caller-side only.
"""

from __future__ import annotations

__all__ = [
    "PolicyDenied",
    "KernelUnavailable",
    "HookConfigError",
    "SignatureInvalid",
    "RevokeError",
]


class PolicyDenied(PermissionError):
    """The Rust kernel returned a DENY decision for this audit event.

    Carries the kernel-side decision token's SHA-256 hex digest
    (``decision_token_sha256``) so adopter-side forensics can
    correlate the raised exception with the chain entry without
    needing to walk the chain from the application.

    Attributes
    ----------
    reason: the kernel-returned reason string (e.g.
        ``"module_not_registered"``, ``"pattern_match_failed"``).
        Stable wire strings; safe to switch on.
    decision_token_sha256: SHA-256 hex of the signed DENY token, or
        ``None`` for fail-closed paths that did not reach the
        signing step (kernel timeout under ``fail_closed=True``).
    """

    def __init__(
        self,
        reason: str,
        *,
        decision_token_sha256: str | None = None,
    ) -> None:
        super().__init__(f"safety-kernel denied: {reason}")
        self.reason = reason
        self.decision_token_sha256 = decision_token_sha256


class KernelUnavailable(ConnectionError):
    """The Rust kernel was not reachable for this audit event.

    Raised when ``fail_closed_on_unreachable=True`` (the default) and
    one of the following happens:

    * The HTTP socket connect fails (kernel down, wrong URL).
    * The HTTP request times out (``timeout_seconds`` exceeded).
    * The kernel returns 503 with body ``error: kernel_unavailable``.

    With ``fail_closed_on_unreachable=False`` the hook logs CRITICAL
    and allows the operation instead of raising this.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(f"safety-kernel unreachable: {detail}")
        self.detail = detail


class HookConfigError(RuntimeError):
    """Install-time configuration error.

    Raised by :func:`install_audit_hook` when the supplied
    configuration is structurally invalid (e.g., re-install with a
    different ``kernel_url``, plain-http URL pointing at a non-loopback
    host, invalid charset for ``caller_subject``). Never raised from
    the audit callback itself — only at install time.
    """


class SignatureInvalid(RuntimeError):
    """An ``ALLOW`` decision arrived but its Ed25519 signature did not
    verify against the configured public key.

    Raised inside :class:`~safety_kernel_defense.middleware.SafetyKernelMiddleware`
    when the kernel returned a 200 ALLOW carrying a token whose
    signature (over the base64url payload) fails verification, whose
    token is malformed, or whose bound claims are expired. This is the
    fail-CLOSED integrity check: a reachable kernel is not enough — the
    reply must be provably minted by the trusted signing key. The
    middleware maps this to HTTP 503 (``signature_invalid``); it is
    never surfaced as an ALLOW.

    Attributes
    ----------
    detail: short machine-friendly reason (``bad_signature``,
        ``malformed_token``, ``token_expired``).
    """

    def __init__(self, detail: str) -> None:
        super().__init__(f"safety-kernel signature verification failed: {detail}")
        self.detail = detail


class RevokeError(RuntimeError):
    """A ``/kernel/v1/revoke/*`` call returned a non-success HTTP status.

    Raised by :class:`~safety_kernel_defense.revoke_client.RevokeClient`
    when the kernel answered with a status outside the endpoint's
    documented success set (e.g. 401/403/422/503). The client raises
    rather than returning a partial/false-success object — a revoke
    surface that swallowed an error into a success would defeat the
    fail-closed contract (a supervisor must never believe a kill was
    minted/pulled/acked when it was not).

    Attributes
    ----------
    status: the HTTP status code the kernel returned.
    error_code: the kernel's stable ``error`` field, if any.
    reason: the kernel's optional human-readable ``reason``, if any.
    """

    def __init__(
        self,
        status: int,
        *,
        error_code: str | None = None,
        reason: str | None = None,
    ) -> None:
        suffix = f" ({error_code})" if error_code else ""
        super().__init__(f"safety-kernel revoke call failed: HTTP {status}{suffix}")
        self.status = status
        self.error_code = error_code
        self.reason = reason
