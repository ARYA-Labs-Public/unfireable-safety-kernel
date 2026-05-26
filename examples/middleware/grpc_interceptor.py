"""gRPC server interceptor for the Safety Kernel.

Drop into any ``grpc.server`` to gate every RPC through the kernel.
The interceptor:

1. Resolves the gRPC method name → policy tier + action.
2. Computes a stable params fingerprint over the serialized request.
3. Calls :meth:`SafetyKernelClient.authorize`.
4. On deny: aborts the RPC with ``PERMISSION_DENIED``.
5. On unreachable + ``GATED`` tier: aborts with ``UNAVAILABLE``.
6. On allow: lets the RPC through and stashes the signed token on
   the servicer context for downstream forwarding.

Usage::

    import grpc
    from examples.middleware import SafetyKernelInterceptor

    server = grpc.server(
        thread_pool,
        interceptors=[
            SafetyKernelInterceptor(client=client, policy=policy, subject="api"),
        ],
    )

The interceptor depends only on ``grpc`` (not on ``starlette`` /
``fastapi``) so it can stand alone in pure-gRPC services.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Callable

from packages.core.safety_tokens import params_fingerprint
from packages.safety.client import (
    KernelClientError,
    KernelDecisionError,
    SafetyKernelClient,
)

from examples.observability.kernel_call_metrics import (
    instrument_authorize,
    record_bypass_attempt,
)
from examples.policy.default_policy import PolicyTier, SafetyPolicy

__all__ = ["SafetyKernelInterceptor", "StreamingNotAuthorizedError"]


class StreamingNotAuthorizedError(RuntimeError):
    """The interceptor refused to register a streaming RPC.

    streaming RPCs cannot be safely gated by the current
    interceptor (it only authorizes the *first* message, not per-message,
    and there is no obvious choke point for half-duplex streams). The
    interceptor's default behaviour is therefore to REFUSE to register a
    streaming handler — refuse-to-deploy is safer than silent-bypass.

    Operators who genuinely need streaming MUST opt in by passing
    ``allow_streaming=True`` to :class:`SafetyKernelInterceptor` AND
    implement their own per-message authorization at the application
    layer.
    """

try:
    import grpc

    _GRPC_AVAILABLE = True
except ImportError:  # pragma: no cover
    grpc = None  # type: ignore[assignment]
    _GRPC_AVAILABLE = False


_GrpcInterceptor: Any
if _GRPC_AVAILABLE:
    _GrpcInterceptor = grpc.ServerInterceptor  # type: ignore[attr-defined]
else:
    _GrpcInterceptor = object  # type: ignore[assignment]


class SafetyKernelInterceptor(_GrpcInterceptor):  # type: ignore[misc,valid-type]
    """gRPC server interceptor that gates every RPC through the kernel.

    Args:
        client: :class:`SafetyKernelClient` to consult.
        policy: :class:`SafetyPolicy` mapping ``method_name`` regex →
            tier + action.
        subject: Default subject string ("api" / "worker" / "operator").
    """

    def __init__(
        self,
        *,
        client: SafetyKernelClient,
        policy: SafetyPolicy,
        subject: str = "api",
        allow_streaming: bool = False,
    ) -> None:
        """Construct the interceptor.

        Args:
            client: :class:`SafetyKernelClient` to consult.
            policy: :class:`SafetyPolicy` mapping ``method_name`` → tier.
            subject: Default subject string.
            allow_streaming: When False (default, recommended), the
                interceptor refuses to register any streaming RPC by
                raising :class:`StreamingNotAuthorizedError` from
                :meth:`intercept_service`. When True the operator MUST
                provide their own per-message authorization at the
                application layer; the interceptor will fall through
                to the unwrapped handler for streaming methods (which
                is the older releases behaviour).
        """
        if not _GRPC_AVAILABLE:  # pragma: no cover
            raise RuntimeError(
                "SafetyKernelInterceptor requires the `grpcio` package."
            )
        self._client = client
        self._policy = policy
        self._subject = subject
        self._allow_streaming = allow_streaming

    def intercept_service(
        self,
        continuation: Callable[[Any], Any],
        handler_call_details: Any,
    ) -> Any:
        method = str(handler_call_details.method)
        # In gRPC the "path" is the method name (e.g. /pkg.Service/Method).
        # We feed it to the policy classifier as if it were an HTTP path
        # so the same SafetyPolicy can govern both stacks.
        tier, action = self._policy.classify(path=method, method="POST")

        if tier == PolicyTier.UNRESTRICTED:
            return continuation(handler_call_details)

        original_handler = continuation(handler_call_details)
        if original_handler is None:
            return None

        # Wrap the handler so we can authorize per-request (the method
        # registration phase isn't per-request — the unary/stream
        # handler is). We support unary-unary here; extend as needed.
        return self._wrap_handler(
            original_handler, tier=tier, action=action
        )

    # ------------------------------------------------------------------
    # Handler wrapping
    # ------------------------------------------------------------------

    def _wrap_handler(self, handler: Any, *, tier: PolicyTier, action: str) -> Any:
        if not (handler.request_streaming or handler.response_streaming):
            return self._wrap_unary_unary(handler, tier=tier, action=action)
        # Streaming RPCs cannot be safely gated by this interceptor (no
        # per-message hook + no half-duplex choke point). Refuse-to-deploy
        # unless the operator has explicitly opted in via
        # ``allow_streaming=True`` AND implemented their own gating.
        if not self._allow_streaming:
            record_bypass_attempt("dispatch")
            raise StreamingNotAuthorizedError(
                f"SafetyKernelInterceptor refuses to register streaming RPC "
                f"(action={action!r}, request_streaming={handler.request_streaming}, "
                f"response_streaming={handler.response_streaming}). "
                "Set `allow_streaming=True` and implement per-message "
                "authorization at the application layer if streaming is required."
            )
        # Operator opted in — fall through to the unwrapped handler.
        # We log a bypass record so this never goes silently into
        # production unnoticed.
        record_bypass_attempt("dispatch")
        return handler

    def _wrap_unary_unary(self, handler: Any, *, tier: PolicyTier, action: str) -> Any:
        original_behavior = handler.unary_unary

        def _new_behavior(request: Any, context: Any) -> Any:
            params_fp = _fingerprint_grpc_request(request)
            run_id = f"grpc-{action}-{uuid.uuid4().hex[:12]}"
            try:
                with instrument_authorize(action=action) as record:
                    decision = self._client.authorize(
                        action=action,
                        params_fingerprint=params_fp,
                        run_id=run_id,
                        subject=self._subject,
                    )
                    record(decision)
            except KernelDecisionError as exc:
                if tier == PolicyTier.GATED:
                    record_bypass_attempt("dispatch")
                    context.abort(
                        grpc.StatusCode.UNAVAILABLE,  # type: ignore[attr-defined]
                        f"safety_kernel_unavailable: {exc}",
                    )
                # SUPERVISED — fail-open with audit metadata.
                return original_behavior(request, context)
            except KernelClientError as exc:
                record_bypass_attempt("dispatch")
                context.abort(
                    grpc.StatusCode.UNAVAILABLE,  # type: ignore[attr-defined]
                    f"safety_kernel_unavailable: {exc}",
                )

            if not decision.allowed:
                context.abort(
                    grpc.StatusCode.PERMISSION_DENIED,  # type: ignore[attr-defined]
                    f"kernel_denied: {decision.reason}",
                )

            # Stash the signed token on the context so downstream
            # interceptors / handlers can forward it.
            try:
                context.set_trailing_metadata(
                    [
                        ("x-kernel-token", str((decision.metadata or {}).get("token") or "")),
                        ("x-kernel-action", action),
                        ("x-kernel-run-id", run_id),
                    ]
                )
            except Exception:  # noqa: BLE001
                pass

            return original_behavior(request, context)

        return grpc.unary_unary_rpc_method_handler(  # type: ignore[attr-defined]
            _new_behavior,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )


def _fingerprint_grpc_request(request: Any) -> str:
    """Stable SHA-256 fingerprint of a serialized gRPC request.

    Falls back to ``repr()`` when the message doesn't implement
    ``SerializeToString`` (e.g. dict-based tests).
    """
    try:
        raw = request.SerializeToString()
    except AttributeError:
        raw = repr(request).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
