"""Reference middleware for the Safety Kernel.

Four enforcement seams per :

1. ``nginx_policy.conf`` — route-level ``auth_request`` (outermost)
2. ``fastapi_safety_middleware.py`` — per-request middleware
3. ``dispatch_hook.py`` — per-tool decorator
4. ``circuit_breaker`` — fail-closed on kernel unreachable (lives in
   ``packages/safety/client/``)

Without all four, the kernel is INERT. See
``docs/integration/enforcement-seams.md``.
"""

from examples.middleware.dispatch_hook import safety_gate
from examples.middleware.fastapi_safety_middleware import (
    SafetyMiddleware,
    WebSocketSafetyDependency,
    install_safety_middleware,
    websocket_safety_dependency,
)
from examples.middleware.handler_guard import (
    MissingSafetyTokenError,
    require_safety_token,
)

__all__ = [
    "MissingSafetyTokenError",
    "SafetyMiddleware",
    "WebSocketSafetyDependency",
    "install_safety_middleware",
    "require_safety_token",
    "safety_gate",
    "websocket_safety_dependency",
]
