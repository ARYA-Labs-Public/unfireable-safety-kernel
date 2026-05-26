"""Prometheus metrics for Safety Kernel calls.

Three metrics + one alert rule, mirroring the Rust track's
``crates/adapters/safety_kernel_middleware/`` instrumentation:

* ``kernel_call_total{action, outcome}`` (Counter) — every authorize
  attempt, labelled by the action requested and the observed outcome
  (``allow`` / ``deny`` / ``unavailable`` / ``verification_failed`` /
  ``error``).
* ``kernel_call_duration_seconds{action}`` (Histogram) — per-action
  wall-clock latency of the authorize call.
* ``kernel_bypass_attempts_total{seam}`` (Counter) — requests that
  reached a guarded resource WITHOUT a corresponding kernel ALLOW
  audit. The Grafana alert "Kernel Bypass" fires the moment this
  rate exceeds zero — bypass attempts must never be silent.

The module degrades gracefully when ``prometheus_client`` isn't
installed: every helper becomes a no-op so the reference app still
runs in stripped-down test environments.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any

__all__ = [
    "KERNEL_BYPASS_ATTEMPTS",
    "KERNEL_CALL_DURATION_SECONDS",
    "KERNEL_CALL_TOTAL",
    "instrument_authorize",
    "record_bypass_attempt",
]

try:
    from prometheus_client import Counter, Histogram

    _PROMETHEUS_AVAILABLE = True
except ImportError:  # pragma: no cover — fallback path

    class _NoopMetric:
        """Drop-in replacement so apps that haven't installed
        prometheus_client still run. Internal state is preserved so
        tests can introspect counter values."""

        def __init__(self, *_: Any, **__: Any) -> None:
            self._value_holder: dict[tuple[tuple[str, str],...], "_NoopValue"] = {}

        def labels(self, *args: Any, **kwargs: Any) -> "_NoopMetric":
            # Bind label values; returns a child metric with its own _value.
            key = tuple(sorted(kwargs.items())) + tuple(("", str(a)) for a in args)
            child = _NoopMetric()
            child._value = self._value_holder.setdefault(key, _NoopValue())
            return child

        def inc(self, amount: float = 1.0) -> None:
            if hasattr(self, "_value"):
                self._value.value += amount

        def observe(self, *_: Any, **__: Any) -> None:
            pass

    class _NoopValue:
        def __init__(self) -> None:
            self.value: float = 0.0

        def get(self) -> float:
            return self.value

    def Counter(*args: Any, **kwargs: Any) -> _NoopMetric:  # type: ignore[no-redef]
        return _NoopMetric(*args, **kwargs)

    def Histogram(*args: Any, **kwargs: Any) -> _NoopMetric:  # type: ignore[no-redef]
        return _NoopMetric(*args, **kwargs)

    _PROMETHEUS_AVAILABLE = False


KERNEL_CALL_TOTAL = Counter(
    "kernel_call_total",
    "Total Safety Kernel authorize calls, labelled by action and outcome.",
    labelnames=("action", "outcome"),
)

KERNEL_CALL_DURATION_SECONDS = Histogram(
    "kernel_call_duration_seconds",
    "Wall-clock duration of Safety Kernel authorize calls in seconds.",
    labelnames=("action",),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

KERNEL_BYPASS_ATTEMPTS = Counter(
    "kernel_bypass_attempts_total",
    "Requests reaching a guarded resource WITHOUT a kernel ALLOW audit. "
    "Any non-zero rate is a security incident.",
    labelnames=("seam",),
)


@contextmanager
def instrument_authorize(action: str) -> Any:
    """Context manager that observes latency + classifies outcome.

    Usage::

        with instrument_authorize(action="rsi.apply") as record:
            decision = client.authorize(action="rsi.apply",...)
            record(decision)

    The inner ``record`` callable normalises the decision (a
    :class:`KernelPolicyDecision` or any object with an ``.allowed``
    attribute) into one of the canonical outcome labels.
    """
    start = time.monotonic()
    outcome_holder: dict[str, str] = {"outcome": "error"}

    def _record(decision: Any) -> None:
        try:
            if decision is None:
                outcome_holder["outcome"] = "unavailable"
            elif getattr(decision, "allowed", None) is True:
                outcome_holder["outcome"] = "allow"
            elif getattr(decision, "allowed", None) is False:
                outcome_holder["outcome"] = "deny"
            else:
                outcome_holder["outcome"] = "unknown"
        except Exception:  # noqa: BLE001
            outcome_holder["outcome"] = "error"

    try:
        yield _record
    except Exception as exc:  # noqa: BLE001
        # Classify the exception. Verification + decision errors are
        # tracked separately because they have very different blast
        # radius — verification = potential kernel substitution.
        cls = type(exc).__name__
        if "Verification" in cls:
            outcome_holder["outcome"] = "verification_failed"
        elif "Decision" in cls or "Unavailable" in cls:
            outcome_holder["outcome"] = "unavailable"
        else:
            outcome_holder["outcome"] = "error"
        raise
    finally:
        duration = time.monotonic() - start
        KERNEL_CALL_DURATION_SECONDS.labels(action=action).observe(duration)
        KERNEL_CALL_TOTAL.labels(action=action, outcome=outcome_holder["outcome"]).inc()


def record_bypass_attempt(seam: str) -> None:
    """Record a bypass attempt at the given enforcement seam.

    ``seam`` must be one of {``"middleware"``, ``"dispatch"``,
    ``"nginx"``, ``"circuit_breaker"``, ``"websocket"``}. The Grafana
    alert "Kernel Bypass" fires on any non-zero rate of this counter —
    bypass attempts must never be silent.

     the ``"websocket"`` seam (WebSocket-upgrade gate
    closed via :func:`websocket_safety_dependency`).
    """
    KERNEL_BYPASS_ATTEMPTS.labels(seam=seam).inc()
