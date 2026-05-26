"""Observability for the Safety Kernel reference middleware."""

from examples.observability.kernel_call_metrics import (
    KERNEL_BYPASS_ATTEMPTS,
    KERNEL_CALL_DURATION_SECONDS,
    KERNEL_CALL_TOTAL,
    instrument_authorize,
    record_bypass_attempt,
)

__all__ = [
    "KERNEL_BYPASS_ATTEMPTS",
    "KERNEL_CALL_DURATION_SECONDS",
    "KERNEL_CALL_TOTAL",
    "instrument_authorize",
    "record_bypass_attempt",
]
