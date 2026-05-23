"""Pythonic DSL for composing :class:`SafetyPolicy` rules.

Usage::

    from examples.policy import policy, PolicyTier

    POLICY = (
        policy()
        .unrestricted("GET",  r"^/healthz$")
        .unrestricted("GET",  r"^/metrics$")
        .supervised(  "GET",  r"^/api/v1/status",     action="api.read.status")
        .gated(       "POST", r"^/api/v1/rsi/apply",  action="rsi.apply_proposal")
        .gated(       "POST", r"^/api/v1/rsi/rollback", action="rsi.rollback")
        .build()
    )

The DSL is a thin convenience layer over
:class:`~examples.policy.default_policy.SafetyPolicy` — same semantics,
nicer ergonomics for declaring 5–50 routes.
"""

from __future__ import annotations

from typing import Self

from examples.policy.default_policy import PolicyEntry, PolicyTier, SafetyPolicy

__all__ = ["PolicyBuilder", "policy"]


class PolicyBuilder:
    """Fluent builder for :class:`SafetyPolicy`."""

    def __init__(self) -> None:
        self._entries: list[PolicyEntry] = []
        self._default_tier: PolicyTier = PolicyTier.GATED
        self._default_action: str = "unclassified"

    def unrestricted(self, method: str, pattern: str) -> Self:
        """Add an UNRESTRICTED rule (no kernel call)."""
        self._entries.append(
            PolicyEntry(route_pattern=pattern, method=method.upper(), tier=PolicyTier.UNRESTRICTED)
        )
        return self

    def supervised(self, method: str, pattern: str, *, action: str) -> Self:
        """Add a SUPERVISED rule (kernel called, fail-open with audit)."""
        self._entries.append(
            PolicyEntry(
                route_pattern=pattern,
                method=method.upper(),
                tier=PolicyTier.SUPERVISED,
                action=action,
            )
        )
        return self

    def gated(self, method: str, pattern: str, *, action: str) -> Self:
        """Add a GATED rule (kernel called fail-closed)."""
        self._entries.append(
            PolicyEntry(
                route_pattern=pattern,
                method=method.upper(),
                tier=PolicyTier.GATED,
                action=action,
            )
        )
        return self

    def default(self, tier: PolicyTier, action: str = "unclassified") -> Self:
        """Override the default tier for routes that match no entry."""
        self._default_tier = tier
        self._default_action = action
        return self

    def build(self) -> SafetyPolicy:
        return SafetyPolicy(
            entries=list(self._entries),
            default_tier=self._default_tier,
            default_action=self._default_action,
        )


def policy() -> PolicyBuilder:
    """Top-level entrypoint for the DSL."""
    return PolicyBuilder()
