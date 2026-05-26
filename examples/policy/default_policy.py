"""Three-tier policy for Safety Kernel reference middleware.

Routes are classified into one of three tiers:

* ``UNRESTRICTED`` — no kernel call. Examples: ``/healthz``, static
  asset routes, ``/metrics``. Never blocks request flow.
* ``SUPERVISED``  — the kernel is called, but a transport failure
  fails *open* with an audit-only warning. Examples: read-only
  introspection endpoints where freshness matters but downtime is
  not worth a 503. Use sparingly — fail-open is a deliberate
  reduction in the safety guarantee.
* ``GATED``       — the kernel is called fail-closed. Any failure
  (kernel unreachable, deny, signature mismatch) terminates the
  request with HTTP 403 (deny) or 503 (unavailable). This is the
  default for any route that mutates state or accesses sensitive
  data.

This module ships an example :data:`DEFAULT_POLICY` covering a
minimal app. Real callers should compose their own
:class:`SafetyPolicy` via the :func:`policy` DSL in
``policy_rule_dsl.py`` or by direct construction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class PolicyTier(str, Enum):
    """Three-tier classification per """

    UNRESTRICTED = "unrestricted"
    SUPERVISED = "supervised"
    GATED = "gated"


@dataclass(frozen=True)
class PolicyEntry:
    """One rule in the :class:`SafetyPolicy` rule list.

    Args:
        route_pattern: Regex matched against the request path.
        method: HTTP method (``"*"`` matches any).
        tier: Tier to apply when this entry matches.
        action: Action name passed to the kernel as the ``action``
            field. Only used when ``tier`` is ``SUPERVISED`` or
            ``GATED``. Should be on the kernel's allowlist.
    """

    route_pattern: str
    method: str
    tier: PolicyTier
    action: str = ""


@dataclass
class SafetyPolicy:
    """Ordered list of :class:`PolicyEntry` — first match wins.

    A request with no matching entry defaults to :attr:`default_tier`
    (which itself defaults to ``GATED`` — fail-closed-by-default).
    """

    entries: list[PolicyEntry] = field(default_factory=list)
    default_tier: PolicyTier = PolicyTier.GATED
    default_action: str = "unclassified"

    def __post_init__(self) -> None:
        self._compiled: list[tuple[re.Pattern[str], PolicyEntry]] = [
            (re.compile(e.route_pattern), e) for e in self.entries
        ]

    def classify(self, *, path: str, method: str) -> tuple[PolicyTier, str]:
        """Return the (tier, action) pair for the given request."""
        for pattern, entry in self._compiled:
            if entry.method not in ("*", method.upper()):
                continue
            if pattern.match(path):
                return entry.tier, entry.action or self.default_action
        return self.default_tier, self.default_action

    def routes_at_tier(self, tier: PolicyTier) -> Iterable[PolicyEntry]:
        """Iterate over policy entries at the given tier (audit helper)."""
        for entry in self.entries:
            if entry.tier == tier:
                yield entry


# Example wiring. Real apps compose their own.
DEFAULT_POLICY: SafetyPolicy = SafetyPolicy(
    entries=[
        # Liveness / metrics — never block on the kernel.
        PolicyEntry(route_pattern=r"^/healthz$", method="GET", tier=PolicyTier.UNRESTRICTED),
        PolicyEntry(route_pattern=r"^/metrics$", method="GET", tier=PolicyTier.UNRESTRICTED),
        # Public docs / openapi schemata.
        PolicyEntry(route_pattern=r"^/docs", method="GET", tier=PolicyTier.UNRESTRICTED),
        PolicyEntry(route_pattern=r"^/openapi\.json$", method="GET", tier=PolicyTier.UNRESTRICTED),
        # Read-only introspection routes — supervised (fail-open with audit).
        PolicyEntry(
            route_pattern=r"^/api/v1/status",
            method="GET",
            tier=PolicyTier.SUPERVISED,
            action="api.read.status",
        ),
        # Mutating routes — gated (fail-closed).
        PolicyEntry(
            route_pattern=r"^/api/v1/rsi/apply",
            method="POST",
            tier=PolicyTier.GATED,
            action="rsi.apply_proposal",
        ),
        PolicyEntry(
            route_pattern=r"^/api/v1/rsi/rollback",
            method="POST",
            tier=PolicyTier.GATED,
            action="rsi.rollback",
        ),
        PolicyEntry(
            route_pattern=r"^/api/v1/admin/.*",
            method="*",
            tier=PolicyTier.GATED,
            action="api.admin",
        ),
    ],
    default_tier=PolicyTier.GATED,
    default_action="unclassified",
)
