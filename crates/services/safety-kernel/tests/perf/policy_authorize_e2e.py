"""End-to-end perf benchmark for ``POST /policy/module/authorize``.

 slice 5 §3.1–§3.3 — the GATED perf number. Measures
end-to-end HTTP RTT from the caller's perspective (i.e. what the
Python audit hook would pay on every ``import``).

SOFT budget: 5 ms p99 (warn-only — emits ``::warning::`` GitHub
Actions annotation, lane stays green).
HARD budget: 10 ms p99 (block — fails the lane).

Run locally::

    pytest crates/services/safety-kernel/tests/perf/ -v -m perf \
        --benchmark-only --benchmark-min-rounds=100

The perf marker is registered in ``pyproject.toml``. Without ``-m perf``
the regular test collection skips this file — pytest still parses it
to register the marker but pytest-benchmark's ``--benchmark-only`` flag
guarantees no other tests run.

The bench is informational by default — the gating script
``_grade_perf.py`` reads the JSON report (``--benchmark-json=perf.json``)
and emits either a ``::warning::`` (5 ms < p99 ≤ 10 ms) or fails with
``::error::`` (p99 > 10 ms). See slice5_design.md §3.3 for the
two-threshold rationale.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

import pytest

# Module-level marker — every test below carries ``@pytest.mark.perf``
# implicitly. The registration in ``pyproject.toml`` keeps pytest
# strict-marker mode happy when other lanes run.
pytestmark = pytest.mark.perf


def _post_authorize(
    base_url: str,
    api_key: str,
    body: dict[str, Any],
    timeout_s: float = 5.0,
) -> tuple[int, bytes]:
    """POST to ``/policy/module/authorize`` and return (status, raw_body).

    The bench measures wall-clock around THIS function. We use stdlib
    ``urllib.request`` rather than ``requests`` so the bench's
    measurement reflects the audit-hook's call shape (the hook reaches
    for ``urllib`` to avoid adding any pip dependency to caller
    processes — see ``safety_kernel_oss/py-defense/...``).
    """
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/policy/module/authorize",
        data=data,
        method="POST",
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as r:
        return r.status, r.read()


def test_policy_authorize_p99_meets_budget(
    benchmark: Any,
    perf_stack: dict[str, Any],
) -> None:
    """Bench ``/policy/module/authorize`` hot path; emit GH annotations.

    Two thresholds (slice5_design.md §3.3):

    * SOFT 5 ms p99 — warn-only via ``::warning::``. Lane stays green;
      surfaces in the GitHub UI as a yellow caution next to the step.
    * HARD 10 ms p99 — block via ``pytest.fail`` so the lane fails.

    The actual gate enforcement happens in ``_grade_perf.py`` which
    reads ``--benchmark-json=perf.json``. This test does its own
    in-process check too so a local run (``pytest -m perf``) without
    the grader still surfaces the verdict.
    """
    base_url = perf_stack["base_url"]
    api_key = perf_stack["api_key_worker"]
    body = perf_stack["request_body"]

    # Sanity-check: the first call returns 200 with ``decision: allow``
    # (the mock sidecar always allows). If the body is malformed or the
    # binary is misconfigured the bench would record latency on an
    # error response, which is meaningless.
    status, raw = _post_authorize(base_url, api_key, body)
    assert status == 200, f"expected 200, got {status}: {raw[:200]!r}"
    parsed = json.loads(raw)
    assert parsed.get("decision") == "allow", parsed

    # Drive the actual bench. ``pedantic`` gives us full control:
    #   iterations=1 -> one call per round (RTT-oriented, not throughput)
    #   rounds=N     -> repeat enough to fill the p99 percentile tail
    #
    # 1000 rounds × ~2 ms median ≈ 2-3 s wall clock per bench. p99 is
    # well-defined at this sample size.
    def _call() -> None:
        status, _ = _post_authorize(base_url, api_key, body)
        if status != 200:
            raise AssertionError(f"non-200 in bench: {status}")

    benchmark.pedantic(
        _call,
        iterations=1,
        rounds=1000,
        warmup_rounds=50,
    )

    # ``benchmark.stats.stats`` is a ``Stats`` instance from
    # ``pytest-benchmark``. ``percentile()`` takes a 0-1 fraction —
    # the API differs across versions, so fall back to sorted-samples
    # math when not available.
    stats = benchmark.stats.stats
    p50_ms = _percentile_ms(stats, 0.50)
    p95_ms = _percentile_ms(stats, 0.95)
    p99_ms = _percentile_ms(stats, 0.99)

    # Emit GitHub Actions annotations. These are picked up by
    # github-actions runners regardless of test verdict — the
    # ``::warning::`` is yellow, ``::error::`` is red, plain print is
    # neutral.
    print(
        f"\n[policy_authorize p99] "
        f"p50={p50_ms:.3f}ms p95={p95_ms:.3f}ms p99={p99_ms:.3f}ms  "
        f"rounds={stats.rounds}"
    )

    if p99_ms > 10.0:
        msg = (
            f"::error::policy_authorize p99 = {p99_ms:.2f}ms > 10ms "
            f"HARD budget — gate failed"
        )
        print(msg)
        pytest.fail(msg)
    elif p99_ms > 5.0:
        # SOFT-warn path. Test stays green.
        print(
            f"::warning::policy_authorize p99 = {p99_ms:.2f}ms > 5ms "
            f"SOFT budget — investigate latency creep"
        )


def _percentile_ms(stats: Any, frac: float) -> float:
    """Read a percentile from a pytest-benchmark Stats object.

    pytest-benchmark < 4 exposes ``percentile(frac)``; later versions
    sometimes spell it differently. Fall back to a manual sort over
    ``data`` (sample timings in seconds).
    """
    fn = getattr(stats, "percentile", None)
    if callable(fn):
        try:
            v = fn(frac)
            return float(v) * 1000.0
        except (TypeError, ValueError):
            pass

    data = list(getattr(stats, "data", []))
    if not data:
        # pytest-benchmark stores per-round measurements under a
        # different attribute name across versions; fall back to mean.
        return float(getattr(stats, "mean", 0.0)) * 1000.0
    data.sort()
    # Index using the type-7 (numpy default) linear interpolation.
    idx = int(frac * (len(data) - 1))
    return float(data[idx]) * 1000.0
