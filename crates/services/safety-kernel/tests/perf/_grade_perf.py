#!/usr/bin/env python3
"""Grade the ``pytest-benchmark`` JSON report against the slice-5 budget.

 slice 5 §3.3 (SOFT recalibrated by -followup item 3,
). Two thresholds:

* SOFT 7 ms p99 — emit ``::warning::`` GitHub Actions annotation;
  exit 0.
* HARD 10 ms p99 — emit ``::error::`` GitHub Actions annotation;
  exit 1.

SOFT recalibration rationale: Test-5 measured the
pytest-benchmark e2e p99 at **5.45 ms** — right on the original 5 ms
SOFT boundary. A standard CI machine running 10-20% slower than the
bench host would trip the SOFT gate on a clean, non-regressed kernel,
producing perpetual false ``::warning::`` noise. SOFT raised 5 -> 7 ms
(≈ 5.45 ms measured + ~28% CI-host headroom) so the SOFT gate signals a
genuine latency-creep regression, not bench-host variance. HARD stays
10 ms (operator-safety wall — unchanged).

Usage::

    python _grade_perf.py perf.json

The JSON file is the output of ``pytest --benchmark-json=perf.json``
against ``policy_authorize_e2e.py``. The script extracts the p99 of
the ``test_policy_authorize_p99_meets_budget`` benchmark and grades
against the two thresholds.

Exit codes:
  0 -> p99 <= 7 ms (clean PASS) OR 7 ms < p99 <= 10 ms (SOFT warn)
  1 -> p99 > 10 ms (HARD fail) OR the JSON file is missing/malformed

The script also fails (exit 1) if the JSON report contains no
benchmark named ``test_policy_authorize_p99_meets_budget`` — that
indicates the pytest run was skipped (no python3/cargo/binary
available), which is itself a SKIP-not-PASS verdict.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# SOFT recalibrated 5.0 -> 7.0 ms by -followup item 3
# — measured e2e p99 was 5.45 ms on the bench host; 7 ms gives CI-host
# headroom so the SOFT gate flags real latency creep, not host variance.
SOFT_BUDGET_MS = 7.0
HARD_BUDGET_MS = 10.0
TARGET_BENCH_NAME = "test_policy_authorize_p99_meets_budget"


def _extract_p99_ms(report: dict) -> float | None:
    """Locate the perf-target benchmark in the JSON report and return p99 (ms).

    pytest-benchmark schema::

        {
          "benchmarks": [
            {
              "name": "test_policy_authorize_p99_meets_budget",
              "stats": {
                "mean": 0.001234, "min":..., "max":...,
                "stddev":..., "iqr":..., "median":...,
                "q1":..., "q3":...,
                "percentile_99": 0.00234,   # may or may not be present
                "data": [...]               # sometimes present
              }
            },
            ...
          ]
        }

    Older pytest-benchmark versions don't include ``percentile_99``;
    we fall back to the explicit ``data`` array and sort. As a last
    resort, p99 ≈ ``mean + 2.326 * stddev`` (normal approx).
    """
    for bench in report.get("benchmarks", []):
        if bench.get("name") != TARGET_BENCH_NAME:
            continue
        stats = bench.get("stats", {})

        # Preferred: explicit p99 field.
        p99 = stats.get("percentile_99") or stats.get("p99")
        if isinstance(p99, (int, float)):
            return float(p99) * 1000.0

        # Fallback 1: sorted data array.
        data = stats.get("data")
        if isinstance(data, list) and data:
            data_sorted = sorted(float(x) for x in data)
            idx = int(0.99 * (len(data_sorted) - 1))
            return float(data_sorted[idx]) * 1000.0

        # Fallback 2: normal approximation.
        mean = stats.get("mean")
        stddev = stats.get("stddev")
        if isinstance(mean, (int, float)) and isinstance(stddev, (int, float)):
            return (float(mean) + 2.326 * float(stddev)) * 1000.0

        return None
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="pytest-benchmark JSON report")
    args = parser.parse_args()

    if not args.report.exists():
        print(
            f"::error::perf report not found at {args.report} — "
            "pytest-benchmark did not run (skipped or crashed)"
        )
        return 1

    try:
        report = json.loads(args.report.read_text())
    except json.JSONDecodeError as e:
        print(f"::error::perf report at {args.report} is not valid JSON: {e}")
        return 1

    p99_ms = _extract_p99_ms(report)
    if p99_ms is None:
        print(
            f"::error::no '{TARGET_BENCH_NAME}' benchmark in {args.report} — "
            "test was likely skipped (missing python3/cargo)"
        )
        return 1

    # Always print a neutral summary line for log-readability.
    print(f"[grade-perf] {TARGET_BENCH_NAME} p99 = {p99_ms:.3f} ms")

    if p99_ms > HARD_BUDGET_MS:
        print(
            f"::error::policy_authorize p99 = {p99_ms:.2f}ms > "
            f"{HARD_BUDGET_MS:.0f}ms HARD budget — gate failed"
        )
        return 1
    if p99_ms > SOFT_BUDGET_MS:
        print(
            f"::warning::policy_authorize p99 = {p99_ms:.2f}ms > "
            f"{SOFT_BUDGET_MS:.0f}ms SOFT budget — investigate latency creep"
        )
        return 0

    print(
        f"[grade-perf] p99 = {p99_ms:.3f}ms <= "
        f"{SOFT_BUDGET_MS:.0f}ms SOFT budget — clean PASS"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
