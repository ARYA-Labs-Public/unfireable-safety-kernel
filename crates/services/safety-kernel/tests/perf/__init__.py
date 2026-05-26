""" slice 5 perf harness package.

Pytest collects this subtree only when invoked with ``-m perf`` (the
marker is registered in ``pyproject.toml``). The harness spawns the
real ``qorch-safety-kernel`` binary + the ``policy_sidecar.py``
process in mock mode and drives ``POST /policy/module/authorize`` via
HTTP — measuring end-to-end p99 latency the way the Python audit hook
would pay it on a per-import basis.

See ``docs/safety_kernel/perf_budget.md`` for the SOFT 5ms / HARD 10ms
budget rationale and reproduction steps.
"""
