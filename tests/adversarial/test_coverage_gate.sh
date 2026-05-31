#!/usr/bin/env bash
# test_coverage_gate.sh — negative-gate tests for
# scripts/audit_adversarial_coverage.sh (ARY-2361 AC4).
#
# Each test mutates the working tree to simulate a gate-bypass attack
# surfaced by the /purple-team assessment (docs/release-gate/qa/
# purple-team-report-ary-1887-ac1.md), then asserts the coverage script
# REJECTS the mutation. A trap restores every touched file from a
# backup, so the tree is left exactly as found even on early exit.
#
# This is the Rule 8 adversarial fixture FOR THE GATE ITSELF: the gate
# must reject the synthetic-fake "coverage" that an attacker (or an
# automated tool regenerating fixtures) might substitute.
#
# Exit 0 = all attacks correctly rejected; exit 1 = a gate-bypass slipped
# through (the script is broken and must NOT ship).
#
# Run from repo root:
#   bash tests/adversarial/test_coverage_gate.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${REPO_ROOT}"
SCRIPT="scripts/audit_adversarial_coverage.sh"

# Files this test mutates, with backup locations.
PY_IMG="tests/adversarial/python/af_image_seed.py"
RS_IMG="crates/services/safety-kernel/tests/seed_af_image.rs"
DEFER_IMG="tests/adversarial/seed/af_image_DEFERRED.md"
BACKUP_DIR="$(mktemp -d)"

restore() {
  [ -f "${BACKUP_DIR}/af_image_seed.py" ] && cp "${BACKUP_DIR}/af_image_seed.py" "${PY_IMG}"
  [ -f "${BACKUP_DIR}/seed_af_image.rs" ] && cp "${BACKUP_DIR}/seed_af_image.rs" "${RS_IMG}"
  rm -f "${DEFER_IMG}"
  rm -rf "${BACKUP_DIR}"
}
trap restore EXIT

# Back up the files we will mutate.
cp "${PY_IMG}" "${BACKUP_DIR}/af_image_seed.py"
cp "${RS_IMG}" "${BACKUP_DIR}/seed_af_image.rs"

fail=0
pass() { echo "  ok   $1"; }
bad()  { echo "  FAIL $1"; fail=1; }

echo "test_coverage_gate.sh — negative-gate tests for the AF coverage script"
echo "----------------------------------------------------------------------"

# ---- Baseline: clean tree must PASS (exit 0). ----
if bash "${SCRIPT}" >/dev/null 2>&1; then
  pass "baseline: clean tree exits 0"
else
  bad "baseline: clean tree should exit 0 but did not"
fi

# ---- F2: no-op fixture substitution must be REJECTED. ----
printf 'def test_noop():\n    pass\n' > "${PY_IMG}"
if bash "${SCRIPT}" >/dev/null 2>&1; then
  bad "F2: no-op fixture substitution was NOT rejected (script exited 0)"
else
  pass "F2: no-op fixture substitution rejected"
fi
cp "${BACKUP_DIR}/af_image_seed.py" "${PY_IMG}"

# ---- F3: fake deferral marker for a non-deferrable class must be REJECTED. ----
rm -f "${PY_IMG}" "${RS_IMG}"
printf '# fake deferral — AF-image cannot be deferred\n' > "${DEFER_IMG}"
if bash "${SCRIPT}" >/dev/null 2>&1; then
  bad "F3: fake AF-image deferral marker was NOT rejected (script exited 0)"
else
  pass "F3: forbidden deferral marker rejected"
fi
rm -f "${DEFER_IMG}"
cp "${BACKUP_DIR}/af_image_seed.py" "${PY_IMG}"
cp "${BACKUP_DIR}/seed_af_image.rs" "${RS_IMG}"

# ---- Post-restore: clean tree must PASS again. ----
if bash "${SCRIPT}" >/dev/null 2>&1; then
  pass "post-restore: clean tree exits 0"
else
  bad "post-restore: clean tree should exit 0 but did not"
fi

echo "----------------------------------------------------------------------"
if [ "${fail}" -eq 0 ]; then
  echo "All gate-bypass attacks correctly rejected. PASS"
else
  echo "A gate-bypass attack slipped through. FAIL — coverage script must NOT ship."
fi
exit "${fail}"
