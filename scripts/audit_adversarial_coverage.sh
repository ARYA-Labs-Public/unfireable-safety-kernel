#!/usr/bin/env bash
# audit_adversarial_coverage.sh — enforce the ARY-1887 AF taxonomy.
#
# For each of the 7 canonical AF classes (see
# docs/release-gate/af-taxonomy.md), this script verifies that at least
# one Rust fixture AND at least one Python fixture exists, OR an
# explicit deferral stub is present (only classes in DEFERRABLE_CLASSES
# qualify — AF-tee in v1.0).
#
# A fixture only COUNTS if it actually asserts something. A file with
# the right name but no assertion (e.g. `def test_noop(): pass`) is NOT
# counted — this closes the ARY-2361 F2 gate-bypass (a no-op fixture
# masquerading as coverage). See docs/release-gate/qa/
# purple-team-report-ary-1887-ac1.md.
#
# Exit codes:
#   0  All 7 classes have asserting evidence (fixtures or allowed deferral)
#   1  At least one class is missing required coverage
#   2  Usage error / script ran in the wrong directory / forbidden deferral
#
# Run from repo root:
#   bash scripts/audit_adversarial_coverage.sh
#
# Testing override: set AF_COVERAGE_ROOT to point the scan at a sandbox
# tree (used by tests/adversarial/test_coverage_gate.sh).
#
# Wire into CI as a separate job; depends only on bash + find + grep.

set -euo pipefail

# The 7 canonical AF class identifiers, in the order they appear in
# docs/release-gate/af-taxonomy.md. The script enforces evidence for
# EACH of these — adding a new class requires updating both this list
# AND the taxonomy doc.
AF_CLASSES=(
  AF-contracts
  AF-sdk
  AF-image
  AF-reconciler
  AF-tlog
  AF-tee
  AF-key
)

# ARY-2361 F3 fix: only these classes may be satisfied by a deferral
# stub. A deferral marker for any class NOT in this allowlist is a hard
# error (exit 2), not a silent pass. Adding a class here requires a
# reviewed script edit AND a matching entry in af-taxonomy.md.
DEFERRABLE_CLASSES=(
  AF-tee
)

# Repo root: env override (for hermetic testing) or the directory
# containing this script's parent (scripts/).
if [ -n "${AF_COVERAGE_ROOT:-}" ]; then
  REPO_ROOT="${AF_COVERAGE_ROOT}"
else
  REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi
if [ ! -f "${REPO_ROOT}/Cargo.toml" ]; then
  echo "error: ${REPO_ROOT}/Cargo.toml not found." >&2
  echo "       This script must run from a checkout of unfireable-safety-kernel" >&2
  echo "       (or set AF_COVERAGE_ROOT to a sandbox tree containing Cargo.toml)." >&2
  exit 2
fi
cd "${REPO_ROOT}"

# ----------------------------------------------------------------------
# Discovery rules.
#
# For a given AF class (e.g. AF-image), we look for:
#
#   Rust fixtures:
#     - Files matching tests/adversarial/seed/${class_underscored}_*.rs
#     - Files matching crates/*/tests/seed_${class_underscored}*.rs
#     - Pre-existing Rust files documented in af-taxonomy.md (EXISTING_RUST).
#
#   Python fixtures:
#     - Files matching tests/adversarial/python/${class_underscored}_*.py
#     - Files matching tests/adversarial/seed/${class_underscored}_*.py
#     - Pre-existing Python files documented in af-taxonomy.md (EXISTING_PY).
#
#   Deferral stub:
#     - A file at tests/adversarial/seed/${class_underscored}_DEFERRED.md
#       satisfies the class ONLY IF the class is in DEFERRABLE_CLASSES.
#
# A discovered fixture only counts if fixture_has_assertion() is true.
#
# All translations from "AF-image" to "af_image" use s/-/_/g + lowercase.
# ----------------------------------------------------------------------

# Pre-existing files that count as Rust coverage for each class.
# This list comes from docs/release-gate/af-taxonomy.md's coverage matrix.
declare -A EXISTING_RUST=(
  [AF-contracts]="crates/services/transparency-log/tests/purple_idempotency_collision.rs"
  [AF-sdk]="crates/adapters/safety_kernel_client/tests/adversarial.rs"
  [AF-reconciler]="crates/services/safety-kernel-reconciler/tests/purple_manifest_replay.rs"
  [AF-tlog]="crates/services/transparency-log/tests/purple_forged_sth.rs"
)

declare -A EXISTING_PY=(
  [AF-contracts]="examples/testing/adversarial_fixtures.py"
  [AF-sdk]="examples/testing/adversarial_fixtures.py"
)

# ARY-2361 F2 fix: a file counts as a fixture only if it actually
# asserts. Returns 0 (true) if the file contains at least one assertion
# statement appropriate to its language.
#
#   Python: an indented `assert` or `raise` statement (not a docstring
#           mention like "What this seed asserts").
#   Rust:   an assert!/assert_eq!/assert_ne!/panic! macro invocation.
fixture_has_assertion() {
  local file="$1"
  [ -f "${file}" ] || return 1
  case "${file}" in
    *.py)
      grep -qE '^[[:space:]]*(assert[[:space:](]|raise[[:space:]])' "${file}"
      ;;
    *.rs)
      grep -qE 'assert(_eq|_ne)?!|panic!' "${file}"
      ;;
    *)
      return 1
      ;;
  esac
}

# ARY-2361 F1/F4 fix: a fixture is "prod-exercised" if it imports a
# production symbol, vs "seed-model-only" if it defines its own oracle
# in the test file. Returns 0 (true) if prod-exercised.
#
#   Python: imports from `packages.` or `safety_kernel_defense`.
#   Rust:   `use qorch_...` (any production crate).
fixture_is_prod_exercised() {
  local file="$1"
  [ -f "${file}" ] || return 1
  case "${file}" in
    *.py)
      grep -qE '^[[:space:]]*(from|import)[[:space:]]+(packages[. ]|safety_kernel_defense)' "${file}"
      ;;
    *.rs)
      grep -qE '^[[:space:]]*use[[:space:]]+qorch_' "${file}"
      ;;
    *)
      return 1
      ;;
  esac
}

# Find matching files. Empty result is a missed class.
find_seed() {
  local pattern="$1"
  # shellcheck disable=SC2086
  find tests/adversarial crates -type f -name "${pattern}" 2>/dev/null || true
}

# Is the given class allowed to be deferred?
is_deferrable() {
  local class="$1"
  local d
  for d in "${DEFERRABLE_CLASSES[@]}"; do
    [ "${d}" = "${class}" ] && return 0
  done
  return 1
}

# Accumulate the set of asserting fixtures from a newline-delimited
# candidate list into two globals: COUNTED (count of asserting files)
# and PROD_EXERCISED (count of those that exercise production code).
# Files without an assertion are dropped and reported on stderr-style
# inline note via the SKIPPED global.
collect_fixtures() {
  COUNTED=0
  PROD_EXERCISED=0
  SKIPPED=""
  local candidates="$1"
  local f
  # De-dup while preserving the asserting-only filter.
  local seen=""
  while IFS= read -r f; do
    [ -z "${f}" ] && continue
    case "${seen}" in
      *"|${f}|"*) continue ;;
    esac
    seen="${seen}|${f}|"
    if fixture_has_assertion "${f}"; then
      COUNTED=$((COUNTED + 1))
      if fixture_is_prod_exercised "${f}"; then
        PROD_EXERCISED=$((PROD_EXERCISED + 1))
      fi
    else
      SKIPPED="${SKIPPED} ${f}"
    fi
  done <<< "${candidates}"
}

# ----------------------------------------------------------------------
# Main loop.
# ----------------------------------------------------------------------
status=0
echo "audit_adversarial_coverage.sh — release-gate AF taxonomy enforcement"
echo "------------------------------------------------------------------"
echo "repo root: ${REPO_ROOT}"
echo ""

for class in "${AF_CLASSES[@]}"; do
  # Normalize "AF-image" → "af_image".
  underscored="$(echo "${class//-/_}" | tr '[:upper:]' '[:lower:]')"

  # Deferral stub: honored ONLY for classes in DEFERRABLE_CLASSES.
  deferral="tests/adversarial/seed/${underscored}_DEFERRED.md"
  if [ -f "${deferral}" ]; then
    if is_deferrable "${class}"; then
      printf '  [DEFERRED] %-16s  %s\n' "${class}" "${deferral}"
      continue
    else
      # ARY-2361 F3: a deferral marker for a non-deferrable class is an
      # attack signal, not a pass. Hard-fail.
      printf '  [FORBIDDEN] %-15s  %s\n' "${class}" "${deferral}"
      echo "             ${class} is NOT in DEFERRABLE_CLASSES; a deferral marker here"
      echo "             cannot satisfy the release gate. Remove the marker and add a"
      echo "             real fixture, or add ${class} to DEFERRABLE_CLASSES in a"
      echo "             reviewed edit to this script + af-taxonomy.md."
      status=2
      continue
    fi
  fi

  # Rust candidates.
  rust_candidates=""
  rust_existing="${EXISTING_RUST[${class}]:-}"
  [ -n "${rust_existing}" ] && rust_candidates="${rust_candidates}${rust_existing}"$'\n'
  rust_candidates="${rust_candidates}$(find_seed "${underscored}_*.rs")"$'\n'
  rust_candidates="${rust_candidates}$(find_seed "seed_${underscored}*.rs")"$'\n'

  collect_fixtures "${rust_candidates}"
  rust_count=${COUNTED}
  rust_prod=${PROD_EXERCISED}
  rust_skipped="${SKIPPED}"

  # Python candidates.
  py_candidates=""
  py_existing="${EXISTING_PY[${class}]:-}"
  [ -n "${py_existing}" ] && py_candidates="${py_candidates}${py_existing}"$'\n'
  py_candidates="${py_candidates}$(find_seed "${underscored}_*.py")"$'\n'

  collect_fixtures "${py_candidates}"
  py_count=${COUNTED}
  py_prod=${PROD_EXERCISED}
  py_skipped="${SKIPPED}"

  if [ "${rust_count}" -eq 0 ] || [ "${py_count}" -eq 0 ]; then
    printf '  [MISSING]  %-16s  rust=%d  python=%d\n' \
      "${class}" "${rust_count}" "${py_count}"
    if [ "${rust_count}" -eq 0 ]; then
      echo "             needs: an asserting Rust fixture at tests/adversarial/seed/${underscored}_*.rs"
      echo "                    OR crates/<crate>/tests/seed_${underscored}*.rs"
      [ -n "${rust_skipped}" ] && echo "             note: found but NOT counted (no assertion):${rust_skipped}"
    fi
    if [ "${py_count}" -eq 0 ]; then
      echo "             needs: an asserting Python fixture at tests/adversarial/python/${underscored}_*.py"
      [ -n "${py_skipped}" ] && echo "             note: found but NOT counted (no assertion):${py_skipped}"
    fi
    status=1
  else
    # ARY-2361 F1/F4: surface prod-exercised vs seed-model-only so a
    # reader is not misled into thinking a seed-model fixture exercises
    # production code.
    rust_tag="seed-model"; [ "${rust_prod}" -gt 0 ] && rust_tag="prod-exercised"
    py_tag="seed-model";   [ "${py_prod}" -gt 0 ]   && py_tag="prod-exercised"
    printf '  [ok]       %-16s  rust=%d (%s)  python=%d (%s)\n' \
      "${class}" "${rust_count}" "${rust_tag}" "${py_count}" "${py_tag}"
  fi
done

echo ""
if [ "${status}" -eq 0 ]; then
  echo "All 7 AF classes have asserting evidence (fixtures or allowed deferral)."
  echo "Release-gate AF coverage: PASS"
elif [ "${status}" -eq 2 ]; then
  echo "Release-gate AF coverage: FAIL — forbidden deferral marker (see [FORBIDDEN] above)."
  echo "See docs/release-gate/af-taxonomy.md for the canonical class definitions."
else
  echo "Release-gate AF coverage: FAIL — see [MISSING] entries above."
  echo "See docs/release-gate/af-taxonomy.md for the canonical class definitions."
fi
exit "${status}"
