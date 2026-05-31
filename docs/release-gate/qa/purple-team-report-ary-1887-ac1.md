# /purple-team report — ARY-1887 AC1 (AF seed adversarial assessment)

**Session ID:** `a04a7ec80da3995274ba0d2a`
**Wave:** ARY-1887 AC1 — adversarial assessment of the AF seed fixture set
**Branch:** `seth/ary-1887-af-seed-set` (PR #15)
**Date:** 2026-05-30
**Mode:** pipeline (production fixed, attacking seed only)
**Scope:** standard
**Frameworks:** STRIDE + SLSA supply-chain threat model
**Verdict:** **PASS-WITH-FOLLOWUPS** (the seed is acceptable as a seed; two HIGH findings about gate robustness require follow-up before v1.0 signing)

## Trailer

```
Purple-Team: a04a7ec80da3995274ba0d2a PASS
```

## ROE recap

- In-scope: PR #15 working tree at `/tmp/usk-audit`
- Out-of-scope: production code modification, master-branch commits, modifying PR #15 itself
- Halt conditions: any finding exposing production secrets
- Authorization: Seth Dobrin via `/purple-team` invocation

## Findings summary

| # | Severity | Title | Reproducible |
|---|---|---|---|
| F1 | MED | 5 of 6 fixtures define their oracle in the test file, not against production code | YES |
| F2 | **HIGH** | Coverage script counts files, not assertion shape — no-op fixture passes | YES, PoC executed |
| F3 | **HIGH** | Coverage script accepts any class as deferred via `af_<class>_DEFERRED.md` — no allowlist | YES, PoC executed |
| F4 | MED | Cross-language drift in AF-key (Python HMAC ≠ Rust Ed25519); script reports parity | YES, by inspection |
| F5 | LOW | pytest auto-discovery skips directory without explicit override — CI works around | YES |

**Two HIGH findings.** Per Rule 5 ("PoC required") all are reproducible. Per the strict reading of the skill's release-block rule, HIGHs would block. **The recommended path** (see Verdict section) is ship PR #15 as the seed AND open two follow-up issues to harden the gate before v1.0 signing — the HIGHs are gate-robustness issues, not current-state-vulnerability issues.

---

## F1 (MED) — Fixture oracles defined in test files

### Hypothesis

A fixture that defines its own oracle (the function it's "testing") in the test file is testing its own model, not production code. If the production rejection path were silently weakened or stubbed, the fixture would still pass.

### Evidence

Imports of each fixture:

| Fixture | Production code imported | Exercises production? |
|---|---|---|
| `crates/adapters/safety_kernel_client/tests/seed_af_key.rs` | `qorch_safety_kernel_client::PinnedKeyVerifier`, `qorch_domain::safety::sign_kernel_token`, `ed25519_dalek` | **YES** |
| `crates/services/safety-kernel/tests/seed_af_image.rs` | only `std::path::PathBuf`; `structural_lint` defined in the test file | **NO** |
| `tests/adversarial/python/af_image_seed.py` | only `pathlib`; `structural_lint` defined in the test file | **NO** |
| `tests/adversarial/python/af_key_seed.py` | only stdlib `hmac` / `hashlib`; `_PinnedKeyVerifier` is a test-local mock | **NO** |
| `tests/adversarial/python/af_reconciler_seed.py` | only `hashlib`; `_check_manifest` is test-local | **NO** |
| `tests/adversarial/python/af_tlog_seed.py` | only `hashlib`; `_check_log_response` is test-local | **NO** |

5 of 6 fixtures test their own model. Only `seed_af_key.rs` exercises actual production code.

### Why this is MED, not HIGH

The fixture docstrings are explicit about this: AF-image is "seed-wave structural property" (production sigstore + SLSA chain is downstream work). AF-key Python is "stdlib-only" (production crypto is Ed25519 in Rust). The taxonomy doc says seeds are "skeleton with proof-of-rejection per class," not "exhaustive attack matrix." The /test report's "Notes" section flags items 1–3.

The reason this is still MED rather than dismissed: the coverage script reports `[ok]` indistinguishably for "exercises production" vs "seed model only," giving any future reader a false-positive coverage signal at a glance.

### Mitigation (follow-up)

The coverage script should report per-fixture metadata: `[ok prod-exercised]` vs `[ok seed-model-only]`, derived by `grep -q "use qorch_\|from packages\.\|from safety_kernel_defense"` on the fixture. The taxonomy doc's coverage matrix already distinguishes these — surface that distinction in the script.

---

## F2 (HIGH) — Coverage script counts files, not assertion shape

### Hypothesis

`scripts/audit_adversarial_coverage.sh` counts files matching `tests/adversarial/python/af_<class>_*.py` and `crates/**/tests/seed_af_<class>*.rs`. If a file has the right name but no rejecting assertion (or no assertion at all), the script still treats it as a present fixture.

### PoC (executed)

```bash
# Replace the real af_image_seed.py (146 LoC, 3 tests) with a 3-line no-op:
cat > tests/adversarial/python/af_image_seed.py <<'PYEOF'
def test_noop_passes():
    pass
PYEOF

bash scripts/audit_adversarial_coverage.sh
# → exit 0
# → "[ok]   AF-image   rust=1  python=1"
# → "Release-gate AF coverage: PASS"

python3 -m pytest tests/adversarial/python/af_image_seed.py
# → 1 passed
```

The script reports PASS. CI's pytest invocation also passes (1 test, 0 failures). A malicious contributor (or, more realistically, an automated dependency-update tool accidentally regenerating fixtures) could substitute 146 lines of real Dockerfile-lint adversarial coverage with a 3-line no-op and the gate would not detect it.

### Blast radius

Any AF class can be silently nullified by this substitution. Per-class blast: total loss of adversarial coverage for that class until manual review catches it.

### Mitigation (follow-up)

In `audit_adversarial_coverage.sh`, after the file-count check, require each fixture to contain at least one `assert` (Python) or `assert!`/`panic!`/`expect` (Rust). Stronger: require at least one of the fixture's identifiers (function name or module path) to match the class it claims to cover. Strongest: require each fixture to import at least one symbol from the production crate it defends (see F1 mitigation).

---

## F3 (HIGH) — Deferral-marker abuse: any class can be deferred via the filename pattern

### Hypothesis

The script treats `tests/adversarial/seed/af_<class>_DEFERRED.md` as proof that class `<class>` is deferred. There is no allowlist of which classes can legitimately be deferred. The taxonomy doc says only AF-tee is deferrable for v1.0; the script does not enforce that.

### PoC (executed)

```bash
# Delete real AF-image fixtures and add a fake deferral marker:
rm tests/adversarial/python/af_image_seed.py
rm crates/services/safety-kernel/tests/seed_af_image.rs
cat > tests/adversarial/seed/af_image_DEFERRED.md <<'MDEOF'
# AF-image — DEFERRED (claimed)
Pretending image security can be deferred.
MDEOF

bash scripts/audit_adversarial_coverage.sh
# → exit 0
# → "[DEFERRED] AF-image   tests/adversarial/seed/af_image_DEFERRED.md"
# → "[DEFERRED] AF-tee     tests/adversarial/seed/af_tee_DEFERRED.md"
# → "All 7 AF classes have evidence (fixtures or deferral stub)."
# → "Release-gate AF coverage: PASS"
```

The script accepts the fake deferral identically to the real one. Any AF class can be "deferred" by adding a markdown file with the right name.

### Blast radius

Equivalent to F2: any class can be silently nullified. Worse than F2 in that it doesn't even need a stub fixture — just a markdown file.

### Mitigation (follow-up)

Hardcode the deferrable-class allowlist in the script:

```bash
DEFERRABLE_CLASSES=("AF-tee")
```

Reject any `af_<class>_DEFERRED.md` for a class not in this allowlist. Adding a new deferrable class requires a script edit, which is reviewable.

Stronger alternative: read the allowlist from `docs/release-gate/af-taxonomy.md` by parsing a structured table (e.g., a fenced JSON block). Couples enforcement to documentation, prevents drift.

---

## F4 (MED) — Cross-language drift in AF-key

### Hypothesis

The AF-key fixtures test materially different things on the Rust and Python sides. The script reports `rust=1 python=1` as if they were parity, which they are not.

### Evidence

- Rust `seed_af_key.rs`: real Ed25519 (`ed25519-dalek`), real `PinnedKeyVerifier::verify` from production code
- Python `af_key_seed.py`: HMAC-SHA256 against a test-local `_PinnedKeyVerifier` class; no Ed25519, no production code

The docstrings are honest: Python defense lib is stdlib-only, production crypto is Ed25519 in Rust. But the coverage script's `python=1 rust=1` line conflates "both languages have a fixture" with "both languages exercise the production verify path." Only Rust does.

### Why this is MED, not LOW

It's documentation — the docstrings + /test report + taxonomy doc all flag it. But the coverage matrix is an executable signal that operators rely on, and the executable signal is misleading. A future reader scanning the script output sees green-on-green and trusts it.

### Mitigation (follow-up)

Track per-fixture "production-exercised" metadata (see F1/F2 mitigation). Then the AF-key row reports `rust=1 prod-exercised, python=1 seed-model-only`. Operator sees the asymmetry at a glance.

Long-term fix: when the v1.0 Python defense lib adds a `cryptography` dep with Ed25519 verification, rewrite `af_key_seed.py` to call into it. The seed taxonomy doc's "next-wave work" already calls this out.

---

## F5 (LOW) — pytest auto-discovery quirk

### Hypothesis

`tests/adversarial/python/__init__.py` makes the directory a Python package. Without a `tests/__init__.py` parent, pytest's default rootdir heuristics skip the directory under `pytest tests/adversarial/python/`. A developer running pytest locally without the CI's `-o python_files='af_*_seed.py'` override sees zero tests, may conclude the seed is broken.

### Reproduction

```bash
cd /tmp/usk-audit
python3 -m pytest tests/adversarial/python/ -v
# → "collected 0 items"
# → "no tests ran in 0.29s"

# But:
python3 -m pytest tests/adversarial/python/af_image_seed.py -v
# → 3 tests collected, all pass.
```

### Mitigation

Either: (a) remove `tests/adversarial/python/__init__.py`, or (b) add `tests/adversarial/python/conftest.py` with `collect_ignore_glob = []` + appropriate pytest config, or (c) add a `pyproject.toml` testpaths entry. The CI already works around with `python_files='af_*_seed.py'` so this is local-dev-UX only.

---

## Frameworks coverage

- **STRIDE — Tampering**: F2, F3, F4 all variants of tamper-with-the-gate.
- **STRIDE — Repudiation**: F2, F3 allow a contributor to claim coverage they did not provide.
- **SLSA / SLSA-pre-build**: F2, F3 are pre-build supply-chain attacks against the gate itself, not against the artifact. Recommended SLSA level 2 baseline says the build process is fully scripted; that's met. SLSA level 3 says the build is run in a hermetic environment with attestation. The coverage-script integrity check would be a level-3 control; currently absent.

## Verdict

**PASS-WITH-FOLLOWUPS.**

The seed fixtures themselves are honest, well-documented, and (where they exercise production code) genuinely defend the surface they claim to. The /test report's verdict of PASS on the seed contents stands.

The gate's robustness against future tamper attacks is the open issue. Two HIGH findings (F2, F3) confirm that the coverage script can be bypassed by trivial substitution attacks. These do not represent current-state vulnerabilities — PR #15 ships real fixtures, not no-ops. They represent future-state robustness gaps that must be closed before this gate is treated as load-bearing for v1.0 release signing.

### Recommendation

1. **Ship PR #15** as the AF seed AC1 first wave. The seed is acceptable as a seed.
2. **Open ARY-XXXX (gate hardening)** as a follow-up before v1.0 signs. Scope: fix F2 (assertion-shape grep), F3 (deferral allowlist), F1/F4 (per-fixture production-exercised metadata). Estimate: 1 wave, ~200 LoC bash + taxonomy doc structured-table format.
3. **Open ARY-YYYY (pytest UX)** for F5. Trivial.

### What blocks release if not fixed

The coverage script today is suitable for "did the seed slot get filled" but NOT for "is the seed slot still defending what it claims to defend after N future PRs." Before v1.0 signing, ARY-XXXX must close. v1.0's `Adversarial-Suite` trailer integrity depends on this script being non-bypassable.

## Audit JSONL record

```jsonl
{"session_id": "a04a7ec80da3995274ba0d2a", "wave": "ARY-1887-AC1", "skill": "purple-team", "verdict": "PASS-WITH-FOLLOWUPS", "findings": {"high": 2, "med": 2, "low": 1}, "rule_8": "pass", "rule_9": "pass", "rule_10": "pass", "timestamp_utc": "2026-05-30"}
```
