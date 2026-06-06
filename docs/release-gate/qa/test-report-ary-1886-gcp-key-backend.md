# QA / Adversarial Test Report — ARY-1886 Step-14R (GCP signing-key backend)

- **Session ID:** `ary1886-test-0004e89-gcpkey`
- **Wave ID:** `ary1886-gcp-key-backend`
- **Repo / branch:** `/tmp/usk-work` @ `seth/ary-1886-gcp-key-backend`
- **HEAD (working-tree base):** `0004e89a59159e6042524dc386682038da4d0001` (change is uncommitted)
- **Crate under test:** `qorch-safety-kernel`
- **Timestamp (UTC):** 2026-06-06T21:31:13Z
- **Toolchain:** rustc 1.96.0 / cargo 1.96.0
- **Gate:** `/test` ceremony, Rules 8 / 9 / 10. Evidence re-derived in-process; no label matching.
- **Verdict:** **PASS** (all 6 checks green; the byte-equality oracle proven non-vacuous via adversarial probe)

This is a safety/provenance surface (Safety Kernel Ed25519 signing-key
resolution). Every PASS below is re-derived, not regex-matched.

---

## Scope of change (re-read in this session)

| File | Kind | Role |
|------|------|------|
| `src/key_backend.rs` | NEW | `KeyBackendKind` enum {Env,Gcp,Aws,Azure,Pkcs11,Tpm}; `resolve_signing_key_b64`; GCP Secret Manager fetch via metadata-server ADC |
| `src/settings.rs` | MOD | +4 fields (`key_backend`, `key_gcp_project`, `key_gcp_secret`, `key_gcp_secret_version`); `KERNEL_KEY_BACKEND` parse; env-backend-forbidden-in-prod guard; conditional seed-env requirement |
| `src/main.rs` | MOD | resolves seed via backend after tokio runtime is up |
| `src/bin/keygen.rs` | NEW | `safety-kernel-keygen` Ed25519 seed generator (seed→stdout, pubkey+fp→stderr) |
| `src/lib.rs`, `Cargo.toml` | MOD | export `key_backend` module; declare keygen bin; add `rand_core` dep |
| `tests/gcp_key_backend_live.rs` | NEW | `#[ignore]` live GCP test (byte-equality + fingerprint re-derivation) |
| `tests/key_backend_prod_guard.rs` | NEW | Rule-8 adversarial config-gate fixtures (prod guard + fail-closed) |
| `docs/deployment/key-management.md` | NEW | operator documentation |
| 7 pre-existing test files | MOD | `Settings{...}` literals patched with the 4 new fields |

---

## Check results

### Check 1 — `cargo build -p qorch-safety-kernel --bins` → **PASS**

Both binaries (`qorch-safety-kernel`, `safety-kernel-keygen`) compiled.
`Finished dev profile ... in 14.41s`. The only warning is a pre-existing
`#[cfg(kani)]` lint in `crates/domain` — out of scope for this change.

### Check 2 — `cargo test -p qorch-safety-kernel` (full crate suite) → **PASS**

Zero failures across every test binary. Aggregate per-binary results:

| Binary | passed | failed | ignored |
|--------|-------:|-------:|--------:|
| lib (incl. `key_backend::tests::*`, `ptzero_probe`) | 24 | 0 | 0 |
| `authorize_transparency_log` (patched) | 5 | 0 | 0 |
| `gcp_key_backend_live` | 0 | 0 | 1 (`#[ignore]`, run separately in Check 4) |
| `key_backend_prod_guard` (new) | 1 | 0 | 0 |
| `policy_forged_event_fingerprint` (patched) | 5 | 0 | 0 |
| `policy_routes_auth` (patched) | 4 | 0 | 0 |
| `policy_routes_charset` (patched) | 11 | 0 | 0 |
| `policy_routes_scaffold` (patched) | 6 | 0 | 0 |
| `purple_tlog_malformed_response` (patched) | 3 | 0 | 0 |
| `test_authorize_emits_ledger_leaf` (patched) | 3 | 0 | 0 |
| `policy_signature_forgery` | 8 | 0 | 0 |
| `purple_tlog_wire` | 5 | 0 | 0 |
| `seed_af_image` | 3 | 0 | 0 |
| `test_transparency_http_wiremock` | 16 | 0 | 0 |
| `tls_smoke` | 1 | 0 | 0 |
| sidecar-dependent suites (pre-existing) | 0 | 0 | 12 (require `policy_sidecar.py`, not shipped in public extraction) |

All 7 patched pre-existing `Settings{...}`-literal files still pass — no
regression from the 4-field struct addition.

### Check 3 — Rule 8 adversarial fixtures REJECT (oracle verified by reading the test body) → **PASS**

`tests/key_backend_prod_guard.rs::key_backend_config_gates` ran green and
its assertions are genuine rejections, not pass-by-accident:

- (a) `KERNEL_KEY_BACKEND=env` + `QORCH_ENV=prod`: `Settings::from_env()`
  → `expect_err`, and the error string is asserted to contain BOTH
  `"KERNEL_KEY_BACKEND=env is forbidden"` AND `"prod"`. Verified against
  `settings.rs:229-237`.
- (b) `aws` / `azure` / `pkcs11` / `tpm` (loop): each → `expect_err` whose
  message contains `"not implemented"`. The fixture deliberately ALSO sets
  `QORCH_KERNEL_SIGNING_KEY_B64` to prove there is **no** silent fallback
  to the env var. Verified against `settings.rs:262-268`.
- (c) unknown name `"vault"` → `Settings::from_env().is_err()` (hard parse
  error). Verified against `key_backend.rs:77-80`.
- Positive controls included: `env` in staging is allowed and populates
  `signing_key_b64`; `gcp` with project+secret is accepted with
  `signing_key_b64` left empty and version defaulted to `latest`. This
  proves the gate is discriminating, not blanket-rejecting.

### Check 4 — Rule 9 live GCP re-derivation → **PASS**

```
KERNEL_KEY_GCP_PROJECT=utopian-spring-473613-r7 \
KERNEL_KEY_GCP_SECRET=safety-kernel-signing-key-test \
GCP_KEY_TEST_EXPECT_SEED_B64="$(cat /tmp/sk_test_seed.txt)" \
  cargo test -p qorch-safety-kernel --test gcp_key_backend_live -- --ignored --nocapture
→ test gcp_backend_fetches_exact_stored_seed ... ok  (1 passed; 0 failed)
```

The test (`gcp_key_backend_live.rs`) makes a real Secret Manager `:access`
call through `resolve_signing_key_b64`, then asserts TWO independent
oracles: (1) the fetched seed byte-equals the operator-stored seed
(`assert_eq!(fetched.trim(), expect_seed_b64.trim())`), and (2) the
SHA-256 fingerprint of the Ed25519 verifying key derived from the fetched
seed equals the fingerprint derived from the expected seed. Both are
recomputed in-process; neither matches a status label. The stored test
seed decodes to exactly 32 bytes.

### Check 5 — `cargo clippy -p qorch-safety-kernel --bins --tests` (new files) → **PASS**

The four new files (`src/key_backend.rs`, `src/bin/keygen.rs`,
`tests/gcp_key_backend_live.rs`, `tests/key_backend_prod_guard.rs`) AND
the two modified source files (`src/settings.rs`, `src/main.rs`) emit
**zero** clippy warnings (grep over clippy output by file path returned no
matches). The 28 total clippy warnings all live in pre-existing files
(`crates/domain/*`, `crates/adapters/*`, and pre-existing test files
`tls_smoke.rs`, `test_transparency_http_wiremock.rs`,
`test_authorize_emits_ledger_leaf.rs`) — explicitly out of scope.

### Check 6 — Adversarial probe: byte-equality oracle is NOT vacuous → **PASS**

Generated a fresh, different seed via the new keygen binary and pointed
the live test's expected-seed at it:

```
fresh wrong seed: An0kcWKB6eYicL0mSwJRLLECC19dy92zeJNqzzN9Xmc
real seed:        0TU36XnJzuNcOm8aXzPDQVXyQl5ukoaFcpGA7sCmuP4
→ panicked at gcp_key_backend_live.rs:70:5:
  assertion `left == right` failed: fetched seed must byte-equal the stored seed
  test gcp_backend_fetches_exact_stored_seed ... FAILED (0 passed; 1 failed)
```

The test correctly FAILS when the expected seed is wrong, proving the
oracle in Check 4 is real (a true byte comparison against the live-fetched
value), not a vacuous assertion that would pass with any key. Re-running
with the real seed (Check 4) passes — no on-disk state was mutated; the
probe used only a per-invocation env var, so nothing required restoration.
The keygen binary also demonstrably produces a valid, distinct 32-byte
Ed25519 seed.

---

## Rule compliance summary

- **Rule 5 (oracle mandatory):** every check has an explicit oracle —
  build success, zero test failures, error-string content, live
  byte-equality + fingerprint, clippy file attribution, and a deliberate
  failing-fixture probe.
- **Rule 8 (adversarial fixtures the gate rejects):** present and verified
  in `key_backend_prod_guard.rs` (prod env-guard, fail-closed unimplemented
  backends with no env fallback, unknown-name parse error).
- **Rule 9 (evidence over labels):** the live GCP test re-derives the seed
  bytes and the Ed25519 public-key fingerprint in-process; Check 6 proves
  the comparison is non-vacuous.
- **Rule 10 (session-bound enforcement):** this report carries the
  Adversarial-Suite trailer below, backed by a `verdict: PASS` record in
  `.claude/state/adversarial_runs.jsonl` for this session id.

## BLOCKING findings

None. No Rule 9 violations, no false-negatives.

---

Adversarial-Suite: ary1886-test-0004e89-gcpkey PASS
