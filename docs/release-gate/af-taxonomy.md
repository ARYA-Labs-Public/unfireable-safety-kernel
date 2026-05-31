# Adversarial-Fixture (AF) Taxonomy — v1.0 Release Gate

Status: canonical taxonomy for the [ARY-1887](https://linear.app/aryalabs/issue/ARY-1887) release-gate adversarial suite. Authored as the planner/architect output for the AF-seed wave (2026-05-30).

## Why this document exists

The [ARY-1887](https://linear.app/aryalabs/issue/ARY-1887) description names a 7-class AF taxonomy: `AF-contracts`, `AF-sdk`, `AF-image`, `AF-reconciler`, `AF-tlog`, `AF-tee`, `AF-key`. The repo already ships substantial adversarial fixture scaffolding using a different organizing axis — the **ARY-1883 SDK 6-fixture set** plus **per-component purple-team campaign letters** (A1, B1, C1, C2, D1, D2, F1, F2, G1a/b, etc.).

The two organizing axes describe the same defensive surface from different angles. The 7-class AF taxonomy is *what the v1.0 release gate signs*; the per-component campaigns are *what the test code physically asserts*. This document **maps existing campaigns onto the 7-class taxonomy** so the release gate has a single coverage matrix to verify.

After this doc lands, `scripts/audit_adversarial_coverage.sh` mechanically enforces "every AF class has ≥1 Rust fixture and ≥1 Python fixture (or an explicit deferral stub)." Any release commit that fails the script is blocked.

## The 7 AF classes

| Class | What it asserts the gate REJECTS | Source of truth |
|---|---|---|
| **AF-contracts** | Request shape / OpenAPI contract violations — malformed bodies, wrong claim types, extra keys, length-bounded fields exceeded, character-set violations. | `contracts/openapi/safety_kernel.yaml` |
| **AF-sdk** | Client-side fail-closed violations — forged tokens, replayed tokens, expired tokens, wrong-tool tokens, kernel-unreachable not silently approved, malformed kernel responses, transport errors. | `crates/adapters/safety_kernel_client/` |
| **AF-image** | Supply-chain bypass — image-digest pin bypass, untrusted-registry pull, builder-stage attestation forgery, runtime-stage filesystem write attempt against the read-only root. | `Dockerfile.prod`, `deployment/`, OCI registry signatures |
| **AF-reconciler** | Drift-detection bypass — replay of stale signed manifest, registry-MITM (OCI digest mismatch), unsigned manifest accepted, drift not flagged when binary hash differs from manifest. | `crates/services/safety-kernel-reconciler/` |
| **AF-tlog** | Transparency-log integrity violation — forged STH (signed with attacker key), tampered inclusion proof, log entry that doesn't correspond to the kernel's local SHA-256 of its own token bytes, idempotency-key collision, concurrent-append races leaving the chain in an inconsistent state. | `crates/services/transparency-log/`, `crates/adapters/transparency_store/` |
| **AF-tee** | TEE attestation forgery — quote signed by attacker, replayed quote, runtime measurement mismatch. **Deferred to v2.0** per [ARY-1886](https://linear.app/aryalabs/issue/ARY-1886); no TEE in v1.0 commodity-hardware target. Stub fixture documents the deferral. | n/a in v1.0 |
| **AF-key** | Operator-key custody / rotation / revocation violation — key issued before the rotation start time accepted past the overlap window, revoked key accepted, dual-sign overlap window honored. | `crates/services/safety-kernel/src/key_*.rs` + ARY-1886 Step 14R |

## Current coverage matrix

| Class | Rust | Python | Status |
|---|---|---|---|
| AF-contracts | implicit in `safety_kernel_client/tests/adversarial.rs` (`BYPASS_ATTEMPT_DIRECT`), `transparency-log/tests/purple_idempotency_collision.rs` F2 (malformed idempotency-key) | implicit in `examples/testing/adversarial_fixtures.py` (`BYPASS_ATTEMPT_DIRECT`) | ⚠️ partial — covered as side-effect, no contract-only fixture |
| AF-sdk | ✅ `safety_kernel_client/tests/adversarial.rs` (5 ARY-1883 fixtures), `safety_kernel_client/tests/purple/adversarial_campaigns.rs` | ✅ `examples/testing/adversarial_fixtures.py` (6 fixtures) | ✅ STRONG |
| AF-image | ❌ none | ❌ none | ❌ MISSING — Phase 4 just shipped Dockerfile.prod |
| AF-reconciler | ✅ `safety-kernel-reconciler/tests/purple_manifest_replay.rs` (D1 stale-manifest replay, D2 registry-MITM) | ❌ none | ⚠️ partial — Rust-only, no Python counterpart |
| AF-tlog | ✅ `transparency-log/tests/purple_forged_sth.rs` (A1, B1), `purple_idempotency_collision.rs` (F1), `purple_tier2_unfireable.rs` (G1a/b), `purple_wave_session_concurrency.rs`, `safety-kernel/tests/purple_tlog_malformed_response.rs` (C1, C2), `purple_tlog_wire.rs` (C1-wire variants) | ❌ none | ⚠️ partial — Rust-only, no Python counterpart |
| AF-tee | ⛔ deferred to v2.0 | ⛔ deferred to v2.0 | ⛔ DEFERRED (documented) |
| AF-key | partial via `FORGED_ED25519_TOKEN` (signature-verification), `purple_tier2_unfireable.rs` G1a (forged STH-signing key) | partial via `FORGED_ED25519_TOKEN` (Python fixture) | ⚠️ partial — token signing covered, key rotation / revocation / overlap window NOT exercised |

## Gaps to fill (AF-seed scope)

Per the **coverage matrix** above, the AF-seed wave adds:

### Hard gaps (no existing coverage)
1. **AF-image** — both Rust and Python seed fixtures. Build a synthetic-fake image manifest (wrong digest, untrusted registry, tampered Dockerfile) and assert the supply-chain check REJECTS.
2. **AF-key** — both Rust and Python seed fixtures. Build a synthetic-fake key-rotation scenario (key issued past overlap window, revoked key, dual-sign mismatch) and assert the key-custody check REJECTS.

### Soft gaps (Rust exists, Python missing)
3. **AF-reconciler-py** — Python counterpart to `purple_manifest_replay.rs`. Reference middleware should reject a stale manifest payload.
4. **AF-tlog-py** — Python counterpart to the rich Rust tlog campaigns. Reference middleware should reject a forged-STH-flavored response.

### Documented deferral
5. **AF-tee** — stub `tests/adversarial/seed/af_tee_DEFERRED.md` documenting that TEE attestation is v2.0 scope and the script SHOULD treat this class as "deferred" (not "missing").

### Soft gaps (existing coverage is side-effect)
6. **AF-contracts-explicit** — both Rust and Python seed fixtures that fail an OpenAPI contract violation directly, not as a side effect of an attack vector. Lower priority because the surface is already implicitly covered, but cleaner for the release gate's coverage proof.

## Coverage script contract

`scripts/audit_adversarial_coverage.sh` MUST:

1. Define the 7 AF class identifiers as `AF_CLASSES=(AF-contracts AF-sdk AF-image AF-reconciler AF-tlog AF-tee AF-key)`.
2. For each class, count Rust fixtures (files matching `tests/adversarial/seed/${class//-/_}_*.rs` plus `crates/*/tests/seed_${class//-/_}*.rs` paths AND any pre-existing files documented in this taxonomy doc as covering the class).
3. For each class, count Python fixtures (same logic, `tests/adversarial/python/${class//-/_}_*.py`).
4. **A discovered file counts ONLY IF it actually asserts** (ARY-2361 F2 fix). Python: an indented `assert`/`raise` statement. Rust: an `assert!`/`assert_eq!`/`assert_ne!`/`panic!` macro. A file with the right name but no assertion (e.g. `def test_noop(): pass`) is reported as `found but NOT counted (no assertion)` and does NOT satisfy the class. This prevents a no-op fixture from masquerading as coverage.
5. If `count_rust == 0 || count_py == 0` and the class is not satisfied by an allowed deferral: exit 1 with `MISSING: $class`.
6. **Deferral markers are honored ONLY for classes in `DEFERRABLE_CLASSES`** (ARY-2361 F3 fix). In v1.0 that allowlist is exactly `("AF-tee")`. A `tests/adversarial/seed/<class>_DEFERRED.md` for any class NOT in the allowlist is a hard error (exit 2, `FORBIDDEN`), not a silent pass. Adding a class to the allowlist requires a reviewed edit to BOTH the script's `DEFERRABLE_CLASSES` array AND this section.
7. The per-class `[ok]` line reports a **prod-exercised vs seed-model** tag per language (ARY-2361 F1/F4 fix), derived by grepping each fixture for a production-crate import (`use qorch_` in Rust; `from packages.`/`safety_kernel_defense` in Python). This makes the "does this fixture exercise production code, or only its own test-local model?" distinction visible at a glance, so a reader is not misled by a green coverage line.
8. If all 7 classes pass, exit 0.

### Deferrable-class allowlist

| Class | Deferrable in v1.0? | Reason |
|---|:---:|---|
| AF-tee | **Yes** | TEE / TDX / SEV-SNP attestation is out of scope for the v1.0 commodity-hardware target (ARY-1886). The deployment surface AF-tee attacks does not exist in v1.0. |
| all others | No | A deferral marker for any other class is rejected with exit 2. |

### Negative-gate test

`tests/adversarial/test_coverage_gate.sh` is the Rule 8 adversarial fixture **for the gate itself**: it substitutes a no-op fixture (F2) and plants a forbidden deferral marker (F3), and asserts the coverage script REJECTS each. Wired into the `af-coverage` CI job. A regression that re-opens either bypass turns this test red.

Wired into `.github/workflows/ci.yml` as a separate `af-coverage` job (bash + find + grep only; no Rust or Python toolchain needed for the coverage check itself; pytest is installed only for the Python-seed run).

## Out-of-scope (not in this seed wave)

- **Adversarial fixture *content*** beyond seeds. The seed wave proves the taxonomy + coverage script. ARY-1885 / 1886 / 1889 / 1890 populate to **full coverage** per ARY-1887's release-gate timeline. The seed wave is "skeleton with proof-of-rejection per class," not "exhaustive attack matrix."
- **Cross-language byte-identical fixture parity.** The existing Python `adversarial_fixtures.py` claims byte-identical IDs across Rust+Python; this property is preserved for the AC16 6-fixture set but does NOT extend to every AF class. Cross-language **structural** parity (every class has both) is the seed-wave requirement; **byte-identical fixture IDs** is a v1.0-release-gate requirement that ARY-1885/86/89/90 will deliver.
- **Per-environment fixture variants.** The seed fixtures run against in-process mocks. End-to-end deployment-shape fixtures (live docker compose, real PostgreSQL, etc.) are out of scope here — they belong in `examples/testing/` end-to-end suites, not `tests/adversarial/seed/`.

## Acceptance — A1 architect role output

This doc IS the A1 deliverable. The /test wave (A4) verifies:

- Every AF class above has either ≥1 fixture (Rust + Python) OR an explicit deferral stub.
- `scripts/audit_adversarial_coverage.sh` returns 0 on the current tree.
- Deliberately removing a fixture causes the script to return 1.
- Existing adversarial test suites still green (the seed wave does not break the AC16/ARY-1883/transparency-log campaigns).

The /purple-team wave (A5) attacks the seed itself: are the new AF-image and AF-key fixtures actually testing the production code path, or false-positives?

## Post-/purple-team hardening (ARY-2361, ARY-2362)

The A5 /purple-team assessment (`docs/release-gate/qa/purple-team-report-ary-1887-ac1.md`, session `a04a7ec80da3995274ba0d2a`) reproduced two HIGH gate-bypass attacks against the coverage script and three lower findings. All were fixed in the same wave before release:

| Finding | Severity | Fix |
|---|---|---|
| F2 — script counts files, not assertion shape | HIGH | Coverage script now requires each fixture to contain an assertion (contract item 4 above) + `test_coverage_gate.sh` negative-gate test. |
| F3 — deferral marker has no allowlist | HIGH | `DEFERRABLE_CLASSES` allowlist (contract item 6 above); forbidden markers hard-fail with exit 2. |
| F1/F4 — no prod-exercised metadata | MED | Per-language `prod-exercised`/`seed-model` tag in the `[ok]` line (contract item 7 above). |
| F5 — pytest auto-discovery skipped the dir | LOW | Removed `tests/adversarial/python/__init__.py` + added repo-root `pytest.ini` with `python_files` including `af_*_seed.py`. `pytest tests/adversarial/python/` now collects all 12 with no flags. |

The "seed-model vs prod-exercised" distinction the script now surfaces matches this doc's coverage matrix: AF-image is seed-model on both languages (structural-lint only; full sigstore + SLSA attestation is downstream), AF-key is prod-exercised on the Rust side (real `PinnedKeyVerifier` + Ed25519) and seed-model on the Python side (stdlib-only HMAC proxy until the Python defense lib adds a `cryptography` dep).
