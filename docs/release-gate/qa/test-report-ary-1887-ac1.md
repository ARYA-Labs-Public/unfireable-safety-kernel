# /test QA report — ARY-1887 AC1 (AF taxonomy seed)

**Session ID:** `d46f1b8ac99e885a74badc48`
**Wave:** ARY-1887 AC1 — AF taxonomy + seed fixtures + coverage script
**Branch:** `seth/ary-1887-af-seed-set` (PR #15)
**Date:** 2026-05-30
**Mode:** pipeline
**Scope:** adversarial
**Verdict:** **PASS**

## Trailer (drop into the release commit)

```
Adversarial-Suite: d46f1b8ac99e885a74badc48 PASS
```

## Audit summary

| AF class | Seed fixture(s) | Rule 8 (rejects fake) | Rule 9 (re-derives evidence) | Verdict |
|---|---|:---:|:---:|:---:|
| AF-contracts | covered by existing `BYPASS_ATTEMPT_DIRECT` + nginx auth_request gate (no new seed needed) | ✅ | ✅ | PASS |
| AF-sdk | covered by existing `crates/adapters/safety_kernel_client/tests/adversarial.rs` + AC16 6-fixture set | ✅ | ✅ | PASS |
| **AF-image** (new) | `tests/adversarial/python/af_image_seed.py` (3 tests), `crates/services/safety-kernel/tests/seed_af_image.rs` (3 tests) | ✅ | ✅ structural lint of committed `Dockerfile.prod` + synthetic-fake reject + partial-fake-missing-USER reject | **PASS** |
| AF-reconciler | covered by existing `purple_manifest_replay.rs` + new `tests/adversarial/python/af_reconciler_seed.py` (3 tests) | ✅ | ✅ recomputes SHA-256 of payload + staleness arithmetic | PASS |
| AF-tlog | covered by 6 existing `purple_*.rs` files + new `tests/adversarial/python/af_tlog_seed.py` (3 tests) | ✅ | ✅ re-derives local SHA-256 of token bytes, compares to claimed `leaf_hash` | PASS |
| **AF-key** (new) | `tests/adversarial/python/af_key_seed.py` (3 tests), `crates/adapters/safety_kernel_client/tests/seed_af_key.rs` (2 tests) | ✅ | ✅ production `PinnedKeyVerifier::verify` (Ed25519-dalek) on Rust side, constant-time HMAC-compare on Python contract-only side | **PASS** |
| AF-tee | `tests/adversarial/seed/af_tee_DEFERRED.md` | ⏸ deferred to v2.0 (no TEE in v1.0 hardware target per ARY-1886) | n/a | DEFERRED |

## Gate results

| Gate | Command | Result |
|---|---|---|
| Python seed tests | `python3 -m pytest tests/adversarial/python/af_image_seed.py af_key_seed.py af_reconciler_seed.py af_tlog_seed.py -v` | **12/12 pass** (0.37s) |
| Rust seed tests | `cargo test --workspace --test seed_af_image --test seed_af_key` | **5/5 pass** (compiled + ran in 1m05s) |
| Coverage script (positive) | `bash scripts/audit_adversarial_coverage.sh` | **exit 0** — `Release-gate AF coverage: PASS` |
| Coverage script (negative — fixture missing) | rename `af_image_seed.py` → `.bak`, re-run | **exit 1** — `[MISSING] AF-image rust=1 python=0` |
| Coverage script (negative — restored) | restore + re-run | **exit 0** — clean |

## Rule 8 enforcement

Every non-deferred fixture supplies a synthetic-fake artifact and asserts the production code path REJECTS:

- **AF-image (Rust + Python)**: synthetic-fake Dockerfile (single-stage, ubuntu base, root user) triggers all three structural violations. Variant fake (missing-only-USER) triggers the non-root violation specifically.
- **AF-key (Rust)**: attacker-signed Ed25519 token rejected by `PinnedKeyVerifier::verify` against legitimate pinned pubkey.
- **AF-key (Python)**: attacker-keyed HMAC token rejected by `_PinnedKeyVerifier::verify`. Tampered-claims-under-legitimate-signature also rejected.
- **AF-reconciler (Python)**: stale manifest (issued 48h ago, 24h threshold) raises `_StaleManifest`. Digest-drift raises `_RegistryDigestDrift`.
- **AF-tlog (Python)**: bogus leaf-hash (all zeros) raises `_LogResponseMismatch`. Truncated leaf-hash also raises.

Counter-assertions present in every fixture: the lint passes the committed Dockerfile; the verifier accepts legitimate tokens; the manifest check passes fresh-and-correct manifests; the t-log check passes correct leaf-hash. **This prevents false-negatives** (a fixture that "passes" by rejecting everything).

## Rule 9 enforcement (evidence over labels)

Every fixture re-derives evidence in-process. No regex against status strings. Specifically:

- **AF-image**: parses `FROM`/`USER` directives from Dockerfile source, returns a structured violations Vec. Tests inspect the Vec contents for specific properties (multi-stage / distroless / non-root).
- **AF-key (Rust)**: uses production `PinnedKeyVerifier::verify` which runs real Ed25519-dalek signature verification. Result is `Result<_, _>` — test inspects via `is_err()`.
- **AF-key (Python)**: uses `hmac.compare_digest` (constant-time) on recomputed HMAC, not log scraping.
- **AF-reconciler**: recomputes `hashlib.sha256(manifest.payload).hexdigest()` and compares to the manifest's declared digest. Timestamp arithmetic for staleness.
- **AF-tlog**: recomputes `hashlib.sha256(my_token_bytes).hexdigest()` and compares to the claimed `leaf_hash_hex`.

## Notes / known gaps that downstream waves must close

These are **not blocking** for AC1 seed acceptance, but they're explicitly the next-wave work:

1. **AF-image production defence is structural-lint-only.** A real supply-chain attack might pass the lint (correct shape, but backdoored binary in the COPY). Full cryptographic build-provenance verification (sigstore + SLSA attestation chain) is ARY-1886 / ARY-1887 follow-up.
2. **AF-key Python is HMAC-modeled, not Ed25519.** The docstring is explicit: stdlib-only Python defense lib uses HMAC to exercise the rejection contract. Production crypto is Ed25519 (Rust side). When the v1.0 Python defense lib gets `cryptography` as a dep, the Python fixture should swap to real Ed25519.
3. **AF-tlog Python is C2-only.** A1 (forged STH), B1 (tampered inclusion proof), F1 (idempotency collision), G1a/b (forged token) are Rust-only (production transparency-log client is Rust). When a Python tlog-client lands, mirror those campaigns.
4. **AF-reconciler Python is stdlib-only.** Same logic as AF-key — production reconciler is Rust; Python seed mirrors the contract.
5. **pytest auto-discovery quirk**: `tests/adversarial/python/__init__.py` causes pytest to skip the directory under default rootdir heuristics. Tests must be invoked by explicit file path OR pytest config (`pyproject.toml` testpaths) added. CI's `AF taxonomy coverage` job calls the bash script, not pytest, so this is documentation-only — but worth fixing in a follow-up so `pytest tests/adversarial/python/` discovers the suite.

## Reproducibility

- Working tree: `/tmp/usk-audit` (fresh clone of `seth/ary-1887-af-seed-set`)
- Python: 3.11.2, pytest 9.0.2
- Rust: 1.85-slim (docker image)
- Fixtures use fixed keys / fixed timestamps / deterministic payloads. No flakes.

## Audit JSONL record

```jsonl
{"session_id": "d46f1b8ac99e885a74badc48", "wave": "ARY-1887-AC1", "skill": "test", "verdict": "PASS", "fixtures": {"python": 12, "rust": 5}, "coverage_script": {"positive_exit": 0, "negative_exit": 1}, "rule_8": "pass", "rule_9": "pass", "timestamp_utc": "2026-05-30"}
```
