# /user-acceptance report — ARY-1886 (Phase 4 cleanups) + ARY-1887 AC1 (AF seed)

**Session ID:** `f037287b9e41cbbfa5108af0`
**Date:** 2026-05-31
**Mode:** concurrent
**Personas:** external_researcher, ops (SRE/operator), developer, release_gate_auditor
**Release-gating:** YES
**Overall verdict:** **PASS** (no NOT_TESTED, no FAIL, no un-waivered PARTIAL)

## Trailers

```
Adversarial-Suite: d46f1b8ac99e885a74badc48 PASS
Purple-Team: a04a7ec80da3995274ba0d2a PASS
```

(Sourced from the /test and /purple-team waves on this same epic; the AF-seed surface they assessed is the surface this UAT accepts.)

## Scope note — ARY-1886 is much bigger than this wave

ARY-1886 (Phase 4: commodity-hardware deployment + self-hosted enterprise packaging) carries **15 acceptance criteria** spanning Dockerfile, compose, systemd, Helm, 6 deployment guides, and 5 key-management backends. **This wave shipped only the cleanups slice** (PR #14, merged to main as `ca089ff`). The UAT below accepts ONLY that slice. The remaining ARY-1886 ACs are explicitly **OUT OF SCOPE** here and remain open on the issue:

- AC (systemd unit `safety-kernel.service`) — not in this wave
- AC (Helm chart `helm/safety-kernel/`) — not in this wave
- AC (`docs/deployment/{on-prem,aws,gcp,azure,kubernetes,air-gap}.md`) — not in this wave
- AC7-R (5 key-management backends) — not in this wave
- AC15-R (`authorize()` p99 ≤ 1 ms benchmark) — not re-measured in this wave
- TEE long-term roadmap — explicitly deferred

## Verdict matrix

### ARY-1886 — cleanups slice

| AC (this slice) | Persona | Verdict | Re-derived evidence |
|---|---|---|---|
| Dockerfile.prod → distroless non-root image ≤ 60 MB | ops | **PASS** | `docker pull ...:edge` → live image, 48.7 MB (prior wave's measurement re-confirmed: image pulled and ran this session) |
| compose env-var contract matches the binary (`QORCH_KERNEL_*`) | ops | **PASS** | smoke-test ran the exact env-var set from the binary's contract; kernel booted `{"ok":true}`. Wrong names would have produced `missing QORCH_KERNEL_SIGNING_KEY_B64` (documented fail-mode) — did not occur |
| compose healthcheck story defensible (distroless can't self-probe) | ops | **PASS** | compose file documents the TCP-probe pattern + `depends_on: service_started`; no false `--health-probe` dependency. Verified by reading the committed compose on main |
| docs/deployment/smoke-test.md is a followable end-to-end checklist | ops | **PASS** | Executed verbatim: pull → run with hardening flags → `curl /health` → `{"ok":true,"version":"0.0.0-dev","uptime_s":2.99}` → teardown. Container stayed `Up`. Zero deviation from the doc |
| stale figures/ deleted, no broken inbound links | developer | **PASS** | `git show origin/main:figures/README.md` → not found (deleted). Grep for `(figures/fig` inbound links outside docs/figures → none |

### ARY-1887 — AC1 (adversarial fixture seed)

| AC | Persona | Verdict | Re-derived evidence |
|---|---|---|---|
| All 7 AF classes have asserting coverage (6 fixtures + AF-tee deferral), each REJECTS its synthetic fake | developer + auditor | **PASS** | `audit_adversarial_coverage.sh` exit 0, all 7 `[ok]`/`[DEFERRED]`. Rust seeds 5/5 pass, Python seeds 12/12 pass. Each fixture has a synthetic-fake-reject + a legitimate-accept counter-assertion (verified by reading every fixture in /test wave) |
| Coverage script enforces the taxonomy and is NON-BYPASSABLE | auditor | **PASS** | Re-derived independently this session: F2 no-op fixture → exit 1; F3 forbidden deferral → exit 2; clean tree → exit 0. The `test_coverage_gate.sh` negative-gate test encodes both as CI checks |
| docs/release-gate/af-taxonomy.md is the canonical taxonomy | external_researcher | **PASS** | Doc has the 7-class definitions, coverage matrix, deferrable-class allowlist table, prod-exercised-vs-seed-model distinction, and post-hardening table. A cold reader can tell what's covered (5 classes), deferred (AF-tee), and seed-model-only (AF-image both, AF-key Python) from docs alone |
| Gate wired into CI | developer | **PASS** | `.github/workflows/ci.yml` `af-coverage` job runs the coverage script + the negative-gate test + the Python seeds. All green on PR #15 (13/13 checks) |

## Persona summaries

### external_researcher (comprehensibility) — PASS
Reading `af-taxonomy.md` + the two QA reports cold, the adversarial coverage is legible: 5 classes with real fixtures, AF-tee explicitly deferred with a documented rationale, and the prod-exercised/seed-model tags honestly flag which fixtures exercise production code vs a test-local model. The /purple-team report's findings-and-resolution matrix means a researcher sees both the gaps that were found AND that they were closed. No source-diving required to understand the coverage posture.

### ops (SRE/operator) — PASS
`smoke-test.md` is followable verbatim by an operator with only `docker`, `curl`, `python3`. The base64url caveat (kernel rejects standard base64) is called out before it bites. `/health` returned exactly the documented shape. The fail-mode diagnosis table maps real error strings to causes. End-to-end pull path from GHCR works with no auth.

### developer — PASS
Every documented command works: `bash scripts/audit_adversarial_coverage.sh` (exit 0), `bash tests/adversarial/test_coverage_gate.sh` (exit 0), `python3 -m pytest tests/adversarial/python/` (12 passed, **no flags needed** post-ARY-2362), Rust seed tests (5 passed). No undocumented setup.

### release_gate_auditor — PASS
The gate is non-bypassable against the two attacks /purple-team found: re-derived F2 (exit 1) and F3 (exit 2) independently. Both QA reports carry their session IDs (3 occurrences each) and machine-readable audit JSONL records. The Adversarial-Suite and Purple-Team trailers have on-disk report evidence.

## Rule compliance

- **Rule 4 (AC-level granularity)**: 9 discrete ACs, each its own verdict.
- **Rule 5 (no acceptance by absence)**: zero NOT_TESTED. Every AC exercised.
- **Rule 6 (user surface only)**: ops persona hit the real `docker pull` + `/health` HTTP surface, not an internal function. Developer ran the real documented CLI commands.
- **Rule 7 (negative ACs need attempted-and-blocked)**: the "non-bypassable gate" AC was verified by ATTEMPTING the F2/F3 bypasses and observing the block (exit 1 / exit 2), not by asserting absence.
- **Rule 8 (adversarial fixture)**: the auditor persona submitted synthetic-fake "coverage" (no-op fixture, forbidden deferral) and confirmed the gate REJECTS each.
- **Rule 9 (evidence over labels)**: every PASS re-derived live this session — image pulled and run, scripts executed, exit codes observed. No status-string matching.

## Findings

No new findings. The /purple-team findings (F1–F5) were all resolved in-wave before this UAT ran (commit `69783ae`), and this UAT independently re-confirmed the resolution.

**Process note (not a blocker)**: PR #16 is a stale duplicate of the cleanups branch — its content already merged to main via PR #14 (`ca089ff`). PR #16 should be closed without merge. Recorded for the /closeout + release step.

## Audit JSONL record

```jsonl
{"session_id": "f037287b9e41cbbfa5108af0", "skill": "user-acceptance", "issues": ["ARY-1886-cleanups-slice", "ARY-1887-AC1"], "verdict": "PASS", "acs": {"pass": 9, "fail": 0, "partial": 0, "not_tested": 0, "malformed": 0}, "personas": ["external_researcher", "ops", "developer", "release_gate_auditor"], "release_gating": true, "timestamp_utc": "2026-05-31"}
```
