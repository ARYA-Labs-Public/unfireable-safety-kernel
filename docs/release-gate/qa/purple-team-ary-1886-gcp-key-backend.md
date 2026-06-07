# Purple-Team Findings — ARY-1886 Step-14R: Pluggable Signing-Key Backend

- **Session ID:** `ary1886-pt-gcpkeybackend`
- **Wave:** `ary1886-gcp-key-backend`
- **Target:** uncommitted working tree at `/tmp/usk-work`, branch `seth/ary-1886-gcp-key-backend`, base `0004e89`
- **Surface:** Rust Safety Kernel signing-key backend — the Ed25519 seed is the kernel's root of trust; every authorization token is signed with it. Maximum-sensitivity signed-output surface.
- **Mode:** pipeline (defense surface is the fixed change under review); red attacks designed against the actual code paths, validated by recompute (Rule 9).
- **Date:** 2026-06-06T21:30:32Z
- **Verdict:** **PASS** (no unmitigated High/Critical findings)

## Files assessed

| File | Role in the change |
|------|--------------------|
| `crates/services/safety-kernel/src/key_backend.rs` | `KeyBackendKind` enum, `resolve_signing_key_b64`, GCP Secret Manager fetch + metadata-server OAuth2 |
| `crates/services/safety-kernel/src/settings.rs` | `KERNEL_KEY_BACKEND` parse, env-backend-blocked-in-prod guard, conditional seed-env requirement |
| `crates/services/safety-kernel/src/main.rs` | resolves seed via backend at boot, logs backend name, 32-byte length check |
| `crates/services/safety-kernel/src/bin/keygen.rs` | Ed25519 seed generator (stdout seed, stderr pubkey/fp) |
| `crates/services/safety-kernel/tests/key_backend_prod_guard.rs` | Rule-8 adversarial fixtures |
| `crates/services/safety-kernel/tests/gcp_key_backend_live.rs` | `#[ignore]` live GCP fetch (Rule-9 byte-equality recompute) |
| `docs/deployment/key-management.md` | operator docs + threat model |

## Reproduction environment

- `cargo build -p qorch-safety-kernel --bins` — green.
- `cargo test -p qorch-safety-kernel --test key_backend_prod_guard` — `1 passed`.
- `cargo test -p qorch-safety-kernel --lib key_backend` — `3 passed`.
- Two throwaway PoC tests (zero-seed validity; whitespace-env bypass) were added, run, and removed; results re-derived below.

---

## Threat-by-threat results

### Threat 1 — Attacker-key injection — NO FINDING (surface NARROWS)

Every input to the seed was traced:

- **`env` backend:** seed = `QORCH_KERNEL_SIGNING_KEY_B64` (settings.rs:238). Operator-controlled, identical trust level to the pre-change behavior.
- **`gcp` backend:** `KERNEL_KEY_GCP_PROJECT` / `KERNEL_KEY_GCP_SECRET` / `KERNEL_KEY_GCP_SECRET_VERSION` come from env (operator/deployment-controlled); the seed *payload* comes from GCP Secret Manager, authenticated by the instance's attached service-account token from the link-local metadata server (`169.254.169.254` via `metadata.google.internal`). An attacker who can set those env vars already owns the deployment manifest; an attacker who can write the named secret needs `secretmanager.versions.add`, which the kernel SA is explicitly NOT granted (`secretAccessor` read-only, docs §2 + keygen has no upload path — verified, see Threat 5).

**Conclusion:** the backend does **not widen** the attack surface versus the env-only baseline. It **narrows** the at-rest exposure (the 32-byte seed leaves `/proc/<pid>/environ`, shell history, systemd `Environment=`, and core dumps). The token never persists beyond the fetch (local `String`, used only for `bearer_auth`). No PoC for injection exists below the "attacker already controls deployment config or the GCP secret" bar.

See also Finding 3 (Low) re: `version=latest` pinning as defense-in-depth.

### Threat 2 — Prod-guard bypass — FINDING PT-1 (Medium)

The env-backend prod block (settings.rs:225-237) keys off `is_prod_env = matches!(env_lower, "prod" | "production")`. `env_lower` is `QORCH_ENV.to_ascii_lowercase()` **without `.trim()`** (settings.rs:181-182). Case is handled; surrounding whitespace is not.

**PoC (re-derived in-process, then removed):** with `QORCH_ENV=" prod"` (one leading space), `KERNEL_KEY_BACKEND=env`, and a seed env var set, `Settings::from_env()` returned `Ok`, `is_prod()` == `false`, `key_backend == "env"`. Observed test output: `BYPASS: booted with env-backend; env=" prod" is_prod=false`.

Because every prod control is gated on the same `matches!(... "prod" | "production")` predicate, a whitespace-padded value silently relaxes **all** of them at once:
1. the env-backend-in-prod block (this change),
2. the `QORCH_KERNEL_API_KEY_OPERATOR` requirement (settings.rs:297),
3. the TLS-required fail-closed (main.rs:222),
4. the transparency-log + client-mTLS prod requirements (settings.rs:373, 399).

**Trust boundary:** `QORCH_ENV` is set by the deployment operator (systemd/compose/k8s), not a remote attacker — so this is not remotely exploitable. It is a *silent-misconfiguration* / defense-in-depth defect: a templated value carrying a trailing newline or stray space (e.g. a k8s ConfigMap or heredoc `QORCH_ENV=prod\n`) would downgrade a "prod" deployment to dev-grade key handling with no error. Given that this defect defeats the headline control of the very change under review, it warrants a fix before ship.

**Severity:** Medium. **Fix:** trim `QORCH_ENV` at read time — `let env_lower = env::var("QORCH_ENV").unwrap_or_else(|_| "dev".into()).trim().to_ascii_lowercase();` — and add a fixture asserting `QORCH_ENV=" prod"` is rejected for the env backend. Single point of change; fixes all four downstream gates at once.

### Threat 3 — Fail-open — NO FINDING (fails CLOSED), with one observation

Every failure path propagates `Err` and aborts boot:

- Missing project/secret config: caught synchronously in `from_env` (settings.rs:250-259) AND again in `resolve_signing_key_b64` (key_backend.rs:114-122).
- Metadata token non-200 / network failure / missing `access_token`: `Err` (key_backend.rs:212-213, 219-220).
- Secret Manager non-200 (403/404/etc): `Err` with the IAM error (key_backend.rs:158-166).
- Missing `payload.data` / non-base64 / non-UTF-8 / **empty** payload: `Err` (key_backend.rs:173-185).
- In `main.rs`, `resolve_signing_key_b64(...).await.context(...)?` (line 91-93) and the **`!= 32` byte length check** (line 101-106) both `?`-propagate out of `main`, so a bad seed aborts the process. There is no degraded/empty/zero-key boot path.

**Zero/known-key consideration (re-derived, probe removed):** Ed25519 accepts *any* 32 bytes as a seed, including all-zero, which yields the well-known public key `3b6a27bc…da29` and a fully functional signer. The code does **not** reject a 32-byte all-zero or other low-entropy seed. However, reaching that state requires the operator/GCP secret to actually *contain* such a seed — it is not reachable from a GCP fetch error, an empty payload, or a malformed response (all of which fail closed before the 32-byte stage). So this is not a fail-open: it would require deliberately storing a bad seed, which is outside the trust boundary. Noted as informational; not a finding. (`keygen.rs` uses `SigningKey::generate(&mut OsRng)`, so the supported provisioning path never produces a weak seed.)

**Conclusion:** fails closed on every error path. No PoC boots the kernel with a degraded key.

### Threat 4 — Token / secret leakage — NO FINDING

- The OAuth2 access token is a local `String` (key_backend.rs:140), passed only to `.bearer_auth(&token)` (line 149). It is never logged, returned, or interpolated into any error/format string (grep-verified: no `{token}` / `token,` in any message).
- The seed is never logged or interpolated either (no `{seed_b64}` / `{data_b64}`; the decode/UTF-8 failures use anyhow `.context(...)`, which prepends a *static* string and does NOT include the value — key_backend.rs:176, 178).
- The Secret Manager non-200 error includes the response **body** verbatim (line 163-165). On a non-200 that body is the GCP IAM/error JSON (names the missing permission, e.g. `secretmanager.versions.access`); it is structurally not the secret payload (the payload only appears on 200, which is the success branch) and not the token (the token is in the request header, never echoed in a GCP error body). Acceptable and useful for ops.
- The metadata-token non-200 error includes its body (line 213); an `access_token` only exists on a 200, which is the success branch — so the token cannot reach that error string.
- `main.rs` startup logs (line 80, 94) emit env / listen / version / **backend name only** — never the seed.

**Conclusion:** no token or seed reaches any log, error, or echo. Clean.

### Threat 5 — Least privilege — NO FINDING

- The kernel only **reads**: grep for write/admin verbs (`add`, `delete`, `destroy`, `setIamPolicy`, `patch`, `.post(`, `.put(`, `.delete(`) over `key_backend.rs` returns nothing — only `.get()` on the `:access` and metadata endpoints. Required IAM is `roles/secretmanager.secretAccessor` (read), as documented.
- `keygen.rs` does **not** auto-upload: it only generates and prints (stdout seed, stderr pubkey/fp). The `gcloud secrets versions add` step is an explicit operator pipe in the docs, never invoked by the binary. No implicit write path.

**Conclusion:** read-only runtime identity confirmed; provisioning is an out-of-band operator step. Clean.

### Threat 6 — Rule-8 fixture authenticity — VERIFIED REAL (not synthetic stamps)

`tests/key_backend_prod_guard.rs::key_backend_config_gates` was read line-by-line and executed:

- The **prod-env-backend case asserts rejection** (lines 44-57): sets `QORCH_ENV=prod` + `KERNEL_KEY_BACKEND=env`, calls `Settings::from_env()`, and `expect_err(...)`, then asserts the message contains `"KERNEL_KEY_BACKEND=env is forbidden"` AND `"prod"`. This is a genuine adversarial fixture the gate must reject — not a stamp.
- It also exercises: staging-allows-env (positive), gcp-requires-project/secret (rejection), gcp-does-not-populate-`signing_key_b64`-from-env (the load-bearing anti-leak invariant), unimplemented backends fail closed with `"not implemented"` (rejection of aws/azure/pkcs11/tpm — no env-var fallback), and unknown-name parse error.
- Re-run result: `test key_backend_config_gates ... ok`.
- The live test `gcp_key_backend_live.rs` satisfies Rule 9 by re-deriving the public-key fingerprint and asserting byte-equality of the fetched seed vs the operator-stored seed (not a status-string match). It is correctly `#[ignore]`-gated for CI (no GCP) and runnable on GCE.

**Conclusion:** fixtures are real and the suite is the gate. Rule 8 satisfied. **Caveat:** the suite does not cover the whitespace-env case (Finding PT-1) — that fixture should be added with the fix.

---

## Findings summary

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| PT-1 | **Medium** | `QORCH_ENV` not trimmed → whitespace-padded `prod` silently bypasses the env-backend prod-guard and all four prod fail-closed gates | Open (recommend fix before ship; not remotely exploitable) |
| PT-2 | **Low / Informational** | `KERNEL_KEY_GCP_SECRET_VERSION` defaults to `latest`; a compromised write-capable provisioning SA could swap the seed under the kernel on restart with no version pin to detect drift | Open (defense-in-depth; requires already-compromised write SA) |
| PT-3 | **Informational** | No `.timeout(...)` on either reqwest client (key_backend.rs:144, 198); a hung metadata/Secret-Manager endpoint stalls boot indefinitely. Boot-time only, link-local metadata server, fail-closed on actual error | Open (hardening) |
| — | Informational | 32-byte low-entropy/zero seeds are accepted by Ed25519; only reachable by deliberately storing a bad seed (outside trust boundary). Supported `keygen` path uses OS CSPRNG | Noted, no action |

No High or Critical findings. The two managed-backend security claims that matter most — **fails closed** (Threat 3) and **no secret/token leakage** (Threat 4) — both hold under recompute.

## Verdict

**PASS.** The change does what it claims: it narrows the signing-key at-rest attack surface, fails closed on every GCP/config error, never leaks the token or seed, and keeps the runtime identity read-only. The one Medium finding (PT-1) is an operator-trust-boundary defense-in-depth gap, not a remotely exploitable vulnerability, and has a one-line fix. Recommend landing PT-1's trim + fixture before the prod cutover; PT-2/PT-3 are follow-up hardening.

---

Adversarial-Suite: ary1886-pt-gcpkeybackend PASS
Purple-Team: ary1886-pt-gcpkeybackend PASS
