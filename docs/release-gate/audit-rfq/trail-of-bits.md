# RFQ — Trail of Bits (first-choice audit firm)

**Status:** Draft. Review and send from `seth@aryalabs.io`. Do not send from this draft verbatim — adjust salutation if you've corresponded with a specific Trail of Bits AE before.

**To:** `info@trailofbits.com` (sales intake) — copy `dan.guido@trailofbits.com` if Dan is your existing contact, otherwise leave him off the initial reach
**Subject:** RFQ — Rust security-kernel audit (Apache-2.0 OSS, ARYA Labs PBC) — Q3 2026 engagement window

---

Hi Trail of Bits team,

ARYA Labs PBC is preparing the v1.0 release of the **Unfireable Safety Kernel**, a fail-closed authorization service for AI agents and other escapable AI systems. The kernel is a separate Rust process that sits between the agent and every consequential action; the agent runtime is treated as untrusted by construction. We are open-sourcing the implementation under Apache-2.0 and would like to engage Trail of Bits for the independent security audit that gates our v1.0 signed release.

Public repo: <https://github.com/ARYA-Labs-Public/unfireable-safety-kernel>

**Why Trail of Bits.** The kernel is Rust + Ed25519-signed transparency log + fail-closed circuit breaker. Trail of Bits' work on `osquery`, `cosign`, `slither`, the Solana audit, and the Coinbase Bitcoin core review lines up with the shape of this engagement more cleanly than any other firm we've evaluated. We would prefer to engage you as the primary auditor; we are quoting two other firms as a hedge against scheduling.

## Scope (target ~280–360 person-hours)

| Component | Code surface | Lines (approx.) |
|---|---|---|
| `crates/services/safety-kernel/` | Kernel binary, axum + tokio, decision logic, signing | ~4,500 LoC Rust |
| `crates/adapters/safety_kernel_client/` | Client SDK with fail-closed circuit breaker | ~1,200 LoC Rust |
| `crates/services/transparency-log/` | Append-only Ed25519-signed audit log | ~2,800 LoC Rust |
| `crates/adapters/transparency_store/` | Postgres-backed log storage | ~900 LoC Rust |
| `py-defense/` | Python audit-hook reference middleware (FastAPI) | ~800 LoC Python |
| `contracts/openapi/safety_kernel.yaml` | API contract (source of truth) | spec only |

Approximate total: ~10,200 LoC Rust + ~800 LoC Python + the OpenAPI spec.

### Specific properties we'd like adversarially examined

1. **Fail-closed invariant on the production path.** The contract is formally proved (Z3 over a symbolic model + 4 `#[kani::proof]` harnesses over the actual Rust `gate_decision` function). We want this proof bound stress-tested: are there agent-reachable execution paths around the verified function?
2. **Process-separation boundary.** The kernel is a separate Rust process. Verify the threat model (paper §2) holds — specifically, that there is no agent-reachable side channel that can write to kernel state, modify the binary, kill the process, or reach the operator signing key.
3. **Ed25519 signing chain.** Operator key custody, signing-key rotation, transparency-log append-only invariant under crash/restart, log entry verifiability against the public key.
4. **Four-seam defense-in-depth.** nginx auth_request gate, axum middleware, dispatch hook, client circuit breaker — each must independently deny on error. Verify no seam can be bypassed by structural construction or by configuration error.
5. **Python defense library.** The audit hook lives in the agent's process and must survive prompt-injection-flavored attempts to silence it (subprocess propagation, audit-hook state).
6. **Supply chain.** All actions in `.github/workflows/*` are pinned to commit SHAs; `deny.toml` bans `native-tls` / OpenSSL. Verify nothing has slipped.

### Out of scope

- TEE / TDX / SEV-SNP attestation (long-term roadmap; not in v1.0)
- Hardware key custody beyond Ed25519 operator-key software handling
- The proprietary policy DSL used internally at ARYA (not in this OSS extraction)

## Logistics

- **Calendar:** Quote needed by **2026-06-13**; SoW signed by **2026-06-20**; audit window ideally Q3 2026 with report delivered no later than **2026-10-03** (we have a hard release-gate dependency on the report).
- **Format:** Standard Trail of Bits report deliverable. We will attach the public-safe version of the report to the v1.0 release on GitHub; any findings we agree on may stay private until remediated.
- **NDA / SoW:** Apache-2.0 OSS, so the code is already public; the engagement scope itself does not require pre-NDA. We are happy to sign your standard SoW + mutual NDA on first call.
- **Commercial framing:** ARYA Labs is a Delaware Public Benefit Corporation whose chartered public benefit is the safe deployment of AI. If Trail of Bits has any nonprofit/PBC discount tier for AI-safety-aligned OSS work, please flag it; if not, that's fine — we have a budget for full-rate engagement.

## Action requested

1. Quote (person-hours, dollar range, delivery window).
2. Earliest engagement-start date with your current Q3 capacity.
3. Lead auditor profile for the Rust + cryptographic-protocol surface.
4. Whether the public-safe report attachment to the GitHub release is something you're comfortable with as part of the deliverable.

Happy to set up a 30-minute call this week or next to walk through the architecture if useful.

Thanks,

Seth Dobrin
Founder & CEO, ARYA Labs PBC
seth@aryalabs.io · <https://aryalabs.io>

---

## Sender notes (not part of the email body)

- Trail of Bits typical lead time is 12–18 weeks from SoW signature; quote in hand by 2026-06-13 gives us slack against the audit window.
- If the response is "Q4 only," fall back to NCC Group as primary; keep Trail of Bits as second-half-2026 if the kernel needs a second-opinion audit pre-v2.
- Discount tiers do exist (security non-profits, some OSS-aligned firms). Worth asking, no cost if no.
- Do not promise the audit report's findings will all be made public — `public-safe version` language is intentional. Some findings will be patched-then-disclosed; that's our normal posture.
