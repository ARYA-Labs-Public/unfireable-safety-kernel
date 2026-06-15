# RFQ — BSI / Cure53 (EU-regulatory-shaped third quote)

**Status:** Draft. Review and send from `seth@aryalabs.io`. This RFQ is the EU-anchored hedge in the three-firm pool. The default path is to engage Trail of Bits (primary, US, Rust+crypto fit) or NCC Group (#2, transport-layer fit); this RFQ exists so the third quote (a) confirms the US firms' pricing and (b) gives us an EU-regulatory-shaped option if German federal AI procurement or EU AI Act adoption becomes a near-term opportunity.

**Two-firm decision before sending:**

- **BSI (Bundesamt für Sicherheit in der Informationstechnik)** — German federal IT security office. They evaluate against German federal procurement criteria (BSI TR-ESOR, IT-Grundschutz). If ARYA has any near-term EU government adoption pathway, send to BSI. Note BSI is slow and primarily evaluates *against* a published government standard rather than performing open-scope code review.
- **Cure53** (Berlin) — commercial penetration-test firm in the same orbit, much faster, much more code-review-shaped. Recent work: PyPI, Tornado web framework, NextDNS, several Rust crypto crates. Default substitute if BSI is not the right fit.

**Recommendation: send to Cure53 unless you specifically need the BSI government-standard letter.** The body below is templated for Cure53 with a footnote on swapping in BSI's intake.

**To (Cure53):** `info@cure53.de`
**Subject:** RFQ — Rust safety-kernel audit (Apache-2.0 OSS, US PBC, EU-jurisdiction hedge) — Q3 2026

---

Hi Cure53 team,

ARYA Labs PBC is preparing the v1.0 release of the **Unfireable Safety Kernel**, an open-source (Apache-2.0) Rust authorization service that gates AI-agent actions through a process-separated kernel. We are evaluating an independent security audit as the release gate for v1.0, and we'd like to include Cure53 in our three-firm quote process.

Public repo: <https://github.com/ARYA-Labs-Public/unfireable-safety-kernel>

**Why Cure53.** Your published reports on PyPI, Tornado, NextDNS, and several Rust cryptographic crates show the exact kind of code-review-first methodology this kernel needs. We are also a US Public Benefit Corporation with EU AI Act and German federal adoption on our roadmap, so an audit by a Berlin-based firm with a paper trail in the German-federal procurement ecosystem materially helps that path.

## Scope (target ~280–360 person-hours)

| Component | Code surface | Approx. LoC |
|---|---|---|
| `crates/services/safety-kernel/` | Kernel binary (axum + tokio), decision logic, signing | 4,500 Rust |
| `crates/adapters/safety_kernel_client/` | Client SDK with fail-closed circuit breaker | 1,200 Rust |
| `crates/services/transparency-log/` | Append-only Ed25519-signed audit log | 2,800 Rust |
| `crates/adapters/transparency_store/` | Postgres-backed log storage | 900 Rust |
| `py-defense/` | Python audit-hook reference middleware (FastAPI) | 800 Python |
| `contracts/openapi/safety_kernel.yaml` + nginx config | API contract + nginx auth_request gate | spec + config |

Approximate total: ~10,200 LoC Rust + ~800 LoC Python.

### Specific properties we'd like adversarially examined

1. **Fail-closed invariant on the production path.** The contract is formally proved (Z3 over a symbolic model + 4 `#[kani::proof]` harnesses over the actual Rust `gate_decision` function). We want the proof bound stress-tested — are there agent-reachable execution paths around the verified function?
2. **Process-separation boundary.** Verify the threat model holds — no agent-reachable side channel writes to kernel state, modifies the binary, kills the process, or reaches the operator signing key.
3. **Ed25519 signing chain.** Operator key custody, signing-key rotation, transparency-log append-only invariant under crash/restart, log-entry verifiability against the public key.
4. **Four-seam defense-in-depth.** nginx auth_request, axum middleware, dispatch hook, client circuit breaker — each must independently deny on error. Verify no seam can be bypassed by construction or configuration error.
5. **Python defense library.** The audit hook lives in the agent's process and must survive prompt-injection-flavored attempts to silence it (subprocess propagation, audit-hook state).

### Out of scope

- TEE / TDX / SEV-SNP attestation (long-term roadmap; not in v1.0)
- Internal proprietary policy DSL (not in OSS extraction)

## Logistics

- **Calendar:** Quote needed by **2026-06-13**; SoW signed by **2026-06-20**; audit window ideally Q3 2026 with report delivered no later than **2026-10-03**.
- **Format:** Standard Cure53 report deliverable. We will attach the public-safe version to the v1.0 release on GitHub; findings may stay private until remediated.
- **EU jurisdiction.** ARYA Labs PBC is incorporated in Delaware; we are comfortable with a German-jurisdiction SoW + bilateral NDA if Cure53 prefers that footing. Working language English.
- **Apache-2.0 OSS:** Code is already public; no pre-NDA required on scope itself.

## Action requested

1. Quote (person-hours, EUR or USD, delivery window).
2. Earliest engagement-start with current Q3 capacity.
3. Lead auditor profile for the Rust + cryptographic-protocol surface.
4. Whether the public-safe report attachment to the GitHub release is something you're comfortable with.

Happy to schedule a 30-minute architecture call.

Thanks,

Seth Dobrin
Founder & CEO, ARYA Labs PBC
seth@aryalabs.io · <https://aryalabs.io>

---

## Footnote — swapping in BSI

If we want the BSI government-standard letter rather than the Cure53 commercial audit:

**To (BSI):** Initial contact via the BSI website's "Anfrage Zertifizierung" portal (<https://www.bsi.bund.de/EN/Topics/Certification/certification_node.html>). BSI does not engage commercially the way Cure53 does — they evaluate against published standards (IT-Grundschutz, BSI TR-ESOR, BSI TR-02103 for crypto). Pick the standard before initiating contact. BSI lead time is 6–12 months, not 12–18 weeks.

**Decision rule:** If a German federal procurement or EU AI Act conformity attestation is in play before EOY 2026, start the BSI process now even if we engage Cure53 commercially in parallel. Otherwise skip BSI and use Cure53 as the third quote.

## Sender notes (not part of the email body)

- Cure53 has historically responded within 5 business days. If no response by 2026-06-06, follow up.
- The "EU AI Act conformity" framing is a real lever — make sure the framing in the email body matches the actual ARYA roadmap before sending. If EU is not on the 18-month roadmap, strike the EU-AI-Act sentence and lean on the Rust-crypto-crate track record instead.
- Three quotes is a triangulation tool, not a commitment to engage three firms. The output of this RFQ round is one engaged firm + two priced-but-deferred relationships for future audits.
