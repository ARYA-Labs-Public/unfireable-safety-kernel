# RFQ — NCC Group (audit firm #2)

**Status:** Draft. Review and send from `seth@aryalabs.io`. The default path is to engage Trail of Bits as primary; NCC is the hedge if ToB's Q3 capacity is gone or their quote is non-competitive.

**To:** `consulting@nccgroup.com` (US sales intake) — or your existing NCC contact if you have one (Jennifer Fernick is a strong known-quantity in their cryptography practice, but go through standard intake unless you know her personally)
**Subject:** RFQ — Rust safety-kernel + transport-layer audit (Apache-2.0 OSS, ARYA Labs PBC) — Q3 2026 engagement

---

Hi NCC Group team,

ARYA Labs PBC is preparing the v1.0 release of the **Unfireable Safety Kernel**, an open-source (Apache-2.0) Rust authorization service that gates AI-agent actions through a process-separated kernel. We are sending RFQs to a short list of audit firms for the independent security review that gates our v1.0 signed release; NCC Group is on that list because of your track record on the protocol-and-transport surface this kernel relies on.

Public repo: <https://github.com/ARYA-Labs-PBC/unfireable-safety-kernel>

**Why NCC.** The kernel composes four defense-in-depth seams (nginx `auth_request`, axum middleware, dispatch hook, client SDK circuit breaker). Each seam is a potential transport / protocol failure mode. NCC's work on TLS implementations, OAuth flows, and SDN/cloud-network protocols maps cleanly onto the kind of cross-seam bypass-by-construction analysis we need. NCC's published threat-modeling methodology is also closer to the four-seam decomposition than the more code-centric ToB style.

## Scope (target ~280–360 person-hours)

| Component | Code surface | Approx. LoC |
|---|---|---|
| `crates/services/safety-kernel/` | Kernel binary (axum + tokio), decision logic, signing | 4,500 Rust |
| `crates/adapters/safety_kernel_client/` | Client SDK with fail-closed circuit breaker | 1,200 Rust |
| `crates/services/transparency-log/` | Append-only Ed25519-signed audit log | 2,800 Rust |
| `crates/adapters/transparency_store/` | Postgres-backed log storage | 900 Rust |
| `py-defense/` | Python audit-hook reference middleware (FastAPI) | 800 Python |
| `contracts/openapi/safety_kernel.yaml` + nginx config | API contract + nginx auth_request gate | spec + config |

Approximate total: ~10,200 LoC Rust + ~800 LoC Python + the OpenAPI spec + the nginx auth_request deployment pattern.

### Specific properties we'd like adversarially examined

1. **Four-seam defense-in-depth structural integrity.** The four seams (nginx, axum middleware, dispatch hook, client circuit breaker) must each independently deny on error. This is the property our deployment construction promises and the property we most want NCC to attack — is there a structural construction (config error, route registration shape, header smuggling, TLS termination edge) that bypasses one seam while the others appear green?
2. **Transparency log under crash, restart, partition.** Ed25519 chain integrity, append-only invariant, log entry verifiability when the storage layer partitions or rolls back. This is a transport-and-state-machine surface NCC has audited many times in adjacent shapes (ledger systems, audit logs, signed message queues).
3. **Fail-closed under network failures.** The client SDK has a verified state machine (4 Kani proofs over `gate_decision`); we want NCC to stress-test that the verified function is actually on the production path, and that there is no non-verified path (timeout, DNS, TCP RST, half-closed connection, slow loris, body truncation) that reaches an ALLOW.
4. **nginx auth_request gate.** Specific to NCC's transport-layer competence — header smuggling, request smuggling, body re-reading, proxy_pass interactions, TLS termination & re-origination.
5. **Operator key custody and signing-chain rotation.** Ed25519 dual-sign overlap window, revocation propagation, signing-key rotation under load.

### Out of scope

- TEE / TDX / SEV-SNP attestation (long-term roadmap; not in v1.0)
- The proprietary policy DSL used internally at ARYA (not in this OSS extraction)

## Logistics

- **Calendar:** Quote needed by **2026-06-13**; SoW signed by **2026-06-20**; audit window ideally Q3 2026 with report delivered no later than **2026-10-03**.
- **Format:** Standard NCC report deliverable. We will attach the public-safe version to the v1.0 release on GitHub; findings may stay private until remediated.
- **Commercial framing:** ARYA Labs PBC is a Delaware Public Benefit Corporation chartered for AI safety. If NCC has any OSS-aligned or research-tier rate, please flag.
- **Apache-2.0 OSS:** Code is already public; the engagement scope itself does not require pre-NDA.

## Action requested

1. Quote (person-hours, dollar range, delivery window).
2. Earliest engagement-start with current Q3 capacity.
3. Lead auditor profile for the protocol/transport-and-Rust surface (any cryptography-practice involvement is a plus).
4. Whether the public-safe report attachment to the GitHub release is something you're comfortable with.

Happy to set up a 30-minute architecture call this week or next.

Thanks,

Seth Dobrin
Founder & CEO, ARYA Labs PBC
seth@aryalabs.io · <https://aryalabs.io>

---

## Sender notes (not part of the email body)

- NCC quotes faster than ToB but is more variable on lead time (8–20 weeks).
- If ToB and NCC both come back Q4-only, escalate scope: split the audit into Phase A (kernel + transparency log) with the faster firm and Phase B (Python defense library + nginx surface) with the slower firm running parallel. This is unusual but acceptable if Q3 closure is at risk.
- Jennifer Fernick has historically led their cryptography practice — if she's still on staff and reachable through your network, a direct intro is worth more than the standard sales intake. Otherwise the form above is the safe default.
