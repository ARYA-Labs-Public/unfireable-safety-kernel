# v1.0 release-gate audit RFQs

Three RFQ drafts for the [ARY-1887](https://linear.app/aryalabs/issue/ARY-1887) v1.0 release-gate external audit (AC3–AC4).

These are **drafts**. They are not sent. Workflow:

1. Seth reviews each draft, edits the parts that are out of date (roadmap claims, headcount, EU framing).
2. Seth sends from `seth@aryalabs.io` — audit firms quote against a named, authorized counterparty; they will not engage with a service identity.
3. As quotes return, decisions land back in this directory as `decision-<firm>.md`.

## Why three firms

Quote triangulation, scope-fit signal, scheduling hedge. The output is **one engaged firm + two priced-but-deferred relationships** for future audits. Not three audits.

| File | Firm | Default position |
|---|---|---|
| [`trail-of-bits.md`](trail-of-bits.md) | Trail of Bits | **Primary.** Rust + crypto + protocol fit. Published audits on cosign, Solana, ed25519-adjacent projects. |
| [`ncc-group.md`](ncc-group.md) | NCC Group | **#2 hedge.** Transport-layer / four-seam defense-in-depth fit. Strong on protocol bypass-by-construction. |
| [`bsi.md`](bsi.md) | Cure53 (default) or BSI (gov-standard path) | **#3, EU jurisdiction.** Either commercial code-review (Cure53) or government-standard attestation (BSI) depending on EU AI Act timing. |

## Calendar

| Date | Milestone |
|---|---|
| **2026-05-30** | RFQs go out |
| **2026-06-13** | All three quotes back |
| **2026-06-20** | SoW signed with chosen firm |
| **2026-09-12 → 2026-10-10** | Audit report delivered (12–18 weeks from SoW signature) |
| **2026-10-04 (worst case)** | v1.0 signed release tag (gated on report delivery) |

## Sender checklist

Before sending each RFQ, confirm:

- [ ] The roadmap claims (EU AI Act, German federal procurement, FDA Class III, etc.) match the current ARYA plan.
- [ ] The LoC counts in the scope table still match the current repo (re-derive with `tokei` if there's been recent code movement).
- [ ] The Q3 2026 calendar is still realistic against the burn-in start (ARY-1887, AC5).
- [ ] The signature block matches what Seth uses externally.

## After-the-fact storage

Once a firm is engaged, the SoW, statement of intent, and final report (public-safe version) all land in `docs/release-gate/audit/<firm>/`. Internal-only artifacts stay in the private monorepo.
