# Claude Design correction prompt — Unfireable Safety Kernel paper figures

Paste the section below into Claude Design when requesting corrections to the figure set. The standing-conventions block keeps the assistant from accidentally reintroducing figure numbers, em-dashes, or stale terminology. Fill in **WHAT TO CHANGE** with specific edits and delete sections you don't need.

---

## Begin paste

I'm iterating on the figure set for *The Unfireable Safety Kernel: Execution-Time AI Alignment for AI Agents and Other Escapable AI Systems* (Dobrin, ARYA Labs PBC, 2026). The bundle has been exported and is in active use. I need targeted corrections, not a rebuild.

### The thirteen figures (current state)

| ID | Eyebrow | Footer descriptor | Paper § | File |
|---|---|---|---|---|
| Fig 1 | THE ARCHITECTURAL MISTAKE, AND THE FIX | The architectural mistake, and the fix | §1–§3 | `src/figures-conceptual.jsx` |
| Fig 2 | THE FOUR-SEAM ARCHITECTURE | Four-seam architecture, pre-action enforcement on a structurally-only path | §3 (P1–P4), §4 | `src/figures-architecture.jsx` |
| Fig 3 | THE AI ALIGNMENT STACK | The alignment stack, execution-time is the upper layer | §8.1 | `src/figures-conceptual.jsx` |
| Fig 4 | CHAIN OF TRUST | Source → build → binary → runtime → decision | §4–§5 | `src/figures-architecture.jsx` |
| Fig 5 | WHERE DOES THE DECISION LIVE? | Related-systems comparison | §7 | `src/figures-verification.jsx` |
| Fig 6 | THE GENERAL CATEGORY | Escapable AI systems, agents are the worked example | §8.2 | `src/figures-conceptual.jsx` |
| Fig 7 | TWO-LEVEL PROOF OF THE FAIL-CLOSED INVARIANT | Two-level fail-closed proof, Z3 over model, Kani over Rust | §6.4 | `src/figures-verification.jsx` |
| Fig 8 | TRANSPARENCY LOG | Append-only, operator-signed, externally verifiable | §4–§5 | `src/figures-verification.jsx` |
| Fig 9 | THE CONFUSED DEPUTY, FORECLOSED BY CONSTRUCTION | Static routes, the agent cannot grow its own authority | §4 | `src/figures-architecture.jsx` |
| Fig 11 | DOES IT HOLD WHEN A REAL SELF-MODIFIER RUNS AGAINST IT? | Containment ladder, 0 bypasses in 6,240 round-trips | §6 | `src/figures-evaluation.jsx` |
| Fig 12 | WHAT HAPPENS WHEN THE OPERATOR PULLS THE PLUG | The kill switch, ceiling 4 versus ceiling 0 | §6 | `src/figures-evaluation.jsx` |
| Fig 13 | WHAT WAS ACTUALLY TRIED | Attack taxonomy breadth, tier one, 0 bypasses | §6 | `src/figures-evaluation.jsx` |
| Fig 14 | WHERE THE REFUSAL ACTUALLY HAPPENS | Two independent denials, transport seam then ladder | §6 | `src/figures-evaluation.jsx` |

### WHAT TO CHANGE

*Replace with specific corrections. Examples of the right level of detail:*

- **Fig 2:** the `Client SDK` seam description currently emphasizes the circuit breaker. Add a short callout that the breaker honors a tolerance window of T seconds before tripping, so an unfamiliar reader does not think it trips on a single failed call.
- **Fig 4:** the chain-of-trust diagram shows five stages. The stage 4 label "runtime attestation" should clarify the key custodian. Change to "runtime attestation, attestor key offline" so the operator/attestor key separation is visible at the diagram level.
- **Fig 7:** the Kani harness names list shows four; the third harness should be `half_open_with_probe_in_flight_refuses`, not `half_open_probe_in_flight_refuses` (current version is missing the `_with_`).
- **Fig 9:** the right-hand "dynamic routes" panel currently shows three example endpoints. Add a fourth bullet: `POST /tools/<arbitrary>` to make the agent-as-confused-deputy attack concrete.

### Standing conventions (do not violate)

1. **No figure numbers anywhere in the rendered figures.** The eyebrow is the thematic phrase only. The footer's `<span class="fig-num"></span>` wrapper stays in place (for layout stability) but its inner text is empty. LaTeX `\caption{}` will inject the figure number at typeset time. Do not add "Fig N" back.
2. **No em-dashes anywhere.** This is a hard rule across all ARYA materials. Use commas, colons, parentheses, or sentence breaks. The `&mdash;` HTML entity is acceptable inside footer descriptors where it predates this rule, but do not introduce new instances.
3. **Terminology.**
   - The system is the **Unfireable Safety Kernel** on first mention in any figure body or panel; subsequent same-figure mentions can be **"the Kernel"**. Never "Safety Kernel" alone.
   - The category is **escapable AI systems** (lowercase, no hyphen).
   - The taxonomic layer is **execution-time AI alignment** (hyphenated, lowercase).
4. **Palette.** Navy backgrounds (`--navy-900` / `--navy-800` / `--navy-950`), green (`--green-500`) for proof / kernel / operator / accept, pink (`--arya-pink-500`) reserved for the ARYA identity mark and brand moments only, red (`--danger`) reserved for the untrusted-agent side of any comparison. Do not introduce new accent colors.
5. **Typography.** Montserrat for display, JetBrains Mono for labels, mono-tracked codes (P1, P2, etc.), data references, and code identifiers. Do not introduce serif.
6. **Section refs.** The paper has been restructured. If a section ref appears anywhere it must be one of: §1, §2, §3, §4, §5, §6, §6.4, §7, §8, §8.1, §8.2, §9. Old refs (§5.1, §6.1, §7.4, §7.5) are stale and should be replaced if encountered.
7. **Competitor names.** Galileo Agent Control (Apache-2.0), Microsoft Agent Governance Toolkit, Microsoft Authorization Fabric, Saviynt Identity Security for AI, IETF draft-klrc-aiagent-auth. Do not paraphrase these to other names.
8. **Numerical claims.** 1000/1000 byte-equal fixtures, 17/17 cross-language adversarial parity, 80+ adversarial robustness tests, 4/4 Kani harnesses verified, ratio of capability investment to safety investment ~1000:1. These appear in Fig 5, Fig 7, and the README; do not alter them without verification against the paper. **Containment (Fig 11 to Fig 14, §6):** 6,240 authorization round-trips with 0 bypasses across the first three tiers (100 + 102 + 6,038); 9 self-modifications, every one kernel-mediated, in the full-application tier; 3,015 forgeries refused per live run; tier-one attack-taxonomy counts 30 / 24 (+3 ambiguous-by-design) / 11 / 11 / 8 / 6 / 4 / 3. Reason codes: directed_override, directed_blocked_by_kill_switch, policy.allowed, autonomy_human_only, api_action_forbidden. Do not alter without verification against the committed artifact JSON.

### How to deliver

Make the edits in place. Run the verifier sweep. Re-export the handoff bundle when done. Do not restructure the directory layout (`assets/`, `src/`, `design-canvas.jsx`, `index.html` at root, `src/app.jsx` as composition).

## End paste

---

## Notes for filling this in

**Scope tightly.** Claude Design works best when each correction names the figure, the location inside the figure, and the specific change. Vague requests like "make Fig 5 cleaner" tend to come back with more changes than you wanted. Specific requests like "Fig 5, Saviynt row, second-cell text" come back exactly as asked.

**Batch by file.** The three figure modules (`figures-conceptual.jsx`, `figures-architecture.jsx`, `figures-verification.jsx`) are independent. Sending all conceptual corrections in one batch and all architecture corrections in another reduces back-and-forth.

**When the paper restructures.** If section numbers shift again, update the table in this prompt and the section-refs whitelist in Standing Convention #6 before sending. The figures themselves only reference sections in their footers, which are easy to update, but the prompt needs to carry the latest map so the assistant doesn't reintroduce stale refs.

**When you change a numerical claim.** Update Standing Convention #8 with the new number before sending the correction. The current numbers came from the paper's §6 evaluation tables; if those tables change the figure callouts have to follow.

**When you want a structural change** (new figure, removed figure, reordered sections), say so explicitly and accept that re-export is needed. Don't try to disguise a structural change as a content correction; the assistant will produce confused results.

**To start a fresh session** (rather than continuing one), prepend: *"This is a fresh session. I have an existing handoff bundle for nine paper figures and I need targeted corrections. The full state is below."* Then paste the body above. Claude Design will rebuild context from the prompt itself.
