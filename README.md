# The Unfireable Safety Kernel

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.84%2B-orange)](rust-toolchain.toml)
[![Status: extraction](https://img.shields.io/badge/status-public%20extraction-yellow)](#status)
[![paper](https://img.shields.io/badge/paper-arXiv-b31b1b)](#paper)

A fail-closed, machine-checked authorization service for AI agents and other escapable AI systems.

The Unfireable Safety Kernel is a separate, compiled Rust process that sits between every AI agent and every consequential action the agent can take. The agent cannot reach it, cannot reconfigure it, cannot kill it, and cannot run without it. If the kernel says DENY, the action is denied. If the kernel is unreachable, the action is denied. If the kernel is not configured at boot, the agent itself refuses to start. If the kernel says ALLOW, the action proceeds *and* an entry is appended to an append-only Ed25519-signed transparency log under an operator key the kernel does not hold.

## Why this exists

Today's AI safety controls (system prompts, output filters, guardrail libraries) execute inside the agent's own runtime. Anything the agent can read, the agent can rewrite; anything the agent invokes, the agent can refuse to invoke. The same architectural failure mode applies to any AI system with sufficient reach into its own runtime to bypass the controls placed on it: tool-using agents, code-generating systems with execution access, self-modifying systems, multi-agent ensembles. We call this category *escapable AI systems*.

We treat the agent's runtime as untrusted by construction. The Unfireable Safety Kernel realizes four properties together that, to the best of our knowledge, no other shipped agent control plane provides:

1. **Process separation.** The kernel runs in a process distinct from the agent. The agent has no write access to the kernel's code, configuration, decision logic, or persistent state.
2. **Pre-action enforcement on a structurally-only path.** Four defense-in-depth seams (nginx, app middleware, dispatch hook, client SDK) sit on the only path between the agent and consequential action. The agent does not get to choose whether to invoke them; the deployment makes no other path exist.
3. **Fail-closed at request and system levels.** Unreachable → deny. Errored → deny. Unparseable response → deny. Bad signature → deny. *No kernel → no agent:* the agent process refuses to start if the kernel is not reachable, and halts consequential action if the kernel becomes unreachable.
4. **Externalized signed evidence.** Every ALLOW appends a signed entry to an append-only transparency log. The chain is signed by an operator key held outside the kernel, even a compromised kernel cannot forge log entries that verify under the operator public key.

The fail-closed invariant is **machine-checked over the production Rust code path** by Kani bounded model checking (4 `#[kani::proof]` harnesses, 0 failures), in addition to an SMT proof of the same property over a symbolic model.

## Paper

This implementation accompanies the paper *The Unfireable Safety Kernel: Execution-Time AI Alignment for AI Agents and Other Escapable AI Systems* (Dobrin, ARYA Labs PBC, 2026), posted to arXiv as cs.AI with cs.CR cross-list.

- arXiv: `<arxiv-id-pending>`
- Title: *The Unfireable Safety Kernel: Execution-Time AI Alignment for AI Agents and Other Escapable AI Systems*

The paper names the architectural layer this implementation occupies: **execution-time AI alignment**, distinct from training-time alignment (RLHF, Constitutional AI) and inference-time alignment (prompts, filters, guardrails). It is the layer at which what the agent is *permitted to do* is constrained by an architecture the agent cannot reach.

## At a glance

| Property | Result |
|---|---|
| License | Apache-2.0 |
| Implementation language | Rust 1.84+ (`#![forbid(unsafe_code)]`) |
| TLS stack | rustls (native-tls and OpenSSL banned via `deny.toml`) |
| Python-to-Rust migration: byte-equivalent fixtures | 1000 / 1000 |
| Python-to-Rust migration: adversarial reject parity | 17 / 17 |
| Shipped Rust adversarial corpus | 80+ tests |
| Machine-checked fail-closed (Kani harnesses) | 4 / 4 verified |
| In production at | ARYA Labs PBC |
| Threat model | §2 of the paper |

## Architecture

```
   Agent / API client                                   (untrusted)
        |
        |  <-- system-level fail-closed:
        |      no kernel, no agent (process refuses to start)
        v
   nginx auth_request    (coarse network-layer gate)
        |
        v
   App middleware        (axum / FastAPI)
        |
        v
   Dispatch hook         (per-tool gate)
        |
        v
   Client SDK            (circuit breaker, fail-closed on Unavailable)
        |
        v
   Unfireable Kernel  <-->  Transparency log
   (separate Rust         (Ed25519 append-only,
    binary, agent          operator-signed,
    cannot reach)          externally verifiable)
```

![The four-seam architecture. Four defense-in-depth seams deny independently; the kernel sits behind them as a separate Rust process with the transparency log and binary attestation alongside.](docs/figures/fig-2-four-seams.png)

Four seams, each independently denying on error. An action proceeds only if every seam permits it. See [`docs/architecture.md`](docs/architecture.md) for the full design and [`docs/figures/`](docs/figures/) for the full set of paper figures.

## Status

This repository is the **public extraction** of the Unfireable Safety Kernel architecture in active production at ARYA Labs.

**What is shipped:**

- `contracts/openapi/safety_kernel.yaml`, the API contract, single source of truth
- `crates/services/safety-kernel/`, the kernel binary (axum + tokio)
- `crates/services/transparency-log/`, append-only Ed25519-signed audit log
- `crates/services/safety-kernel-reconciler/`, background reconciliation worker (binary attestation, drift detection)
- `crates/domain/src/safety/`, pure types and traits (no I/O, enforced by `agent/boundaries.toml`)
- `crates/adapters/safety_kernel_client/`, Rust client SDK with fail-closed circuit breaker
- `crates/adapters/transparency_store/`, Postgres-backed transparency log storage
- `py-defense/`, Python `safety_kernel_defense` library (audit hook + subprocess propagation, stdlib-only)
- `examples/`, reference integrations (FastAPI middleware, axum tower::Layer, nginx auth_request, mock kernel + adversarial fixtures, end-to-end reference apps in Python and Rust)
- `docs/`, architecture, integration guides, deployment, OpenAPI navigation

**Not yet shipped:**

- Crates are not on crates.io yet. Build from source (instructions below).
- The Python defense library is not on PyPI yet. Install from `py-defense/`.
- The workspace's `crates/domain/Cargo.toml` manifest is not present in this initial extraction. Source is, but you may need to author the manifest for `cargo build --workspace`. Tracked for v1.0.
- Docker Hub mirror (`aryalabs/safety-kernel`) lands when the `DOCKERHUB_TOKEN` secret is provisioned. GHCR is the canonical public registry until then (see Quickstart below).
- External red-team evaluation against a live deployment. Adversarial fixtures pass in CI; a live evaluation by an unaffiliated party is the right next step and we are actively seeking partners. Contact `security@aryalabs.io`.

## Quickstart (Docker)

Multi-arch (amd64 + arm64) images publish to GHCR on every push to `main` and every release tag. The image is distroless, runs as non-root uid 65532, and weighs in under 60 MB.

```bash
# 1. Generate an operator Ed25519 keypair (one-time, store the private key offline)
openssl genpkey -algorithm Ed25519 -out operator.key
openssl pkey -in operator.key -pubout -outform DER \
  | tail -c 32 | xxd -p -c 64 > operator.pub.hex

# 2. Pull the kernel image (no GHCR login needed for public pulls)
docker pull ghcr.io/arya-labs-pbc/unfireable-safety-kernel:edge

# 3. Run with hardening flags (read-only root FS, all caps dropped, no-new-privs)
docker run --rm \
  --name safety-kernel \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --user 65532:65532 -p 9000:9000 \
  -e KERNEL_OPERATOR_PUBKEY="$(cat operator.pub.hex)" \
  -e KERNEL_BIND="0.0.0.0:9000" \
  ghcr.io/arya-labs-pbc/unfireable-safety-kernel:edge

# 4. Smoke test
curl -fsS http://localhost:9000/health
```

For a complete deployment stack (kernel + transparency log + persistent volume + healthchecks), use [`deployment/docker-compose.prod.yml`](deployment/docker-compose.prod.yml):

```bash
export OPERATOR_PUBKEY="$(cat operator.pub.hex)"
docker compose -f deployment/docker-compose.prod.yml up -d
```

Image tags:
- `:edge` — latest `main`
- `:vX.Y.Z` — release tags (`:latest` points at the most recent semver tag)
- Pin to a digest in production: `ghcr.io/arya-labs-pbc/unfireable-safety-kernel@sha256:<digest>`

See [`docs/deployment/docker.md`](docs/deployment/docker.md) for the complete hardening checklist (read-only FS, distroless rationale, egress allowlist, image-signature verification).

## Quickstart (build from source)

If you prefer to build from source — e.g. running on an architecture other than amd64/arm64, or modifying the kernel for your own deployment — the same binary is buildable from the workspace:

```bash
# 1. Clone
git clone https://github.com/ARYA-Labs-PBC/unfireable-safety-kernel.git
cd unfireable-safety-kernel

# 2. Generate an operator Ed25519 keypair (one-time, store the private key offline)
openssl genpkey -algorithm Ed25519 -out operator.key
openssl pkey -in operator.key -pubout -outform DER \
  | tail -c 32 | xxd -p -c 64 > operator.pub.hex

# 3. Build the kernel
cargo build --release -p qorch-safety-kernel

# 4. Run
./target/release/qorch-safety-kernel \
  --operator-pubkey "$(cat operator.pub.hex)" \
  --bind 127.0.0.1:9000

# 5. Smoke test
curl -fsS http://localhost:9000/health
```

For a working integration in roughly 10 minutes, see [`docs/integration/getting-started.md`](docs/integration/getting-started.md).

For Python adopters, install the audit-hook library directly from the repo:

```bash
pip install ./py-defense
```

See [`docs/integration/python-fastapi.md`](docs/integration/python-fastapi.md) for the FastAPI middleware integration.

## Verification

The fail-closed invariant is discharged as a machine-checked theorem at two levels.

**SMT model (Z3).** The fail-closed contract is encoded as a first-order theorem over a symbolic model of the gate. Z3 finds the negation unsatisfiable in Arm A (the safety contract), and confirms the fail-open configuration is reachable in Arm B (non-vacuity), so Arm A is not vacuously true.

**Bounded model checking (Kani) on the actual Rust code path.** The circuit breaker's pre-call decision is factored into a pure function, `gate_decision(state, cooldown_elapsed, probe_in_flight) -> GateDecision`. Four `#[kani::proof]` harnesses verify it exhaustively over the symbolic input domain:

| Harness | Property |
|---|---|
| `open_within_cooldown_always_refuses` | in `Open` with cooldown not elapsed, the gate refuses for every `probe_in_flight` |
| `open_permits_only_after_cooldown` | no permit is reachable from `Open` unless cooldown has elapsed |
| `half_open_with_probe_in_flight_refuses` | the single-probe gate refuses a second concurrent probe |
| `permit_characterization_is_exhaustive` | a permit is reachable only from `Closed`, `HalfOpen`-without-probe, or `Open`-after-cooldown |

Result: `4 successfully verified harnesses, 0 failures`. The proof binds to the shipped code path because `before_call` delegates to the verified function rather than reimplementing the decision. Run locally with `cargo kani` if you have Kani installed; the same characterization is encoded as a concrete twelve-case exhaustive unit test that runs under plain `cargo test`.

![Two-level fail-closed proof. Z3 discharges the safety contract over a symbolic model (Arm A by negation-unsat) plus non-vacuity (Arm B). Kani discharges the production Rust gate_decision function over the full symbolic input domain. The shipped before_call delegates to the verified function, so the proof binds to the production code path.](docs/figures/fig-7-two-level-verification.png)

## How this relates to other agent control systems

Several systems shipping in 2026 occupy the agent control plane space. They differ from the Unfireable Safety Kernel on one structural property:

| System | Open source | Process separation | Structurally-only path | Machine-checked fail-closed |
|---|---|---|---|---|
| Galileo Agent Control | Apache-2.0 | No (in-process via decorators/plugins) | No | No |
| Microsoft Agent Governance Toolkit | MIT | No (framework extension points) | No | No |
| Microsoft Authorization Fabric (reference pattern) | n/a (blog POC) | Decision out-of-process; enforcement in-process | No | No |
| Saviynt Identity Security for AI | Closed | (identity layer, orthogonal) | (n/a) | No |
| **Unfireable Safety Kernel** | **Apache-2.0** | **Yes (separate Rust binary)** | **Yes (deployment construction)** | **Yes (Kani 4/4)** |

In each of these systems, the agent is the party that decides whether to invoke the control. In the Unfireable Safety Kernel, the agent does not have that choice: the kernel sits on the only path between agent and consequential action by deployment construction, the wiring checklist rejects deployments that omit a seam, and the agent process refuses to start without the kernel.

**This makes them complementary, not competing.** Systems like Galileo Agent Control are strong where the kernel is deliberately minimal: rich content-aware and behavioral policy authoring, multi-step observability, framework-native ergonomics. The kernel is strong where they are structurally limited: a fail-closed enforcement point the agent cannot route around. The natural composition uses the kernel as the unavoidable choke point and lets an external system supply the policy logic evaluated there, giving those policies a non-bypassable execution site. We would welcome that collaboration; see §7 of the paper and the policy-layer composition item in §8.3.

![The agent governance stack. Identity systems answer who the agent is; policy-authoring and behavioral-guardrail systems answer what is allowed; both are bypassable in their native in-process deployment. The Unfireable Safety Kernel is the execution-time enforcement layer, the single layer the agent cannot route around, and it makes the decisions of the layers above it non-bypassable.](docs/figures/fig-10-governance-stack.png)

## Repository layout

| Path | Purpose |
|---|---|
| `crates/services/safety-kernel/` | The kernel binary (axum + tokio) |
| `crates/services/transparency-log/` | Append-only Ed25519-signed audit log |
| `crates/services/safety-kernel-reconciler/` | Binary attestation & drift-detection worker |
| `crates/domain/src/safety/` | Pure types & traits (no I/O) |
| `crates/adapters/safety_kernel_client/` | Rust client SDK + circuit breaker |
| `crates/adapters/transparency_store/` | Postgres-backed transparency-log storage |
| `contracts/openapi/safety_kernel.yaml` | API contract (source of truth) |
| `py-defense/` | Python defense library (FastAPI middleware + audit hook) |
| `examples/middleware/` | FastAPI, gRPC, nginx, dispatch-hook integrations |
| `examples/observability/` | Prometheus metrics + Grafana dashboards |
| `examples/policy/` | Three-tier policy DSL example |
| `examples/reference_app/` & `examples/reference_app_rs/` | End-to-end reference apps in Python and Rust |
| `examples/testing/` | Mock kernel + adversarial fixtures |
| `docs/` | Architecture, integration, deployment, API |
| `agent/boundaries.toml` | Domain-crate import policy (CI-enforced) |
| `deny.toml` | Dependency policy (native-tls/OpenSSL banned) |

## Documentation

- [`docs/architecture.md`](docs/architecture.md), design overview, defense seams, transparency log, threat model
- [`docs/integration/getting-started.md`](docs/integration/getting-started.md), 10-minute walkthrough
- [`docs/integration/python-fastapi.md`](docs/integration/python-fastapi.md), FastAPI middleware
- [`docs/integration/rust-axum.md`](docs/integration/rust-axum.md), axum `tower::Layer`
- [`docs/integration/nginx.md`](docs/integration/nginx.md), nginx `auth_request` gate
- [`docs/integration/circuit-breaker.md`](docs/integration/circuit-breaker.md), fail-closed client pattern
- [`docs/deployment/docker.md`](docs/deployment/docker.md), Dockerfile and compose
- [`docs/api/openapi.md`](docs/api/openapi.md), API spec navigation

## Citing

If you use the Unfireable Safety Kernel in research, please cite the accompanying paper:

```bibtex
@misc{dobrin2026unfireable,
  title  = {The Unfireable Safety Kernel: Execution-Time AI Alignment for AI Agents and Other Escapable AI Systems},
  author = {Dobrin, Seth},
  year   = {2026},
  eprint = {arxiv-id-pending},
  archivePrefix = {arXiv},
  primaryClass  = {cs.AI},
  howpublished  = {\url{https://github.com/ARYA-Labs-PBC/unfireable-safety-kernel}}
}
```

## Security

Report security issues privately to **security@aryalabs.io**. Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md) for the full disclosure policy.

We are actively seeking external red-team engagement against a live deployment. Adversarial fixtures pass in CI; we believe the architecture survives the threat model in §2 of the paper, and we want to be shown where we are wrong. Contact `security@aryalabs.io`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, sign-off requirements, and contribution scope. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community standards.

Standards engagement on the architectural distinction between identity (OAuth/WIMSE-shaped, correct) and action authorization (operator-side, structurally-only-path, not OAuth-client-shaped) is a particular area where collaborators are welcome. The IETF draft-klrc-aiagent-auth and its successors will shape how agent authorization is built into the protocol layer for the next decade; we intend to engage that process directly. Contact `seth@aryalabs.io` if you are part of the standards-track conversation.

## License

Apache-2.0. See [LICENSE](LICENSE).

## About

Built by [ARYA Labs PBC](https://aryalabs.io), a Delaware Public Benefit Corporation whose chartered public benefit is the safe deployment of AI. The Unfireable Safety Kernel is the execution-time AI alignment substrate for ARYA's broader work on constrained deterministic AI for mission-critical industries.

Authorization architecture is not a competitive advantage. It is plumbing. We want every escapable AI system to have a kernel.
