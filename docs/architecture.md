# Architecture

## Overview

The Safety Kernel is an **unfireable gate**: a small, hardened authorization
service that sits between every AI agent and every consequential action the
agent can take. It is a separate process, in a separate repository, with no
write path from the agent's runtime. The agent can ask the kernel for
permission — it cannot rewrite the kernel, redeploy it, or silently disable
it. That structural separation is the only property the kernel claims, and
everything below derives from it.

## The fail-closed property

The kernel guarantees one thing across every documented integration seam:

> If the kernel is unreachable, or the kernel responds with `DENY`, or any
> seam in front of the kernel fails to reach a definite `ALLOW`, the call
> is refused.

There is no silent allow. There is no "best effort" mode. There is no
exception path that returns success on timeout. Every seam is wired to
treat ambiguity as denial.

What the kernel **does**:

- Verifies that a requested action is on the allowlist for the caller's role.
- Signs an Ed25519 decision token (short-lived, bound to action + run + parameter fingerprint).
- Appends every allowed decision to an append-only, externally verifiable transparency log.
- Refuses every request it cannot decide.

What the kernel **does not** do:

- Verify the *correctness* of an AI model's output. The kernel decides
  whether the agent is allowed to invoke an action — not whether the
  action's content is good.
- Filter prompts, detect prompt injection, or score inputs for safety.
  Those are upstream concerns that sit *before* the agent reaches the
  kernel.
- Provide a general "AI alignment" guarantee. The kernel provides one
  structural property: fail-closed authorization across a process boundary
  the agent cannot rewrite.

## The four defense seams

```
   Agent / API client
        │
        ▼
   nginx auth_request   ← seam 1: coarse network-layer gate
        │
        ▼
   App middleware       ← seam 2: app-layer gate (FastAPI / axum)
        │
        ▼
   Dispatch hook        ← seam 3: per-tool gate (defense-in-depth)
        │
        ▼
   Client SDK           ← seam 4: circuit breaker, fail-closed on Unavailable
        │
        ▼
   Safety Kernel  ←→  Transparency log (Ed25519, append-only)
```

Each seam denies independently. A misconfigured seam is a configuration
bug; the getting-started guide (`docs/integration/getting-started.md`) is
the review surface that catches a missing seam before the integration
reaches production.

### Seam 1 — nginx `auth_request`

The outermost gate. Nginx receives the incoming request, issues a
sub-request to the kernel, and only forwards the request upstream if the
sub-request returns `2xx`. Any non-2xx (including the kernel being
unreachable) terminates the request at the edge with a 4xx or 5xx. This
seam catches misrouted traffic before it ever reaches application code.

### Seam 2 — App middleware

In-process middleware (FastAPI dependency, axum layer, equivalent in
other stacks) re-checks authorization against the kernel for every
request that reaches a protected handler. This catches the case where
nginx is bypassed (direct service-to-service traffic on the internal
network, or a developer running the app outside the production
ingress).

### Seam 3 — Dispatch hook

A per-tool / per-action gate sitting at the dispatch boundary inside the
agent's runtime. Before any sensitive function executes, the hook
verifies the action has a valid, unexpired, signed token from the
kernel. This seam exists because the same agent process may dispatch
many actions over the course of a single HTTP request, and each one
deserves its own authorization decision.

### Seam 4 — Client SDK circuit breaker

The kernel client SDK opens a circuit breaker after consecutive
`Unavailable` responses. While the breaker is open, every call returns
`DENY` locally — no network round trip, no chance for a partial failure
to leak through as a "soft allow". The breaker half-opens on a timer and
closes only after a successful probe. The default state on
initialization is **closed but unprimed** — the first probe must succeed
before any `ALLOW` is honored.

## Transparency log

Every `ALLOW` decision is appended to a tamper-evident transparency log.
The log is:

- **Ed25519-signed.** Each entry carries the kernel's signature; the
  log structure carries a Merkle-style chain so a verifier can audit
  any single entry against the head without trusting the log server.
- **Append-only.** The log service refuses overwrites. Compaction (if
  any) is operator-driven and itself audited.
- **Externally verifiable.** Anyone with the operator public key can
  verify any entry. The verifier does not need to trust the kernel or
  the log — only the pinned public key.

Key custody splits cleanly:

| Key | Held by | Used for |
|---|---|---|
| Operator signing key | Operator (HSM / KMS / offline) | Authorizing kernel releases, rotating kernel keys |
| Kernel signing key | The running kernel binary | Signing decision tokens and log entries |

The kernel **signs** decision tokens and log entries with its own key.
The kernel **verifies** that its own key has been authorized by the
operator key — but never holds the operator key. An attacker who roots
a kernel host cannot mint a new authorized kernel identity; they can
only sign with the existing kernel key, which the operator can revoke
and rotate out.

## Reconciler

A background worker (`qorch-safety-kernel-reconciler` in this repo)
periodically reconciles the set of actions the kernel *believes* it has
allowed against the entries actually present in the transparency log.

The reconciler exists because:

1. The kernel could in principle issue a token but fail to log it
   (network partition between kernel and log, crash mid-write, etc.).
2. The log could in principle be ahead of the kernel's local view
   (replication lag, restart timing).
3. A discrepancy is itself an actionable signal: it means at least one
   of the two systems has lost durability, and the deployment is no
   longer in the fully-verifiable state.

When the reconciler finds a discrepancy, it raises an alert. It does
not attempt to "fix" the log — append-only means any repair is itself
an auditable operator action.

## Process boundary

The kernel runs as a separate binary (`qorch-safety-kernel`) in a
separate process, typically a separate container with no shared
filesystem with the agent runtime. The agent process can:

- Open a TCP/Unix-socket connection to the kernel.
- Send authorization requests over the documented contract.
- Receive signed decision tokens or denial responses.

The agent process **cannot**:

- Write to the kernel binary on disk.
- Send signals to the kernel process.
- Modify the kernel's configuration at runtime.
- Read the kernel's signing key material.

This boundary is the foundation of every other property. It is enforced
by the operating system's process model, by container isolation, and by
the deployment topology — not by code inside the kernel itself.

## Threat model summary

The kernel's threat model treats everything below the process boundary
as potentially compromised, including the agent runtime, the application
code, and any data the agent has touched. The kernel itself, its release
pipeline, the operator key custody, and the reviewers who approve
releases are the trusted boundary.

For the full adversary-by-adversary breakdown — network attackers,
compromised application code, tampered binaries, substituted keys,
replay attacks, caller-language bypass, and the explicit out-of-scope
items — see [`docs/security/threat-model.md`](security/threat-model.md).

## What's out of scope

The kernel is deliberately small. The following are **not** the
kernel's job, and integrating with the kernel does not solve them:

- **Input filtering and prompt-injection detection.** The kernel
  authorizes actions; it does not score prompts. Input safety belongs
  to a layer that runs before the agent reaches the kernel.
- **Model behavior verification.** The kernel cannot tell you whether
  a model output is correct, calibrated, or aligned. It only tells
  you whether the action the model wants to invoke is on the
  allowlist.
- **General application authorization (RBAC, ABAC, row-level security).**
  The kernel covers consequential, agent-initiated actions. Standard
  human-user authorization for normal API surfaces should use standard
  tools.
- **Secret management.** The kernel verifies that an action is
  allowed; it does not store or vend secrets to the calling process.

These are upstream concerns. They compose with the kernel — they do
not replace it.
