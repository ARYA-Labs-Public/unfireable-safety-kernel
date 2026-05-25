# Security Policy

The Safety Kernel exists to be the trustworthy authorization seam in an AI
system. Security reports are the highest-priority class of issue this project
accepts.

## Reporting a Vulnerability

**Do not open a public issue for a security vulnerability.** Public issues
become advisories the moment they are filed.

Report privately by one of the following channels:

1. **Email** — send to **security@aryalabs.io**. Encrypt with PGP if you
   prefer; the public key fingerprint is published below.
2. **GitHub Security Advisory** — file a private advisory at
   [https://github.com/ARYA-Labs-PBC/safety-kernel/security/advisories/new](https://github.com/ARYA-Labs-PBC/safety-kernel/security/advisories/new).

A good report includes:

- A description of the vulnerability and the impact you believe it has.
- Steps to reproduce, ideally as a minimal failing test case.
- Affected versions or commit SHAs.
- Any suggested remediation.

## Response SLA

| Stage | Target |
|---|---|
| Initial acknowledgment | within **3 business days** of receipt |
| Triage decision (accepted / declined / needs-info) | within **10 business days** |
| Fix landed and released | varies by severity; tracked in the private advisory |

## Coordinated Disclosure Window

The default disclosure window is **90 days** from the date we acknowledge
your report. Within that window we will:

- Investigate, develop a fix, and validate it.
- Coordinate a release that includes the fix.
- Publish a security advisory with credit to the reporter (with permission).

If a vulnerability is **actively being exploited in the wild**, we reserve
the right to extend the embargo as needed to protect adopters, in
coordination with the reporter. We will not extend embargoes simply
because a fix is inconvenient to ship.

## Scope

In scope for this policy:

- The kernel binary (`crates/services/safety-kernel/`).
- The transparency log service (`crates/services/transparency-log/`).
- The reconciler worker (`crates/services/safety-kernel-reconciler/`).
- The Rust client SDK (`crates/adapters/safety_kernel_client/`).
- The Python defense crate (`py-defense/`).
- The OpenAPI contract (`contracts/openapi/safety_kernel.yaml`).
- The reference examples (`examples/`) when used as documented.

Out of scope:

- Anything outside this repository.
- Configuration errors in adopter deployments (e.g. a kernel deployed
  without mTLS). These are documentation issues; please file a normal
  issue or PR.
- Vulnerabilities in third-party dependencies that have an upstream fix.
  We track these via Dependabot; please prefer reporting upstream.
- Theoretical attacks that require already-root access on the host.

## PGP Key

PGP key for `security@aryalabs.io`: **TBD — coming with v1.0 release.**
Until then, email-only reports are fine. GitHub Security Advisories are
encrypted at rest by GitHub.

## Acknowledgments

We credit reporters in the release notes accompanying the fix, with their
permission. If you would prefer to remain anonymous, please say so in your
report and we will respect that.

## Hardening Reports

If you are deploying the kernel and want a second pair of eyes on your
wiring, you can request a hardening review by opening a Discussion at
[https://github.com/ARYA-Labs-PBC/safety-kernel/discussions](https://github.com/ARYA-Labs-PBC/safety-kernel/discussions).
These are not vulnerability reports and do not trigger this policy; they
are best-effort community help.
