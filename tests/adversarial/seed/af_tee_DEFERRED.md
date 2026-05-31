# AF-tee — DEFERRED (v2.0)

`AF-tee` covers TEE attestation forgery: attacker-signed quote, replayed
quote, runtime measurement mismatch against the expected enclave
identity.

## Why deferred

[ARY-1886](https://linear.app/aryalabs/issue/ARY-1886) targets commodity hardware for v1.0. TEE / TDX / SEV-SNP attestation is documented in that issue's "Long-term roadmap" section but is **not** in scope for v1.0 acceptance criteria. The deployment surface that AF-tee would attack does not exist in the v1.0 build.

## What unblocks AF-tee

A separate epic (TEE roadmap, post-v1.0) that:

1. Adds TEE attestation to the kernel boot path (Intel TDX / AMD SEV-SNP / AWS Nitro).
2. Defines the kernel's expected quote-verification path (where the AF-tee fixtures will sit).
3. Identifies a customer or regulator (FDA Class III, defense, finance Tier-1) that requires hardware-attested deployment.

Until that epic opens, AF-tee remains a documented gap. `scripts/audit_adversarial_coverage.sh` reads this file's presence as the deferral signal and does NOT fail the coverage check.

## What this file is

A marker. Its existence in `tests/adversarial/seed/` tells the coverage script "AF-tee has been considered and explicitly deferred to v2.0; do not block the release gate on missing fixtures for this class."
