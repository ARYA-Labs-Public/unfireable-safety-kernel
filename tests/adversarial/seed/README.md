# Adversarial-Fixture Seed Set

Status: seed-wave deliverable for [ARY-1887](https://linear.app/aryalabs/issue/ARY-1887) AC1. See [`../../../docs/release-gate/af-taxonomy.md`](../../../docs/release-gate/af-taxonomy.md) for the canonical 7-class taxonomy this directory implements.

## What lives here

| File | AF class | Language | What the synthetic fake is |
|---|---|---|---|
| `af_tee_DEFERRED.md` | AF-tee | n/a | Documents that TEE attestation is v2.0 scope per [ARY-1886](https://linear.app/aryalabs/issue/ARY-1886). The coverage script treats this as "deferred," not "missing." |
| `../python/af_image_seed.py` | AF-image | Python | Python mirror of the Dockerfile structural lint. |
| `../python/af_key_seed.py` | AF-key | Python | Python mirror of the pinned-key forged-token rejection. |
| `../python/af_reconciler_seed.py` | AF-reconciler | Python | Python counterpart to the existing Rust `purple_manifest_replay.rs` campaigns — replays a stale signed manifest, asserts REJECT. |
| `../python/af_tlog_seed.py` | AF-tlog | Python | Python counterpart to the existing Rust `purple_forged_sth.rs` campaigns — sends a forged-STH-flavored response, asserts REJECT. |
| `crates/services/safety-kernel/tests/seed_af_image.rs` | AF-image | Rust | A Dockerfile string that violates structural properties of `Dockerfile.prod` — asserts the structural lint REJECTS. (Lives under the crate's `tests/` dir so Cargo picks it up as a test target.) |
| `crates/adapters/safety_kernel_client/tests/seed_af_key.rs` | AF-key | Rust | A token signed by a non-pinned Ed25519 key — asserts `PinnedKeyVerifier` REJECTS. (Complementary to the existing `FORGED_ED25519_TOKEN` fixture; this file is the canonical seed entry for the taxonomy. Lives under the crate's `tests/` dir.) |

## What the seeds intentionally are NOT

These fixtures are **skeleton + one rejection per AF class**. They are **not** exhaustive attack matrices. The release-gate v1.0 (ARY-1885/1886/1889/1890) populates each class to full coverage during its own wave. The seed wave's contract: *every AF class has at least one fixture that fails closed against a synthetic fake.*

## The contract `scripts/audit_adversarial_coverage.sh` enforces

For each of the 7 AF classes, the script must find at least one Rust fixture AND at least one Python fixture, OR an explicit deferral stub (only `AF-tee` qualifies in v1.0). Any class without satisfying evidence exits 1 with `MISSING: <class>`. The script runs in CI on every PR.

## How to extend

When ARY-1885/1886/1889/1890 add new adversarial fixtures, place them under `tests/adversarial/<crate>/` for Rust (existing per-crate convention) or `tests/adversarial/python/<area>/` for Python. The coverage script discovers them by file-name prefix (`af_<class>_*`).
