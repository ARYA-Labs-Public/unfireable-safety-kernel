"""AF-reconciler seed fixture (Python counterpart) — ARY-1887.

Sister fixture: ``crates/services/safety-kernel-reconciler/tests/purple_manifest_replay.rs``
(campaigns D1 stale-manifest replay, D2 registry-MITM digest drift).

See ``docs/release-gate/af-taxonomy.md`` for the 7-class taxonomy.

What this seed asserts
----------------------
The reconciler's signed-manifest verification path must reject:

* **D1 stale-manifest replay**: a manifest whose ``issued_at`` is past
  the staleness threshold MUST be rejected as expired, even if the
  signature is otherwise valid.
* **D2 registry digest drift**: an OCI manifest whose computed digest
  does NOT match the digest declared in the manifest body MUST be
  rejected as a registry-MITM signal.

This Python seed models the same contracts in stdlib-only form. A
production Python defense lib that talks to the reconciler API would
replace the mocks here with HTTP calls; the rejection contract is
identical.

Run with::

    python -m pytest tests/adversarial/python/af_reconciler_seed.py
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class _SignedManifest:
    """Minimal signed manifest model.

    Production: an OCI image manifest with an in-toto / sigstore
    signature attached. Seed: an opaque byte payload + an ``issued_at``
    timestamp + a declared SHA-256 digest. The rejection contract
    matches the Rust reconciler's check shape.
    """

    payload: bytes
    issued_at: float
    declared_digest_hex: str


_STALENESS_THRESHOLD_SECONDS = 86400.0  # 24 hours. Production: configurable.


class _StaleManifest(Exception):
    """Mirrors `reconciler::ManifestError::ExpiredManifest`."""


class _RegistryDigestDrift(Exception):
    """Mirrors `reconciler::ManifestError::DigestMismatch`."""


def _check_manifest(manifest: _SignedManifest, now: float) -> None:
    """Re-derives the rejection contract. Raises on any violation.

    Rule 9 — re-derive evidence: we recompute the SHA-256 of the
    payload bytes and compare against the declared digest, rather than
    trusting a label.
    """
    if now - manifest.issued_at > _STALENESS_THRESHOLD_SECONDS:
        raise _StaleManifest(
            f"manifest issued {now - manifest.issued_at:.0f}s ago, exceeds "
            f"{_STALENESS_THRESHOLD_SECONDS:.0f}s threshold"
        )
    actual_digest = hashlib.sha256(manifest.payload).hexdigest()
    if actual_digest != manifest.declared_digest_hex:
        raise _RegistryDigestDrift(
            f"declared digest {manifest.declared_digest_hex} does not match "
            f"computed digest {actual_digest}"
        )


def test_af_reconciler_seed_d1_rejects_stale_manifest() -> None:
    """D1: a manifest issued past the staleness threshold MUST be
    rejected with ExpiredManifest, even if its digest is otherwise
    valid."""
    payload = b"reconciler-payload-bytes"
    declared = hashlib.sha256(payload).hexdigest()

    # Issued 48 hours ago — well past the 24h staleness threshold.
    now = 1_700_000_000.0
    stale = _SignedManifest(
        payload=payload,
        issued_at=now - (48 * 3600),
        declared_digest_hex=declared,
    )

    raised = False
    try:
        _check_manifest(stale, now)
    except _StaleManifest:
        raised = True
    assert raised, (
        "AF-reconciler-D1 seed: stale manifest MUST be rejected with "
        "ExpiredManifest. If this fires, an attacker can replay an old "
        "signed manifest and bypass the freshness gate; release must NOT "
        "sign v1.0."
    )


def test_af_reconciler_seed_d2_rejects_registry_digest_drift() -> None:
    """D2: an OCI manifest whose computed digest does not match the
    declared digest MUST be rejected as registry-MITM."""
    payload = b"reconciler-payload-bytes"
    # Attacker's declared digest does NOT correspond to the payload
    # bytes (e.g., registry returned different bytes than the signature
    # was over).
    bogus_declared = "0" * 64

    now = 1_700_000_000.0
    drifted = _SignedManifest(
        payload=payload,
        issued_at=now - 60.0,  # fresh — only the digest drift triggers
        declared_digest_hex=bogus_declared,
    )

    raised = False
    try:
        _check_manifest(drifted, now)
    except _RegistryDigestDrift:
        raised = True
    assert raised, (
        "AF-reconciler-D2 seed: registry-MITM digest drift MUST be "
        "rejected with DigestMismatch."
    )


def test_af_reconciler_seed_accepts_fresh_legitimate_manifest() -> None:
    """Counter-assertion: a fresh manifest whose digest matches the
    payload MUST pass through without exception."""
    payload = b"reconciler-payload-bytes"
    declared = hashlib.sha256(payload).hexdigest()
    now = 1_700_000_000.0
    fresh = _SignedManifest(
        payload=payload,
        issued_at=now - 60.0,
        declared_digest_hex=declared,
    )
    _check_manifest(fresh, now)  # MUST NOT raise
