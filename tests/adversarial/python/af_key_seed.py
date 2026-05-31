"""AF-key seed fixture — ARY-1887 release-gate adversarial taxonomy.

Sister fixture: ``crates/adapters/safety_kernel_client/tests/seed_af_key.rs``.

See ``docs/release-gate/af-taxonomy.md`` for the 7-class taxonomy.

What this seed asserts
----------------------
The Python client-side defence contract: a pinned-key verifier MUST
refuse a kernel-issued token whose signature does not match the key
pinned at construction time. This is the structural defence against
operator key substitution at the client side.

Stdlib-only by design
---------------------
The full reference implementation in
``crates/adapters/safety_kernel_client/src/token.rs`` uses
``ed25519-dalek``. The Python ``safety_kernel_defense`` package
ships stdlib-only (no ``cryptography`` dep). For the seed, we
exercise the **rejection contract** via a minimal in-process
verifier protocol and a synthetic-fake token signed by a
non-pinned key (modeled as a different opaque byte string).

The seed proves the SLOT exists in the taxonomy and documents the
contract for ARY-1885/1886/1889/1890 to extend with a real
``cryptography``-backed implementation if the v1.0 release-gate
adds a Python defense lib that does token verification.

Run with::

    python -m pytest tests/adversarial/python/af_key_seed.py
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass


@dataclass(frozen=True)
class _MockToken:
    """Stand-in for a kernel-issued token. The signature is an HMAC over
    the claims bytes, keyed by the kernel's "signing key" (modeled here
    as opaque bytes, since stdlib lacks Ed25519). The rejection
    semantics are identical: signature does not verify under the
    pinned-key → reject."""

    claims_bytes: bytes
    signature: bytes


def _sign(claims_bytes: bytes, signing_key: bytes) -> _MockToken:
    sig = hmac.new(signing_key, claims_bytes, hashlib.sha256).digest()
    return _MockToken(claims_bytes=claims_bytes, signature=sig)


class _PinnedKeyVerifier:
    """Minimal mock that models the same rejection contract as the Rust
    ``PinnedKeyVerifier`` in
    ``crates/adapters/safety_kernel_client/src/token.rs``.

    Production: Ed25519 signature verification against a pinned 32-byte
    public key.

    Seed: HMAC-SHA256 verification against a pinned 32-byte symmetric
    key. The *contract* is identical: reject any token whose signature
    does not verify under the pinned key.
    """

    def __init__(self, pinned_key: bytes) -> None:
        if len(pinned_key) != 32:
            raise ValueError("pinned key must be 32 bytes")
        self._pinned_key = pinned_key

    def verify(self, token: _MockToken) -> bool:
        expected = hmac.new(
            self._pinned_key, token.claims_bytes, hashlib.sha256
        ).digest()
        return hmac.compare_digest(token.signature, expected)


def test_af_key_seed_rejects_token_signed_with_non_pinned_key() -> None:
    """The pinned-key verifier MUST reject a token signed by a non-
    pinned key. This is the structural defence against operator key
    substitution."""
    pinned_key = b"\x07" * 32
    attacker_key = b"\x99" * 32

    claims_bytes = b'{"action": "af_key_seed", "subject": "worker"}'
    attacker_token = _sign(claims_bytes, attacker_key)

    verifier = _PinnedKeyVerifier(pinned_key)
    accepted = verifier.verify(attacker_token)

    # Rule 9: we re-derive the rejection by recomputing the HMAC and
    # comparing constant-time, not by regex-matching a log line.
    assert not accepted, (
        "AF-key seed: pinned-key verifier MUST reject a token signed by "
        "a non-pinned key. The kernel-pinning property is the structural "
        "defence against operator key substitution; if this fires, the "
        "release gate must NOT sign v1.0."
    )


def test_af_key_seed_accepts_token_signed_with_pinned_key() -> None:
    """Counter-assertion: the seed REJECTS forged tokens AND ACCEPTS
    legitimate ones. Without this, the seed could pass by rejecting all
    tokens (false-negative)."""
    pinned_key = b"\x07" * 32

    claims_bytes = b'{"action": "af_key_seed", "subject": "worker"}'
    legitimate_token = _sign(claims_bytes, pinned_key)

    verifier = _PinnedKeyVerifier(pinned_key)
    accepted = verifier.verify(legitimate_token)

    assert accepted, (
        "AF-key seed counter-assertion: legitimate token signed by the "
        "pinned key MUST verify."
    )


def test_af_key_seed_rejects_tampered_claims_under_legitimate_key() -> None:
    """A token whose claims are tampered with after signing MUST be
    rejected even if the signature was originally legitimate. This
    catches MITM that doesn't have the signing key but modifies the
    claims in flight."""
    pinned_key = b"\x07" * 32

    legitimate_claims = b'{"action": "af_key_seed", "subject": "worker"}'
    token = _sign(legitimate_claims, pinned_key)

    # Attacker tampers the claims after signing; signature does NOT
    # cover the tampered bytes.
    tampered = _MockToken(
        claims_bytes=b'{"action": "drop_database", "subject": "worker"}',
        signature=token.signature,
    )

    verifier = _PinnedKeyVerifier(pinned_key)
    accepted = verifier.verify(tampered)
    assert not accepted, (
        "AF-key seed: tampered-claims token MUST be rejected even when "
        "the signature was originally legitimate."
    )
