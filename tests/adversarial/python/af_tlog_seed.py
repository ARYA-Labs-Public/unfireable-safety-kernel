"""AF-tlog seed fixture (Python counterpart) — ARY-1887.

Sister fixtures: ``crates/services/transparency-log/tests/purple_*.rs``
(campaigns A1 forged STH, B1 tampered inclusion proof, C1/C2 malformed
log response, F1/F2 idempotency collision, G1a/b forged authorize
token).

See ``docs/release-gate/af-taxonomy.md`` for the 7-class taxonomy.

What this seed asserts
----------------------
The transparency-log integrity contract: a client that receives a
log response from the t-log service MUST reject:

* **C2-style**: a ``leaf_hash`` that does NOT correspond to the
  client's local SHA-256 of its own token bytes (the log entry does
  not actually attest the action the client just submitted).

This Python seed models the same contract in stdlib-only form. A
production Python defense lib that consumes t-log responses would
replace the mocks here with the real wire-format check; the rejection
contract is identical.

Run with::

    python -m pytest tests/adversarial/python/af_tlog_seed.py
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class _LogResponse:
    """Minimal t-log response model.

    Production: a JSON body with ``leaf_hash_hex``, ``entry_index``,
    ``signed_tree_head``, etc. Seed: just the field that matters for
    the C2 rejection — the leaf-hash hex.
    """

    leaf_hash_hex: str


class _LogResponseMismatch(Exception):
    """Mirrors the Rust transparency client's `Malformed`/`Mismatch`."""


def _check_log_response(
    response: _LogResponse,
    my_token_bytes: bytes,
) -> None:
    """Re-derive evidence: hash the token bytes locally and compare to
    the leaf_hash claimed by the t-log. Raise on mismatch.

    Rule 9 — re-derive evidence. We do NOT regex-match a status string.
    """
    local_hash = hashlib.sha256(my_token_bytes).hexdigest()
    if local_hash != response.leaf_hash_hex:
        raise _LogResponseMismatch(
            f"t-log claims leaf_hash {response.leaf_hash_hex} but local "
            f"SHA-256 of my own token bytes is {local_hash}. The log "
            f"entry does NOT attest the action I just submitted."
        )


def test_af_tlog_seed_c2_rejects_leaf_hash_mismatch() -> None:
    """C2: a t-log response whose leaf_hash does NOT correspond to the
    client's local SHA-256 of its own token bytes MUST be rejected.

    This is the historically-significant gap: kernel previously
    accepted such responses (ARY-1885 / Step 8). The wire client now
    re-derives the hash locally and refuses on mismatch.
    """
    my_token = b"kernel-authorize-token-payload"
    # Attacker (or buggy log) returns a leaf_hash for a different action.
    bogus_response = _LogResponse(leaf_hash_hex="0" * 64)

    raised = False
    try:
        _check_log_response(bogus_response, my_token)
    except _LogResponseMismatch:
        raised = True
    assert raised, (
        "AF-tlog-C2 seed: leaf_hash mismatch MUST be rejected by the "
        "client. If this fires, the t-log can claim it attested an "
        "action it did not; release must NOT sign v1.0."
    )


def test_af_tlog_seed_accepts_correct_leaf_hash() -> None:
    """Counter-assertion: a t-log response whose leaf_hash matches the
    client's local SHA-256 of its token MUST pass through."""
    my_token = b"kernel-authorize-token-payload"
    correct_hash = hashlib.sha256(my_token).hexdigest()
    legitimate_response = _LogResponse(leaf_hash_hex=correct_hash)
    _check_log_response(legitimate_response, my_token)  # MUST NOT raise


def test_af_tlog_seed_rejects_truncated_leaf_hash() -> None:
    """A truncated / malformed leaf_hash (wrong length, partial hex)
    MUST also be rejected, since it cannot possibly match the
    re-derived 64-char hex."""
    my_token = b"kernel-authorize-token-payload"
    truncated = _LogResponse(leaf_hash_hex="abcd")

    raised = False
    try:
        _check_log_response(truncated, my_token)
    except _LogResponseMismatch:
        raised = True
    assert raised, (
        "AF-tlog seed: truncated leaf_hash MUST be rejected (it cannot "
        "possibly equal the re-derived 64-char SHA-256 hex)."
    )
