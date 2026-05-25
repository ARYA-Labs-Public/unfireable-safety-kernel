"""Canonical JSON serializer + event_fingerprint computation.

Bit-for-bit equivalence with the Rust kernel's `params_fingerprint`
(`crates/domain/src/safety/token.rs::stable_json` +
`params_fingerprint`). This is the contract that the kernel uses to
recompute `event_fingerprint` server-side and reject mismatches with
HTTP 400 — every byte of the canonicalization MUST match or every
hook event 400s.

The Rust `stable_json`:

* Object keys sorted lexicographically.
* No whitespace between tokens (no spaces, no newlines).
* No trailing newline.
* ASCII-only output (non-ASCII characters become ``\\uXXXX`` escapes).
* No floating-point in the canonicalized payload (the hook's payload
  is all strings).

Python's :func:`json.dumps` with ``sort_keys=True, separators=(",", ":"),
ensure_ascii=True`` produces output that matches this contract for
the payload shape this hook uses (4 string-valued keys). The equivalence
is tested in :mod:`safety_kernel_defense.tests.test_install_audit_hook`
with a hard-coded anchor that was computed by the Rust kernel.
"""

from __future__ import annotations

import hashlib
import json
from typing import Mapping

__all__ = [
    "canonical_json",
    "compute_event_fingerprint",
]


def canonical_json(payload: Mapping[str, str]) -> str:
    """Canonical JSON encode the payload.

    Matches the Rust kernel's ``stable_json`` exactly for the
    string-only payload shape this hook uses. Caller must pass a
    mapping whose values are all strings (the hook's
    ``event_kind``/``module_path``/``caller_subject``/``caller_run_id``
    tuple).

    Args:
        payload: mapping of string keys to string values. All keys
            sorted; no whitespace; non-ASCII characters escaped.

    Returns:
        The canonical JSON string.
    """
    # Defensive type check: a non-string slipping in (e.g. None from
    # an upstream bug) would change the canonical form and silently
    # widen the accept set. Catch it here.
    for k, v in payload.items():
        if not isinstance(k, str):
            raise TypeError(f"canonical_json: non-string key {k!r}")
        if not isinstance(v, str):
            raise TypeError(
                f"canonical_json: non-string value for key {k!r}: {v!r}"
            )
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def compute_event_fingerprint(
    *,
    event_kind: str,
    module_path: str,
    caller_subject: str,
    caller_run_id: str,
) -> str:
    """Compute the canonical event fingerprint.

    SHA-256 hex digest of the canonical-JSON encoding of the 4-field
    fingerprint payload. Bit-for-bit identical to the Rust kernel's
    server-side recomputation in
    `crates/services/safety-kernel/src/routes/policy/authorize.rs::recompute_event_fingerprint`.

    Args:
        event_kind: one of ``"import"`` / ``"exec"`` / ``"compile"``.
        module_path: dotted module name (import) or sha256-hex
            (exec/compile).
        caller_subject: adopter app identity, frozen at install time.
        caller_run_id: run identifier, frozen at install time.

    Returns:
        Lowercase 64-char hex SHA-256 digest.
    """
    payload = {
        "event_kind": event_kind,
        "module_path": module_path,
        "caller_subject": caller_subject,
        "caller_run_id": caller_run_id,
    }
    canonical = canonical_json(payload)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()
