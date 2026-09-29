//! internal-ref — Step 2 (/test) Rule-9 evidence-recompute: pinned
//! `WaveSessionRecord::canonical_bytes` golden vector.
//!
//! Companion to `tools/test_adversarial_transparency_log_ed25519.py`
//! function `test_canonical_bytes_python_rust_parity`. Both tests
//! project the SAME synthetic record to canonical bytes and assert
//! the SAME hard-coded byte sequence comes out. Any drift on EITHER
//! side (Rust serde declaration-order change, Python json.dumps
//! key-ordering drift, gate_surfaces sort-order drift) trips here.
//!
//! Stake: if this vector ever needs to change, the migration ADR
//! (`docs/migration/transparency-log-ed25519-migration.md`) needs a
//! breaking-change entry AND every published signature over the old
//! shape becomes unverifiable — i.e. the entire ledger has to be
//! re-signed. We pin this vector so a quiet drift is impossible.

#![allow(clippy::all)] // generated parity gate: reference-vector data, not idiomatic Rust
#![allow(clippy::unwrap_used)]

use std::collections::HashSet;

use qorch_domain::wave::context::WaveId;
use qorch_domain::wave::session_record::WaveSessionRecord;
use qorch_domain::wave::stage::{WaveOutcome, WaveStage};

/// Pinned canonical bytes for the (w-parity, TESTED, parity-1, /test,
/// outcome=PASS, evidence="evidence", gate_surfaces=[], linear=internal-ref,
/// occurred_at=1716500000) record. Sourced from the Rust side and
/// mirrored byte-for-byte into the Python parity test.
const PINNED_CANONICAL_BYTES: &[u8] = concat!(
    r#"{"evidence":"evidence","gate_surfaces":[],"#,
    r#""linear_issue":"internal-ref","occurred_at_epoch_seconds":1716500000,"#,
    r#""outcome":"PASS","session_id":"parity-1","stage":"TESTED","#,
    r#""wave_id":"w-parity","written_by":"/test"}"#,
)
.as_bytes();

#[test]
fn pinned_canonical_bytes_byte_identical() {
    let r = WaveSessionRecord::new(
        WaveId::new("w-parity"),
        "internal-ref",
        WaveStage::Tested,
        "parity-1",
        WaveOutcome::Pass,
        "evidence",
        HashSet::new(),
        "/test",
        1_716_500_000,
    );
    let derived = r.canonical_bytes().unwrap();
    assert_eq!(
        derived, PINNED_CANONICAL_BYTES,
        "canonical_bytes drift; the Python parity vector (in \
         tools/test_adversarial_transparency_log_ed25519.py) must be \
         re-pinned in lockstep AND the migration ADR updated."
    );
}
