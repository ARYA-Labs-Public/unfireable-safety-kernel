//! internal-ref — `wave_session_detail` sqlite denorm side-table.
//!
//! ## Why this exists
//!
//! internal-ref Phase 1 / internal-ref stashed the per-leaf
//! [`crate::state::WaveSessionLeafSide`] in an
//! `Arc<Mutex<HashMap<u64, WaveSessionLeafSide>>>` (see
//! [`crate::state::WaveSessionPayloadMap`]). That map is held entirely
//! in process memory and grows monotonically with the leaf count —
//! the Phase 1 spec called out a "Phase 2: denormalize into Postgres"
//! TODO precisely because the in-memory shape does not bound.
//!
//! internal-ref closes that gap, but with two corrections vs the original
//! Phase-2 sketch:
//!
//! 1. **Sqlite, not Postgres.** The kernel-side transparency-log
//!    already uses an embedded sqlite for its `kernel_audit.sqlite3`
//!    side-state. Adding a Postgres dependency for a single denorm
//!    table is wrong scope (more deps, more ops surface, no benefit
//!    over sqlite at the access pattern this table sees — single
//!    writer, point lookups by leaf hash).
//! 2. **Schema-as-code, not migrations.** Mirrors the ADR-018 §1
//!    pattern (`policy_module_registry`, `policy_api_prefix_registry`):
//!    the schema is created at boot via [`ensure_schema`], so the
//!    rollback path is "drop the table + reconstruct from the ledger"
//!    — no external migration tool in the loop. AC6 (reversible
//!    migration) is satisfied by [`drop_schema`] + the reconstruction
//!    helper in tests (the transparency-log ledger remains the source
//!    of truth, so reconstruction is always possible).
//!
//! ## Storage shape
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS wave_session_detail (
//!   leaf_hash_sha256 TEXT PRIMARY KEY,  -- hex(32-byte leaf hash)
//!   detail_json TEXT NOT NULL,          -- serde_json of WaveSessionLeafSide
//!   detail_size_bytes INTEGER NOT NULL,
//!   created_at_unix_ms INTEGER NOT NULL
//! );
//! CREATE INDEX IF NOT EXISTS idx_wave_session_detail_created_at
//!   ON wave_session_detail(created_at_unix_ms);
//! ```
//!
//! The `leaf_hash_sha256` is the same RFC-6962 leaf hash the
//! `TransparencyStore` records, so it functions as a foreign key to
//! the ledger (AC1) — re-deriving the leaf-hash for a row and not
//! finding it in the ledger is the integrity-flag the verify path
//! checks. **NOTE**: sqlite does not enforce the FK because the
//! ledger lives in a separate store (memory / Postgres in production);
//! the foreign-key semantic is enforced at the read path by
//! [`crate::state::AppState::lookup_wave_session_payload`] which
//! consults the ledger via `leaf_index` and only consults this
//! side-table on a hit.
//!
//! ## Leaf integrity guarantee
//!
//! The Merkle leaf payload still contains the FULL
//! `canonical_bytes(record)` + 32-byte HMAC (see
//! [`crate::routes::wave_session::build_leaf_payload`]). The
//! transparency-log's inclusion proof commits to those bytes. The
//! side-table here is a denormalization for fast read — corrupting a
//! row in `wave_session_detail` cannot tamper the Merkle root, and a
//! mismatch between (a) what the side-table returns and (b) what the
//! leaf-payload commits to is caught by the verify-route's
//! integrity check (see
//! [`SideTable::lookup_with_integrity_check`]).
//!
//! ## Test ergonomics
//!
//! Construct an in-memory store with [`SideTable::in_memory`]; the
//! production path uses [`SideTable::open`] with a filesystem path.
//! All operations are sync (rusqlite) but route handlers wrap calls
//! in `tokio::task::spawn_blocking` to avoid blocking the runtime —
//! the access pattern is small writes (≤1 MiB body limit) so blocking
//! a worker thread for the round-trip is acceptable and faster than
//! the equivalent async-pool cost at this scale.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::state::WaveSessionLeafSide;

/// On-wire shape persisted to the `detail_json` column. Mirrors
/// [`crate::state::WaveSessionLeafSide`] but is `Serialize +
/// Deserialize` (the in-memory side carries `[u8; 32]` /
/// `Option<[u8; 64]>` for cheap clone; here we hex-encode for
/// readability + cross-tooling — `sqlite3 *.db` should be readable).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DetailPayload {
    /// Hex-encoded 32-byte kernel HMAC.
    kernel_hmac_hex: String,
    /// Hex-encoded 64-byte Ed25519 signature, when present.
    ed25519_signature_hex: Option<String>,
    /// `"hmac"` or `"ed25519"`.
    signature_type: String,
    /// Hex SHA-256 fingerprint of the binding key material.
    key_fingerprint_hex: String,
    /// The decoded wave-session record itself, as canonical JSON.
    record: serde_json::Value,
}

impl DetailPayload {
    /// Project a [`WaveSessionLeafSide`] into the on-wire row shape.
    fn from_side(side: &WaveSessionLeafSide) -> Self {
        let record = serde_json::to_value(&side.record).unwrap_or(serde_json::Value::Null);
        Self {
            kernel_hmac_hex: hex::encode(side.kernel_hmac),
            ed25519_signature_hex: side.ed25519_signature.map(hex::encode),
            signature_type: side.signature_type.as_wire().to_string(),
            key_fingerprint_hex: side.key_fingerprint_hex.clone(),
            record,
        }
    }

    /// Inverse of [`Self::from_side`]. Fails when the persisted row
    /// is structurally invalid (bad hex, wrong-length signature). A
    /// row-shape failure is treated as `Backend` error by the caller.
    fn into_side(self) -> Result<WaveSessionLeafSide, SideTableError> {
        use crate::dto::SignatureType;
        use qorch_domain::wave::session_record::WaveSessionRecord;

        let kernel_hmac_vec = hex::decode(self.kernel_hmac_hex.trim())
            .map_err(|e| SideTableError::Backend(format!("hmac hex decode: {e}")))?;
        if kernel_hmac_vec.len() != 32 {
            return Err(SideTableError::Backend(format!(
                "hmac must be 32 bytes, got {}",
                kernel_hmac_vec.len()
            )));
        }
        let mut kernel_hmac = [0u8; 32];
        kernel_hmac.copy_from_slice(&kernel_hmac_vec);

        let ed25519_signature = match self.ed25519_signature_hex {
            None => None,
            Some(hex_s) => {
                let raw = hex::decode(hex_s.trim())
                    .map_err(|e| SideTableError::Backend(format!("ed25519 hex: {e}")))?;
                if raw.len() != 64 {
                    return Err(SideTableError::Backend(format!(
                        "ed25519 sig must be 64 bytes, got {}",
                        raw.len()
                    )));
                }
                let mut a = [0u8; 64];
                a.copy_from_slice(&raw);
                Some(a)
            }
        };

        let signature_type = match self.signature_type.as_str() {
            "hmac" => SignatureType::Hmac,
            "ed25519" => SignatureType::Ed25519,
            other => {
                return Err(SideTableError::Backend(format!(
                    "unknown signature_type: {other}"
                )))
            }
        };

        let record: WaveSessionRecord = serde_json::from_value(self.record)
            .map_err(|e| SideTableError::Backend(format!("record decode: {e}")))?;

        Ok(WaveSessionLeafSide {
            record,
            kernel_hmac,
            ed25519_signature,
            signature_type,
            key_fingerprint_hex: self.key_fingerprint_hex,
        })
    }
}

/// Errors surfaced by [`SideTable`] operations. Lifted to
/// [`crate::error::ServiceError::Backend`] at the route layer.
#[derive(Debug, thiserror::Error)]
pub enum SideTableError {
    /// Underlying sqlite failure (cannot open file, disk-full,
    /// schema-out-of-date, etc.).
    #[error("wave-session-detail backend error: {0}")]
    Backend(String),

    /// The persisted row's hash does not match the announced leaf
    /// hash — flag for the verify path. Detection is in
    /// [`SideTable::lookup_with_integrity_check`].
    #[error("wave-session-detail integrity check failed for leaf {leaf_hash_hex}")]
    IntegrityMismatch {
        /// The hex leaf-hash that failed the integrity check.
        leaf_hash_hex: String,
    },
}

impl From<rusqlite::Error> for SideTableError {
    fn from(e: rusqlite::Error) -> Self {
        SideTableError::Backend(e.to_string())
    }
}

/// Embedded-sqlite store for the `wave_session_detail` side-table.
///
/// Thread-safety: `rusqlite::Connection` is `Send` but not `Sync`. We
/// wrap a single connection in a `Mutex` — the access pattern is
/// point-lookup-by-key, so lock contention is negligible vs the
/// HashMap mutex it replaces. Operations are SYNC; the route layer
/// wraps them in `tokio::task::spawn_blocking`.
pub struct SideTable {
    conn: Mutex<Connection>,
}

impl SideTable {
    /// Open or create the sqlite database at `path` and ensure the
    /// schema is installed. The path is created as a regular file
    /// (sqlite handles the rest). `:memory:` is supported for tests.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SideTableError> {
        let conn = Connection::open(path).map_err(SideTableError::from)?;
        ensure_schema(&conn)?;
        // WAL improves concurrent-reader behaviour without changing the
        // single-writer model; we ignore the result if the journal-mode
        // pragma is unsupported (e.g. :memory:) — schema still installs.
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        let _ = conn.pragma_update(None, "synchronous", "NORMAL");
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory database. Used by tests + dev wiring.
    pub fn in_memory() -> Result<Self, SideTableError> {
        Self::open(":memory:")
    }

    /// Insert (or replace) a row for `leaf_hash`. The hex string is
    /// the lowercase RFC-6962 SHA-256 leaf hash. Replacement is OK
    /// because the leaf-hash is itself derived from the framed leaf
    /// payload — two writes with the same key carry the same bytes.
    pub fn insert(
        &self,
        leaf_hash_hex: &str,
        side: &WaveSessionLeafSide,
        created_at_unix_ms: i64,
    ) -> Result<(), SideTableError> {
        let payload = DetailPayload::from_side(side);
        let json = serde_json::to_string(&payload)
            .map_err(|e| SideTableError::Backend(format!("detail json encode: {e}")))?;
        let size_bytes = i64::try_from(json.len()).unwrap_or(i64::MAX);
        let conn = self
            .conn
            .lock()
            .expect("side-table connection mutex poisoned");
        conn.execute(
            "INSERT INTO wave_session_detail \
               (leaf_hash_sha256, detail_json, detail_size_bytes, created_at_unix_ms) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(leaf_hash_sha256) DO NOTHING",
            params![leaf_hash_hex, json, size_bytes, created_at_unix_ms],
        )?;
        Ok(())
    }

    /// Point-lookup by leaf hash. Returns `Ok(None)` when the row is
    /// absent — the caller treats this as a cache miss + ledger
    /// re-derivation opportunity.
    pub fn lookup(
        &self,
        leaf_hash_hex: &str,
    ) -> Result<Option<WaveSessionLeafSide>, SideTableError> {
        let conn = self
            .conn
            .lock()
            .expect("side-table connection mutex poisoned");
        let row = conn
            .query_row(
                "SELECT detail_json FROM wave_session_detail WHERE leaf_hash_sha256 = ?1",
                params![leaf_hash_hex],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some(json) => {
                let payload: DetailPayload = serde_json::from_str(&json)
                    .map_err(|e| SideTableError::Backend(format!("row decode: {e}")))?;
                Ok(Some(payload.into_side()?))
            }
        }
    }

    /// AC6 / Rule 8 adversarial — lookup AND recompute the
    /// canonical-bytes-derived integrity fingerprint, asserting it
    /// matches `expected_record_sha256_hex`. Detects in-place row
    /// tampering of `detail_json` (where the on-row hash and the
    /// leaf-bound canonical bytes diverge).
    ///
    /// The expected fingerprint is `SHA-256(canonical_bytes(record))` —
    /// the same bytes the leaf payload commits to. The caller has
    /// these bytes from the ledger; we recompute them from the
    /// persisted row and compare.
    pub fn lookup_with_integrity_check(
        &self,
        leaf_hash_hex: &str,
        expected_record_sha256_hex: &str,
    ) -> Result<Option<WaveSessionLeafSide>, SideTableError> {
        let Some(side) = self.lookup(leaf_hash_hex)? else {
            return Ok(None);
        };
        let canonical_bytes = side
            .record
            .canonical_bytes()
            .map_err(|e| SideTableError::Backend(format!("canonical_bytes failed: {e}")))?;
        let mut h = Sha256::new();
        h.update(&canonical_bytes);
        let derived = hex::encode(h.finalize());
        if !constant_time_str_eq(&derived, expected_record_sha256_hex) {
            return Err(SideTableError::IntegrityMismatch {
                leaf_hash_hex: leaf_hash_hex.to_string(),
            });
        }
        Ok(Some(side))
    }

    /// Number of rows currently in the side-table. Useful for tests +
    /// metrics endpoints.
    pub fn row_count(&self) -> Result<u64, SideTableError> {
        let conn = self
            .conn
            .lock()
            .expect("side-table connection mutex poisoned");
        let n: i64 =
            conn.query_row("SELECT COUNT(*) FROM wave_session_detail", [], |r| r.get(0))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Cumulative byte size of all persisted detail payloads. Useful
    /// for operator metrics — does the side-table need pruning?
    pub fn total_bytes(&self) -> Result<u64, SideTableError> {
        let conn = self
            .conn
            .lock()
            .expect("side-table connection mutex poisoned");
        let n: i64 = conn.query_row(
            "SELECT COALESCE(SUM(detail_size_bytes), 0) FROM wave_session_detail",
            [],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// AC6 reversible-migration path: drop the table. The
    /// transparency-log ledger is the source of truth, so the
    /// side-table can always be rebuilt by walking the ledger. Used
    /// in tests + the documented rollback procedure. Returns the
    /// underlying connection to its empty-schema state.
    pub fn drop_schema(&self) -> Result<(), SideTableError> {
        let conn = self
            .conn
            .lock()
            .expect("side-table connection mutex poisoned");
        drop_schema_with_conn(&conn)?;
        Ok(())
    }

    /// internal-ref Rule 8 — tamper-test seam. Returns a guard the caller
    /// uses to run raw sql against the underlying connection. Tests
    /// use this to simulate an attacker who mutates a persisted row
    /// in place; production code MUST NOT use this entry point
    /// (it's `#[doc(hidden)]` and only meaningful when paired with a
    /// re-derive-from-ledger integrity check on the read path).
    #[doc(hidden)]
    pub fn conn_for_tests(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .expect("side-table connection mutex poisoned")
    }

    /// Re-install the schema after a [`Self::drop_schema`] call. The
    /// pair is the documented reversible-migration loop (AC6).
    pub fn rebuild_schema(&self) -> Result<(), SideTableError> {
        let conn = self
            .conn
            .lock()
            .expect("side-table connection mutex poisoned");
        ensure_schema(&conn)?;
        Ok(())
    }
}

/// Idempotently install the schema-as-code (ADR-018 §1 pattern).
/// Mirrors the safety-kernel's `policy_module_registry::ensure_schema`
/// shape: a single function the bin calls at boot, and tests call
/// against `:memory:` connections directly.
pub fn ensure_schema(conn: &Connection) -> Result<(), SideTableError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS wave_session_detail (
            leaf_hash_sha256   TEXT    PRIMARY KEY,
            detail_json        TEXT    NOT NULL,
            detail_size_bytes  INTEGER NOT NULL,
            created_at_unix_ms INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_wave_session_detail_created_at
             ON wave_session_detail(created_at_unix_ms);",
    )?;
    Ok(())
}

/// AC6 inverse of [`ensure_schema`]. Documented for the rollback
/// procedure; not called on the hot path.
pub fn drop_schema_with_conn(conn: &Connection) -> Result<(), SideTableError> {
    conn.execute_batch(
        "DROP INDEX IF EXISTS idx_wave_session_detail_created_at;
         DROP TABLE  IF EXISTS wave_session_detail;",
    )?;
    Ok(())
}

/// Constant-time byte-equality on two ASCII-hex strings of equal
/// length. Same shape as the one in `routes::wave_session`; copied
/// here to avoid cross-module visibility tweaks and keep this module
/// self-contained.
fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Unit tests (mod-local; integration tests live under tests/).
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use crate::dto::SignatureType;
    use qorch_domain::wave::context::WaveId;
    use qorch_domain::wave::session_record::WaveSessionRecord;
    use qorch_domain::wave::stage::{WaveOutcome, WaveStage};

    fn fixture_side(wave: &str) -> WaveSessionLeafSide {
        let r = WaveSessionRecord::new(
            WaveId::new(wave),
            "internal-ref",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            "re-derived",
            HashSet::new(),
            "/test",
            1_716_400_000,
        );
        WaveSessionLeafSide {
            record: r,
            kernel_hmac: [0xAB; 32],
            ed25519_signature: None,
            signature_type: SignatureType::Hmac,
            key_fingerprint_hex: hex::encode([0x11; 32]),
        }
    }

    fn sha256_canonical(side: &WaveSessionLeafSide) -> String {
        let bytes = side.record.canonical_bytes().unwrap();
        let mut h = Sha256::new();
        h.update(&bytes);
        hex::encode(h.finalize())
    }

    #[test]
    fn ensure_schema_is_idempotent() {
        // AC1 — schema-as-code via `CREATE TABLE IF NOT EXISTS`. Two
        // calls in a row must not raise.
        let st = SideTable::in_memory().unwrap();
        st.rebuild_schema().unwrap();
        st.rebuild_schema().unwrap();
        assert_eq!(st.row_count().unwrap(), 0);
    }

    #[test]
    fn insert_then_lookup_round_trip() {
        // AC2 / AC3 — write via insert, read via lookup, bytes equal.
        let st = SideTable::in_memory().unwrap();
        let side = fixture_side("w-roundtrip");
        let leaf_hex = hex::encode([0x55; 32]);
        st.insert(&leaf_hex, &side, 1_716_400_000_000).unwrap();
        let got = st.lookup(&leaf_hex).unwrap().unwrap();
        assert_eq!(got.kernel_hmac, side.kernel_hmac);
        assert_eq!(got.signature_type, side.signature_type);
        assert_eq!(got.record, side.record);
    }

    #[test]
    fn lookup_returns_none_on_miss() {
        let st = SideTable::in_memory().unwrap();
        let got = st.lookup(&hex::encode([0xFF; 32])).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn duplicate_insert_is_noop() {
        // Two inserts under the same leaf hash do not raise (ON
        // CONFLICT DO NOTHING). Idempotency mirrors the ledger's own
        // dedup behaviour.
        let st = SideTable::in_memory().unwrap();
        let side = fixture_side("w-dup");
        let leaf_hex = hex::encode([0x66; 32]);
        st.insert(&leaf_hex, &side, 1_716_400_000_000).unwrap();
        st.insert(&leaf_hex, &side, 1_716_400_000_999).unwrap();
        assert_eq!(st.row_count().unwrap(), 1);
    }

    #[test]
    fn ed25519_side_round_trips() {
        let mut side = fixture_side("w-ed25519");
        side.signature_type = SignatureType::Ed25519;
        side.ed25519_signature = Some([0xCD; 64]);
        let st = SideTable::in_memory().unwrap();
        let leaf_hex = hex::encode([0x77; 32]);
        st.insert(&leaf_hex, &side, 1_716_400_000_000).unwrap();
        let got = st.lookup(&leaf_hex).unwrap().unwrap();
        assert_eq!(got.signature_type, SignatureType::Ed25519);
        assert_eq!(got.ed25519_signature, Some([0xCD; 64]));
    }

    #[test]
    fn integrity_check_passes_on_clean_row() {
        // AC6 / Rule 8 — integrity check on a row that has not been
        // tampered must pass.
        let st = SideTable::in_memory().unwrap();
        let side = fixture_side("w-clean");
        let leaf_hex = hex::encode([0x99; 32]);
        st.insert(&leaf_hex, &side, 1_716_400_000_000).unwrap();
        let expected = sha256_canonical(&side);
        let got = st
            .lookup_with_integrity_check(&leaf_hex, &expected)
            .unwrap()
            .unwrap();
        assert_eq!(got.record.wave_id.as_str(), "w-clean");
    }

    #[test]
    fn integrity_check_detects_tampered_row_adversarial() {
        // AC6 / Rule 8 ADVERSARIAL — tamper the persisted JSON to
        // mutate `evidence`. The recomputed sha256 over the on-row
        // canonical bytes diverges from the original; the check
        // surfaces `IntegrityMismatch`.
        let st = SideTable::in_memory().unwrap();
        let side = fixture_side("w-tamper");
        let leaf_hex = hex::encode([0xAB; 32]);
        let original_expected = sha256_canonical(&side);
        st.insert(&leaf_hex, &side, 1_716_400_000_000).unwrap();
        // Directly tamper the row via raw sql.
        {
            let conn = st.conn.lock().unwrap();
            conn.execute(
                "UPDATE wave_session_detail \
                   SET detail_json = REPLACE(detail_json, 're-derived', 'TAMPERED') \
                 WHERE leaf_hash_sha256 = ?1",
                params![leaf_hex],
            )
            .unwrap();
        }
        let err = st.lookup_with_integrity_check(&leaf_hex, &original_expected);
        assert!(matches!(err, Err(SideTableError::IntegrityMismatch { .. })));
    }

    #[test]
    fn drop_schema_then_rebuild_is_reversible() {
        // AC6 — the side-table can be dropped + reconstructed. The
        // ledger remains the source of truth; this proves the
        // schema lifecycle is reversible.
        let st = SideTable::in_memory().unwrap();
        let side = fixture_side("w-drop");
        st.insert(&hex::encode([0x01; 32]), &side, 1).unwrap();
        assert_eq!(st.row_count().unwrap(), 1);
        st.drop_schema().unwrap();
        // After drop the table is gone — re-install + verify it is
        // empty (caller would re-walk the ledger to refill).
        st.rebuild_schema().unwrap();
        assert_eq!(st.row_count().unwrap(), 0);
    }

    #[test]
    fn total_bytes_reflects_persisted_payload_size() {
        let st = SideTable::in_memory().unwrap();
        let side = fixture_side("w-bytes");
        st.insert(&hex::encode([0x02; 32]), &side, 1).unwrap();
        let n = st.total_bytes().unwrap();
        assert!(n > 0, "total_bytes should be > 0 after insert");
    }
}
