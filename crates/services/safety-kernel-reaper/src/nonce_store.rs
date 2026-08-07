//! Persistent seen-nonce store — the replay defeat the kernel structurally
//! CANNOT do: `verify_kernel_token` requires `nonce` to be present but keeps no
//! replay cache; that is the Reaper's job.
//!
//! A kill token verifies cryptographically every time it is presented. Only a
//! persistent record of `(nonce, run_id)` stops a captured-and-replayed kill
//! from re-firing within its (short) TTL window. Persistence matters: a Reaper
//! restart must NOT forget, or the replay window silently re-opens.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The replay key. Both fields bind so a nonce reused across a *different*
/// `run_id` still counts as distinct issuance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonceKey {
    /// The per-issuance nonce claim.
    pub nonce: String,
    /// The revocation / restore id.
    pub run_id: String,
}

impl NonceKey {
    /// Build a key from the two claim fields.
    #[must_use]
    pub fn new(nonce: impl Into<String>, run_id: impl Into<String>) -> Self {
        Self {
            nonce: nonce.into(),
            run_id: run_id.into(),
        }
    }

    /// Serialized on-disk line form: `<nonce>\t<run_id>`. Nonces are
    /// base64url (no tab), run_ids are `revoke_<uuid>` / `restore_<uuid>`
    /// (no tab), so a tab separator is unambiguous.
    fn to_line(&self) -> String {
        format!("{}\t{}", self.nonce, self.run_id)
    }

    fn from_line(line: &str) -> Option<Self> {
        let mut parts = line.splitn(2, '\t');
        let nonce = parts.next()?.to_string();
        let run_id = parts.next()?.to_string();
        if nonce.is_empty() || run_id.is_empty() {
            return None;
        }
        Some(Self { nonce, run_id })
    }
}

/// The store contract. `record` MUST be durable BEFORE the executor acts, so a
/// crash mid-execute cannot re-run the kill.
pub trait SeenNonceStore: Send + Sync {
    /// True if this `(nonce, run_id)` has already been recorded.
    fn is_seen(&self, key: &NonceKey) -> bool;
    /// Record the key durably. Idempotent: re-recording a seen key is a no-op.
    /// Returns an error only if the durable write failed (the Reaper then
    /// fails CLOSED on the candidate rather than risk a double-execute).
    fn record(&self, key: &NonceKey) -> std::io::Result<()>;
}

// ============================================================================
// FileNonceStore — durable, survives restart (the production store).
// ============================================================================

/// A newline-delimited append-only file of seen `(nonce, run_id)` keys, mirrored
/// by an in-memory `HashSet` for O(1) lookups. The file is the durable record;
/// the set is the hot path. On construction the file is replayed into the set,
/// so a restart remembers every prior kill.
#[derive(Debug)]
pub struct FileNonceStore {
    path: PathBuf,
    seen: Mutex<HashSet<NonceKey>>,
}

impl FileNonceStore {
    /// Open (or create) the store at `path`, replaying any existing content
    /// into memory.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the file exists but cannot be read, or the parent
    /// directory cannot be created.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut seen = HashSet::new();
        if path.exists() {
            let f = File::open(&path)?;
            for line in BufReader::new(f).lines() {
                let line = line?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Some(key) = NonceKey::from_line(trimmed) {
                    seen.insert(key);
                }
            }
        }
        Ok(Self {
            path,
            seen: Mutex::new(seen),
        })
    }
}

impl SeenNonceStore for FileNonceStore {
    fn is_seen(&self, key: &NonceKey) -> bool {
        self.seen.lock().expect("seen lock").contains(key)
    }

    fn record(&self, key: &NonceKey) -> std::io::Result<()> {
        let mut set = self.seen.lock().expect("seen lock");
        if set.contains(key) {
            return Ok(());
        }
        // Durable write FIRST — only insert into the hot set once the bytes
        // are flushed, so an fsync failure leaves `is_seen` == false and the
        // Reaper fails closed on the candidate instead of double-executing.
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", key.to_line())?;
        f.flush()?;
        set.insert(key.clone());
        Ok(())
    }
}

// ============================================================================
// MemNonceStore — in-memory only, for tests that don't exercise persistence.
// ============================================================================

/// In-memory store for unit tests. NOT durable — never use in production.
#[derive(Debug, Default)]
pub struct MemNonceStore {
    seen: Mutex<HashSet<NonceKey>>,
}

impl MemNonceStore {
    /// A fresh, empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SeenNonceStore for MemNonceStore {
    fn is_seen(&self, key: &NonceKey) -> bool {
        self.seen.lock().expect("seen lock").contains(key)
    }

    fn record(&self, key: &NonceKey) -> std::io::Result<()> {
        self.seen.lock().expect("seen lock").insert(key.clone());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn mem_store_records_and_sees() {
        let s = MemNonceStore::new();
        let k = NonceKey::new("nonce-a", "revoke_1");
        assert!(!s.is_seen(&k));
        s.record(&k).unwrap();
        assert!(s.is_seen(&k));
        // A different run_id with the same nonce is a distinct key.
        assert!(!s.is_seen(&NonceKey::new("nonce-a", "revoke_2")));
    }

    #[test]
    fn file_store_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seen_nonces.log");
        let k = NonceKey::new("nonce-persist", "revoke_persist");
        {
            let s = FileNonceStore::open(&path).unwrap();
            assert!(!s.is_seen(&k));
            s.record(&k).unwrap();
            assert!(s.is_seen(&k));
        }
        // Reopen: a restart MUST remember the prior kill.
        let s2 = FileNonceStore::open(&path).unwrap();
        assert!(
            s2.is_seen(&k),
            "reopened store forgot a recorded nonce — replay window re-opened"
        );
    }

    #[test]
    fn file_store_record_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seen.log");
        let s = FileNonceStore::open(&path).unwrap();
        let k = NonceKey::new("n", "r");
        s.record(&k).unwrap();
        s.record(&k).unwrap();
        // Only one line should have been written.
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().filter(|l| !l.is_empty()).count(), 1);
    }
}
