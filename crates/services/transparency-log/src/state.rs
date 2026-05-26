//! `AppState` for the transparency-log service (,
//!  Step 5).
//!
//! Holds the (Send + Sync) handles every route handler needs:
//!
//! - `store` — `Arc<dyn TransparencyStore>` (Step 4 trait). The
//!   Postgres impl in production; the memory impl in tests + dev.
//! - `signing_key` — the Ed25519 private key used to mint STHs. STH
//!   signs with a separate, independently-rotated key per 
//!    §4b — distinct from the kernel's token-signing key. Read
//!   from env var `QORCH_TRANSPARENCY_SIGNING_KEY_B64` at service
//!   startup.
//! - `signing_key_fingerprint_hex` — SHA-256 of the raw 32-byte public
//!   key, hex-encoded. Echoed in `GET /v1/sth` so external verifiers
//!   know which key to use.
//! - `kernel_key_fingerprint_hex` — SHA-256 of the kernel's signing
//!   public key. `POST /v1/append` rejects any submission that does not
//!   carry this fingerprint (binds the ledger to a specific kernel).
//! - `clock` — `Arc<dyn Clock>` for the STH timestamp + inserted_at
//!   columns. The pure-domain `mint_sth` takes a caller-supplied
//!   `timestamp_epoch_seconds`; we drive that from this clock so tests
//!   can pin it.
//! - `api_key` — the kernel-supplied `x-api-key` value the middleware
//!   compares against. Held as a single string (only one caller is
//!   authorized to append); empty string means the service was started
//!   with no auth (dev only).

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use tokio::sync::Mutex;

use qorch_domain::safety::Clock;
use qorch_domain::wave::context::WaveId;
use qorch_domain::wave::session_record::WaveSessionRecord;
use qorch_transparency_store::TransparencyStore;

/// Auxiliary index from `wave_id -> ordered list of (stage-time,
/// leaf_index)` so the `GET /v1/wave/{wave_id}/verify` route can
/// stream a wave's full session chain without scanning the entire
/// ledger. Populated on every successful append; the underlying
/// Merkle store stays the source of truth (the index is rebuildable
/// from the leaves on cold start by walking the store at boot).
///
///   keeps this in-memory; the Postgres slice ()
/// will denormalize via a `wave_session_leaves(wave_id, leaf_index)`
/// view.
pub type WaveSessionIndex = Arc<Mutex<HashMap<String, Vec<u64>>>>;

/// Per-leaf side map: `leaf_index -> (record, hmac)`.  holds
/// this in-memory;  will denormalize into Postgres. The
/// transparency-log ledger remains the source of truth — this map is
/// rebuildable by walking the leaves at boot..
pub type WaveSessionPayloadMap =
    Arc<Mutex<HashMap<u64, (WaveSessionRecord, [u8; 32])>>>;

/// Process-level state shared by every handler.
///
/// `Clone` is `Arc`-cheap; axum's `State<AppState>` extractor requires
/// `Clone` and we hold every heavy field behind `Arc`.
#[derive(Clone)]
pub struct AppState {
    /// Append-only Merkle store (Postgres in prod, memory in tests).
    pub store: Arc<dyn TransparencyStore>,
    /// Ed25519 private key used to mint STHs. Wrapped in `Arc` so route
    /// handlers can hand it to `mint_sth` without cloning the seed.
    pub signing_key: Arc<SigningKey>,
    /// Hex SHA-256 of the raw 32-byte STH-signer public key (this
    /// service's signing key). Echoed in `GET /v1/sth` responses so
    /// external verifiers know which key to use.
    pub signing_key_fingerprint_hex: String,
    /// Hex SHA-256 of the kernel's signing public key. Pinned at
    /// startup; `POST /v1/append` rejects any payload that does not
    /// carry this fingerprint — binds the ledger to a specific kernel.
    pub kernel_key_fingerprint_hex: String,
    /// Production `Clock` adapter — `SystemClock`. Tests inject a
    /// `FixedClock` so STH timestamps are deterministic.
    pub clock: Arc<dyn Clock>,
    /// `x-api-key` value the middleware compares against. Empty string
    /// disables the gate (dev only).
    pub api_key: String,
    /// Shared symmetric HMAC key the kernel signs `WaveSessionRecord`
    /// canonical-bytes with. Held as `Vec<u8>` so the kernel can
    /// rotate (HMAC supports arbitrary key lengths up to the block
    /// size). Sourced from env var `QORCH_KERNEL_HMAC_KEY_B64` at
    /// service startup; empty in tests that explicitly do not exercise
    /// the wave-session-record path. (.)
    pub kernel_hmac_key: Vec<u8>,
    /// In-process index from `wave_id -> [leaf_index]` so the verify
    /// route can stream a chain in O(records-in-wave). See
    /// [`WaveSessionIndex`]. (.)
    pub wave_session_index: WaveSessionIndex,
    /// Per-leaf side map carrying the decoded record + HMAC so the
    /// verify route does not have to re-derive from raw leaf bytes
    /// (the `TransparencyStore` trait does not expose raw payload
    /// today;   will denormalize into Postgres).
    pub wave_session_payloads: WaveSessionPayloadMap,
}

impl AppState {
    /// Construct an `AppState`. Held by `Arc` inside axum but we
    /// expose a non-`Arc` constructor here so tests can build one
    /// without ceremony.
    #[must_use]
    pub fn new(
        store: Arc<dyn TransparencyStore>,
        signing_key: Arc<SigningKey>,
        signing_key_fingerprint_hex: String,
        kernel_key_fingerprint_hex: String,
        clock: Arc<dyn Clock>,
        api_key: String,
    ) -> Self {
        Self {
            store,
            signing_key,
            signing_key_fingerprint_hex,
            kernel_key_fingerprint_hex,
            clock,
            api_key,
            kernel_hmac_key: Vec::new(),
            wave_session_index: Arc::new(Mutex::new(HashMap::new())),
            wave_session_payloads: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Builder-style: install the kernel HMAC key the wave-session
    /// route checks against. Returns `self` for chained construction.
    /// (.)
    #[must_use]
    pub fn with_kernel_hmac_key(mut self, key: Vec<u8>) -> Self {
        self.kernel_hmac_key = key;
        self
    }

    /// Record a successful wave-session append in the in-process
    /// index so the verify route can find it. Called by
    /// `routes::wave_session::append_session` after the underlying
    /// store accepts the leaf.
    pub async fn record_wave_session_leaf(&self, wave_id: &WaveId, leaf_index: u64) {
        let mut idx = self.wave_session_index.lock().await;
        let entry = idx.entry(wave_id.as_str().to_string()).or_default();
        if !entry.contains(&leaf_index) {
            entry.push(leaf_index);
        }
    }

    /// Look up all leaf indices for a wave. Returns an empty vec when
    /// the wave is unknown (the verify route surfaces that as 404).
    pub async fn wave_session_leaves(&self, wave_id: &WaveId) -> Vec<u64> {
        let idx = self.wave_session_index.lock().await;
        idx.get(wave_id.as_str()).cloned().unwrap_or_default()
    }

    /// Stash the decoded (record, hmac) pair for a leaf. Idempotent.
    pub async fn record_wave_session_payload(
        &self,
        leaf_index: u64,
        record: WaveSessionRecord,
        hmac: [u8; 32],
    ) {
        let mut p = self.wave_session_payloads.lock().await;
        p.entry(leaf_index).or_insert((record, hmac));
    }

    /// Look up the (record, hmac) pair for a leaf. Returns `None` if
    /// the leaf was not produced by the wave-session route.
    pub async fn lookup_wave_session_payload(
        &self,
        leaf_index: u64,
    ) -> Option<(WaveSessionRecord, [u8; 32])> {
        let p = self.wave_session_payloads.lock().await;
        p.get(&leaf_index).cloned()
    }
}
