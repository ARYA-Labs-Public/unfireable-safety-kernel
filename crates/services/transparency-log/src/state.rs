//! `AppState` for the transparency-log service (ADR-014 Phase 3 §3,
//! internal-ref Step 5).
//!
//! Holds the (Send + Sync) handles every route handler needs:
//!
//! - `store` — `Arc<dyn TransparencyStore>` (Step 4 trait). The
//!   Postgres impl in production; the memory impl in tests + dev.
//! - `signing_key` — the Ed25519 private key used to mint STHs. STH
//!   signs with a separate, independently-rotated key per ADR-014
//!   Phase 3 §4b — distinct from the kernel's token-signing key. Read
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
use std::num::NonZeroUsize;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use lru::LruCache;
use tokio::sync::Mutex;

use qorch_domain::safety::Clock;
use qorch_domain::transparency::HashTree;
use qorch_domain::wave::context::WaveId;
use qorch_domain::wave::session_record::WaveSessionRecord;
use qorch_transparency_store::TransparencyStore;

use crate::per_skill_keys::PerSkillKeys;
use crate::wave_session_detail::SideTable;

/// Auxiliary index from `wave_id -> ordered list of (stage-time,
/// leaf_index)` so the `GET /v1/wave/{wave_id}/verify` route can
/// stream a wave's full session chain without scanning the entire
/// ledger. Populated on every successful append; the underlying
/// Merkle store stays the source of truth (the index is rebuildable
/// from the leaves on cold start by walking the store at boot).
///
/// internal-ref Phase 1 keeps this in-memory; the Postgres slice (Phase 2)
/// will denormalize via a `wave_session_leaves(wave_id, leaf_index)`
/// view.
pub type WaveSessionIndex = Arc<Mutex<HashMap<String, Vec<u64>>>>;

/// internal-ref — per-leaf BOUNDED LRU cache: `leaf_index ->
/// WaveSessionLeafSide`. Replaces the unbounded
/// `Arc<Mutex<HashMap<u64, ...>>>` from internal-ref Phase 1 / internal-ref.
/// Durable storage now lives in the sqlite side-table
/// (`wave_session_detail`); this cache is a hot-path optimisation on
/// top of it.
///
/// Eviction policy: LRU. When the cache reaches
/// [`DEFAULT_PAYLOAD_LRU_CAPACITY`] entries (1024), the least-recently
/// inserted/accessed entry is dropped. A cache miss re-reads from
/// the sqlite side-table.
///
/// Bounded residency is AC5 of internal-ref.
pub type WaveSessionPayloadCache = Arc<Mutex<LruCache<u64, WaveSessionLeafSide>>>;

/// internal-ref — auxiliary `leaf_index -> leaf_hash_hex` map. We need
/// this to translate the in-process index (which the verify route
/// derives from `wave_session_index`) into the sqlite primary key
/// (RFC-6962 hex leaf hash). The map is bounded by the wave-id
/// index's size and rebuildable from the ledger at boot — same
/// durability story as `wave_session_index`.
pub type WaveSessionLeafHashMap = Arc<Mutex<HashMap<u64, String>>>;

/// internal-ref default LRU capacity. 1024 entries × ~1 KiB average row
/// size ≈ 1 MiB ceiling on cache memory. Picked to comfortably fit
/// the typical hot wave (one wave touches ~5 leaves; 200 hot waves
/// covered) while staying well under the runtime's stack-of-stacks
/// footprint. Operators who want a larger / smaller window pass
/// their own capacity into [`AppState::with_payload_cache_capacity`].
pub const DEFAULT_PAYLOAD_LRU_CAPACITY: usize = 1024;

/// internal-ref — per-leaf side-map value. Holds the decoded record AND
/// the signature material the leaf was minted with. `kernel_hmac`
/// is always populated: for HMAC leaves it is the load-bearing
/// signature; for Ed25519 leaves it is the verbatim (possibly
/// placeholder) value the caller supplied — preserved so the verify
/// response round-trips byte-for-byte.
#[derive(Debug, Clone)]
pub struct WaveSessionLeafSide {
    /// The decoded wave-session record this leaf was minted from.
    pub record: WaveSessionRecord,
    /// The verbatim 32-byte HMAC the caller supplied (load-bearing on
    /// HMAC leaves, preserved-only on Ed25519 leaves).
    pub kernel_hmac: [u8; 32],
    /// `Some(bytes)` for Ed25519-signed leaves — the raw 64-byte
    /// signature over `canonical_bytes(record)`. `None` for HMAC
    /// leaves.
    pub ed25519_signature: Option<[u8; 64]>,
    /// Which algorithm the caller used to sign this leaf — drives the
    /// verify-route's `signature_type` field per entry.
    pub signature_type: crate::dto::SignatureType,
    /// Hex SHA-256 fingerprint of the key material binding this leaf.
    /// For HMAC: the kernel public-key fingerprint (binding identity).
    /// For Ed25519: the transparency-log Ed25519 public-key
    /// fingerprint. Stored at append-time so the verify route does
    /// not have to recompute or thread state.
    pub key_fingerprint_hex: String,
}

/// Process-level state shared by every handler.
///
/// `Clone` is `Arc`-cheap; axum's `State<AppState>` extractor requires
/// `Clone` and we hold every heavy field behind `Arc`.
#[derive(Clone)]
pub struct AppState {
    /// Append-only Merkle store (Postgres in prod, memory in tests).
    pub store: Arc<dyn TransparencyStore>,
    /// In-process mirror of the ledger's leaf hashes with every
    /// internal node cached (`HashTree`). `GET /v1/consistency` extends
    /// it from `store` only for leaves appended since the last request,
    /// then builds the proof from O(log n) cached subtree roots. Before
    /// this the route reloaded and re-hashed every leaf `0..second` per
    /// request, an O(n) amplification a public client could drive at
    /// will (public repo issue #84). Rebuildable from the store at any
    /// time; the store stays the source of truth.
    pub consistency_tree: Arc<Mutex<HashTree>>,
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
    /// the wave-session-record path. (internal-ref Phase 1.)
    pub kernel_hmac_key: Vec<u8>,
    /// In-process index from `wave_id -> [leaf_index]` so the verify
    /// route can stream a chain in O(records-in-wave). See
    /// [`WaveSessionIndex`]. (internal-ref Phase 1.)
    pub wave_session_index: WaveSessionIndex,
    /// internal-ref — index of leaves that are wave-shaped but failed
    /// strict deserialization. Holds `wave_id -> [leaf_index]` for
    /// leaves that could be identified as belonging to a wave but
    /// whose record bytes could not be decoded. The verify route uses
    /// this to distinguish "wave does not exist" (404) from "wave
    /// exists but records are unreadable" (a distinct error state).
    pub unreadable_wave_index: WaveSessionIndex,
    /// internal-ref — bounded LRU cache of per-leaf side values. Hot
    /// reads land here; misses go to the sqlite side-table via
    /// [`Self::wave_session_detail_store`]. Eviction is LRU under a
    /// configurable capacity ceiling (default
    /// [`DEFAULT_PAYLOAD_LRU_CAPACITY`]).
    pub wave_session_payloads: WaveSessionPayloadCache,
    /// internal-ref — `leaf_index -> hex(leaf_hash)` so the LRU-miss path
    /// can translate the in-process index into the sqlite primary
    /// key. Populated alongside the wave-session index.
    pub wave_session_leaf_hashes: WaveSessionLeafHashMap,
    /// internal-ref — durable denormalization for the per-leaf side data.
    /// `None` only in tests that don't exercise the wave-session
    /// path; production wiring always installs an in-memory or
    /// on-disk [`SideTable`]. The transparency-log ledger remains the
    /// source of truth — the side-table is a denorm that bounds the
    /// in-process LRU's residency.
    pub wave_session_detail_store: Option<Arc<SideTable>>,
    /// internal-ref — asymmetric (Ed25519) signing keypair for the
    /// transparency-log itself. Distinct from the STH signing key
    /// (`signing_key`) — that one signs tree heads; this one validates
    /// `signature_type: "ed25519"` wave-session-record appends.
    ///
    /// `None` when the service was started without an Ed25519 keypair
    /// configured (pre-internal-ref deployments). The route handler
    /// downgrades to "HMAC-only" in that case — a forward-compatible
    /// stance that does not break the legacy contract.
    ///
    /// Sourced from env var `QORCH_TRANSPARENCY_LOG_ED25519_PRIVATE`
    /// (32-byte hex seed); if missing in dev, generated at first boot
    /// and persisted to `.claude/state/transparency_ed25519_keypair.json`.
    /// Production fail-closes when the env var is missing (the bin
    /// enforces this — `AppState` is agnostic).
    pub transparency_ed25519_signing_key: Option<Arc<SigningKey>>,
    /// internal-ref — hex-encoded raw 32-byte Ed25519 public key derived
    /// from `transparency_ed25519_signing_key`. Echoed by the
    /// `GET /v1/keys/transparency` endpoint. `None` iff the signing
    /// key is `None`.
    pub transparency_ed25519_public_key_hex: Option<String>,
    /// internal-ref — SHA-256 fingerprint (hex) of the raw public-key
    /// bytes. Echoed by `/v1/keys/transparency` AND by every Ed25519
    /// wave-session-verify entry so verifiers can pin once and
    /// recompute per-entry.
    pub transparency_ed25519_key_fingerprint_hex: Option<String>,
    /// internal-ref — Unix-epoch seconds when the Ed25519 keypair was
    /// generated. `0` when the keypair was injected via env var (we
    /// don't know when the operator minted it).
    pub transparency_ed25519_generated_at_epoch_s: u64,

    /// internal-ref — per-skill (per-stage) HMAC `x-api-key` table.
    /// `None` ⇒ legacy single-shared-key mode (back-compat). `Some(_)`
    /// ⇒ the `/v1/wave/session` route requires the supplied
    /// `x-api-key` to match the configured key for `record.stage`;
    /// rejects 403 `stage_key_mismatch` on any mismatch.
    ///
    /// The middleware-layer `api_key` check still runs first — per-
    /// skill enforcement is an additive identity check, not a
    /// replacement. A request with a valid per-skill key for stage X
    /// must ALSO present a value that passes the shared `api_key`
    /// gate (which is typically configured as the per-skill key the
    /// kernel forwards on the writer's behalf).
    pub per_skill_keys: Option<Arc<PerSkillKeys>>,

    /// internal-ref / ADR-016 — DEDICATED Ed25519 public-key fingerprint
    /// (hex SHA-256) for the MCP-audit surface (`POST /v1/audit/mcp`).
    /// DISTINCT from `transparency_ed25519_key_fingerprint_hex` (the
    /// wave-session signing identity) and the kernel key — so a
    /// compromise of the MCP server cannot forge wave-session or kernel
    /// leaves (open-question 1, dedicated-key recommendation adopted).
    ///
    /// `None` ⇒ the MCP-audit append route is unavailable (503). The
    /// route verifies the caller-announced public key matches this
    /// fingerprint (constant-time) then verifies the Ed25519 signature
    /// over `canonical_bytes(record)`.
    pub mcp_audit_ed25519_key_fingerprint_hex: Option<String>,

    /// internal-ref — DEDICATED Ed25519 public-key fingerprint (hex SHA-256)
    /// for the Safety-Kernel reconciler drift-event surface
    /// (`POST /v1/audit/drift`). DISTINCT from `mcp_audit_ed25519_key_fingerprint_hex`,
    /// `transparency_ed25519_key_fingerprint_hex`, and the kernel key:
    /// a compromised reconciler must not be able to forge MCP-audit,
    /// wave-session, or kernel leaves, and vice versa.
    ///
    /// `None` ⇒ the reconciler-drift append route is unavailable (503).
    /// The route verifies the caller-announced public key matches this
    /// fingerprint (constant-time) then verifies the Ed25519 signature
    /// over `canonical_bytes(record)`.
    pub reconciler_drift_ed25519_key_fingerprint_hex: Option<String>,
}

impl AppState {
    /// Construct an `AppState`. Held by `Arc` inside axum but we
    /// expose a non-`Arc` constructor here so tests can build one
    /// without ceremony.
    ///
    /// internal-ref — `wave_session_payloads` is initialized as an LRU
    /// cache with [`DEFAULT_PAYLOAD_LRU_CAPACITY`] entries. Override
    /// via [`Self::with_payload_cache_capacity`]. The durable
    /// side-table is `None` here; production wiring calls
    /// [`Self::with_wave_session_detail_store`] with an on-disk
    /// `SideTable`. Tests that exercise the wave-session path call
    /// [`Self::with_in_memory_wave_session_detail_store`].
    #[must_use]
    pub fn new(
        store: Arc<dyn TransparencyStore>,
        signing_key: Arc<SigningKey>,
        signing_key_fingerprint_hex: String,
        kernel_key_fingerprint_hex: String,
        clock: Arc<dyn Clock>,
        api_key: String,
    ) -> Self {
        let cap = NonZeroUsize::new(DEFAULT_PAYLOAD_LRU_CAPACITY)
            .expect("DEFAULT_PAYLOAD_LRU_CAPACITY > 0");
        Self {
            store,
            consistency_tree: Arc::new(Mutex::new(HashTree::new())),
            signing_key,
            signing_key_fingerprint_hex,
            kernel_key_fingerprint_hex,
            clock,
            api_key,
            kernel_hmac_key: Vec::new(),
            wave_session_index: Arc::new(Mutex::new(HashMap::new())),
            unreadable_wave_index: Arc::new(Mutex::new(HashMap::new())),
            wave_session_payloads: Arc::new(Mutex::new(LruCache::new(cap))),
            wave_session_leaf_hashes: Arc::new(Mutex::new(HashMap::new())),
            wave_session_detail_store: None,
            transparency_ed25519_signing_key: None,
            transparency_ed25519_public_key_hex: None,
            transparency_ed25519_key_fingerprint_hex: None,
            transparency_ed25519_generated_at_epoch_s: 0,
            per_skill_keys: None,
            mcp_audit_ed25519_key_fingerprint_hex: None,
            reconciler_drift_ed25519_key_fingerprint_hex: None,
        }
    }

    /// internal-ref / ADR-016 — install the DEDICATED MCP-audit Ed25519
    /// public-key fingerprint the `POST /v1/audit/mcp` route pins
    /// against. The route never holds the private key (callers sign
    /// out-of-band under the MCP-audit signing key and announce the
    /// matching public key); the service only verifies. Returns `self`.
    #[must_use]
    pub fn with_mcp_audit_ed25519_fingerprint(mut self, fingerprint_hex: String) -> Self {
        self.mcp_audit_ed25519_key_fingerprint_hex = Some(fingerprint_hex);
        self
    }

    /// internal-ref — install the DEDICATED reconciler-drift Ed25519
    /// public-key fingerprint the `POST /v1/audit/drift` route pins
    /// against. The route never holds the private key (callers sign
    /// out-of-band under the reconciler-drift signing key and announce the
    /// matching public key); the service only verifies. Returns `self`.
    #[must_use]
    pub fn with_reconciler_drift_ed25519_fingerprint(mut self, fingerprint_hex: String) -> Self {
        self.reconciler_drift_ed25519_key_fingerprint_hex = Some(fingerprint_hex);
        self
    }

    /// Builder-style: install the kernel HMAC key the wave-session
    /// route checks against. Returns `self` for chained construction.
    /// (internal-ref Phase 1.)
    #[must_use]
    pub fn with_kernel_hmac_key(mut self, key: Vec<u8>) -> Self {
        self.kernel_hmac_key = key;
        self
    }

    /// internal-ref — override the LRU capacity. A capacity of `0` is
    /// rejected (rust `NonZeroUsize`); pass at least 1 entry. The
    /// existing cache is replaced (no data migration; the side-table
    /// remains the durable source).
    #[must_use]
    pub fn with_payload_cache_capacity(mut self, capacity: NonZeroUsize) -> Self {
        self.wave_session_payloads = Arc::new(Mutex::new(LruCache::new(capacity)));
        self
    }

    /// internal-ref — install a durable [`SideTable`] for the
    /// `wave_session_detail` denormalization. Production wiring uses
    /// `SideTable::open(path)`; tests use
    /// [`Self::with_in_memory_wave_session_detail_store`].
    #[must_use]
    pub fn with_wave_session_detail_store(mut self, store: Arc<SideTable>) -> Self {
        self.wave_session_detail_store = Some(store);
        self
    }

    /// internal-ref — convenience for tests: install an in-memory
    /// [`SideTable`]. Panics if sqlite refuses to open the in-memory
    /// database (it has never been observed to do so on supported
    /// targets; the call is infallible in practice).
    #[must_use]
    pub fn with_in_memory_wave_session_detail_store(self) -> Self {
        let st = SideTable::in_memory().expect("in-memory sqlite open should not fail");
        self.with_wave_session_detail_store(Arc::new(st))
    }

    /// internal-ref — Builder-style: install the transparency-log's
    /// Ed25519 signing keypair. Derives the public-key hex and SHA-256
    /// fingerprint hex eagerly so route handlers do not have to
    /// recompute on every request. `generated_at_epoch_s = 0` is
    /// allowed (means "unknown" — env-injected). Returns `self`.
    #[must_use]
    pub fn with_transparency_ed25519_keypair(
        mut self,
        signing_key: SigningKey,
        generated_at_epoch_s: u64,
    ) -> Self {
        use sha2::{Digest, Sha256};
        let pk_bytes = signing_key.verifying_key().to_bytes();
        let public_key_hex = hex::encode(pk_bytes);
        let mut h = Sha256::new();
        h.update(pk_bytes);
        let fingerprint_hex = hex::encode(h.finalize());
        self.transparency_ed25519_signing_key = Some(Arc::new(signing_key));
        self.transparency_ed25519_public_key_hex = Some(public_key_hex);
        self.transparency_ed25519_key_fingerprint_hex = Some(fingerprint_hex);
        self.transparency_ed25519_generated_at_epoch_s = generated_at_epoch_s;
        self
    }

    /// internal-ref — Builder-style: install the per-skill (per-stage)
    /// HMAC `x-api-key` table. Wrapping in `Arc` so handlers can hand
    /// it across `.await` boundaries cheaply; the table is read-only
    /// at runtime (rotations restart the bin).
    #[must_use]
    pub fn with_per_skill_keys(mut self, keys: PerSkillKeys) -> Self {
        self.per_skill_keys = Some(Arc::new(keys));
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

    /// internal-ref — Record a wave-shaped leaf that failed strict
    /// deserialization in the unreadable-wave index so the verify
    /// route can distinguish "wave does not exist" from "wave exists
    /// but records are unreadable".
    pub async fn record_unreadable_wave_leaf(&self, wave_id: &WaveId, leaf_index: u64) {
        let mut idx = self.unreadable_wave_index.lock().await;
        let entry = idx.entry(wave_id.as_str().to_string()).or_default();
        if !entry.contains(&leaf_index) {
            entry.push(leaf_index);
        }
    }

    /// internal-ref — Look up all unreadable leaf indices for a wave.
    /// Returns an empty vec when the wave has no unreadable leaves.
    pub async fn unreadable_wave_leaves(&self, wave_id: &WaveId) -> Vec<u64> {
        let idx = self.unreadable_wave_index.lock().await;
        idx.get(wave_id.as_str()).cloned().unwrap_or_default()
    }

    /// Stash the decoded record + signature material for a leaf.
    /// Idempotent — a re-append on the same leaf-index is a no-op.
    /// internal-ref stashed `(record, hmac)`; internal-ref extended this to a
    /// richer side-value carrying `signature_type`, the optional
    /// Ed25519 signature, and the key fingerprint so the verify route
    /// has all the material it needs without re-deriving.
    ///
    /// internal-ref — durability moved off the in-process HashMap (which
    /// grew unboundedly) and onto a sqlite `wave_session_detail`
    /// side-table. The LRU cache acts as a hot-path optimisation in
    /// front of the side-table. `leaf_hash_hex` is the row's primary
    /// key (the RFC-6962 leaf hash returned by the underlying
    /// `TransparencyStore`).
    ///
    /// This call is idempotent on `leaf_index` for both the cache and
    /// the side-table (the side-table uses `ON CONFLICT DO NOTHING`).
    pub async fn record_wave_session_payload(
        &self,
        leaf_index: u64,
        leaf_hash_hex: String,
        side: WaveSessionLeafSide,
    ) {
        // Cache the hot side-value first so subsequent verifies hit
        // the LRU.
        {
            let mut p = self.wave_session_payloads.lock().await;
            // `put` is a no-op when the key already exists for the
            // same value — but `LruCache::put` always inserts, which
            // is the desired idempotent behaviour: a re-append carries
            // the same bytes.
            if p.get(&leaf_index).is_none() {
                p.put(leaf_index, side.clone());
            }
        }
        {
            let mut m = self.wave_session_leaf_hashes.lock().await;
            m.entry(leaf_index).or_insert_with(|| leaf_hash_hex.clone());
        }
        // Durable side-table. Errors here are best-effort logged but
        // NOT propagated — the LRU + leaf bytes in the ledger remain
        // a recovery path. (The route layer treats a missing
        // side-table at lookup time as a cache miss; the same applies
        // to a failed insert.)
        if let Some(store) = self.wave_session_detail_store.clone() {
            let leaf_hash_hex_clone = leaf_hash_hex.clone();
            let side_clone = side.clone();
            // sqlite `INSERT` is sync; run it on a blocking worker so
            // we don't stall the runtime — same shape Postgres
            // workers would take. Outcome is logged via `tracing`
            // when the route layer wires it.
            // `Clock::now()` returns f64 epoch seconds; multiply for
            // ms and saturate to i64.
            let now_ms = {
                let ms = self.clock.now() * 1000.0;
                if ms.is_finite() && ms >= 0.0 && ms < i64::MAX as f64 {
                    ms as i64
                } else {
                    i64::MAX
                }
            };
            let _ = tokio::task::spawn_blocking(move || {
                let _ = store.insert(&leaf_hash_hex_clone, &side_clone, now_ms);
            })
            .await;
        }
    }

    /// internal-ref — register only the `leaf_index -> leaf_hash_hex`
    /// mapping (the sqlite side-table primary key) without touching the
    /// LRU or the detail store. Used by boot reconstruction: the map is
    /// lost on restart, so rebuilding it lets the [`Self::lookup_wave_session_payload`]
    /// step-2 path resolve a leaf's side from a durable side-table when
    /// one is configured. Idempotent (`entry(..).or_insert`).
    pub async fn register_wave_session_leaf_hash(&self, leaf_index: u64, leaf_hash_hex: String) {
        let mut m = self.wave_session_leaf_hashes.lock().await;
        m.entry(leaf_index).or_insert(leaf_hash_hex);
    }

    /// Look up the per-leaf side data. Returns `None` if the leaf was
    /// not produced by the wave-session route.
    ///
    /// internal-ref — lookup order:
    ///   1. LRU cache hit → return immediately.
    ///   2. LRU miss + side-table configured → translate `leaf_index`
    ///      to `leaf_hash_hex` (via the in-process map) and read the
    ///      side-table. Repopulate the LRU on success.
    ///   3. LRU miss + no side-table → return `None`.
    ///
    /// The side-table read is dispatched via `spawn_blocking` because
    /// rusqlite is sync.
    pub async fn lookup_wave_session_payload(
        &self,
        leaf_index: u64,
    ) -> Option<WaveSessionLeafSide> {
        // Step 1: LRU hit.
        {
            let mut p = self.wave_session_payloads.lock().await;
            if let Some(hit) = p.get(&leaf_index) {
                return Some(hit.clone());
            }
        }
        // Step 2: side-table fallback.
        let store = self.wave_session_detail_store.clone()?;
        let leaf_hash_hex = {
            let m = self.wave_session_leaf_hashes.lock().await;
            m.get(&leaf_index).cloned()?
        };
        let st = store.clone();
        let key = leaf_hash_hex.clone();
        let side = tokio::task::spawn_blocking(move || st.lookup(&key).ok().flatten())
            .await
            .ok()
            .flatten()?;
        // Repopulate LRU so subsequent reads hit it.
        {
            let mut p = self.wave_session_payloads.lock().await;
            p.put(leaf_index, side.clone());
        }
        Some(side)
    }
}
