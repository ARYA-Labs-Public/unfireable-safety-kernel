//! Wire-shape request/response types for the transparency-log
//! service (ADR-014 Phase 3 §3, ARY-1885 Step 5).
//!
//! Field ordering is lexicographic per ADR-014 Slice 1 Addendum 2a §5
//! (byte-stable JSON via deterministic struct layout). Add new fields
//! lex-sorted, never insertion-order.

use serde::{Deserialize, Serialize};

use qorch_domain::transparency::{ConsistencyProof, InclusionProof, MerkleLeaf, SignedTreeHead};

/// `POST /v1/append` request body.
///
/// `token_b64` is the kernel-emitted authorize token in its
/// base64url form. `kernel_key_fingerprint_sha256` is the SHA-256
/// fingerprint of the kernel's Ed25519 public key (hex-encoded)
/// — the transparency-log binds appends to a specific signing key.
/// `idempotency_key_hex` is the kernel-computed 32-byte fingerprint
/// (SHA-256 of the token bytes per ADR-014 Phase 3 §6) the store
/// de-duplicates on. `occurred_at_epoch_seconds` is the kernel-asserted
/// wall-clock instant the underlying decision was minted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendRequest {
    /// 32-byte idempotency fingerprint, hex-encoded (64 chars).
    pub idempotency_key_hex: String,

    /// SHA-256 fingerprint of the kernel signing public key (hex).
    pub kernel_key_fingerprint_sha256: String,

    /// Kernel-asserted wall-clock instant the decision was minted
    /// (seconds since the Unix epoch).
    pub occurred_at_epoch_seconds: u64,

    /// Base64url-encoded kernel authorize token (the leaf payload).
    pub token_b64: String,
}

/// `POST /v1/append` response body. Success-of-an-idempotent-retry is
/// surfaced as HTTP 200 with `idempotent_replay: true`; a NEW append
/// returns HTTP 201 with `idempotent_replay: false`. A
/// **same-idempotency-key, different-payload** call returns
/// HTTP 409 Conflict via the `ErrorResponse` envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendResponse {
    /// Opaque identifier the caller can hand to `GET /v1/verify/:id`.
    pub entry_id: String,

    /// True when this response surfaces an EXISTING row (idempotent
    /// retry). False on a fresh insert.
    pub idempotent_replay: bool,

    /// SHA-256 leaf hash that was appended (hex).
    pub leaf_hash_hex: String,

    /// 0-based position assigned by the storage adapter.
    pub leaf_index: u64,

    /// Always `true` on a successful response.
    pub ok: bool,
}

/// `GET /v1/verify/:entry_id` response body — bundles the leaf, the
/// RFC-6962 inclusion proof, and the tree head the proof was issued
/// against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Current SHA-256 root hash (hex) — the root the proof was
    /// issued against.
    pub current_root_hash: String,

    /// Current tree size — the size the proof was issued against.
    pub current_tree_size: u64,

    /// The appended leaf.
    pub entry: MerkleLeaf,

    /// RFC-6962 inclusion proof for `entry` against the tree of size
    /// `current_tree_size`.
    pub inclusion_proof: InclusionProof,
}

/// `GET /v1/sth` response body — wraps the Ed25519-signed tree head.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHeadResponse {
    /// Always `true` on a successful response.
    pub ok: bool,

    /// SHA-256 fingerprint of the signing key used to mint this STH
    /// (hex). Lets external verifiers check they have the right key.
    pub signing_key_fingerprint_sha256: String,

    /// The signed tree head itself.
    pub sth: SignedTreeHead,
}

/// `GET /v1/consistency?first=X&second=Y` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyResponse {
    /// RFC-6962 consistency proof between `from_size` and `to_size`.
    pub consistency_proof: ConsistencyProof,

    /// Always `true` on a successful response.
    pub ok: bool,
}

/// `GET /health` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Liveness flag — always `true` from the running service.
    pub ok: bool,
    /// Current tree size (echoed for operator visibility).
    pub tree_size: u64,
}

// ---------------------------------------------------------------------------
// ARY-2181 Phase 1 — wave-session-record routes
// ---------------------------------------------------------------------------

use qorch_domain::wave::session_record::WaveSessionRecord;

/// `POST /v1/wave/session` request body.
///
/// `record` is the canonical [`WaveSessionRecord`] content. The
/// service derives the idempotency key from
/// `SHA-256(wave_id || stage || session_id)` (per
/// [`WaveSessionRecord::record_idempotency_key`]). The kernel HMAC is
/// computed over `canonical_bytes(record)` and supplied as
/// `kernel_hmac_hex`; the service rejects with 403 if it does not
/// verify against the pinned shared secret. Lex-sorted field order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendWaveSessionRequest {
    /// Hex-encoded HMAC-SHA256 over `canonical_bytes(record)`. Must
    /// be exactly 64 chars (32 bytes).
    pub kernel_hmac_hex: String,

    /// SHA-256 fingerprint of the kernel signing public key (hex).
    /// Same pin as the existing `/v1/append` route — the wave-session
    /// surface is bound to the same kernel identity.
    pub kernel_key_fingerprint_sha256: String,

    /// The canonical wave-session record.
    pub record: WaveSessionRecord,
}

/// `POST /v1/wave/session` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendWaveSessionResponse {
    /// True when this response surfaces an EXISTING leaf (idempotent
    /// retry on the same wave/stage/session). False on a fresh append.
    pub idempotent_replay: bool,

    /// SHA-256 leaf hash that was appended (hex).
    pub leaf_hash_hex: String,

    /// 0-based ledger position.
    pub leaf_index: u64,

    /// Always `true` on a successful response.
    pub ok: bool,
}

/// One entry in the chain returned by `GET /v1/wave/{wave_id}/verify`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaveSessionChainEntry {
    /// Hex-encoded HMAC-SHA256 the kernel signed this record with.
    pub kernel_hmac_hex: String,
    /// 0-based ledger position.
    pub leaf_index: u64,
    /// The canonical wave-session record.
    pub record: WaveSessionRecord,
}

/// `GET /v1/wave/{wave_id}/verify` response body.
///
/// Returns the full chain (one entry per (stage, session_id) tuple
/// for this wave) plus the closeout gate's
/// `all_required_stages_present` predicate. The chain is sorted by
/// (stage canonical order, leaf_index ascending) so consumers can
/// render a deterministic timeline without an extra sort step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyWaveSessionResponse {
    /// True iff the chain covers TESTED + ACCEPTED + CLOSED, plus
    /// PURPLE_TEAMED when any record in the chain carries a non-empty
    /// `gate_surfaces`. (Predicate is computed by
    /// `qorch_domain::wave::session_record::all_required_stages_present`.)
    pub all_required_stages_present: bool,

    /// Full chain of session records for this wave.
    pub chain: Vec<WaveSessionChainEntry>,

    /// SHA-256 fingerprint of the kernel public key the records were
    /// HMAC-bound to. Echoed so external auditors can confirm they
    /// have the right pinning. (The HMAC itself is a symmetric secret
    /// — the fingerprint is the *kernel's* public-key fingerprint,
    /// not the HMAC key.)
    pub kernel_key_fingerprint_sha256: String,

    /// Always `true` on a successful response.
    pub ok: bool,

    /// Identity of the wave being verified.
    pub wave_id: String,
}
