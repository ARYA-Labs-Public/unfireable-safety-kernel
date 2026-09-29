//! Wire-shape request/response types for the transparency-log
//! service (ADR-014 Phase 3 §3, internal-ref Step 5).
//!
//! Field ordering is lexicographic per ADR-014 Slice 1 Addendum 2a §5
//! (byte-stable JSON via deterministic struct layout). Add new fields
//! lex-sorted, never insertion-order.

use std::collections::BTreeMap;

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
// internal-ref Phase 1 — wave-session-record routes
// ---------------------------------------------------------------------------

use qorch_domain::wave::session_record::WaveSessionRecord;

/// Which cryptographic algorithm a wave-session record was signed under
/// (internal-ref). HMAC remains the LEGACY path; Ed25519 is the additive
/// ASYMMETRIC path that lets external verifiers validate without any
/// secret material. See `docs/migration/transparency-log-ed25519-migration.md`
/// for the deprecation timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureType {
    /// Symmetric HMAC-SHA256 over `canonical_bytes(record)`. The
    /// LEGACY path the kernel has used since internal-ref Phase 1. Requires
    /// the shared secret to verify.
    Hmac,
    /// Asymmetric Ed25519 over `canonical_bytes(record)`. The PUBLIC
    /// path — external auditors verify with only the public key
    /// published at `GET /v1/keys/transparency`.
    Ed25519,
}

impl SignatureType {
    /// Stable wire string ("hmac" / "ed25519") for echoing back in
    /// `VerifyWaveSessionResponse` and the `/v1/keys/transparency`
    /// response. Lowercase to match the snake_case serde rename.
    #[must_use]
    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::Hmac => "hmac",
            Self::Ed25519 => "ed25519",
        }
    }
}

/// `POST /v1/wave/session` request body.
///
/// `record` is the canonical [`WaveSessionRecord`] content. The
/// service derives the idempotency key from
/// `SHA-256(wave_id || stage || session_id)` (per
/// [`WaveSessionRecord::record_idempotency_key`]). Lex-sorted field order.
///
/// **Dual signing surface (internal-ref).** Callers may sign in EITHER:
///
/// - LEGACY HMAC path (`signature_type` absent or `"hmac"`): supply
///   `kernel_hmac_hex` over `canonical_bytes(record)` with the shared
///   secret. The original internal-ref contract — bytes-for-bytes unchanged.
/// - Ed25519 path (`signature_type: "ed25519"`): supply
///   `ed25519_signature_hex` (64 bytes hex / 128 chars) over
///   `canonical_bytes(record)` AND the announced public key in
///   `ed25519_public_key_hex` (32 bytes hex / 64 chars). The service
///   verifies the announced public key matches the one published at
///   `GET /v1/keys/transparency` (constant-time fingerprint compare)
///   then runs the Ed25519 signature verification. A forged signature
///   under a different keypair → 403 Forbidden (AC6).
///
/// The HMAC and Ed25519 fields are mutually exclusive: when
/// `signature_type` is `"ed25519"`, `kernel_hmac_hex` is ignored;
/// when it is `"hmac"` or absent, the Ed25519 fields are ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendWaveSessionRequest {
    /// internal-ref — hex-encoded raw 32-byte Ed25519 public key announced
    /// by the caller. The service verifies this matches the published
    /// transparency-log Ed25519 public key (constant-time compare on
    /// the SHA-256 fingerprint) before running signature verification.
    /// Required when `signature_type == "ed25519"`; ignored otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed25519_public_key_hex: Option<String>,

    /// internal-ref — hex-encoded raw 64-byte Ed25519 signature over
    /// `canonical_bytes(record)`. Required when
    /// `signature_type == "ed25519"`; ignored otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed25519_signature_hex: Option<String>,

    /// Hex-encoded HMAC-SHA256 over `canonical_bytes(record)`. Must
    /// be exactly 64 chars (32 bytes). Required on the LEGACY HMAC
    /// path; ignored when `signature_type == "ed25519"`.
    ///
    /// internal-ref — to keep this field bytes-compatible with the
    /// legacy internal-ref contract, it is still REQUIRED on the wire
    /// (callers send a zero-byte placeholder if they want only the
    /// Ed25519 path validated and not the HMAC). The route ignores
    /// the placeholder when `signature_type == "ed25519"`.
    pub kernel_hmac_hex: String,

    /// SHA-256 fingerprint of the kernel signing public key (hex).
    /// Same pin as the existing `/v1/append` route — the wave-session
    /// surface is bound to the same kernel identity, regardless of
    /// which signing algorithm is used.
    pub kernel_key_fingerprint_sha256: String,

    /// The canonical wave-session record.
    pub record: WaveSessionRecord,

    /// internal-ref — which signing algorithm the caller used. Absent or
    /// `"hmac"` → legacy HMAC path (default for backward compatibility).
    /// `"ed25519"` → asymmetric path; the Ed25519 fields above are
    /// then required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_type: Option<SignatureType>,
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
///
/// internal-ref: also reports the `signature_type` the leaf was minted
/// under and the `key_fingerprint_hex` of the verifying material so an
/// external auditor can decide which public key (or shared secret) to
/// use without parsing the body separately.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaveSessionChainEntry {
    /// internal-ref — hex-encoded Ed25519 signature when the leaf was
    /// signed via the asymmetric path. `None` for legacy HMAC leaves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed25519_signature_hex: Option<String>,

    /// internal-ref — hex SHA-256 fingerprint of the key material that
    /// signed this entry. For HMAC leaves, this is the kernel-public-key
    /// fingerprint (the binding identity, NOT the HMAC secret itself).
    /// For Ed25519 leaves, this is the transparency-log Ed25519 public
    /// key's SHA-256 fingerprint. Lets external verifiers pick the
    /// right key WITHOUT calling `/v1/keys/transparency`.
    pub key_fingerprint_hex: String,

    /// Hex-encoded HMAC-SHA256 the kernel signed this record with.
    /// Present on every leaf — HMAC entries always carry their HMAC;
    /// Ed25519 entries carry the placeholder zero-bytes the caller
    /// supplied (the verifier MUST consult `signature_type` to know
    /// which field is load-bearing).
    pub kernel_hmac_hex: String,

    /// 0-based ledger position.
    pub leaf_index: u64,

    /// The canonical wave-session record.
    pub record: WaveSessionRecord,

    /// internal-ref — which algorithm signed this leaf. `"hmac"` or
    /// `"ed25519"`. Required so external auditors know which
    /// `*_hex` field is the load-bearing signature.
    pub signature_type: SignatureType,
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

    /// internal-ref — hex SHA-256 fingerprint of the transparency-log's
    /// Ed25519 public key (the asymmetric signing identity served at
    /// `GET /v1/keys/transparency`). Echoed so a verifier that only
    /// reads `/v1/wave/{id}/verify` already has the fingerprint it
    /// needs for Ed25519 entries. `None` when the service was started
    /// without an Ed25519 keypair (pre-internal-ref hosts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_log_ed25519_key_fingerprint_sha256: Option<String>,

    /// Identity of the wave being verified.
    pub wave_id: String,
}

// ---------------------------------------------------------------------------
// internal-ref — GET /v1/keys/transparency
// ---------------------------------------------------------------------------

/// `GET /v1/keys/transparency` response body (internal-ref AC1).
///
/// Publishes the transparency-log's asymmetric signing identity so
/// EXTERNAL verifiers can validate `signature_type: "ed25519"` leaves
/// with NO secret material. The endpoint is intentionally PUBLIC (no
/// `x-api-key`) — anyone can fetch a public key; that's the whole point
/// of asymmetric signing.
///
/// Wire shape (lex-sorted): `algorithm`, `generated_at_epoch_seconds`,
/// `key_fingerprint_sha256_hex`, `public_key_hex`. Add new fields
/// lex-sorted to preserve byte-stable JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyKeyResponse {
    /// Always `"Ed25519"` for this endpoint. Future algorithm
    /// negotiation would add new endpoints, not change this field.
    pub algorithm: String,

    /// Unix-epoch seconds when the transparency-log Ed25519 keypair
    /// was generated (or `0` when the service was bootstrapped from
    /// an injected env-var seed and the generation time is unknown).
    pub generated_at_epoch_seconds: u64,

    /// SHA-256 fingerprint (hex) of `public_key_hex` raw bytes. The
    /// same value that appears in `VerifyWaveSessionResponse.
    /// transparency_log_ed25519_key_fingerprint_sha256` and in each
    /// Ed25519 entry's `key_fingerprint_hex` — letting verifiers pin
    /// the key by fingerprint once and check every subsequent entry
    /// against the pin.
    pub key_fingerprint_sha256_hex: String,

    /// internal-ref — per-stage HMAC `x-api-key` fingerprints. `Some` when
    /// the service was started with per-skill keys configured;
    /// `None` (skipped on the wire) under back-compat single-shared-
    /// key mode. The map is `stage_wire_name → sha256(key) hex`
    /// (lex-sorted by key via `BTreeMap`); raw keys are NEVER
    /// exposed.
    ///
    /// External auditors use this to confirm a key rotation actually
    /// happened (fingerprints change) without learning the secrets.
    /// Inserted lex-sorted with the other fields to preserve
    /// byte-stable JSON output across versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_skill_fingerprints: Option<BTreeMap<String, String>>,

    /// Raw 32-byte Ed25519 public key, hex-encoded (64 chars).
    pub public_key_hex: String,
}

// ---------------------------------------------------------------------------
// internal-ref / ADR-016 — POST /v1/audit/mcp (MCP audit-record append)
// ---------------------------------------------------------------------------

/// `POST /v1/audit/mcp` request body (ADR-016, internal-ref Slice 1).
///
/// Mirrors the `wave_session` Ed25519 path but for an MCP audit record.
/// The caller supplies the record's CANONICAL BYTES directly
/// (`McpAuditRecord::canonical_bytes(prev_hash)`, hex) rather than a
/// typed record — the transparency log is record-type-agnostic; it
/// stores the leaf, the SEMANTIC schema lives in `mcp_audit.mcp_audit_log`.
///
/// The leaf is framed `length_prefix(canonical_bytes) || ed25519_sig`
/// (same shape as the wave-session route's `build_leaf_payload`, with a
/// 64-byte Ed25519 trailer instead of a 32-byte HMAC). Idempotent on the
/// caller-supplied `idempotency_key_hex` (`SHA-256(schema_version ||
/// event_id)`). Ed25519-signed so EXTERNAL auditors verify with the
/// published MCP-audit public key — no secret material.
///
/// Lex-sorted fields (byte-stable JSON convention).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendMcpAuditRequest {
    /// Hex of `McpAuditRecord::canonical_bytes(prev_hash)` — the leaf
    /// content the signature commits to.
    pub canonical_bytes_hex: String,

    /// Hex of the announced raw 32-byte Ed25519 public key (the
    /// DEDICATED MCP-audit signing identity). Verified against the
    /// pinned fingerprint before signature verification.
    pub ed25519_public_key_hex: String,

    /// Hex of the raw 64-byte Ed25519 signature over the bytes decoded
    /// from `canonical_bytes_hex`.
    pub ed25519_signature_hex: String,

    /// Hex of the 32-byte idempotency key (`SHA-256(schema_version ||
    /// event_id)`). The store de-duplicates on this; a same-key
    /// different-bytes call returns 409.
    pub idempotency_key_hex: String,

    /// Caller-asserted event instant (epoch seconds) — recorded on the
    /// leaf, NOT the insertion time.
    pub occurred_at_epoch_seconds: u64,
}

/// `POST /v1/audit/mcp` response body. Same shape as the wave-session
/// append response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendMcpAuditResponse {
    /// True on an idempotent replay of an already-appended leaf.
    pub idempotent_replay: bool,
    /// SHA-256 leaf hash that was appended (hex). The client
    /// cross-checks this against its locally-computed
    /// `SHA-256(0x00 || framed_payload)` (internal-ref).
    pub leaf_hash_hex: String,
    /// 0-based ledger position.
    pub leaf_index: u64,
    /// Always `true` on success.
    pub ok: bool,
}

// ---------------------------------------------------------------------------
// internal-ref — POST /v1/audit/reconciler-drift (Reconciler drift append)
// ---------------------------------------------------------------------------

/// `POST /v1/audit/reconciler-drift` request body (internal-ref).
///
/// Mirrors the MCP-audit append path for reconciler drift events.
/// The transparency log is record-type-agnostic: it pins the signing
/// identity, verifies the signature, and frames the leaf. It does not
/// parse the record, so the drift-event schema is owned entirely by
/// the Safety-Kernel reconciler.
///
/// Lex-sorted fields (byte-stable JSON convention).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendReconcilerDriftRequest {
    /// Hex of the Safety-Kernel reconciler's canonical drift-event
    /// bytes — the leaf content the signature commits to.
    pub canonical_bytes_hex: String,

    /// Hex of the announced raw 32-byte Ed25519 public key (the
    /// DEDICATED reconciler-drift identity — distinct from the
    /// MCP-audit, wave-session, and kernel keys). Verified against
    /// the pinned fingerprint before signature verification.
    pub ed25519_public_key_hex: String,

    /// Hex of the raw 64-byte Ed25519 signature over the bytes decoded
    /// from `canonical_bytes_hex`.
    pub ed25519_signature_hex: String,

    /// Hex of the 32-byte idempotency key (`SHA-256(schema_version ||
    /// event_id)`). The store de-duplicates on this; a same-key
    /// different-bytes call returns 409.
    pub idempotency_key_hex: String,

    /// Caller-asserted event instant (epoch seconds) — recorded on the
    /// leaf, NOT the insertion time.
    pub occurred_at_epoch_seconds: u64,
}

/// `POST /v1/audit/reconciler-drift` response body. Same shape as the
/// MCP-audit append response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendReconcilerDriftResponse {
    /// True on an idempotent replay of an already-appended leaf.
    pub idempotent_replay: bool,
    /// SHA-256 leaf hash that was appended (hex). The client
    /// cross-checks this against its locally-computed
    /// `SHA-256(0x00 || framed_payload)` (internal-ref).
    pub leaf_hash_hex: String,
    /// 0-based ledger position.
    pub leaf_index: u64,
    /// Always `true` on success.
    pub ok: bool,
}
