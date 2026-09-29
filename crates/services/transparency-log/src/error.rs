#![allow(clippy::doc_overindented_list_items, clippy::doc_lazy_continuation)]
//! HTTP error envelope + service-internal error type (internal-ref Step 5).
//!
//! Mirrors the kernel's `dto::ErrorResponse` shape so client SDKs only
//! have to learn ONE error envelope. `ServiceError` is the local
//! taxonomy mapped to HTTP status codes via `IntoResponse`.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

use qorch_domain::transparency::VerificationError;
use qorch_transparency_store::StoreError;

/// Stable wire-shape for 4xx / 5xx responses. `ok` is always `false`;
/// `error` carries a high-level category and `reason` a stable machine
/// code. Lex-sorted by serde field order (insertion order in struct
/// declaration). Add new fields lex-sorted.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    /// High-level error category (`"invalid_request"`, `"unauthorized"`,
    /// `"conflict"`, `"server_error"`, ...).
    pub error: String,
    /// Always `false`.
    pub ok: bool,
    /// Stable machine code (e.g. `"idempotency_payload_mismatch"`,
    /// `"kernel_fingerprint_mismatch"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ErrorResponse {
    /// Build an envelope with category + reason code.
    #[must_use]
    pub fn with_reason(error: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            ok: false,
            reason: Some(reason.into()),
        }
    }

    /// Build an envelope with category only (no machine reason code).
    #[must_use]
    pub fn simple(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            ok: false,
            reason: None,
        }
    }
}

/// Local error taxonomy for route handlers. Each variant maps to ONE
/// HTTP status code. The kernel client treats 5xx as fail-closed.
#[derive(Debug, Error)]
pub enum ServiceError {
    /// Caller sent malformed JSON or violated a contract (e.g. wrong
    /// base64 padding, missing field). 400 Bad Request.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Kernel-key fingerprint in the body does not match the pinned
    /// kernel public key. 403 Forbidden.
    #[error("kernel fingerprint mismatch")]
    KernelFingerprintMismatch,

    /// Idempotency-key collision with mismatched payload (Step 4
    /// `StoreError::Conflict`). 409 Conflict. This is a SUCCESS signal
    /// for retries of the same key+payload — the store returns the
    /// existing row, NOT this error.
    #[error("idempotency payload mismatch")]
    IdempotencyPayloadMismatch,

    /// Requested entry does not exist. 404 Not Found.
    #[error("entry not found")]
    NotFound,

    /// The wave's leaf exists in the ledger but could not be
    /// deserialized -- deliberately NOT 404, because it must be
    /// distinguishable from a wave that never existed.
    #[error("entry unreadable")]
    EntryUnreadable,

    /// Invalid query-string parameter (e.g. negative tree size). 400
    /// Bad Request.
    #[error("invalid query parameter: {0}")]
    InvalidQuery(String),

    /// Domain verification error (empty tree, bounds check). Mapped to
    /// 400 Bad Request — the caller asked for something the tree
    /// cannot answer.
    #[error("verification error: {0}")]
    Verification(#[from] VerificationError),

    /// Backend failure (DB connection, transaction abort). 500.
    #[error("backend error: {0}")]
    Backend(String),

    /// Kernel HMAC signature on a wave-session record does not verify
    /// against the canonical-bytes projection. 403 Forbidden.
    /// (internal-ref — wave-session-record append.)
    #[error("kernel hmac signature mismatch")]
    KernelHmacMismatch,

    /// `record.stage` and the writing skill's `written_by` field
    /// disagree — e.g. `/test` writing a `CLOSED` record. 400 Bad
    /// Request. (internal-ref — wave-session-record append.)
    #[error("stage / written_by mismatch")]
    StageWrittenByMismatch,

    /// internal-ref — caller asked for `signature_type: "ed25519"` but
    /// the service was started without an Ed25519 keypair (legacy
    /// pre-internal-ref deployment). 503 Service Unavailable — operator
    /// needs to configure `QORCH_TRANSPARENCY_LOG_ED25519_PRIVATE`.
    #[error("ed25519 signing path is not configured on this server")]
    Ed25519NotConfigured,

    /// internal-ref — caller-announced Ed25519 public key does not match
    /// the key published by this transparency-log. Always a forged
    /// (or stale-key) submission — 403 Forbidden. The constant-time
    /// fingerprint compare prevents trial-and-error key probing.
    #[error("ed25519 public key fingerprint mismatch")]
    Ed25519KeyFingerprintMismatch,

    /// internal-ref — Ed25519 signature does not verify against the
    /// announced public key and `canonical_bytes(record)`. 403
    /// Forbidden. This is the AC6 adversarial outcome — a forged
    /// signature under a wrong keypair lands here.
    #[error("ed25519 signature verification failed")]
    Ed25519SignatureMismatch,

    /// internal-ref — `signature_type: "ed25519"` requested but one of
    /// the required `ed25519_*_hex` fields is missing on the wire.
    /// 400 Bad Request — caller-side schema error.
    #[error("ed25519 path requires ed25519_public_key_hex and ed25519_signature_hex")]
    Ed25519MissingFields,

    /// internal-ref — per-skill `x-api-key` enforcement is armed AND the
    /// caller's `x-api-key` does not match the configured key for the
    /// `record.stage` they are trying to write. 403 Forbidden, reason
    /// `stage_key_mismatch`. Catches a `/test` skill attempting to
    /// write a `Closed` record (the `/closeout` key is not in the
    /// caller's possession). Covers two failure modes:
    ///   - Caller supplied a per-skill key bound to a DIFFERENT stage.
    ///   - The stage has no per-skill key configured at all (operator
    ///     forgot to set `QORCH_TRANSPARENCY_KEY_<stage>`).
    /// Both surface as the same 403 — disclosing which one failed
    /// would help an attacker map the configured-key surface.
    #[error("per-skill x-api-key does not match record.stage")]
    StageKeyMismatch,
}

impl From<StoreError> for ServiceError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Conflict => ServiceError::IdempotencyPayloadMismatch,
            StoreError::Backend(s) => ServiceError::Backend(s),
            StoreError::Verification(v) => ServiceError::Verification(v),
        }
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ServiceError::BadRequest(msg) | ServiceError::InvalidQuery(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::with_reason("invalid_request", msg.clone()),
            ),
            ServiceError::KernelFingerprintMismatch => (
                StatusCode::FORBIDDEN,
                ErrorResponse::with_reason("forbidden", "kernel_fingerprint_mismatch"),
            ),
            ServiceError::IdempotencyPayloadMismatch => (
                StatusCode::CONFLICT,
                ErrorResponse::with_reason("conflict", "idempotency_payload_mismatch"),
            ),
            ServiceError::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorResponse::with_reason("not_found", "entry_not_found"),
            ),
            ServiceError::EntryUnreadable => (
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorResponse::with_reason("entry_unreadable", "entry_unreadable"),
            ),
            ServiceError::Verification(v) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::with_reason("verification_error", v.to_string()),
            ),
            ServiceError::KernelHmacMismatch => (
                StatusCode::FORBIDDEN,
                ErrorResponse::with_reason("forbidden", "kernel_hmac_mismatch"),
            ),
            ServiceError::StageWrittenByMismatch => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::with_reason("invalid_request", "stage_written_by_mismatch"),
            ),
            ServiceError::Ed25519NotConfigured => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorResponse::with_reason("service_unavailable", "ed25519_not_configured"),
            ),
            ServiceError::Ed25519KeyFingerprintMismatch => (
                StatusCode::FORBIDDEN,
                ErrorResponse::with_reason("forbidden", "ed25519_key_fingerprint_mismatch"),
            ),
            ServiceError::Ed25519SignatureMismatch => (
                StatusCode::FORBIDDEN,
                ErrorResponse::with_reason("forbidden", "ed25519_signature_mismatch"),
            ),
            ServiceError::Ed25519MissingFields => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::with_reason("invalid_request", "ed25519_missing_fields"),
            ),
            ServiceError::StageKeyMismatch => (
                StatusCode::FORBIDDEN,
                ErrorResponse::with_reason("forbidden", "stage_key_mismatch"),
            ),
            ServiceError::Backend(msg) => {
                tracing::warn!(
                    target = "qorch.transparency_log",
                    kind = "backend_error",
                    detail = %msg,
                    "service backend error",
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::simple("server_error"),
                )
            }
        };
        (status, Json(body)).into_response()
    }
}
