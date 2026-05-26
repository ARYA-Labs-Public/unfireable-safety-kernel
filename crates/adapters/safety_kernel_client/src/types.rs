//! Request/response DTOs and error taxonomy for the Safety Kernel
//! client. Mirrors the byte-stable wire format pinned by
//! `contracts/openapi/safety_kernel.yaml`; the canonical claim shapes
//! live in `qorch_domain::safety::{AuthorizeClaims, ApprovalClaims}`.
//!
//!   Step 2 — kernel-decision pure types moved to
//! `qorch_domain::safety::decision` (Addendum 2a §4). The adapter
//! re-exports them so existing callers (`use...::types::KernelDecision`)
//! keep resolving; the adapter-local error taxonomy
//! `KernelClientError` now wraps the domain's `KernelDecisionError`.

use qorch_domain::safety::KernelTokenError;
// Re-exported from the domain crate so adapter call sites can keep
// importing them from `types.rs` (Addendum 2a §4 — "pure-types
// inventory" / "Static fail-closed invariant"). The Allow constructor
// is private-by-discipline: it requires `VerifiedClaims`, which can
// only be built by `verify_kernel_token`.
pub use qorch_domain::safety::{KernelDecision, KernelDecisionError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

/// Request body for `POST /kernel/v1/authorize`. Field set matches
/// the Python `AuthorizeRequest` at
/// `apps/safety_kernel/routes/authorize.py` — kept in lockstep via the
/// generated types from `contracts/openapi/safety_kernel.yaml`.
///
/// **Field declaration order is lexicographic** per 
/// Addendum 2a §5 (rule 1). `boundary_check.rs` enforces this
/// structurally; reordering fields here will break a structural test.
/// `traceparent` is NOT sent in the body — it is an HTTP header — but
/// it lives on the struct so callers can plumb a w3c traceparent string
/// through the same API surface (see `client.rs::authorize`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    /// Sensitive action being requested (must be on the allowlist).
    pub action: String,
    /// SHA-256 of `params_json` — `qorch_domain::safety::params_fingerprint`.
    pub params_fingerprint: String,
    /// Run identifier bound into the issued token.
    pub run_id: String,
    /// Subject (caller) requesting authorization.
    pub subject: String,
    /// Optional traceparent for cross-process correlation (W4 of
    /// ). `#[serde(skip)]` keeps this field strictly out of
    /// the JSON wire body — `traceparent` is an HTTP header (emitted
    /// by `SafetyKernelClient::authorize`), NEVER a body field. The
    /// adversarial / boundary tests (Step 6 `boundary_check.rs`)
    /// assert the serialized body does not contain the substring
    /// `"traceparent"`, so this attribute is load-bearing.
    #[serde(skip, default)]
    pub traceparent: Option<String>,
}

/// Response body for `POST /kernel/v1/authorize`. The signed token is
/// the only authoritative field; the optional `claims_hint` is the
/// kernel's pre-decoded claim map (informational only — every caller
/// re-derives via `PinnedKeyVerifier`).
///
/// We do NOT embed `qorch_domain::safety::VerifiedClaims` here because
/// it deliberately does not implement `Serialize` / `Deserialize`
/// (the kernel re-encodes via `stable_json` on the byte boundary, not
/// via serde derive). The wire-level hint is a plain `BTreeMap`.
///
/// **Lex-sorted fields** per ADR §5 rule 1. The server (`dto.rs`)
/// emits four fields `{ok, token, token_sha256, claims}` — the adapter
/// only needs the signed token (everything else is re-derived locally),
/// so unrecognised fields are tolerated by serde's default behaviour
/// (no `deny_unknown_fields` on the response path).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    /// Optional pre-decoded claims map. Informational only — the
    /// adapter re-derives via `PinnedKeyVerifier::verify`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims_hint: Option<BTreeMap<String, Value>>,
    /// Compact signed token (Ed25519, see ).
    pub token: String,
}

/// Response body for `GET /kernel/v1/health` (and `/health`). Mirrors
/// the server-side DTO at `crates/services/safety-kernel/src/dto.rs::
/// HealthResponse`. **Lex-sorted fields** per ADR §5 rule 1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Liveness flag — always `true` from the running service.
    pub ok: bool,
    /// Wall-clock seconds since process start.
    pub uptime_s: f64,
    /// Semver build version.
    pub version: String,
}

/// Response body for `GET /kernel/v1/public_key`. Mirrors the
/// server-side DTO at `crates/services/safety-kernel/src/dto.rs::
/// PublicKeyResponse`. **Lex-sorted fields** per ADR §5 rule 1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    /// Always `"Ed25519"` for.
    pub algorithm: String,
    /// Liveness flag — Python parity.
    pub ok: bool,
    /// Base64url-no-pad of the raw 32-byte Ed25519 public key.
    pub public_key_b64: String,
    /// Hex sha256 of the raw 32-byte Ed25519 public key.
    pub public_key_fingerprint: String,
}

/// One row of the client-local audit trail. Mirrors the Python
/// `audit_trail()` accessor surface: each entry captures a single
/// `authorize()` call and its outcome so callers can produce a
/// post-hoc transparency log without re-running the request.
///
/// **Lex-sorted fields** per ADR §5 rule 1. This struct is NEVER
/// serialized over the wire — it is a local accessor type only.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuditEntry {
    /// `"ALLOW"` | `"DENY"` | `"UNAVAILABLE"` | `"VERIFICATION_FAILED"`
    /// — the caller-observed outcome of the `authorize()` call.
    pub outcome: String,
    /// Wall-clock seconds (from the adapter's `Clock`) at the moment
    /// the call returned.
    pub recorded_at_epoch_seconds: f64,
    /// Echo of the request's `run_id` — lets the caller correlate
    /// audit entries with their own logs.
    pub run_id: String,
    /// Echo of the request's `subject`.
    pub subject: String,
    /// Optional w3c traceparent header value used on the request.
    /// `None` when the caller did not supply one.
    pub traceparent: Option<String>,
}

/// All failure modes a caller observes from the SDK. FAIL-CLOSED
/// semantics: every variant here causes the caller's operation to be
/// rejected — none of them are recoverable as ALLOW.
///
///   Step 2 / Addendum 2a §4 — promoted from the
/// monolithic `KernelError` so that:
///
/// - `Decision(KernelDecisionError)` carries the **caller-visible**
///   outcome (kernel unreachable or kernel-refused); that variant is
///   pure-types and lives in `qorch_domain::safety::decision`.
/// - `Transport` / `Decode` / `Verification` carry **adapter-internal**
///   failure modes (HTTP transport drift, JSON decode drift, signature
///   verification failure) and therefore stay in this crate.
#[derive(Debug, Error)]
pub enum KernelClientError {
    /// HTTP transport problem distinct from `Decision::Unavailable`
    /// (e.g. 4xx from the kernel that is not a DENY — typically a
    /// contract mismatch the caller cannot fix at runtime).
    #[error("transport error: {0}")]
    Transport(String),

    /// Deserialization failure on response body (contract drift).
    #[error("decode error: {0}")]
    Decode(String),

    /// Kernel response signature did not match the pinned public key,
    /// or the token failed any structural / temporal verification
    /// step. Treated as a hard refusal — possibly a tampered or
    /// substituted kernel (  /  key-pinning AC).
    #[error("signature verification failed: {0}")]
    Verification(#[from] KernelTokenError),

    /// Caller-visible decision-channel failure: kernel unreachable
    /// (transport / breaker / 5xx) or kernel-refused. Carries the pure
    /// `KernelDecisionError` from `qorch_domain::safety::decision`.
    #[error("kernel decision error: {0:?}")]
    Decision(KernelDecisionError),
}

/// Convenience: lift a `KernelDecisionError` into the adapter-side
/// `KernelClientError`. Used by the breaker + client paths that
/// originate the Unavailable / Denied conditions.
impl From<KernelDecisionError> for KernelClientError {
    fn from(value: KernelDecisionError) -> Self {
        Self::Decision(value)
    }
}

//   Step 2 — the pre-promotion `KernelError` enum has
// been replaced by `KernelClientError` above per Addendum 2a §4. There
// is no transitional alias: the spec calls for the old enum to be
// removed and the in-crate callers (`client.rs`, `circuit_breaker.rs`)
// updated to use the new shape mechanically. Out-of-crate callers
// (workers/qorch_ddi_dispatch) do not import this enum directly; they
// go through the `qorch_application::safety_kernel::SafetyKernelError`
// trait surface served by `reqwest_client.rs`.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn authorize_request_traceparent_omitted_when_none() {
        // Per W4, traceparent is optional. JSON output must
        // not emit `"traceparent": null` — the contract pins
        // skip_serializing_if = "Option::is_none".
        let req = AuthorizeRequest {
            action: "sio_run_cycles".to_string(),
            run_id: "run-42".to_string(),
            subject: "worker".to_string(),
            params_fingerprint: "0".repeat(64),
            traceparent: None,
        };
        let j = serde_json::to_string(&req).unwrap();
        assert!(!j.contains("traceparent"));
    }

    #[test]
    fn unavailable_error_is_fail_closed_path() {
        //  AC2 (R): Unavailable must NOT be confusable with
        // an ALLOW path. After the Step 2 type split the
        // unavailable signal lives inside KernelDecisionError, wrapped
        // by the adapter's KernelClientError::Decision variant. The
        // structural test is unchanged: it must remain distinguishable.
        let err = KernelClientError::Decision(KernelDecisionError::Unavailable {
            reason: "circuit breaker open".to_string(),
        });
        match err {
            KernelClientError::Decision(KernelDecisionError::Unavailable { reason }) => {
                assert!(reason.contains("circuit"));
            }
            _ => panic!("Unavailable variant must be distinguishable"),
        }
    }
}
