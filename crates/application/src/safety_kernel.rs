//! Safety Kernel client trait — a downstream service's authorization
//! attestation surface ( MED-2 remediation,  cross-slice
//! between  /  and  / ).
//!
//! The trait lives in the application crate so the dispatcher modules
//! (`crates/application/src/ddi/`) can call it without depending on
//! the concrete reqwest impl in `crates/adapters`. Same dependency-
//! inversion pattern as [`crate::ddi::adapter::DdiAdapter`].
//!
//! Per CLAUDE.md "Safety Kernel Consolidation" §"Principle: One
//! Authority, One Client, Fail-Safe on Inference Path":
//! - ** self-modification** → fail-closed (SK must approve).
//! - **Inference / cognitive loop** → fail-safe (SK unreachable →
//!   degraded mode, local gates only).
//!
//!  is on the cognitive-loop side. The dispatcher's
//! integration policy:
//! - SK reachable + approves → token embedded in envelope (`safety_token`,
//!   `safety_token_sha256` keys).
//! - SK reachable + rejects (4xx response) → dispatcher returns
//!   `error: "policy_rejected"`.
//! - SK unreachable (network error, timeout) → log a warning, proceed
//!   with local gates only (degraded mode).

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Errors the SK client can return.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum SafetyKernelError {
    /// SK reachable but the request was rejected with a 4xx response.
    /// Examples: forbidden `caller_role`, action not in API allowlist,
    /// malformed claims. Dispatcher fail-closes on this.
    #[error("policy_rejected: {status_code}: {detail}")]
    PolicyRejected {
        /// HTTP status code (typically 403 or 422).
        status_code: u16,
        /// Detail message from the SK error response, truncated.
        detail: String,
    },

    /// SK unreachable: network error, DNS failure, connection refused,
    /// timeout. Dispatcher fail-safes (degraded mode) on this.
    #[error("unreachable: {detail}")]
    Unreachable {
        /// Underlying transport-layer error detail.
        detail: String,
    },

    /// SK returned a response we couldn't parse. Treated as fail-safe
    /// (degraded) — same as unreachable.
    #[error("malformed_response: {detail}")]
    MalformedResponse {
        /// Parse-failure detail.
        detail: String,
    },
}

/// Claims for an `authorize` request. Built by the dispatcher per
/// invocation. See `crates/services/safety-kernel/src/dto.rs::
/// AuthorizeRequest`.
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizeClaimsRequest {
    /// Tool name (e.g. `"ddi_atlas_exp2_run"`).
    pub action: String,
    /// Unique run identifier the dispatcher generates per invocation.
    pub run_id: String,
    /// Identifier for the calling subject — for a downstream service
    /// binary, this is always `"qorch-ddi-dispatch"`. The SK overwrites
    /// the SIGNED `subject` with the `caller_role` anyway.
    pub subject: String,
    /// SHA-256 of canonical-JSON serialization of the args dict.
    pub params_fingerprint: String,
    /// Params dict — when present, SK recomputes the fingerprint to
    /// validate equality.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, Value>>,
    /// Requested TTL in seconds. SK clamps to its configured maximum.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_s: Option<i64>,
}

/// Successful authorization. Mirrors the SK service's
/// `AuthorizeResponse` DTO.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizeOutcome {
    /// `true` on success; the SK service emits this in every 200 response.
    pub ok: bool,
    /// Compact `<payload_b64>.<signature_b64>` token.
    pub token: String,
    /// Hex sha256 of the token bytes.
    pub token_sha256: String,
    /// Decoded claims map (sorted-key, byte-stable).
    pub claims: BTreeMap<String, Value>,
}

/// Trait a downstream service calls to attest a ddi_* invocation.
///
/// Async because the production impl issues an HTTP request to the
/// SK service over the network.
#[async_trait]
pub trait SafetyKernelClient: Send + Sync {
    /// Submit an authorization request to the SK service.
    ///
    /// Returns:
    /// - `Ok(AuthorizeOutcome)` when SK issued a token.
    /// - `Err(PolicyRejected)` when SK was reachable but refused.
    /// - `Err(Unreachable | MalformedResponse)` when SK was not
    ///   reachable or its response was malformed.
    async fn authorize(
        &self,
        claims: AuthorizeClaimsRequest,
    ) -> Result<AuthorizeOutcome, SafetyKernelError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{AuthorizeClaimsRequest, AuthorizeOutcome, SafetyKernelError};

    #[test]
    fn claims_request_serializes_with_optional_fields_omitted() {
        let claims = AuthorizeClaimsRequest {
            action: "ddi_atlas_exp2_run".into(),
            run_id: "run-abc".into(),
            subject: "qorch-ddi-dispatch".into(),
            params_fingerprint: "deadbeef".into(),
            params: None,
            ttl_s: None,
        };
        let s = serde_json::to_string(&claims).unwrap();
        // `s.contains("params")` would false-match `params_fingerprint`,
        // so check for the exact field-prefix.
        assert!(!s.contains("\"params\":"), "params should be omitted: {s}");
        assert!(!s.contains("\"ttl_s\":"), "ttl_s should be omitted: {s}");
        assert!(s.contains("\"action\":\"ddi_atlas_exp2_run\""));
        assert!(s.contains("\"params_fingerprint\":\"deadbeef\""));
    }

    #[test]
    fn outcome_deserializes_from_sk_service_response_shape() {
        let body = r#"{
            "ok": true,
            "token": "abc.def",
            "token_sha256": "0123",
            "claims": {"action": "ddi_atlas_exp2_run", "subject": "worker"}
        }"#;
        let outcome: AuthorizeOutcome = serde_json::from_str(body).unwrap();
        assert!(outcome.ok);
        assert_eq!(outcome.token, "abc.def");
        assert_eq!(outcome.claims.len(), 2);
    }

    #[test]
    fn error_variants_distinguish_fail_closed_from_fail_safe() {
        // Policy-rejected (SK reachable, said NO) → fail-closed.
        let rejected = SafetyKernelError::PolicyRejected {
            status_code: 403,
            detail: "caller_role_forbidden".into(),
        };
        assert!(format!("{rejected}").contains("policy_rejected"));

        // Unreachable (SK down) → fail-safe degraded.
        let unreachable = SafetyKernelError::Unreachable {
            detail: "connection refused".into(),
        };
        assert!(format!("{unreachable}").contains("unreachable"));
        assert_ne!(rejected, unreachable);
    }
}
