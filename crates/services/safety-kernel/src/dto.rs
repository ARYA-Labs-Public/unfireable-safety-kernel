//! Hand-rolled HTTP request / response DTOs — port of the `OpenAPI`
//! schemas in `contracts/openapi/safety_kernel.yaml`.
//!
//! Per ADR-014 Slice 1 §7, the DTOs are NOT generated. Codegen
//! produces `serde_json::Value` for every `additionalProperties: true`
//! field and `HashMap<String, Value>` for free-form objects, which
//! does NOT preserve stable key order — we rely on `BTreeMap<String,
//! Value>` everywhere instead, so byte-stable serialization through
//! `qorch_domain::safety::token::stable_json` Just Works.
//!
//! `#[serde(deny_unknown_fields)]` on REQUEST types is intentional:
//! unexpected fields produce 422 (matches `FastAPI`'s `extra="forbid"`
//! Pydantic default).
//!
//! File-level allow: doc comments below reference `serde_json` /
//! `request_id` / `subject` in English prose. Adding backticks per
//! occurrence is visual noise; the allow keeps the docs readable.

#![allow(clippy::doc_markdown)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ============================================================================
// Health
// ============================================================================

/// `/health` and `/kernel/v1/health`. Three required fields per
/// `contracts/openapi/safety_kernel.yaml::HealthResponse` (and the
/// §5.3 patch that landed in W1).
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    /// Liveness flag — always `true` from the running service.
    pub ok: bool,
    /// Semver build version sourced from `QORCH_KERNEL_BUILD_VERSION`
    /// (default `"0.0.0-dev"`).
    pub version: String,
    /// Wall-clock seconds since process start. f64 to match Python.
    pub uptime_s: f64,
}

// ============================================================================
// Public key
// ============================================================================

/// `/kernel/v1/public_key`. The `OpenAPI` schema declares only the
/// required field set; Python emits two additional fields (`ok`,
/// `algorithm`) — Rust matches Python's wire so equivalence holds
/// (ADR-014 Slice 1 §10 inconsistency note 2).
#[derive(Debug, Clone, Serialize)]
pub struct PublicKeyResponse {
    pub ok: bool,
    /// Always `"Ed25519"` for Slice 1.
    pub algorithm: String,
    /// Base64url-no-pad of the raw 32-byte Ed25519 public key.
    pub public_key_b64: String,
    /// Hex sha256 of the raw 32-byte Ed25519 public key.
    pub public_key_fingerprint: String,
}

// ============================================================================
// Authorize
// ============================================================================

/// `/kernel/v1/authorize` request body. `BTreeMap` for the free-form
/// fields so when we re-serialize them into the policy IPC envelope
/// the key order is stable.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeRequest {
    /// Sensitive action being authorized (e.g. `sio_run_cycles`).
    pub action: String,
    /// Run identifier bound into the token.
    pub run_id: String,
    /// Worker-supplied identifier — recorded as audit metadata only;
    /// the SIGNED `claims.subject` is the trusted `caller_role`
    /// (ADR-014 Slice 1 §10 inconsistency note 4).
    pub subject: String,
    /// Sha256 fingerprint of the params dict (stable JSON).
    pub params_fingerprint: String,
    /// Optional params dict — when present, fingerprint is recomputed
    /// and compared (`routes/authorize.py:94-100`).
    #[serde(default)]
    pub params: Option<BTreeMap<String, Value>>,
    /// Requested TTL (kernel clamps).
    #[serde(default)]
    pub ttl_s: Option<i64>,
    /// Free-form audit metadata.
    #[serde(default)]
    pub metadata: Option<BTreeMap<String, Value>>,
}

/// `/kernel/v1/authorize` success response.
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizeResponse {
    pub ok: bool,
    /// Compact `<payload_b64>.<signature_b64>` token.
    pub token: String,
    /// Hex sha256 of `token` (UTF-8 bytes).
    pub token_sha256: String,
    /// Decoded claims (sorted-key `BTreeMap` → stable serialization).
    pub claims: BTreeMap<String, Value>,
}

// ============================================================================
// Approvals
// ============================================================================

/// `/kernel/v1/approvals/{item_id}/approve` request body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    pub approver: String,
    pub proposal_fingerprint: String,
    #[serde(default)]
    pub metadata: Option<BTreeMap<String, Value>>,
}

/// `/kernel/v1/approvals/{item_id}/reject` request body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectRequest {
    pub approver: String,
    pub proposal_fingerprint: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub metadata: Option<BTreeMap<String, Value>>,
}

/// Shared response shape for both approve / reject. Mirrors
/// `apps/safety_kernel/routes/approvals.py::SignedDecisionResponse`.
#[derive(Debug, Clone, Serialize)]
pub struct SignedDecisionResponse {
    pub ok: bool,
    pub item_id: String,
    /// `"approved"` | `"rejected"`.
    pub decision: String,
    pub token: String,
    pub token_sha256: String,
    pub claims: BTreeMap<String, Value>,
}

// ============================================================================
// Errors
// ============================================================================

/// Generic 4xx / 5xx error envelope. `ok` is always `false`. Note: the
/// Python deny path uses `error: "forbidden" | "denied" | ...` plus a
/// stable `reason` machine code; Rust echoes the same shape for byte
/// equivalence on the deny path.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    pub ok: bool,
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ErrorResponse {
    /// Build a no-`reason` error envelope (e.g. 401 unauthorized).
    #[must_use]
    pub fn simple(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: error.into(),
            reason: None,
        }
    }

    /// Build an error envelope with a stable machine reason code.
    #[must_use]
    pub fn with_reason(error: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: error.into(),
            reason: Some(reason.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    //! W4 purple-team T5 — panic-fuzz the request DTOs.
    //!
    //! Iterate hostile JSON payloads through the deserializers and
    //! assert NO panics. Any panic is a CRITICAL finding (server
    //! restart loop / DoS).
    //!
    //! Categories:
    //! - deeply-nested objects (1000+ levels)
    //! - giant strings (10 MiB)
    //! - large ints (i64::MAX, i128 boundary)
    //! - duplicate keys (serde_json keeps last)
    //! - wrong types
    //! - JSON in JSON (string-encoded JSON)
    //! - escape bombs
    //! - control characters in keys
    //! - empty/whitespace-only input
    //!
    //! All errors are expected to be `serde_json::Error` (graceful).

    use super::*;

    fn try_authorize(input: &str) -> Result<AuthorizeRequest, serde_json::Error> {
        serde_json::from_str(input)
    }

    fn try_approve(input: &str) -> Result<ApproveRequest, serde_json::Error> {
        serde_json::from_str(input)
    }

    fn try_reject(input: &str) -> Result<RejectRequest, serde_json::Error> {
        serde_json::from_str(input)
    }

    /// Build a deeply nested JSON object literal: `{"a":{"a":...}}`
    /// to depth `n`. serde_json's default recursion limit is 128,
    /// so 1000 levels MUST hit the limit and produce an Err — but
    /// not a panic / stack overflow (serde_json uses an iterative
    /// parser).
    fn nested_object(n: usize) -> String {
        let mut s = String::new();
        for _ in 0..n {
            s.push_str("{\"a\":");
        }
        s.push('1');
        for _ in 0..n {
            s.push('}');
        }
        s
    }

    #[test]
    fn t5_panic_fuzz_authorize_dto() {
        // Build a battery of hostile inputs.
        let giant_string = format!(
            r#"{{"action":"{}","run_id":"x","subject":"x","params_fingerprint":"x"}}"#,
            "A".repeat(10_000_000)
        );
        let inputs: Vec<String> = vec![
            // Deep nesting — must NOT panic.
            nested_object(1000),
            nested_object(10_000),
            // Giant string (10 MiB).
            giant_string.clone(),
            // i64::MAX / i64::MIN / 2^63
            r#"{"action":"x","run_id":"x","subject":"x","params_fingerprint":"x","ttl_s":9223372036854775807}"#.to_string(),
            r#"{"action":"x","run_id":"x","subject":"x","params_fingerprint":"x","ttl_s":-9223372036854775808}"#.to_string(),
            // Past i64 max (would need to use parsing carefully).
            r#"{"action":"x","run_id":"x","subject":"x","params_fingerprint":"x","ttl_s":18446744073709551616}"#.to_string(),
            // Duplicate keys.
            r#"{"action":"x","action":"y","run_id":"x","subject":"x","params_fingerprint":"x"}"#.to_string(),
            // Wrong types.
            r#"{"action":1234,"run_id":"x","subject":"x","params_fingerprint":"x"}"#.to_string(),
            r#"{"action":"x","run_id":[],"subject":"x","params_fingerprint":"x"}"#.to_string(),
            // JSON in JSON (escaped string containing JSON).
            r#"{"action":"\"{\\\"foo\\\":1}\"","run_id":"x","subject":"x","params_fingerprint":"x"}"#.to_string(),
            // Escape bomb.
            format!(r#"{{"action":"{}","run_id":"x","subject":"x","params_fingerprint":"x"}}"#, "\\\"".repeat(1000)),
            // Control chars in key.
            r#"{" ":"x","action":"x","run_id":"x","subject":"x","params_fingerprint":"x"}"#.to_string(),
            // Empty body.
            String::new(),
            // Whitespace only.
            "    \n\t".to_string(),
            // Just `null`.
            "null".to_string(),
            // Array as top-level.
            "[]".to_string(),
            // String as top-level.
            r#""hello""#.to_string(),
            // Number as top-level.
            "42".to_string(),
            // Truncated.
            r#"{"action":"x","run_id":"x","subject":"x","params_fingerprint":"x""#.to_string(),
            // BOM-prefixed (UTF-8 BOM is INVALID at start of JSON per RFC 8259).
            "\u{feff}{\"action\":\"x\"}".to_string(),
            // Unicode in fields.
            r#"{"action":"café","run_id":"x","subject":"x","params_fingerprint":"x"}"#.to_string(),
            // Surrogates (invalid JSON since they don't pair).
            r#"{"action":"\uD800","run_id":"x","subject":"x","params_fingerprint":"x"}"#.to_string(),
        ];

        // Each input MUST produce either Ok or a `serde_json::Error`
        // — never a panic. We don't care about the outcome's truthiness
        // (deny_unknown_fields will reject most of them); we only
        // care that the parser doesn't blow up.
        let mut ok_count = 0_usize;
        let mut err_count = 0_usize;
        for input in &inputs {
            match try_authorize(input) {
                Ok(_) => ok_count += 1,
                Err(_) => err_count += 1,
            }
            // Also pump approve / reject parsers.
            let _ = try_approve(input);
            let _ = try_reject(input);
        }
        // Sanity: at least some inputs were rejected (we expect most
        // to fail; if they all pass, the test isn't testing what we
        // think it is).
        assert!(
            err_count >= inputs.len() / 2,
            "expected most fuzz inputs to be rejected; got ok={ok_count} err={err_count}"
        );
    }

    /// Reject deeply-nested literal (depth ~10000) does NOT cause a
    /// stack overflow — serde_json uses an iterative parser.
    #[test]
    fn t5_panic_fuzz_deep_nesting_does_not_stack_overflow() {
        let s = nested_object(10_000);
        // We don't care what the result is — just that this returns.
        let _ = serde_json::from_str::<AuthorizeRequest>(&s);
    }
}
