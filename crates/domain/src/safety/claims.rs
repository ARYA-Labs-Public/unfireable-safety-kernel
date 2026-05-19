//! Typed claim wrappers — Slice 1 (ADR-014 §1.2 binding).
//!
//! Both authorize and approval claim sets are represented as typed
//! structs that emit a `BTreeMap<String, serde_json::Value>` for
//! byte-stable serialization (see `super::token::stable_json`).
//!
//! Required keys per `packages/core/safety_tokens.py:116-124`:
//! `action`, `run_id`, `subject`, `params_fingerprint`, `issued_at`,
//! `expires_at`, `nonce`. Approvals add `decision`, `reason`, `approver`,
//! `proposal_fingerprint` (`apps/safety_kernel/routes/approvals.py:97-101`).
//!
//! `reason` is `JSON null` (NOT omitted) when absent on approve / on
//! reject without a body-supplied reason — see ADR-014 Slice 1 §1.2
//! "Approval tokens" paragraph and `routes/approvals.py:97-98`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Trait emitted by every claim shape — converts the typed struct to
/// the canonical `BTreeMap<String, Value>` ordering used by
/// `super::token::stable_json` for byte-stable signing.
pub trait ToClaimsMap {
    /// Build the signed-claims map. Key set MUST match the Python
    /// `_REQUIRED_FIELDS` (and approval extras) exactly.
    fn to_btreemap(&self) -> BTreeMap<String, Value>;
}

/// Canonical `aud` claim value for `/kernel/v1/authorize` tokens.
///
/// Introduced in internal-ref slice 5 (Bundle A, PT-S2-M1 carry-forward).
/// The kernel signing key is shared across `/kernel/v1/authorize` and
/// the policy-engine endpoints; the `aud` claim partitions the audience
/// space so a token minted for one endpoint cannot be replayed against
/// another. Verifiers MUST opt-in to enforcement by passing
/// `Some(KERNEL_AUTHORIZE_AUD)` to `verify_kernel_token`.
pub const KERNEL_AUTHORIZE_AUD: &str = "kernel/authorize";

/// Canonical `aud` claim value for `/kernel/v1/approvals/decision` tokens.
///
/// Introduced in internal-ref-followup item 1 (PT-S5-M1). Slice 5 closed the
/// `aud` cross-tenant replay surface on the authorize + policy claim
/// types only; `ApprovalClaims` was left without an audience tag, so an
/// approval-decision token signed by the shared kernel key could in
/// principle be replayed against the `/kernel/v1/authorize` or
/// `/policy/*` verifiers (or vice versa). This constant partitions the
/// approval-decision audience space exactly as `KERNEL_AUTHORIZE_AUD`
/// does for authorize. Verifiers MUST opt-in to enforcement by passing
/// `Some(APPROVAL_AUD)` to `verify_kernel_token`; legacy callers that
/// pass `expected_aud = None` keep working (backwards-compat).
pub const APPROVAL_AUD: &str = "kernel/approvals/decision";

/// Authorize-token claim set — required keys per ADR-014 Slice 1 §1.2.
///
/// `subject` is overwritten by the Rust HTTP handler with `caller_role`
/// before signing — the request-body subject is recorded only as audit
/// metadata (ADR-014 Slice 1 §10 inconsistency note 4). This struct
/// holds whatever the handler decides to sign; it is shape-only.
///
/// **`aud` claim (internal-ref slice 5, PT-S2-M1 fold-in):** the kernel
/// signing key is the SAME key used by the policy-engine endpoints;
/// without an audience tag, a `/kernel/v1/authorize` token could in
/// principle be presented to a `/policy/*` verifier (or vice versa).
/// The `aud` claim closes that cross-tenant replay surface. New
/// handlers set `aud` to `KERNEL_AUTHORIZE_AUD`; legacy callers that
/// do not pass `expected_aud` to `verify_kernel_token` keep working
/// (backwards-compat, see `token::verify_kernel_token`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizeClaims {
    /// Sensitive action being authorized (e.g. `sio_run_cycles`).
    pub action: String,
    /// Audience tag — for `/kernel/v1/authorize` always
    /// `KERNEL_AUTHORIZE_AUD` (`"kernel/authorize"`). PT-S2-M1 fold-in.
    pub aud: String,
    /// Run identifier bound into the token.
    pub run_id: String,
    /// Subject (typically the `caller_role`: `worker` or `api`).
    pub subject: String,
    /// SHA-256 fingerprint of the action's params dict (stable JSON).
    pub params_fingerprint: String,
    /// Wall-clock issuance time, f64 epoch seconds.
    pub issued_at: f64,
    /// Wall-clock expiry time, f64 epoch seconds (= `issued_at + ttl_s`).
    pub expires_at: f64,
    /// Per-issuance nonce (base64url-no-pad, ~22 chars from 16 bytes).
    pub nonce: String,
}

impl ToClaimsMap for AuthorizeClaims {
    fn to_btreemap(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("action".to_string(), Value::String(self.action.clone()));
        // `aud` claim (PT-S2-M1). `BTreeMap` already gives lex-sorted
        // iteration so the insertion order here is decorative — the
        // emitted byte stream is sorted at serialization time.
        m.insert("aud".to_string(), Value::String(self.aud.clone()));
        m.insert("run_id".to_string(), Value::String(self.run_id.clone()));
        m.insert("subject".to_string(), Value::String(self.subject.clone()));
        m.insert(
            "params_fingerprint".to_string(),
            Value::String(self.params_fingerprint.clone()),
        );
        // Floats — `serde_json::Number::from_f64` returns Option because
        // NaN/infinity are not valid JSON. The Safety Kernel only emits
        // finite times, so a non-finite value here is a programming
        // error; we map None to JSON null so the signature still
        // produces a stable byte sequence (and downstream verification
        // will fail loudly on the type check).
        m.insert(
            "issued_at".to_string(),
            serde_json::Number::from_f64(self.issued_at).map_or(Value::Null, Value::Number),
        );
        m.insert(
            "expires_at".to_string(),
            serde_json::Number::from_f64(self.expires_at).map_or(Value::Null, Value::Number),
        );
        m.insert("nonce".to_string(), Value::String(self.nonce.clone()));
        m
    }
}

/// Approval-token claim set — adds `decision`, `reason`, `approver`,
/// `proposal_fingerprint` to the authorize-shape required keys (see
/// `apps/safety_kernel/routes/approvals.py:90-101`).
///
/// `reason` is JSON null when absent (on approve, or on reject without a
/// caller-supplied reason); Rust must emit `Value::Null`, not omit the
/// key, for byte equality with Python.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalClaims {
    /// Sensitive action being attested (e.g. `kernel_signed_approval`).
    pub action: String,
    /// Audience tag — for `/kernel/v1/approvals/decision` always
    /// `APPROVAL_AUD` (`"kernel/approvals/decision"`). PT-S5-M1 fold-in
    /// (internal-ref-followup item 1). Mirrors `AuthorizeClaims::aud`: closes
    /// the cross-tenant approval-token replay surface left open by
    /// slice 5 (which tagged authorize + policy claims only).
    pub aud: String,
    /// Run identifier bound into the token.
    pub run_id: String,
    /// Subject — always `"operator"` for approval claims
    /// (`apps/safety_kernel/routes/approvals.py:90-91`).
    pub subject: String,
    /// SHA-256 fingerprint of the params dict.
    pub params_fingerprint: String,
    /// Wall-clock issuance time.
    pub issued_at: f64,
    /// Wall-clock expiry time.
    pub expires_at: f64,
    /// Per-issuance nonce.
    pub nonce: String,
    /// Decision string — `"approved"` or `"rejected"`.
    pub decision: String,
    /// Human-readable reason — `None` serializes to JSON null.
    pub reason: Option<String>,
    /// Approver identifier (email / system / name).
    pub approver: String,
    /// SHA-256 fingerprint of the proposal content being approved.
    pub proposal_fingerprint: String,
}

impl ToClaimsMap for ApprovalClaims {
    fn to_btreemap(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("action".to_string(), Value::String(self.action.clone()));
        // `aud` claim (PT-S5-M1, internal-ref-followup item 1). `BTreeMap`
        // already gives lex-sorted iteration so the insertion order here
        // is decorative — the emitted byte stream is sorted at
        // serialization time ("aud" sorts between "approver" and
        // "decision").
        m.insert("aud".to_string(), Value::String(self.aud.clone()));
        m.insert("approver".to_string(), Value::String(self.approver.clone()));
        m.insert("decision".to_string(), Value::String(self.decision.clone()));
        m.insert(
            "expires_at".to_string(),
            serde_json::Number::from_f64(self.expires_at).map_or(Value::Null, Value::Number),
        );
        m.insert(
            "issued_at".to_string(),
            serde_json::Number::from_f64(self.issued_at).map_or(Value::Null, Value::Number),
        );
        m.insert("nonce".to_string(), Value::String(self.nonce.clone()));
        m.insert(
            "params_fingerprint".to_string(),
            Value::String(self.params_fingerprint.clone()),
        );
        m.insert(
            "proposal_fingerprint".to_string(),
            Value::String(self.proposal_fingerprint.clone()),
        );
        // `reason` is null (NOT omitted) when absent — binding contract
        // per ADR-014 Slice 1 §1.2.
        m.insert(
            "reason".to_string(),
            self.reason
                .as_ref()
                .map_or(Value::Null, |s| Value::String(s.clone())),
        );
        m.insert("run_id".to_string(), Value::String(self.run_id.clone()));
        m.insert("subject".to_string(), Value::String(self.subject.clone()));
        m
    }
}
