//! Policy-engine claim shapes —  ( binding).
//!
//! Two new typed claim shapes, both signed via the existing
//! `super::super::sign_kernel_token` primitive in
//! `crates/domain/src/safety/token.rs`. No new crypto, no new envelope,
//! no new hash. The Ed25519 signing key, the `stable_json`
//! canonicalization, and the `<payload_b64>.<sig_b64>` compact form
//! are all reused unchanged.
//!
//! # Required-claim-slot reuse
//!
//! `verify_kernel_token` (`token.rs:155-163`) requires the seven keys
//! `action`, `run_id`, `subject`, `params_fingerprint`, `issued_at`,
//! `expires_at`, `nonce` to be present in EVERY signed token. The
//! policy-engine claim shapes satisfy this contract by:
//!
//! - emitting `action` as a constant discriminator (`policy_module_authorize`
//!   or `policy_module_register`),
//! - reusing `run_id` as the caller's `caller_run_id` (authorize) or
//!   the `caller_subject` (register has no per-run context),
//! - emitting `subject` as the `caller_subject` from the request body
//!   (the trusted `caller_role` is `worker` for both endpoints, so the
//!   application-level `subject` field adds discrimination),
//! - reusing `params_fingerprint` to carry the operation-specific
//!   fingerprint (`event_fingerprint` for authorize, the registered
//!   payload's fingerprint for register) — per the
//!   `event_fingerprint` claim is REUSED into the `params_fingerprint`
//!   required slot so `verify_kernel_token` validates unchanged,
//! - `issued_at` / `expires_at` are `f64` epoch seconds (binding with
//!   `verify_kernel_token::as_f64` lookup at `token.rs:277-284`).
//!
//! # Forbidden imports
//!
//! Per `agent/boundaries.toml` and `crates/domain/Cargo.toml`, this file
//! imports nothing beyond `std::collections::BTreeMap`, `serde`,
//! `serde_json`, and `super::super::claims::ToClaimsMap`. Time and
//! randomness enter the signed claim via the calling handler (which
//! pulls from `Clock` and `NonceSource` adapters 1).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::claims::ToClaimsMap;
use super::types::{ModuleAuthorizeDecision, ModuleEventKind};

// ============================================================================
// ModuleAuthorizeClaims — `POST /policy/module/authorize` (allow OR deny)
// ============================================================================

/// Constant `action` value emitted into the signed claim map. The
/// equivalence harness pins this string byte-equal across implementations.
pub const POLICY_AUTHORIZE_ACTION: &str = "policy_module_authorize";

/// Constant `action` value for the register-receipt claim.
pub const POLICY_REGISTER_ACTION: &str = "policy_module_register";

/// Canonical `aud` value for `POST /policy/module/authorize` tokens.
/
/// Introduced in slice 5 (Bundle A,  carry-forward).
/// Closes the cross-tenant replay surface between
/// `/kernel/v1/authorize` and `/policy/module/authorize` — both endpoints
/// sign with the same kernel key, so without an audience tag a token
/// minted by one could be presented to the other's verifier.
pub const POLICY_AUTHORIZE_AUD: &str = "policy/module/authorize";

/// Canonical `aud` value for `POST /policy/module/register` receipt tokens.
/
/// Introduced in slice 5 (Bundle A,  carry-forward).
/// Same rationale as `POLICY_AUTHORIZE_AUD`.
pub const POLICY_REGISTER_AUD: &str = "policy/module/register";

/// Signed claim set for `POST /policy/module/authorize` — emitted for
/// BOTH `Allow` and `Deny` decisions ( table, lines 522-540).
/
/// `decision` and `reason` are payload fields; the §1.2 required-claim
/// set is satisfied via `action` / `run_id` / `subject` /
/// `params_fingerprint` / `issued_at` / `expires_at` / `nonce`. The
/// `event_fingerprint` value is duplicated into the `params_fingerprint`
/// slot so the existing `verify_kernel_token` accepts the token without
/// modification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModuleAuthorizeClaims {
    /// Audience tag — for `/policy/module/authorize` always
    /// `POLICY_AUTHORIZE_AUD` (`"policy/module/authorize"`).
    ///  fold-in ( slice 5).
    pub aud: String,
    /// Kernel identity — `"qorch-safety-kernel/<build_version>@<pk_fingerprint[:16]>"`.
    pub iss: String,
    /// Issued-at, `f64` epoch seconds. Matches `AuthorizeClaims::issued_at`
    /// for binding consistency with `verify_kernel_token`.
    pub iat: f64,
    /// Expiry, `f64` epoch seconds. Default `iat + 60` (
    /// "Why `ttl_s` = 60s default").
    pub exp: f64,
    /// `caller_subject` from the request body (NOT the trusted
    /// `caller_role` — that's always `worker` here).
    pub subject: String,
    /// `caller_run_id` from the request body.
    pub run_id: String,
    /// Audit-event class — `Import` / `Exec` / `Compile`.
    pub event_kind: ModuleEventKind,
    /// Module path (dotted name for `Import`, source-hash hex for
    /// `Exec`/`Compile`).
    pub module_path: String,
    /// Server-recomputed event fingerprint (NOT the value supplied by
    /// the caller — bind the trusted recomputation 
    pub event_fingerprint: String,
    /// `Allow` or `Deny` — the actual verdict.
    pub decision: ModuleAuthorizeDecision,
    /// Machine-readable refusal reason on `Deny`; `None` (→ JSON null)
    /// on `Allow`.  binds the key to be PRESENT in both
    /// cases — `Value::Null` on allow, NOT omitted.
    pub reason: Option<String>,
    /// Per-issuance nonce (base64url-no-pad).
    pub nonce: String,
}

impl ToClaimsMap for ModuleAuthorizeClaims {
    fn to_btreemap(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        // Required §1.2 keys (verify_kernel_token contract).
        m.insert(
            "action".to_string(),
            Value::String(POLICY_AUTHORIZE_ACTION.to_string()),
        );
        // `aud` claim. Position in the
        // emitted byte stream is determined by `BTreeMap` lex iteration
        // at serialization time, not by insertion order here.
        m.insert("aud".to_string(), Value::String(self.aud.clone()));
        m.insert("run_id".to_string(), Value::String(self.run_id.clone()));
        m.insert("subject".to_string(), Value::String(self.subject.clone()));
        // params_fingerprint mirrors event_fingerprint so the existing
        // verify_kernel_token required-claim check passes unchanged
        // (, deliverable #1).
        m.insert(
            "params_fingerprint".to_string(),
            Value::String(self.event_fingerprint.clone()),
        );
        m.insert(
            "issued_at".to_string(),
            serde_json::Number::from_f64(self.iat).map_or(Value::Null, Value::Number),
        );
        m.insert(
            "expires_at".to_string(),
            serde_json::Number::from_f64(self.exp).map_or(Value::Null, Value::Number),
        );
        m.insert("nonce".to_string(), Value::String(self.nonce.clone()));

        // Policy-specific keys (sorted by BTreeMap iteration order).
        m.insert(
            "decision".to_string(),
            Value::String(match self.decision {
                ModuleAuthorizeDecision::Allow => "allow".to_string(),
                ModuleAuthorizeDecision::Deny => "deny".to_string(),
                // KernelUnavailable never reaches a signed claim
                // (handler returns 503 before signing) — defensive only.
                ModuleAuthorizeDecision::KernelUnavailable => "kernel_unavailable".to_string(),
            }),
        );
        m.insert(
            "event_fingerprint".to_string(),
            Value::String(self.event_fingerprint.clone()),
        );
        m.insert(
            "event_kind".to_string(),
            Value::String(match self.event_kind {
                ModuleEventKind::Import => "import".to_string(),
                ModuleEventKind::Exec => "exec".to_string(),
                ModuleEventKind::Compile => "compile".to_string(),
            }),
        );
        m.insert("iss".to_string(), Value::String(self.iss.clone()));
        m.insert(
            "module_path".to_string(),
            Value::String(self.module_path.clone()),
        );
        // `reason` is null (NOT omitted) when absent on Allow — binding
        // contract per  (mirrors the existing approval-claims
        // pattern at `claims.rs:140-148`).
        m.insert(
            "reason".to_string(),
            self.reason
                .as_ref()
                .map_or(Value::Null, |s| Value::String(s.clone())),
        );

        m
    }
}

// ============================================================================
// ModuleRegisterClaims — `POST /policy/module/register` (signed receipt)
// ============================================================================

/// Signed receipt for a successful `POST /policy/module/register`
/// ( table, lines 542-552).
/
/// `register` has no per-run context, so `run_id` is set to the
/// `caller_subject` (per the ADR). The regex set is bound into the
/// receipt via a fingerprint, so the registered patterns can be
/// re-derived for audit without re-sending the set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModuleRegisterClaims {
    /// Audience tag — for `/policy/module/register` always
    /// `POLICY_REGISTER_AUD` (`"policy/module/register"`).
    ///  fold-in ( slice 5).
    pub aud: String,
    /// Kernel identity — same format as `ModuleAuthorizeClaims::iss`.
    pub iss: String,
    /// Issued-at, `f64` epoch seconds.
    pub iat: f64,
    /// Expiry, `f64` epoch seconds.
    pub exp: f64,
    /// `caller_subject` from the request body.
    pub subject: String,
    /// Echo of `subject` per  ("`run_id` is the
    /// `caller_subject` since `register` has no per-run context").
    pub run_id: String,
    /// Registered module path.
    pub module_path: String,
    /// SHA-256 hex of `stable_json({"patterns":[...]})` over the
    /// registered regex set.
    pub required_patterns_regex_set_fingerprint: String,
    /// Sidecar-assigned registration timestamp (unix milliseconds).
    pub registered_at_unix_ms: i64,
    /// `params_fingerprint(json!({module_path, required_patterns_regex_set}))`
    /// — required claim slot per `verify_kernel_token`.
    pub params_fingerprint: String,
    /// Per-issuance nonce.
    pub nonce: String,
}

impl ToClaimsMap for ModuleRegisterClaims {
    fn to_btreemap(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert(
            "action".to_string(),
            Value::String(POLICY_REGISTER_ACTION.to_string()),
        );
        // `aud` claim.
        m.insert("aud".to_string(), Value::String(self.aud.clone()));
        m.insert(
            "expires_at".to_string(),
            serde_json::Number::from_f64(self.exp).map_or(Value::Null, Value::Number),
        );
        m.insert(
            "issued_at".to_string(),
            serde_json::Number::from_f64(self.iat).map_or(Value::Null, Value::Number),
        );
        m.insert("iss".to_string(), Value::String(self.iss.clone()));
        m.insert(
            "module_path".to_string(),
            Value::String(self.module_path.clone()),
        );
        m.insert("nonce".to_string(), Value::String(self.nonce.clone()));
        m.insert(
            "params_fingerprint".to_string(),
            Value::String(self.params_fingerprint.clone()),
        );
        m.insert(
            "registered_at_unix_ms".to_string(),
            Value::Number(self.registered_at_unix_ms.into()),
        );
        m.insert(
            "required_patterns_regex_set_fingerprint".to_string(),
            Value::String(self.required_patterns_regex_set_fingerprint.clone()),
        );
        m.insert("run_id".to_string(), Value::String(self.run_id.clone()));
        m.insert("subject".to_string(), Value::String(self.subject.clone()));
        m
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    //! Stable key-order assertions for both claim shapes — the
    //! equivalence harness asserts byte equality of the signed payload
    //! against a Python reference. If the key ordering drifts, the
    //! signature bytes drift, and equivalence fails silently.

    use super::*;

    /// `ModuleAuthorizeClaims::to_btreemap` emits keys in lex order
    /// and includes EVERY field, including the `aud` claim
    /// added in slice 5.
    #[test]
    fn authorize_claims_emit_all_keys_in_lex_order() {
        let c = ModuleAuthorizeClaims {
            aud: POLICY_AUTHORIZE_AUD.to_string(),
            iss: "qorch-safety-kernel/0.0.0@deadbeefcafef00d".to_string(),
            iat: 1_715_212_345.0,
            exp: 1_715_212_405.0,
            subject: "worker-subj".to_string(),
            run_id: "run-1".to_string(),
            event_kind: ModuleEventKind::Import,
            module_path: "pkg.sub.mod".to_string(),
            event_fingerprint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                .to_string(),
            decision: ModuleAuthorizeDecision::Allow,
            reason: None,
            nonce: "n0nc3-string-aBc".to_string(),
        };
        let m = c.to_btreemap();
        let keys: Vec<&String> = m.keys().collect();
        // BTreeMap iterates in lex order — assert the EXACT sequence.
        // lex order: "action" < "aud" <... < "iss" < "issued_at" (empty
        // segment after shared "iss" prefix is less than any char).
        assert_eq!(
            keys,
            vec![
                "action",
                "aud",
                "decision",
                "event_fingerprint",
                "event_kind",
                "expires_at",
                "iss",
                "issued_at",
                "module_path",
                "nonce",
                "params_fingerprint",
                "reason",
                "run_id",
                "subject",
            ]
        );
        // params_fingerprint MUST equal event_fingerprint (the slot
        // reuse pattern documented at the top of this file).
        assert_eq!(
            m.get("params_fingerprint"),
            m.get("event_fingerprint"),
            "params_fingerprint claim slot must echo event_fingerprint",
        );
        // reason is JSON null (NOT omitted) on Allow.
        assert_eq!(m.get("reason"), Some(&Value::Null));
        // action is the constant discriminator.
        assert_eq!(
            m.get("action").and_then(Value::as_str),
            Some(POLICY_AUTHORIZE_ACTION),
        );
        // aud is the canonical policy-module-authorize tag.
        assert_eq!(
            m.get("aud").and_then(Value::as_str),
            Some(POLICY_AUTHORIZE_AUD),
        );
    }

    /// On `Deny`, the `reason` claim is a string (not null).
    #[test]
    fn authorize_claims_deny_reason_is_string() {
        let c = ModuleAuthorizeClaims {
            aud: POLICY_AUTHORIZE_AUD.to_string(),
            iss: "iss".to_string(),
            iat: 1.0,
            exp: 2.0,
            subject: "s".to_string(),
            run_id: "r".to_string(),
            event_kind: ModuleEventKind::Exec,
            module_path: "p".to_string(),
            event_fingerprint: "0".repeat(64),
            decision: ModuleAuthorizeDecision::Deny,
            reason: Some("module_not_registered".to_string()),
            nonce: "n".to_string(),
        };
        let m = c.to_btreemap();
        assert_eq!(
            m.get("reason").and_then(Value::as_str),
            Some("module_not_registered"),
        );
        assert_eq!(m.get("decision").and_then(Value::as_str), Some("deny"));
    }

    /// `ModuleRegisterClaims::to_btreemap` emits keys in lex order
    /// and includes all fields plus the `aud` claim added
    /// in slice 5.
    #[test]
    fn register_claims_emit_all_keys_in_lex_order() {
        let c = ModuleRegisterClaims {
            aud: POLICY_REGISTER_AUD.to_string(),
            iss: "qorch-safety-kernel/0.0.0@deadbeefcafef00d".to_string(),
            iat: 1_715_212_345.0,
            exp: 1_715_212_405.0,
            subject: "worker".to_string(),
            run_id: "worker".to_string(),
            module_path: "pkg.sub.mod".to_string(),
            required_patterns_regex_set_fingerprint: "f".repeat(64),
            registered_at_unix_ms: 1_715_212_345_000,
            params_fingerprint: "p".repeat(64),
            nonce: "n0nc3".to_string(),
        };
        let m = c.to_btreemap();
        let keys: Vec<&String> = m.keys().collect();
        // lex order: "iss" < "issued_at" — empty < any char after
        // the shared "iss" prefix.
        assert_eq!(
            keys,
            vec![
                "action",
                "aud",
                "expires_at",
                "iss",
                "issued_at",
                "module_path",
                "nonce",
                "params_fingerprint",
                "registered_at_unix_ms",
                "required_patterns_regex_set_fingerprint",
                "run_id",
                "subject",
            ]
        );
        assert_eq!(
            m.get("action").and_then(Value::as_str),
            Some(POLICY_REGISTER_ACTION),
        );
        // aud is the canonical policy-module-register tag.
        assert_eq!(
            m.get("aud").and_then(Value::as_str),
            Some(POLICY_REGISTER_AUD),
        );
    }

    /// Stable JSON serialization round-trip: signing the same claims
    /// twice yields the same compact payload. Critical guard against
    /// non-deterministic map iteration.
    #[test]
    fn authorize_claims_stable_under_repeated_serialization() {
        let c = ModuleAuthorizeClaims {
            aud: POLICY_AUTHORIZE_AUD.to_string(),
            iss: "iss".to_string(),
            iat: 1.0,
            exp: 2.0,
            subject: "s".to_string(),
            run_id: "r".to_string(),
            event_kind: ModuleEventKind::Compile,
            module_path: "pkg.mod".to_string(),
            event_fingerprint: "0".repeat(64),
            decision: ModuleAuthorizeDecision::Allow,
            reason: None,
            nonce: "n".to_string(),
        };
        let s1 = super::super::super::stable_json(&c.to_btreemap());
        let s2 = super::super::super::stable_json(&c.to_btreemap());
        assert_eq!(s1, s2);
    }
}
