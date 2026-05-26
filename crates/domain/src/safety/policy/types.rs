//! Pure types for the policy-engine HTTP surface — slice 2 binding.
//!
//! All four endpoint request/response shapes are now frozen by 
//! §" design". `ModuleAuthorizeRequest` / `ModuleAuthorizeResponse`
//! were locked in slice 1; `ModuleRegisterRequest` / `ModuleAuditEventRequest`
//! / `ModuleStatusResponse` are locked here in slice 2 and the handler
//! shapes in `crates/services/safety-kernel/src/routes/policy/` deserialize
//! these types directly.
//!
//! Forbidden-import discipline (`agent/boundaries.toml`): no `std::fs`,
//! `std::env`, `std::net`, `std::time::SystemTime`, `rand::*`,
//! `sqlx::*`, `diesel::*`, `reqwest::*`, `rdkafka::*`, `tracing::*`,
//! `log::*`. Time enters via the existing `Clock` trait in
//! `crates/domain/src/safety/mod.rs`; randomness via `NonceSource`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ============================================================================
// Frozen — `POST /policy/module/authorize`
// ============================================================================

/// `CPython` audit-event class that triggered the authorize call (PEP 578).
/
/// `Import` covers the standard `import` audit event; `Exec` and
/// `Compile` cover string-source execution and compilation respectively.
/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleEventKind {
    /// `import` audit event — module load by dotted name.
    Import,
    /// `exec` audit event — string source executed by `exec()`.
    Exec,
    /// `compile` audit event — source compiled by `compile()`.
    Compile,
}

/// Frozen request body for `POST /policy/module/authorize` (
/// §`OpenAPI` delta). Field set is binding; slice 2 implementation MUST
/// conform byte-equivalently.
/
/// Free-form audit `metadata` is `BTreeMap<String, Value>` so when the
/// slice-2 handler re-serializes it through `stable_json`, the key
/// order stays deterministic (matches the existing kernel pattern in
/// `crates/services/safety-kernel/src/dto.rs`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAuthorizeRequest {
    /// `CPython` audit-event class that triggered the call.
    pub event_kind: ModuleEventKind,
    /// For `import`: the dotted module name (`pkg.sub.mod`).
    /// For `exec` / `compile`: the SHA-256 hex of the source string
    /// (the source itself is NOT sent over the wire).
    pub module_path: String,
    /// Worker identity (matches the `subject` field on
    /// `/kernel/v1/authorize`). Lets the kernel correlate this event
    /// to an in-flight action authorization.
    pub caller_subject: String,
    /// Run identifier bound into the resulting decision token.
    pub caller_run_id: String,
    /// SHA-256 of the canonicalized event payload — bound into the
    /// signed decision so a recorded ALLOW cannot be replayed against
    /// a different event.
    pub event_fingerprint: String,
    /// Optional regex patterns the caller expects this module path to
    /// require — slice 2 uses these for validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_required_patterns: Option<Vec<String>>,
    /// Optional audit metadata (NOT bound into the signed token).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, Value>>,
}

/// Decision verdict for a module-authorize call.
/
/// `KernelUnavailable` is wire-distinct from `Deny`: the kernel issues
/// `Deny` only when policy says no, and `KernelUnavailable` when the
/// decision backend itself is unreachable. The Python audit-hook
/// reference treats both as fail-closed (slice 3), but downstream
/// audit replay needs to distinguish them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleAuthorizeDecision {
    /// Policy allows the module load / exec / compile.
    Allow,
    /// Policy refuses the operation.
    Deny,
    /// Decision backend unreachable (fail-closed downstream).
    KernelUnavailable,
}

/// Signed-envelope response for `POST /policy/module/authorize`.
/
/// Field set mirrors  §`OpenAPI` delta — the Allow shape requires
/// `ok` / `decision` / `token` / `token_sha256` / `claims`; the Deny
/// shape additionally requires `reason`. One Rust struct covers both
/// wire shapes; the optionality is at the field level because slice-1
/// handlers return `501 Not Implemented` and never populate the signed
/// envelope.
/
/// `token` / `token_sha256` / `claims` reuse the existing
/// `AuthorizeResponse` envelope from `crates/domain/src/safety/token.rs`
/// (`sign_kernel_token`, `token_sha256`) — same Ed25519 key, same
/// canonicalization, no new crypto.  wires these fields through;
/// slice 1 leaves them `None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleAuthorizeResponse {
    /// `true` when `decision == Allow`; `false` for `Deny` /
    /// `KernelUnavailable`. Redundant with `decision` but required by
    /// the envelope so non-Rust clients (Python audit hook)
    /// can short-circuit without parsing the enum string.
    pub ok: bool,
    /// Verdict (`allow` / `deny` / `kernel_unavailable`).
    pub decision: ModuleAuthorizeDecision,
    /// Compact `<payload_b64>.<signature_b64>` `Ed25519` token. `None`
    /// in slice-1 scaffolds; required by for both Allow and
    /// Deny responses in slice 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// `SHA-256` hex of the compact token bytes — the transparency-log
    /// handle. Mirrors `super::super::token::token_sha256`. `None` in
    /// slice 1; required by in slice 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_sha256: Option<String>,
    /// Decoded claims for debugging / replay (`event_kind`,
    /// `module_path`, `exp`, etc.). `None` in slice 1; required by
    ///  in slice 2. Same `BTreeMap` shape as
    /// `super::super::token::VerifiedKernelToken::claims` so key order
    /// stays deterministic across signing + replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<BTreeMap<String, Value>>,
    /// Machine-readable refusal reason when `decision == Deny` (e.g.,
    /// `module_not_registered`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ============================================================================
// Frozen — `POST /policy/module/register` (slice 2)
// ============================================================================

/// `POST /policy/module/register` request body — 
/
/// Registers a module path + the regex set every authorize call for
/// that path will be evaluated against. The signed receipt returned to
/// the caller is built from `ModuleRegisterClaims` (see `claims.rs`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleRegisterRequest {
    /// Dotted module name (or source-hash hex for code-execution
    /// events).
    pub module_path: String,
    /// Regex patterns the module path must match on every subsequent
    /// authorize call. ALL patterns must match (`RegexSet` semantics);
    /// an empty set allows everything (operators register the empty
    /// set for "allow anything from this path").
    pub required_patterns_regex_set: Vec<String>,
    /// Worker identity calling register — recorded as audit metadata.
    pub caller_subject: String,
}

/// `POST /policy/module/register` 201 success body — 
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRegisterResponse {
    /// Always `true` on 201.
    pub ok: bool,
    /// Echo of the registered path.
    pub module_path: String,
    /// Sidecar-assigned registration timestamp.
    pub registered_at_unix_ms: i64,
    /// SHA-256 hex of the compact token (UTF-8 bytes).
    pub token_sha256: String,
    /// Compact `<payload_b64>.<signature_b64>` Ed25519 receipt token.
    pub token: String,
    /// Decoded claims for caller-side verification.
    pub claims: BTreeMap<String, Value>,
}

// ============================================================================
// Frozen — `POST /policy/audit-event` (slice 2)
// ============================================================================

/// `event_kind` enum for the audit-event endpoint — 
/// frozen set. New variants require an ADR amendment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    /// Audit hook detected modules loaded BEFORE installation.
    HookInstallViolation,
    /// A subprocess worker failed to install its own hook.
    SubprocessPropagationFailed,
    /// Audit hook saw an `module_authorize` ALLOW for an unknown path.
    RegistryConsistencyWarning,
}

/// `POST /policy/audit-event` request body — 
/
/// Non-decision audit surface. Does not render a verdict, does not
/// sign a token; appends one entry to the chain and returns 202.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAuditEventRequest {
    /// Event class — closed enum 3.
    pub event_kind: AuditEventKind,
    /// Caller identity from request body (NOT the trusted `caller_role`).
    pub subject: String,
    /// Free-form audit metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, Value>>,
}

/// `POST /policy/audit-event` 202 success body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleAuditEventResponse {
    /// Always `true` on 202.
    pub ok: bool,
    /// `"policy_audit_event"` — echoes the audit-chain `audit_kind`.
    pub audit_kind: String,
    /// Server-side timestamp of the audit append (unix milliseconds).
    pub ts_unix_ms: i64,
}

// ============================================================================
// Frozen — `GET /policy/module/{module_path}/status` (slice 2)
// ============================================================================

/// One row of the recent-decisions history returned by `status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatusDecisionRow {
    /// Decision timestamp (unix milliseconds).
    pub ts_unix_ms: i64,
    /// `"allow"` or `"deny"`.
    pub decision: String,
    /// Echo of the caller's `run_id` at decision time.
    pub caller_run_id: String,
    /// SHA-256 hex of the signed decision token.
    pub token_sha256: String,
}

/// Sub-object of `ModuleStatusResponse` containing registration state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatusRegistration {
    /// When the module path was registered (unix milliseconds).
    pub registered_at_unix_ms: i64,
    /// Caller subject that performed the registration.
    pub registered_by: String,
    /// Regex set associated with this registration.
    pub required_patterns_regex_set: Vec<String>,
    /// Revocation timestamp, `None` while active.
    pub revoked_at_unix_ms: Option<i64>,
}

/// `GET /policy/module/{module_path}/status` 200 success body —
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatusResponse {
    /// Always `true` on 200.
    pub ok: bool,
    /// Echo of the requested module path.
    pub module_path: String,
    /// Current registration record.
    pub registration: ModuleStatusRegistration,
    /// Up to 20 newest-first decision rows.
    pub recent_decisions: Vec<ModuleStatusDecisionRow>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    //! Shape sanity — slice 1 only confirms the types serialize and
    //! deserialize as expects. Real protocol equivalence lands
    //! in slice 2 alongside `sign_kernel_token` wiring.

    use super::*;

    #[test]
    fn event_kind_round_trip_lowercase() {
        for (kind, wire) in [
            (ModuleEventKind::Import, "\"import\""),
            (ModuleEventKind::Exec, "\"exec\""),
            (ModuleEventKind::Compile, "\"compile\""),
        ] {
            let s = serde_json::to_string(&kind).expect("serialize");
            assert_eq!(s, wire, "event kind {kind:?} serialized wrong");
            let back: ModuleEventKind = serde_json::from_str(wire).expect("deserialize");
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn decision_round_trip_snake_case() {
        for (dec, wire) in [
            (ModuleAuthorizeDecision::Allow, "\"allow\""),
            (ModuleAuthorizeDecision::Deny, "\"deny\""),
            (
                ModuleAuthorizeDecision::KernelUnavailable,
                "\"kernel_unavailable\"",
            ),
        ] {
            let s = serde_json::to_string(&dec).expect("serialize");
            assert_eq!(s, wire);
            let back: ModuleAuthorizeDecision = serde_json::from_str(wire).expect("deserialize");
            assert_eq!(back, dec);
        }
    }

    #[test]
    fn authorize_request_rejects_unknown_field() {
        let bad = r#"{
            "event_kind":"import",
            "module_path":"pkg.mod",
            "caller_subject":"worker",
            "caller_run_id":"run-1",
            "event_fingerprint":"0000000000000000000000000000000000000000000000000000000000000000",
            "extra":"nope"
        }"#;
        assert!(serde_json::from_str::<ModuleAuthorizeRequest>(bad).is_err());
    }

    #[test]
    fn authorize_request_minimal_round_trip() {
        let body = ModuleAuthorizeRequest {
            event_kind: ModuleEventKind::Import,
            module_path: "pkg.mod".to_string(),
            caller_subject: "worker".to_string(),
            caller_run_id: "run-1".to_string(),
            event_fingerprint: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            expected_required_patterns: None,
            metadata: None,
        };
        let s = serde_json::to_string(&body).expect("serialize");
        let back: ModuleAuthorizeRequest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back.module_path, "pkg.mod");
        assert_eq!(back.event_kind, ModuleEventKind::Import);
    }
}
