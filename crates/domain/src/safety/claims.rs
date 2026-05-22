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
/// Introduced in ARY-2028 slice 5 (Bundle A, PT-S2-M1 carry-forward).
/// The kernel signing key is shared across `/kernel/v1/authorize` and
/// the policy-engine endpoints; the `aud` claim partitions the audience
/// space so a token minted for one endpoint cannot be replayed against
/// another. Verifiers MUST opt-in to enforcement by passing
/// `Some(KERNEL_AUTHORIZE_AUD)` to `verify_kernel_token`.
pub const KERNEL_AUTHORIZE_AUD: &str = "kernel/authorize";

/// Canonical `aud` claim value for `/kernel/v1/approvals/decision` tokens.
///
/// Introduced in ARY-2028-followup item 1 (PT-S5-M1). Slice 5 closed the
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
/// **`aud` claim (ARY-2028 slice 5, PT-S2-M1 fold-in):** the kernel
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
    /// (ARY-2028-followup item 1). Mirrors `AuthorizeClaims::aud`: closes
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
        // `aud` claim (PT-S5-M1, ARY-2028-followup item 1). `BTreeMap`
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

// ---------------------------------------------------------------------------
// Core constraints — per ARY-2103.
//
// Customer-supplied compliance / brand / privacy / scope rules that the
// Safety Kernel loads per tenant at request time. The cogcore `CoreLane`
// (arya-speaks-language-core commit `a0dc571`) stores `CoreConstraint`
// structs in the Core lane — this is the shared domain type both repos
// must use so per-tenant compliance can be enforced at the type level.
// ---------------------------------------------------------------------------

/// Discriminator for the kind of customer-supplied rule. `Custom(name)`
/// allows verticals to introduce new categories without changing the
/// domain crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintKind {
    /// Regulatory compliance rule (HIPAA, SOX, FINRA, GDPR, etc.).
    ComplianceRule,
    /// Brand / messaging / tone-of-voice rule.
    BrandRule,
    /// Privacy / data-handling rule (PII redaction, retention, etc.).
    PrivacyRule,
    /// Scope-of-deployment rule (what topics ARYA may engage on).
    ScopeRule,
    /// Vertical-specific kind. Free-text name; the verticals own
    /// taxonomy outside this crate.
    Custom(String),
}

/// A single per-tenant compliance / brand / privacy / scope rule that
/// the Safety Kernel must enforce at request time. Versioned and
/// provenance-tracked so cogcore's `CoreLane` can store, retrieve, and
/// supersede rules without losing history.
///
/// Construction is direct field-by-field — there is no builder. The
/// struct is logically immutable: cogcore writes a new entry with
/// `version + 1` rather than mutating in place (see ARY-2103 design
/// notes). Note however that Rust ownership rules do not forbid an
/// owner of a `CoreConstraintSet` from mutating fields in place;
/// callers wishing to expose a `CoreConstraintSet` as read-only should
/// hand out `&CoreConstraintSet` rather than `&mut`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreConstraint {
    /// Unique constraint identifier within `tenant_id`.
    pub id: String,
    /// Customer / tenant that owns this rule.
    pub tenant_id: String,
    /// Discriminator (compliance / brand / privacy / scope / custom).
    pub kind: ConstraintKind,
    /// Free-text rule body — what the Safety Kernel actually
    /// enforces.
    pub rule_text: String,
    /// Priority. `0` = must-never-violate (hard); higher values are
    /// progressively softer. `255` is the softest the type allows.
    pub priority: u8,
    /// RFC3339 UTC timestamp from which this rule is in force
    /// (inclusive lower bound).
    pub valid_from: String,
    /// RFC3339 UTC timestamp after which this rule is retired
    /// (exclusive upper bound). `None` = open-ended (still in force).
    pub valid_to: Option<String>,
    /// Free-text provenance (e.g. `"HIPAA §164.502(a)"`, `"customer
    /// email 2026-05-15"`). Audit-grade; never empty in production.
    pub provenance: String,
    /// Monotonic version, starting at `1`. Increment on any text
    /// edit; older versions stay in the cogcore Core lane as history.
    pub version: u32,
}

/// All Core constraints loaded for a given tenant. The Safety Kernel
/// loads a `CoreConstraintSet` per tenant at request time from the
/// cogcore Core lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreConstraintSet {
    /// Tenant this set belongs to.
    pub tenant_id: String,
    /// All constraints for this tenant. Order is insertion order;
    /// uniqueness by `id` is the caller's responsibility (not enforced
    /// at the type level so the wire format is round-tripable).
    pub constraints: Vec<CoreConstraint>,
}

impl CoreConstraintSet {
    /// Return constraints with `priority == 0` (must-never-violate).
    ///
    /// AC3 — the returned slice contains exclusively `priority == 0`
    /// entries; any non-zero-priority constraint is filtered out.
    #[must_use]
    pub fn hard_constraints(&self) -> Vec<&CoreConstraint> {
        self.constraints
            .iter()
            .filter(|c| c.priority == 0)
            .collect()
    }

    /// Return constraints active at the given RFC3339 timestamp.
    ///
    /// A constraint is active iff
    /// `valid_from <= ts && (valid_to.is_none() || ts < valid_to)`.
    /// The lower bound is inclusive and the upper bound is exclusive:
    /// a constraint whose `valid_to` exactly equals `ts` is considered
    /// already retired.
    ///
    /// Comparison is lexicographic on the RFC3339 strings, which is
    /// correct when `ts`, `valid_from`, and `valid_to` are all
    /// well-formed RFC3339 UTC (`Z` suffix, identical precision).
    /// Mixed offsets, missing `Z`, or differing fractional-second
    /// precision are the caller's responsibility — `active_at` does
    /// not parse.
    ///
    /// AC4 — filters by `valid_from`/`valid_to` boundaries.
    #[must_use]
    pub fn active_at<'a>(&'a self, ts: &str) -> Vec<&'a CoreConstraint> {
        self.constraints
            .iter()
            .filter(|c| {
                c.valid_from.as_str() <= ts
                    && c.valid_to.as_ref().map_or(true, |v| ts < v.as_str())
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod core_constraint_tests {
    use super::*;

    fn mk(id: &str, priority: u8, valid_from: &str, valid_to: Option<&str>) -> CoreConstraint {
        CoreConstraint {
            id: id.to_string(),
            tenant_id: "acme".to_string(),
            kind: ConstraintKind::ComplianceRule,
            rule_text: format!("rule-{id}"),
            priority,
            valid_from: valid_from.to_string(),
            valid_to: valid_to.map(str::to_string),
            provenance: "test".to_string(),
            version: 1,
        }
    }

    /// AC3 — `hard_constraints` returns ONLY `priority == 0`.
    #[test]
    fn hard_constraints_returns_only_priority_zero() {
        let set = CoreConstraintSet {
            tenant_id: "acme".to_string(),
            constraints: vec![
                mk("hipaa", 0, "2026-01-01T00:00:00Z", None),
                mk("brand-1", 5, "2026-01-01T00:00:00Z", None),
                mk("sox", 0, "2026-01-01T00:00:00Z", None),
                mk("preference", 200, "2026-01-01T00:00:00Z", None),
            ],
        };
        let hard = set.hard_constraints();
        assert_eq!(hard.len(), 2);
        assert!(hard.iter().all(|c| c.priority == 0));
        let ids: Vec<&str> = hard.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["hipaa", "sox"]);
    }

    /// AC3 (negative) — `hard_constraints` excludes priority > 0
    /// even when only one constraint exists at the higher priority.
    #[test]
    fn hard_constraints_excludes_any_non_zero_priority() {
        let set = CoreConstraintSet {
            tenant_id: "acme".to_string(),
            constraints: vec![mk("soft", 1, "2026-01-01T00:00:00Z", None)],
        };
        assert!(set.hard_constraints().is_empty());
    }

    /// AC4 — `active_at` filters by `valid_from`/`valid_to` boundaries.
    #[test]
    fn active_at_filters_by_validity_window() {
        let set = CoreConstraintSet {
            tenant_id: "acme".to_string(),
            constraints: vec![
                mk("never-yet", 0, "2027-01-01T00:00:00Z", None),
                mk(
                    "retired",
                    0,
                    "2025-01-01T00:00:00Z",
                    Some("2026-01-01T00:00:00Z"),
                ),
                mk("open-ended", 0, "2024-01-01T00:00:00Z", None),
                mk(
                    "active-window",
                    0,
                    "2026-01-01T00:00:00Z",
                    Some("2027-01-01T00:00:00Z"),
                ),
            ],
        };
        let active = set.active_at("2026-06-01T00:00:00Z");
        let ids: Vec<&str> = active.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["open-ended", "active-window"]);
    }

    /// Boundary — `ts` exactly equal to `valid_from` is INCLUSIVE.
    #[test]
    fn active_at_inclusive_at_valid_from() {
        let set = CoreConstraintSet {
            tenant_id: "acme".to_string(),
            constraints: vec![mk("boundary", 0, "2026-05-22T18:00:00Z", None)],
        };
        let active = set.active_at("2026-05-22T18:00:00Z");
        assert_eq!(active.len(), 1);
    }

    /// Boundary — `ts` exactly equal to `valid_to` is EXCLUSIVE
    /// (already retired).
    #[test]
    fn active_at_exclusive_at_valid_to() {
        let set = CoreConstraintSet {
            tenant_id: "acme".to_string(),
            constraints: vec![mk(
                "boundary",
                0,
                "2026-05-22T18:00:00Z",
                Some("2026-05-22T19:00:00Z"),
            )],
        };
        let active = set.active_at("2026-05-22T19:00:00Z");
        assert!(active.is_empty());
    }

    /// Open-ended constraint (`valid_to = None`) stays active at any
    /// far-future timestamp.
    #[test]
    fn active_at_open_ended_is_active_far_future() {
        let set = CoreConstraintSet {
            tenant_id: "acme".to_string(),
            constraints: vec![mk("open", 0, "2020-01-01T00:00:00Z", None)],
        };
        let active = set.active_at("2099-01-01T00:00:00Z");
        assert_eq!(active.len(), 1);
    }

    /// AC5 — serde round-trip preserves all fields, including the
    /// `Custom(_)` variant of `ConstraintKind`.
    #[test]
    fn core_constraint_serde_roundtrip_custom_kind() {
        let c = CoreConstraint {
            id: "x".to_string(),
            tenant_id: "acme".to_string(),
            kind: ConstraintKind::Custom("vertical-specific".to_string()),
            rule_text: "r".to_string(),
            priority: 0,
            valid_from: "2026-01-01T00:00:00Z".to_string(),
            valid_to: None,
            provenance: "p".to_string(),
            version: 1,
        };
        let s = serde_json::to_string(&c).expect("serialize CoreConstraint");
        let back: CoreConstraint = serde_json::from_str(&s).expect("deserialize CoreConstraint");
        assert_eq!(back, c);
    }

    /// AC5 — `CoreConstraintSet` serde round-trip preserves order and
    /// every field.
    #[test]
    fn core_constraint_set_serde_roundtrip() {
        let set = CoreConstraintSet {
            tenant_id: "acme".to_string(),
            constraints: vec![
                mk("a", 0, "2026-01-01T00:00:00Z", None),
                mk("b", 5, "2026-01-01T00:00:00Z", Some("2027-01-01T00:00:00Z")),
            ],
        };
        let s = serde_json::to_string(&set).expect("serialize set");
        let back: CoreConstraintSet = serde_json::from_str(&s).expect("deserialize set");
        assert_eq!(back, set);
    }
}
