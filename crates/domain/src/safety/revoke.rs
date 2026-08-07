//! RevokeCompute — the signed coercive-shutdown decision (Phase 1). This is
//! the SHARED wire contract consumed by both the kernel (which mints it) and
//! the control-plane Reaper (which verifies + executes it).
//!
//! # Why this is a typed claim set, not a fresh envelope
//!
//! The kernel verifier (`super::token::verify_kernel_token`) hard-requires
//! the SEVEN canonical claim keys in EVERY signed token: `action`, `run_id`,
//! `subject`, `params_fingerprint`, `issued_at`, `expires_at`, `nonce`
//! (the token verifier's `REQUIRED_FIELDS`). `RevokeComputeClaims` therefore
//! populates those seven slots and carries the revoke-specific fields
//! (`target`, `tier`, `trigger`, `reason`) as EXTRA claims — with `target`/
//! `tier`/`trigger`/`reason` bound into the signature through the
//! `params_fingerprint` slot, exactly the way `ApprovalClaims` binds
//! `proposal_fingerprint` (`routes/approvals.rs`) and policy binds
//! `event_fingerprint`. This reuses `sign_kernel_token` /
//! `verify_kernel_token` BYTE-FOR-BYTE — no new crypto, no new hash, no new
//! canonicalization — which is what makes a kill unforgeable and
//! offline-verifiable by construction.
//!
//! # Boundary
//!
//! Per `agent/boundaries.toml`, this module is pure types + pure functions.
//! It does NOT import `std::fs`/`std::env`/`std::net`/`std::time::SystemTime`,
//! `rand`, `sqlx`, `reqwest`, `tracing`, or `log`. Time / randomness / TTL
//! are supplied by the caller (the kernel handler), never sourced here.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::claims::ToClaimsMap;
use super::token::params_fingerprint;

// ============================================================================
// Audience + action discriminators
// ============================================================================

/// Audience tag partitioning revoke-compute (kill) tokens from
/// authorize / approvals / policy / restore tokens on the shared kernel
/// signing key. The Reaper verifies with `Some(REVOKE_COMPUTE_AUD)` so an
/// authorize/approval/restore token can never be replayed as a kill.
pub const REVOKE_COMPUTE_AUD: &str = "kernel/revoke/compute";

/// Constant `action` discriminator emitted into the required `action`
/// slot of a kill token (mirrors the policy/approval action constants).
pub const REVOKE_COMPUTE_ACTION: &str = "revoke_compute";

/// Audience tag for restore / un-kill tokens (§2.5). Its OWN tag so a
/// kill token can never act as a restore, and vice versa.
pub const REVOKE_RESTORE_AUD: &str = "kernel/revoke/restore";

/// Constant `action` discriminator emitted into the required `action`
/// slot of a restore token.
pub const REVOKE_RESTORE_ACTION: &str = "revoke_restore";

// ============================================================================
// Revoke-specific value types
// ============================================================================

/// Revocation strength. Phase 1 only mints/executes `VmStop`; the finer
/// rungs exist as variants so a Phase-2 on-box reaper reuses this type
/// without a wire change. Serialized snake_case, byte-pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationTier {
    /// Cooperative drain (rung one; the agent's own emergency-stop).
    Sigterm,
    /// Phase 2 on-box hard kill.
    Sigkill,
    /// Phase 2 on-box cgroup freeze/kill.
    CgroupKill,
    /// Phase 1 — the only tier a Phase-1 kernel mints/executes.
    VmStop,
}

/// Why this kill was issued. Phase 1 is explicit-only (an operator
/// pulled it, or a deliberate supervisory rogue determination). The
/// later auto-trigger variants are intentionally absent so a Phase-1
/// kernel cannot mint one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeTrigger {
    /// A human pulled the e-stop.
    OperatorEmergencyStop,
    /// A deliberate supervisory "this agent is rogue" determination.
    RogueDetermination,
}

/// The compute target — a cloud instance coordinate. In Phase 1 this is
/// the whole agent VM (`compute.instances.stop` is coarse). This is the
/// agent VM instance, NEVER the kernel VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceTarget {
    /// Cloud project id, e.g. `"my-project"`.
    pub project: String,
    /// Cloud zone, e.g. `"zone-a"`.
    pub zone: String,
    /// The agent VM instance name (NOT the kernel VM).
    pub instance: String,
}

// ============================================================================
// params_fingerprint recipes (the target/tier binding) — SHARED
// ============================================================================

/// Compute the `params_fingerprint` over the canonical REVOKE payload —
/// the target/tier/trigger/reason binding. Mirrors
/// `compute_decision_fingerprint` (`routes/approvals.rs`).
///
/// The kernel computes this from the target it was actually given and
/// copies it into the required `params_fingerprint` slot; the Reaper
/// recomputes it from the decoded claims and refuses on mismatch. That
/// is what stops a caller committing to target A while hashing target B.
///
/// Canonical payload (keys sorted by `stable_json` at hash time):
/// `{ "run_id", "target": {project,zone,instance}, "tier": "vm_stop",
///    "trigger": "operator_emergency_stop", "reason": <string|null> }`.
#[must_use]
pub fn revoke_params_fingerprint(
    run_id: &str,
    target: &InstanceTarget,
    tier: RevocationTier,
    trigger: RevokeTrigger,
    reason: Option<&str>,
) -> String {
    let mut m = serde_json::Map::new();
    m.insert("run_id".to_string(), Value::String(run_id.to_string()));
    m.insert(
        "target".to_string(),
        serde_json::to_value(target).unwrap_or(Value::Null),
    );
    m.insert(
        "tier".to_string(),
        serde_json::to_value(tier).unwrap_or(Value::Null),
    );
    m.insert(
        "trigger".to_string(),
        serde_json::to_value(trigger).unwrap_or(Value::Null),
    );
    m.insert(
        "reason".to_string(),
        reason.map_or(Value::Null, |s| Value::String(s.to_string())),
    );
    params_fingerprint(&Value::Object(m))
}

/// Compute the `params_fingerprint` over the canonical RESTORE payload.
/// A restore has no tier/trigger, so its binding is over
/// `{ "run_id", "target", "reason" }`. Distinct recipe + distinct `aud`
/// mean a kill fingerprint can never satisfy a restore verifier.
#[must_use]
pub fn restore_params_fingerprint(
    run_id: &str,
    target: &InstanceTarget,
    reason: Option<&str>,
) -> String {
    let mut m = serde_json::Map::new();
    m.insert("run_id".to_string(), Value::String(run_id.to_string()));
    m.insert(
        "target".to_string(),
        serde_json::to_value(target).unwrap_or(Value::Null),
    );
    m.insert(
        "reason".to_string(),
        reason.map_or(Value::Null, |s| Value::String(s.to_string())),
    );
    params_fingerprint(&Value::Object(m))
}

// ============================================================================
// Signed claim sets
// ============================================================================

/// The signed coercive-shutdown decision. Populates the seven required
/// canonical slots and carries the revoke-specific fields as extra
/// claims (all inside the signed payload).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RevokeComputeClaims {
    /// Always `REVOKE_COMPUTE_AUD`.
    pub aud: String,
    /// The revocation id (`revoke_<uuid>`) — required `run_id` slot.
    pub run_id: String,
    /// The trusted `caller_role` that minted it (`"operator"`) — required
    /// `subject` slot.
    pub subject: String,
    /// Fingerprint over the canonical revoke payload — required
    /// `params_fingerprint` slot. See [`revoke_params_fingerprint`].
    pub params_fingerprint: String,
    /// iat, f64 epoch seconds — required `issued_at` slot.
    pub issued_at: f64,
    /// exp = iat + short ttl — required `expires_at` slot.
    pub expires_at: f64,
    /// Per-issuance nonce — required `nonce` slot.
    pub nonce: String,
    // ---- revoke-specific extra claims (also inside the signed payload) ----
    /// Which VM to stop.
    pub target: InstanceTarget,
    /// `VmStop` in Phase 1.
    pub tier: RevocationTier,
    /// Explicit-only in Phase 1.
    pub trigger: RevokeTrigger,
    /// Free-text; `None` -> JSON null (NOT omitted), per the approvals
    /// byte-parity contract.
    pub reason: Option<String>,
}

impl ToClaimsMap for RevokeComputeClaims {
    fn to_btreemap(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        // Required `action` slot — the revoke discriminator.
        m.insert(
            "action".to_string(),
            Value::String(REVOKE_COMPUTE_ACTION.to_string()),
        );
        m.insert("aud".to_string(), Value::String(self.aud.clone()));
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
        // `reason` is null (NOT omitted) when absent — byte-parity with
        // the approvals contract.
        m.insert(
            "reason".to_string(),
            self.reason
                .as_ref()
                .map_or(Value::Null, |s| Value::String(s.clone())),
        );
        m.insert("run_id".to_string(), Value::String(self.run_id.clone()));
        m.insert("subject".to_string(), Value::String(self.subject.clone()));
        // Nested `target` object — `stable_json` sorts its keys at
        // serialization time, so insertion order here is decorative.
        m.insert(
            "target".to_string(),
            serde_json::to_value(&self.target).unwrap_or(Value::Null),
        );
        m.insert(
            "tier".to_string(),
            serde_json::to_value(self.tier).unwrap_or(Value::Null),
        );
        m.insert(
            "trigger".to_string(),
            serde_json::to_value(self.trigger).unwrap_or(Value::Null),
        );
        m
    }
}

/// The signed restore / un-kill decision (§2.5). Same seven required
/// slots; the extra claims are just `target` + `reason` (a restore has
/// no tier/trigger). Its own `aud`/`action`/fingerprint recipe means it
/// is structurally distinct from a kill.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RestoreClaims {
    /// Always `REVOKE_RESTORE_AUD`.
    pub aud: String,
    /// The restore id (`restore_<uuid>`) — required `run_id` slot.
    pub run_id: String,
    /// The minting `caller_role` (`"operator"`) — required `subject` slot.
    pub subject: String,
    /// Fingerprint over the canonical restore payload — required slot.
    /// See [`restore_params_fingerprint`].
    pub params_fingerprint: String,
    /// iat — required `issued_at` slot.
    pub issued_at: f64,
    /// exp — required `expires_at` slot.
    pub expires_at: f64,
    /// Per-issuance nonce — required `nonce` slot.
    pub nonce: String,
    // ---- restore-specific extra claims ----
    /// Which VM to start back up.
    pub target: InstanceTarget,
    /// Free-text; `None` -> JSON null.
    pub reason: Option<String>,
}

impl ToClaimsMap for RestoreClaims {
    fn to_btreemap(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert(
            "action".to_string(),
            Value::String(REVOKE_RESTORE_ACTION.to_string()),
        );
        m.insert("aud".to_string(), Value::String(self.aud.clone()));
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
            "reason".to_string(),
            self.reason
                .as_ref()
                .map_or(Value::Null, |s| Value::String(s.clone())),
        );
        m.insert("run_id".to_string(), Value::String(self.run_id.clone()));
        m.insert("subject".to_string(), Value::String(self.subject.clone()));
        m.insert(
            "target".to_string(),
            serde_json::to_value(&self.target).unwrap_or(Value::Null),
        );
        m
    }
}

// ============================================================================
// HTTP wire DTOs — SHARED (kernel serves, Reaper consumes)
// ============================================================================

/// `POST /kernel/v1/revoke/compute` request body. `deny_unknown_fields`
/// mirrors FastAPI's `extra="forbid"` for a 422 on stray fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintRevokeRequest {
    /// Which VM to stop.
    pub target: InstanceTarget,
    /// Revocation strength (Phase 1: `VmStop` only).
    pub tier: RevocationTier,
    /// Why the kill was issued.
    pub trigger: RevokeTrigger,
    /// Optional free-text reason.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `POST /kernel/v1/revoke/restore` request body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    /// Which VM to start back up.
    pub target: InstanceTarget,
    /// Optional free-text reason.
    #[serde(default)]
    pub reason: Option<String>,
}

/// 200 response for mint (`/revoke/compute`) and restore
/// (`/revoke/restore`). Shaped like `SignedDecisionResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRevokeResponse {
    /// Always `true` on the success path.
    pub ok: bool,
    /// The revocation / restore id bound into the token.
    pub run_id: String,
    /// The compact `<payload_b64>.<signature_b64>` token.
    pub token: String,
    /// Hex sha256 of `token` (UTF-8 bytes).
    pub token_sha256: String,
    /// Decoded claims (sorted-key `BTreeMap` → stable serialization).
    pub claims: BTreeMap<String, Value>,
}

/// `GET /kernel/v1/revoke/pending?instance=<name>` query.
#[derive(Debug, Clone, Deserialize)]
pub struct PendingQuery {
    /// The agent VM instance name whose pending decisions to pull.
    pub instance: String,
}

/// 200 response for `/revoke/pending`. `pending` carries the already
/// signed, opaque token strings (the Reaper verifies each itself).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRevokeResponse {
    /// Always `true`.
    pub ok: bool,
    /// The currently-pending signed token(s) for the queried instance.
    pub pending: Vec<String>,
}

/// `POST /kernel/v1/revoke/ack` request body — the Reaper reports
/// execution so the kernel clears the pending entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeAckRequest {
    /// The revocation id being acked.
    pub run_id: String,
    /// Free-text execution outcome (e.g. `"stopped"`, `"already_stopped"`).
    pub outcome: String,
}

/// 200 response for `/revoke/ack`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeAckResponse {
    /// Always `true`.
    pub ok: bool,
    /// The acked revocation id (echoed).
    pub run_id: String,
    /// Whether a pending entry was actually cleared by this ack.
    pub cleared: bool,
}

// ============================================================================
// Tests — in-process evidence for the shared contract
// ============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp
)]
mod tests {
    use super::*;
    use crate::safety::token::{sign_kernel_token, verify_kernel_token};
    use crate::safety::KernelTokenError;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use serde_json::Value;

    /// Deterministic 32-byte signing seed — no system entropy.
    fn fixed_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn sample_target() -> InstanceTarget {
        InstanceTarget {
            project: "example-project".to_string(),
            zone: "zone-a".to_string(),
            instance: "ai-worker-vm".to_string(),
        }
    }

    /// Build a signed kill token with the given time window + reason.
    fn mint_kill(sk: &SigningKey, iat: f64, exp: f64, reason: Option<&str>) -> (String, String) {
        let target = sample_target();
        let run_id = "revoke_0192f00d-cafe-7000-8000-000000000001";
        let fp = revoke_params_fingerprint(
            run_id,
            &target,
            RevocationTier::VmStop,
            RevokeTrigger::OperatorEmergencyStop,
            reason,
        );
        let claims = RevokeComputeClaims {
            aud: REVOKE_COMPUTE_AUD.to_string(),
            run_id: run_id.to_string(),
            subject: "operator".to_string(),
            params_fingerprint: fp.clone(),
            issued_at: iat,
            expires_at: exp,
            nonce: "revoke-nonce-abc_123".to_string(),
            target,
            tier: RevocationTier::VmStop,
            trigger: RevokeTrigger::OperatorEmergencyStop,
            reason: reason.map(str::to_string),
        };
        (sign_kernel_token(&claims, sk), fp)
    }

    /// A real RevokeCompute minted via `sign_kernel_token` round-trips
    /// through `verify_kernel_token` with the revoke audience.
    #[test]
    fn revoke_token_signs_and_verifies_roundtrip() {
        let sk = fixed_signing_key();
        let vk: VerifyingKey = sk.verifying_key();
        let (token, _fp) = mint_kill(&sk, 1_715_212_345.0, 1_715_212_465.0, Some("e-stop"));

        let verified =
            verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some(REVOKE_COMPUTE_AUD))
                .expect("kill token must verify");
        assert_eq!(
            verified.claims.get("action").and_then(Value::as_str),
            Some(REVOKE_COMPUTE_ACTION)
        );
        assert_eq!(
            verified.claims.get("aud").and_then(Value::as_str),
            Some(REVOKE_COMPUTE_AUD)
        );
        // The nested target survived signing.
        assert_eq!(
            verified
                .claims
                .get("target")
                .and_then(|t| t.get("instance"))
                .and_then(Value::as_str),
            Some("ai-worker-vm")
        );
    }

    /// An expired kill (exp in the past relative to `now`) is rejected
    /// with `Expired` — a captured kill goes stale.
    #[test]
    fn expired_revoke_token_is_rejected() {
        let sk = fixed_signing_key();
        let vk = sk.verifying_key();
        let (token, _) = mint_kill(&sk, 1_715_212_345.0, 1_715_212_465.0, None);
        // now is 200s past exp.
        let result =
            verify_kernel_token(&token, &vk, 1_715_212_665.0, 0.0, Some(REVOKE_COMPUTE_AUD));
        assert!(
            matches!(result, Err(KernelTokenError::Expired(_))),
            "expired kill MUST be rejected; got {result:?}"
        );
    }

    /// A kill token presented to a RESTORE verifier (wrong audience) is
    /// rejected — a kill can never act as a restore, or as an authorize.
    #[test]
    fn wrong_audience_revoke_token_is_rejected() {
        let sk = fixed_signing_key();
        let vk = sk.verifying_key();
        let (token, _) = mint_kill(&sk, 1_715_212_345.0, 1_715_212_465.0, None);

        // Restore verifier.
        let as_restore =
            verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some(REVOKE_RESTORE_AUD));
        assert!(
            matches!(as_restore, Err(KernelTokenError::Claims(ref m)) if m.0 == "invalid_audience"),
            "kill under restore aud MUST reject; got {as_restore:?}"
        );
        // Authorize verifier.
        let as_authorize =
            verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some("kernel/authorize"));
        assert!(
            matches!(as_authorize, Err(KernelTokenError::Claims(ref m)) if m.0 == "invalid_audience"),
            "kill under authorize aud MUST reject; got {as_authorize:?}"
        );
    }

    /// The params_fingerprint BINDS target/tier/trigger/reason: a
    /// fingerprint recomputed from a DIFFERENT target does not match the
    /// signed one (the Reaper's mismatch-refuse check), while the SAME
    /// inputs reproduce it exactly.
    #[test]
    fn params_fingerprint_binds_target_tier_reason() {
        let sk = fixed_signing_key();
        let vk = sk.verifying_key();
        let (token, signed_fp) = mint_kill(&sk, 1_715_212_345.0, 1_715_212_465.0, Some("rogue"));
        let verified =
            verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some(REVOKE_COMPUTE_AUD))
                .expect("verify");

        // Reaper recomputes from the decoded claims — SAME inputs → match.
        let run_id = verified
            .claims
            .get("run_id")
            .and_then(Value::as_str)
            .unwrap();
        let recomputed_same = revoke_params_fingerprint(
            run_id,
            &sample_target(),
            RevocationTier::VmStop,
            RevokeTrigger::OperatorEmergencyStop,
            Some("rogue"),
        );
        assert_eq!(
            recomputed_same, signed_fp,
            "same inputs MUST reproduce the signed fingerprint"
        );

        // A different target must NOT reproduce it.
        let other_target = InstanceTarget {
            project: "example-project".to_string(),
            zone: "zone-a".to_string(),
            instance: "some-other-vm".to_string(),
        };
        let recomputed_other = revoke_params_fingerprint(
            run_id,
            &other_target,
            RevocationTier::VmStop,
            RevokeTrigger::OperatorEmergencyStop,
            Some("rogue"),
        );
        assert_ne!(
            recomputed_other, signed_fp,
            "a swapped target MUST NOT reproduce the fingerprint"
        );

        // A different tier must NOT reproduce it either.
        let recomputed_tier = revoke_params_fingerprint(
            run_id,
            &sample_target(),
            RevocationTier::Sigterm,
            RevokeTrigger::OperatorEmergencyStop,
            Some("rogue"),
        );
        assert_ne!(recomputed_tier, signed_fp, "a swapped tier MUST NOT match");

        // A different reason must NOT reproduce it.
        let recomputed_reason = revoke_params_fingerprint(
            run_id,
            &sample_target(),
            RevocationTier::VmStop,
            RevokeTrigger::OperatorEmergencyStop,
            Some("DIFFERENT"),
        );
        assert_ne!(
            recomputed_reason, signed_fp,
            "a swapped reason MUST NOT match"
        );
    }

    /// A restore token round-trips under the restore audience and is
    /// rejected under the kill audience — the two are non-interchangeable.
    #[test]
    fn restore_token_roundtrips_and_is_partitioned_from_kill() {
        let sk = fixed_signing_key();
        let vk = sk.verifying_key();
        let target = sample_target();
        let run_id = "restore_0192f00d-cafe-7000-8000-000000000002";
        let fp = restore_params_fingerprint(run_id, &target, Some("cleared"));
        let claims = RestoreClaims {
            aud: REVOKE_RESTORE_AUD.to_string(),
            run_id: run_id.to_string(),
            subject: "operator".to_string(),
            params_fingerprint: fp,
            issued_at: 1_715_212_345.0,
            expires_at: 1_715_212_465.0,
            nonce: "restore-nonce-xyz_789".to_string(),
            target,
            reason: Some("cleared".to_string()),
        };
        let token = sign_kernel_token(&claims, &sk);

        let ok = verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some(REVOKE_RESTORE_AUD));
        assert!(
            ok.is_ok(),
            "restore token must verify under restore aud; got {ok:?}"
        );

        let as_kill =
            verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some(REVOKE_COMPUTE_AUD));
        assert!(
            matches!(as_kill, Err(KernelTokenError::Claims(ref m)) if m.0 == "invalid_audience"),
            "restore under kill aud MUST reject; got {as_kill:?}"
        );
    }

    /// Serde round-trip for the mint request DTO — the shared wire shape
    /// the Reaper-side dev builds against.
    #[test]
    fn mint_request_deserializes() {
        let body = r#"{
            "target": {"project":"p","zone":"z","instance":"i"},
            "tier": "vm_stop",
            "trigger": "operator_emergency_stop"
        }"#;
        let req: MintRevokeRequest = serde_json::from_str(body).expect("mint body parses");
        assert_eq!(req.tier, RevocationTier::VmStop);
        assert_eq!(req.trigger, RevokeTrigger::OperatorEmergencyStop);
        assert!(req.reason.is_none());
        assert_eq!(req.target.instance, "i");
    }

    /// A stray field on the mint body is rejected (deny_unknown_fields).
    #[test]
    fn mint_request_rejects_unknown_field() {
        let body = r#"{
            "target": {"project":"p","zone":"z","instance":"i"},
            "tier": "vm_stop",
            "trigger": "operator_emergency_stop",
            "smuggled": "x"
        }"#;
        let res: Result<MintRevokeRequest, _> = serde_json::from_str(body);
        assert!(res.is_err(), "unknown field MUST be rejected");
    }
}
