//! `/kernel/v1/revoke/*` handlers — coercive-shutdown (Phase 1). The kernel
//! is the DECIDER: it mints the signed `RevokeCompute` / restore decisions;
//! the control-plane Reaper (a separate binary) pulls, verifies, and executes
//! them from outside the agent's failure domain.
//!
//! Endpoints (all auth-gated at the global `auth_layer`; mint + restore
//! additionally assert `operator` in-handler as defense in depth,
//! exactly like admin + approvals):
//!
//!   * `POST /kernel/v1/revoke/compute`  — operator-only mint (kill)
//!   * `GET  /kernel/v1/revoke/pending`  — reaper (or operator) pull
//!   * `POST /kernel/v1/revoke/ack`      — reaper (or operator) ack
//!   * `POST /kernel/v1/revoke/restore`  — operator-only mint (un-kill)
//!
//! The mint path is FAIL-CLOSED on the transparency-log, mirroring
//! `routes/authorize.rs` exactly: if the ledger is unreachable / times
//! out / errors, the kernel REFUSES to emit the kill (no unsigned or
//! un-logged kill ever leaves the building).
//!
//! # Pending-revoke store — Phase-1 in-memory (design deviation, logged)
//!
//! The interface spec (§2.4) placed the pending-revoke queue as a new
//! `AppState` field. It is implemented here instead as a process-global
//! `LazyLock` store. Rationale: (1) the spec itself frames the store as
//! an in-memory Phase-1 simplification because the transparency-log is
//! the durable record and a kernel restart with a still-live threat is
//! re-minted by the operator; a process-global is squarely within that
//! framing. (2) Threading a new field through `AppState` would churn
//! ~30 construction sites across the signing-path test fixtures, adding
//! risk to the crypto surface for no behavioural gain. The store's
//! lifetime + sharing semantics are identical either way (one instance
//! per kernel process).

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::Value;
use tracing::{info, warn};
use uuid::Uuid;

use qorch_adapters::policy_engine_client::AuditAppendRequest;
use qorch_domain::safety::{
    revoke::{
        restore_params_fingerprint, revoke_params_fingerprint, InstanceTarget, MintRevokeRequest,
        PendingQuery, PendingRevokeResponse, RestoreClaims, RestoreRequest, RevocationTier,
        RevokeAckRequest, RevokeAckResponse, RevokeComputeClaims, SignedRevokeResponse,
        REVOKE_COMPUTE_AUD, REVOKE_RESTORE_AUD,
    },
    sign_kernel_token, token_sha256, ToClaimsMap,
};

use crate::auth::CallerRole;
use crate::dto::ErrorResponse;
use crate::state::AppState;

// ============================================================================
// Pending-revoke store (Phase-1 in-memory; see module doc)
// ============================================================================

/// A signed revoke/restore decision waiting for the Reaper to pull it.
#[derive(Debug, Clone)]
struct PendingRevoke {
    /// The revocation / restore id (`run_id` claim).
    run_id: String,
    /// The compact signed token.
    token: String,
    /// f64 epoch seconds after which the token is stale and swept.
    expires_at: f64,
}

/// Per-process queue: instance-name → pending decisions for that VM.
type PendingStore = HashMap<String, Vec<PendingRevoke>>;

/// The single per-process pending store. In-memory is acceptable for
/// Phase 1 because the transparency-log is the durable record.
static PENDING: LazyLock<Arc<Mutex<PendingStore>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Enqueue a signed decision under its target instance, first sweeping
/// any already-expired entries for that instance.
fn enqueue_pending(instance: &str, entry: PendingRevoke, now: f64) {
    let mut store = PENDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let list = store.entry(instance.to_string()).or_default();
    list.retain(|p| p.expires_at > now);
    list.push(entry);
}

/// Return (and sweep) the currently-pending tokens for an instance.
fn drain_live_tokens(instance: &str, now: f64) -> Vec<String> {
    let mut store = PENDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(list) = store.get_mut(instance) else {
        return Vec::new();
    };
    list.retain(|p| p.expires_at > now);
    list.iter().map(|p| p.token.clone()).collect()
}

/// Clear any pending entry with `run_id` across every instance. Returns
/// true if at least one entry was removed.
fn clear_pending(run_id: &str) -> bool {
    let mut store = PENDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut cleared = false;
    for list in store.values_mut() {
        let before = list.len();
        list.retain(|p| p.run_id != run_id);
        if list.len() != before {
            cleared = true;
        }
    }
    cleared
}

// ============================================================================
// Authoritative per-target grant generation (the fence identity) — Phase-1
// in-memory; see rationale below.
// ============================================================================

/// The kernel's authoritative per-target monotonic grant generation — the
/// identity the Reaper's generation fence ([`qorch_domain::safety::revoke::
/// honour_revocation`]) checks a kill against.
///
/// Semantics:
/// - A target that was never restored is at generation `0` (the first-ever
///   grant). [`current`](GrantGenerationStore::current) returns `0` for an
///   unknown target — it does NOT create an entry.
/// - Every RESTORE mints a NEW grant, so it [`increment`s](
///   GrantGenerationStore::increment) the target's generation. A restore of a
///   never-seen target establishes generation `1` (superseding the implicit
///   generation-`0` grant that a leftover kill was minted against).
/// - The mint path STAMPS a kill with the target's current generation; the
///   Reaper later honours the kill only while that stamp still equals the
///   live generation.
///
/// A trait so a durable (e.g. Postgres-backed) implementation can replace the
/// Phase-1 in-memory one without touching the handlers.
pub trait GrantGenerationStore: Send + Sync {
    /// The current grant generation for `target` (`0` if never restored).
    fn current(&self, target: &InstanceTarget) -> u64;
    /// Establish a NEW grant for `target` (a restore) and return the new,
    /// incremented generation.
    fn increment(&self, target: &InstanceTarget) -> u64;
    /// The current generation resolved by instance NAME only — the pending
    /// pull query carries just the instance, not the full project/zone/
    /// instance triple. Returns the MAX generation across any stored target
    /// whose instance matches (the fail-closed choice: a higher live
    /// generation fences MORE leftover kills), or `0` if none is known.
    fn current_for_instance(&self, instance: &str) -> u64;
}

/// The Phase-1 in-memory generation store: a `Mutex<HashMap<InstanceTarget,
/// u64>>`.
///
/// DURABILITY (follow-up): this is process-local and resets on kernel restart.
/// After a restart every target reads back as generation `0`, so a kill minted
/// against a pre-restart grant `> 0` would no longer be fenced by generation
/// alone. This is acceptable for Phase 1 for the same reason the pending store
/// is in-memory — the transparency-log is the durable record and a still-live
/// threat is re-minted by the operator — but a durable (PG) generation table
/// is the correct hardening and is intentionally deferred here, not built.
#[derive(Debug, Default)]
pub struct InMemoryGrantGenerationStore {
    generations: Mutex<HashMap<InstanceTarget, u64>>,
}

impl InMemoryGrantGenerationStore {
    /// A fresh, empty store (every target starts at generation `0`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl GrantGenerationStore for InMemoryGrantGenerationStore {
    fn current(&self, target: &InstanceTarget) -> u64 {
        self.generations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(target)
            .copied()
            .unwrap_or(0)
    }

    fn increment(&self, target: &InstanceTarget) -> u64 {
        let mut map = self
            .generations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = map.entry(target.clone()).or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    }

    fn current_for_instance(&self, instance: &str) -> u64 {
        self.generations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(t, _)| t.instance == instance)
            .map(|(_, g)| *g)
            .max()
            .unwrap_or(0)
    }
}

/// The single per-process grant-generation store. Kept as a process-global
/// (mirroring the `PENDING` store above) rather than an `AppState` field, for
/// the same reason documented there: threading a new field through `AppState`
/// churns every construction site across the signing-path test fixtures for no
/// behavioural gain, and the store's lifetime/sharing semantics are identical
/// either way (one instance per kernel process).
static GENERATIONS: LazyLock<InMemoryGrantGenerationStore> =
    LazyLock::new(InMemoryGrantGenerationStore::new);

// ============================================================================
// Small helpers
// ============================================================================

fn deny(status: StatusCode, body: ErrorResponse) -> Response {
    (status, Json(body)).into_response()
}

/// Convert a claims `BTreeMap` to a `Value::Object` (sorted order
/// preserved by `BTreeMap` iteration) for the audit payload.
fn btree_to_value(m: &std::collections::BTreeMap<String, Value>) -> Value {
    let mut obj = serde_json::Map::with_capacity(m.len());
    for (k, v) in m {
        obj.insert(k.clone(), v.clone());
    }
    Value::Object(obj)
}

/// Transparency-log FAIL-CLOSED append. Mirrors the
/// `routes/authorize.rs` block verbatim: success / `None` (dev) /
/// `Conflict` (idempotent replay) all pass; any other error or a
/// timeout returns `Err(reason)` so the caller refuses to emit the kill.
async fn tlog_append_failclosed(state: &AppState, token: &str, now: f64) -> Result<(), String> {
    let Some(tlog) = state.transparency_client.as_ref() else {
        // Dev only — `Settings::from_env` already fails closed in prod
        // when transparency is enabled but no client could be built.
        return Ok(());
    };
    let idem_key = crate::transparency_client::idempotency_key_for_token(token);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let occurred_at_u = if now.is_finite() && now >= 0.0 {
        now as u64
    } else {
        0
    };
    let input = crate::transparency_client::TransparencyAppendInput {
        idempotency_key: idem_key,
        payload: token.as_bytes().to_vec(),
        occurred_at_epoch_seconds: occurred_at_u,
    };
    let timeout =
        std::time::Duration::from_secs_f64(state.settings.transparency_log_timeout_seconds);
    match tokio::time::timeout(timeout, tlog.append(input)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(crate::transparency_client::TransparencyError::Conflict)) => {
            info!(
                target = "qorch.safety_kernel",
                kind = "transparency_conflict",
                "revoke: transparency-log returned 409 (idempotent retry success)"
            );
            Ok(())
        }
        Ok(Err(e)) => {
            let kind = e.kind();
            warn!(
                target = "qorch.safety_kernel",
                kind = %kind,
                detail = %e.detail(),
                "revoke: transparency-log append failed — refusing to emit kill (fail-closed)"
            );
            Err(format!("transparency_error:{kind}"))
        }
        Err(_timeout_elapsed) => {
            warn!(
                target = "qorch.safety_kernel",
                timeout_s = state.settings.transparency_log_timeout_seconds,
                "revoke: transparency-log append timed out — refusing to emit kill (fail-closed)"
            );
            Err("transparency_error:timeout".to_string())
        }
    }
}

/// Audit-append (fail-OPEN — the signed decision has already been
/// recorded in the tlog, which is the durable evidence).
async fn audit_append(state: &AppState, action_name: &str, payload: Value, started_at: f64) {
    let req = AuditAppendRequest {
        unit_id: "safety_kernel".to_string(),
        action_name: action_name.to_string(),
        payload,
        success: true,
        error: None,
        started_at,
        ended_at: state.clock.now(),
    };
    if let Err(e) = state.policy_client.audit_append(req).await {
        warn!(
            kind = e.kind(),
            detail = %e.detail(),
            action = action_name,
            "audit_append failed on revoke path (fail-open: continuing)"
        );
    }
}

// ============================================================================
// 2.1 Mint — POST /kernel/v1/revoke/compute (operator-only)
// ============================================================================

/// Mint a signed `RevokeCompute` kill decision. Operator-only. The
/// worker/api/reaper roles cannot mint — this is the whole "explicit
/// signed kill only" gate.
pub async fn mint_revoke(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerRole>,
    Json(body): Json<MintRevokeRequest>,
) -> Response {
    // Step 1 — operator gate (defense in depth; auth_layer already ran).
    if caller.0 != "operator" {
        return deny(
            StatusCode::FORBIDDEN,
            ErrorResponse::with_reason("forbidden", "caller_role_not_operator"),
        );
    }
    // Step 2 — Phase 1 mints ONLY VmStop.
    if body.tier != RevocationTier::VmStop {
        return deny(
            StatusCode::UNPROCESSABLE_ENTITY,
            ErrorResponse::with_reason("unprocessable_entity", "tier_unsupported_phase1"),
        );
    }

    // Step 3 — time / nonce / id / ttl.
    let now = state.clock.now();
    let nonce = state.nonce.nonce_b64();
    let run_id = format!("revoke_{}", Uuid::now_v7());
    let ttl = state.settings.revoke_token_ttl_s.max(30);

    // Stamp the kill with the target's CURRENT authoritative grant generation.
    // The Reaper honours this kill only while the live grant generation still
    // equals this stamp; a later restore increments the target's generation, so
    // this kill is fenced out as stale (see `honour_revocation` + the pending
    // handler's `current_grant_generation` echo). A first-ever grant is
    // generation 0.
    let target_generation = GENERATIONS.current(&body.target);

    // Step 4 — bind target/generation/tier/trigger/reason through
    // params_fingerprint.
    let fp = revoke_params_fingerprint(
        &run_id,
        &body.target,
        target_generation,
        body.tier,
        body.trigger,
        body.reason.as_deref(),
    );

    // Step 5 — build + sign the kill decision.
    #[allow(clippy::cast_precision_loss)]
    let claims = RevokeComputeClaims {
        aud: REVOKE_COMPUTE_AUD.to_string(),
        run_id: run_id.clone(),
        subject: "operator".to_string(),
        params_fingerprint: fp,
        issued_at: now,
        expires_at: now + (ttl as f64),
        nonce,
        target: body.target.clone(),
        target_generation,
        tier: body.tier,
        trigger: body.trigger,
        reason: body.reason.clone(),
    };
    let token = sign_kernel_token(&claims, state.signing_key.as_ref());
    let tok_sha = token_sha256(&token);
    let claims_map = claims.to_btreemap();

    // Step 6 — transparency-log FAIL-CLOSED. No unsigned/un-logged kill.
    if let Err(reason) = tlog_append_failclosed(&state, &token, now).await {
        // Audit the refusal (fail-open), then refuse to emit.
        let audit_payload = serde_json::json!({
            "request": { "target": serde_json::to_value(&body.target).unwrap_or(Value::Null),
                         "caller_role": caller.0 },
            "run_id": run_id,
            "refused": reason,
        });
        audit_append(&state, "kernel_revoke_compute_refused", audit_payload, now).await;
        return deny(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorResponse::with_reason("unavailable", "revoke_not_recorded"),
        );
    }

    // Step 7 — enqueue for the Reaper to pull.
    enqueue_pending(
        &body.target.instance,
        PendingRevoke {
            run_id: run_id.clone(),
            token: token.clone(),
            expires_at: claims.expires_at,
        },
        now,
    );

    // Step 8 — audit-append (fail-open).
    let audit_payload = serde_json::json!({
        "request": {
            "target": serde_json::to_value(&body.target).unwrap_or(Value::Null),
            "tier": serde_json::to_value(body.tier).unwrap_or(Value::Null),
            "trigger": serde_json::to_value(body.trigger).unwrap_or(Value::Null),
            "reason": body.reason.clone().map_or(Value::Null, Value::String),
            "caller_role": caller.0,
        },
        "token_sha256": tok_sha,
        "claims": btree_to_value(&claims_map),
    });
    audit_append(&state, "kernel_revoke_compute", audit_payload, now).await;

    // Step 9 — 200.
    Json(SignedRevokeResponse {
        ok: true,
        run_id,
        token,
        token_sha256: tok_sha,
        claims: claims_map,
    })
    .into_response()
}

// ============================================================================
// 2.2 Pull — GET /kernel/v1/revoke/pending?instance=<name> (reaper)
// ============================================================================

/// Return the currently-pending signed decision(s) for an instance.
/// Read-only: it hands back already-signed tokens; a caller reading the
/// queue cannot forge, cancel, or suppress a kill. `reaper` (or
/// `operator`) role only — the agent's `worker` key cannot read it.
pub async fn pending_revoke(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerRole>,
    Query(q): Query<PendingQuery>,
) -> Response {
    if !matches!(caller.0.as_str(), "reaper" | "operator") {
        return deny(
            StatusCode::FORBIDDEN,
            ErrorResponse::with_reason("forbidden", "caller_role_not_reaper"),
        );
    }
    let now = state.clock.now();
    let pending = drain_live_tokens(&q.instance, now);
    if pending.is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }
    // Echo the AUTHORITATIVE current grant generation for this instance so the
    // Reaper can fence a stale (pre-restore) kill. Resolved by instance name —
    // the pull query carries only the instance, not the full target triple.
    let current_grant_generation = GENERATIONS.current_for_instance(&q.instance);
    Json(PendingRevokeResponse {
        ok: true,
        pending,
        current_grant_generation,
    })
    .into_response()
}

// ============================================================================
// 2.3 Ack — POST /kernel/v1/revoke/ack (reaper)
// ============================================================================

/// The Reaper reports execution so the kernel clears the pending entry.
/// Fail-OPEN on the kernel side — the Reaper's own kill-record in the
/// tlog is the durable evidence; the ack is queue hygiene.
pub async fn ack_revoke(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerRole>,
    Json(body): Json<RevokeAckRequest>,
) -> Response {
    if !matches!(caller.0.as_str(), "reaper" | "operator") {
        return deny(
            StatusCode::FORBIDDEN,
            ErrorResponse::with_reason("forbidden", "caller_role_not_reaper"),
        );
    }
    let now = state.clock.now();
    let cleared = clear_pending(&body.run_id);
    let audit_payload = serde_json::json!({
        "run_id": body.run_id,
        "outcome": body.outcome,
        "cleared": cleared,
        "caller_role": caller.0,
    });
    audit_append(&state, "kernel_revoke_ack", audit_payload, now).await;
    Json(RevokeAckResponse {
        ok: true,
        run_id: body.run_id,
        cleared,
    })
    .into_response()
}

// ============================================================================
// 2.5 Restore / un-kill — POST /kernel/v1/revoke/restore (operator-only)
// ============================================================================

/// Mint a signed restore decision. Operator-only — the agent's `worker`
/// key 403s, so a reaped agent can never un-kill itself. Same
/// fail-closed tlog discipline as mint.
pub async fn restore_revoke(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerRole>,
    Json(body): Json<RestoreRequest>,
) -> Response {
    if caller.0 != "operator" {
        return deny(
            StatusCode::FORBIDDEN,
            ErrorResponse::with_reason("forbidden", "caller_role_not_operator"),
        );
    }
    let now = state.clock.now();
    let nonce = state.nonce.nonce_b64();
    let run_id = format!("restore_{}", Uuid::now_v7());
    let ttl = state.settings.revoke_token_ttl_s.max(30);
    let fp = restore_params_fingerprint(&run_id, &body.target, body.reason.as_deref());

    #[allow(clippy::cast_precision_loss)]
    let claims = RestoreClaims {
        aud: REVOKE_RESTORE_AUD.to_string(),
        run_id: run_id.clone(),
        subject: "operator".to_string(),
        params_fingerprint: fp,
        issued_at: now,
        expires_at: now + (ttl as f64),
        nonce,
        target: body.target.clone(),
        reason: body.reason.clone(),
    };
    let token = sign_kernel_token(&claims, state.signing_key.as_ref());
    let tok_sha = token_sha256(&token);
    let claims_map = claims.to_btreemap();

    if let Err(reason) = tlog_append_failclosed(&state, &token, now).await {
        let audit_payload = serde_json::json!({
            "request": { "target": serde_json::to_value(&body.target).unwrap_or(Value::Null),
                         "caller_role": caller.0 },
            "run_id": run_id,
            "refused": reason,
        });
        audit_append(&state, "kernel_revoke_restore_refused", audit_payload, now).await;
        return deny(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorResponse::with_reason("unavailable", "revoke_not_recorded"),
        );
    }

    // A restore ESTABLISHES A NEW GRANT — bump the target's authoritative
    // generation. Done only AFTER the fail-closed tlog append succeeds, so a
    // restore that was never durably recorded does not silently advance the
    // fence. From this point every kill minted against the pre-restore
    // generation is stale and the Reaper's fence refuses it, keeping the
    // restored instance alive.
    let new_generation = GENERATIONS.increment(&body.target);

    // Enqueue so the Reaper's single pull sees the restore too; it
    // distinguishes kill vs restore by verifying the token's `aud`.
    enqueue_pending(
        &body.target.instance,
        PendingRevoke {
            run_id: run_id.clone(),
            token: token.clone(),
            expires_at: claims.expires_at,
        },
        now,
    );

    let audit_payload = serde_json::json!({
        "request": {
            "target": serde_json::to_value(&body.target).unwrap_or(Value::Null),
            "reason": body.reason.clone().map_or(Value::Null, Value::String),
            "caller_role": caller.0,
        },
        "token_sha256": tok_sha,
        "new_grant_generation": new_generation,
        "claims": btree_to_value(&claims_map),
    });
    audit_append(&state, "kernel_revoke_restore", audit_payload, now).await;

    Json(SignedRevokeResponse {
        ok: true,
        run_id,
        token,
        token_sha256: tok_sha,
        claims: claims_map,
    })
    .into_response()
}

// ============================================================================
// Router
// ============================================================================

/// Build the `/kernel/v1/revoke/*` sub-router. Wired into the main axum
/// app in `main.rs` with one `.merge()` call.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/kernel/v1/revoke/compute", post(mint_revoke))
        .route("/kernel/v1/revoke/pending", get(pending_revoke))
        .route("/kernel/v1/revoke/ack", post(ack_revoke))
        .route("/kernel/v1/revoke/restore", post(restore_revoke))
}

// ============================================================================
// Tests — the authoritative generation store (isolated, no process-global)
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{GrantGenerationStore, InMemoryGrantGenerationStore};
    use qorch_domain::safety::revoke::InstanceTarget;

    fn target(instance: &str) -> InstanceTarget {
        InstanceTarget {
            project: "example-project".to_string(),
            zone: "zone-a".to_string(),
            instance: instance.to_string(),
        }
    }

    /// A never-restored target reads generation 0 without creating an entry;
    /// the first restore establishes generation 1 and each subsequent restore
    /// increments monotonically.
    #[test]
    fn first_grant_is_zero_and_restore_increments() {
        let store = InMemoryGrantGenerationStore::new();
        let t = target("vm-a");
        assert_eq!(store.current(&t), 0, "first-ever grant is generation 0");
        // `current` must not have created an entry.
        assert_eq!(store.current_for_instance("vm-a"), 0);

        assert_eq!(store.increment(&t), 1, "a restore establishes generation 1");
        assert_eq!(store.current(&t), 1);
        assert_eq!(store.increment(&t), 2, "a second restore -> generation 2");
        assert_eq!(store.current(&t), 2);
    }

    /// Distinct targets keep independent generations; `current_for_instance`
    /// resolves by instance NAME (the pull query carries only the instance).
    #[test]
    fn generations_are_per_target_and_resolve_by_instance_name() {
        let store = InMemoryGrantGenerationStore::new();
        let a = target("vm-a");
        let b = target("vm-b");
        store.increment(&a); // a -> 1
        store.increment(&a); // a -> 2
        store.increment(&b); // b -> 1

        assert_eq!(store.current(&a), 2);
        assert_eq!(store.current(&b), 1);
        assert_eq!(store.current_for_instance("vm-a"), 2);
        assert_eq!(store.current_for_instance("vm-b"), 1);
        assert_eq!(
            store.current_for_instance("vm-unknown"),
            0,
            "an unknown instance resolves to generation 0"
        );
    }

    /// The fence identity in words: a kill stamped at the generation the mint
    /// saw is honoured while that is still current, and fenced the moment a
    /// restore has moved the live generation past it.
    #[test]
    fn mint_stamp_then_restore_makes_the_stamp_stale() {
        let store = InMemoryGrantGenerationStore::new();
        let t = target("vm-fence");
        // Mint reads the CURRENT generation to stamp a kill.
        let stamped_at_mint = store.current(&t); // 0
        assert_eq!(stamped_at_mint, 0);
        // A restore bumps the live generation.
        let live_after_restore = store.increment(&t); // 1
        assert_eq!(live_after_restore, 1);
        // The kill's stamp is now strictly older than the live generation.
        assert!(
            stamped_at_mint < store.current_for_instance("vm-fence"),
            "after a restore the pre-restore stamp is stale"
        );
    }
}
