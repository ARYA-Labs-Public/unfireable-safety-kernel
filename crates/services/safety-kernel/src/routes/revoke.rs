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
        restore_params_fingerprint, revoke_params_fingerprint, MintRevokeRequest, PendingQuery,
        PendingRevokeResponse, RestoreClaims, RestoreRequest, RevocationTier, RevokeAckRequest,
        RevokeAckResponse, RevokeComputeClaims, SignedRevokeResponse, REVOKE_COMPUTE_AUD,
        REVOKE_RESTORE_AUD,
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

    // Step 4 — bind target/tier/trigger/reason through params_fingerprint.
    let fp = revoke_params_fingerprint(
        &run_id,
        &body.target,
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
    Json(PendingRevokeResponse { ok: true, pending }).into_response()
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
