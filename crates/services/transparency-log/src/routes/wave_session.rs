//! ARY-2181 Phase 1 — wave-session-record routes.
//!
//! Two endpoints:
//!
//! - `POST /v1/wave/session` — append a kernel-HMAC-signed wave session
//!   record as a Merkle leaf. Idempotent on
//!   `SHA-256(wave_id || stage || session_id)`. Returns 201 Created on
//!   fresh insert, 200 OK on idempotent replay. 403 Forbidden on
//!   kernel-key-fingerprint mismatch OR HMAC verify failure. 400 on
//!   `stage` / `written_by` inconsistency or other validation errors.
//!
//! - `GET /v1/wave/{wave_id}/verify` — return the wave's full session
//!   chain in canonical pipeline order. Body carries
//!   `all_required_stages_present: bool`, the pinned kernel-key
//!   fingerprint, and per-entry HMACs so external auditors can re-run
//!   verification against the kernel's public material.
//!
//! Design notes (per ARY-2181 spec):
//!
//! - The Merkle leaf payload IS the canonical-bytes projection of
//!   [`WaveSessionRecord`] (see
//!   `qorch_domain::wave::session_record::WaveSessionRecord::canonical_bytes`).
//! - The HMAC is appended verbatim to the leaf payload as a
//!   length-prefixed trailer (see [`build_leaf_payload`] /
//!   [`split_leaf_payload`]). Storing the HMAC in the leaf bytes —
//!   rather than alongside in a separate column — keeps the
//!   transparency-log storage adapter agnostic of the wave-session
//!   schema and means an external auditor only needs the ledger to
//!   reconstruct the chain.
//! - The kernel HMAC verifies against `canonical_bytes(record)`, NOT
//!   against the framed leaf bytes — so a tampered HMAC fails the
//!   constant-time compare without leaking which byte differs.
//! - `idempotency_key = WaveSessionRecord::record_idempotency_key(record)`.
//!   The underlying store de-duplicates by this 32-byte key; a same-key
//!   different-bytes call (i.e. a forged retry with mutated record)
//!   returns 409 from the store, which we surface as
//!   `IdempotencyPayloadMismatch`.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use qorch_domain::wave::context::WaveId;
use qorch_domain::wave::session_record::{all_required_stages_present, WaveSessionRecord};
use qorch_transparency_store::AppendInput;

use crate::dto::{
    AppendWaveSessionRequest, AppendWaveSessionResponse, VerifyWaveSessionResponse,
    WaveSessionChainEntry,
};
use crate::error::ServiceError;
use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

/// Length-prefixed framing: 8-byte big-endian record length, then
/// `record_bytes`, then the 32-byte raw HMAC. The transparency-log
/// stores this as the leaf payload. The framing means the leaf hash
/// commits to BOTH the record content AND the HMAC — so an attacker
/// who swaps the HMAC after the fact would also have to forge the
/// leaf hash + Merkle root, which the inclusion-proof verifier catches.
fn build_leaf_payload(record_bytes: &[u8], hmac_bytes: &[u8; 32]) -> Vec<u8> {
    // `usize -> u64` is widening on all supported targets (32+ bit).
    let n: u64 = u64::try_from(record_bytes.len()).unwrap_or(u64::MAX);
    let mut out = Vec::with_capacity(8 + record_bytes.len() + 32);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(record_bytes);
    out.extend_from_slice(hmac_bytes);
    out
}

/// Inverse of [`build_leaf_payload`]. Returns `(record_bytes,
/// hmac_bytes)` or a [`ServiceError::Backend`] on malformed framing
/// (shouldn't happen for leaves we wrote ourselves, but defensive).
///
/// Currently unused at the route layer because Phase 1 stashes the
/// decoded record in [`AppState::wave_session_payloads`]. Phase 2
/// (Postgres-backed denormalization) drops the side map and this
/// function becomes the verify-route's payload decoder. Kept here
/// (a) as documentation of the committed-to framing, and (b) so the
/// Phase 2 work has a single drop-in.
#[allow(dead_code)]
fn split_leaf_payload(payload: &[u8]) -> Result<(Vec<u8>, [u8; 32]), ServiceError> {
    if payload.len() < 8 + 32 {
        return Err(ServiceError::Backend(
            "wave-session leaf payload too short".into(),
        ));
    }
    let mut n_bytes = [0u8; 8];
    n_bytes.copy_from_slice(&payload[..8]);
    let n = usize::try_from(u64::from_be_bytes(n_bytes))
        .map_err(|_| ServiceError::Backend("wave-session payload length overflow".into()))?;
    if 8 + n + 32 != payload.len() {
        return Err(ServiceError::Backend(
            "wave-session leaf payload length mismatch".into(),
        ));
    }
    let record_bytes = payload[8..8 + n].to_vec();
    let mut hmac = [0u8; 32];
    hmac.copy_from_slice(&payload[8 + n..]);
    Ok((record_bytes, hmac))
}

/// Verify a kernel HMAC against the canonical record bytes. Returns
/// `Ok(())` on success, [`ServiceError::KernelHmacMismatch`] otherwise.
/// Constant-time via `hmac::Mac::verify_slice` (which uses
/// `subtle::ConstantTimeEq` internally).
///
/// # Errors
///
/// - [`ServiceError::Backend`] if the HMAC key is empty (service
///   misconfigured — should never happen with a `with_kernel_hmac_key`
///   AppState).
/// - [`ServiceError::KernelHmacMismatch`] on verification failure.
fn verify_kernel_hmac(
    record_bytes: &[u8],
    supplied_hmac: &[u8; 32],
    key: &[u8],
) -> Result<(), ServiceError> {
    if key.is_empty() {
        return Err(ServiceError::Backend(
            "kernel HMAC key not configured".into(),
        ));
    }
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| ServiceError::Backend(format!("invalid HMAC key length: {e}")))?;
    mac.update(record_bytes);
    mac.verify_slice(supplied_hmac)
        .map_err(|_| ServiceError::KernelHmacMismatch)
}

/// Map a `/test` / `/purple-team` / `/user-acceptance` / `/closeout`
/// `written_by` string to the stage it is allowed to attest to.
/// Returns true if the pair is consistent.
fn written_by_matches_stage(
    written_by: &str,
    stage: qorch_domain::wave::stage::WaveStage,
) -> bool {
    use qorch_domain::wave::stage::WaveStage;
    let normalized = written_by.trim().trim_start_matches('/').to_ascii_lowercase();
    match stage {
        // Planned and Decomposed are allowed from either /plan or /team —
        // the writing skill name is informational at those stages.
        WaveStage::Planned => matches!(normalized.as_str(), "plan" | "planner"),
        WaveStage::Decomposed => matches!(
            normalized.as_str(),
            "team" | "planner" | "plan" | "architect"
        ),
        WaveStage::Tested => normalized == "test",
        WaveStage::PurpleTeamed => normalized == "purple-team" || normalized == "purple_team",
        WaveStage::Accepted => {
            normalized == "user-acceptance" || normalized == "user_acceptance" || normalized == "uat"
        }
        WaveStage::Closed => normalized == "closeout",
    }
}

/// `POST /v1/wave/session`.
pub async fn append_session(
    State(state): State<AppState>,
    Json(body): Json<AppendWaveSessionRequest>,
) -> Result<Response, ServiceError> {
    // 1. Kernel-fingerprint pin (re-uses the same field shape as
    //    /v1/append for operator familiarity).
    let supplied_fpr = body.kernel_key_fingerprint_sha256.trim().to_ascii_lowercase();
    let expected_fpr = state.kernel_key_fingerprint_hex.to_ascii_lowercase();
    if supplied_fpr != expected_fpr {
        return Err(ServiceError::KernelFingerprintMismatch);
    }

    // 2. Decode the kernel HMAC bytes.
    let supplied_hmac = hex_to_32(&body.kernel_hmac_hex)?;

    // 3. Validate stage / written_by consistency. The transparency-log
    //    cannot stop a misbehaving skill from impersonating another,
    //    but it can refuse the cheapest mistake.
    if !written_by_matches_stage(&body.record.written_by, body.record.stage) {
        return Err(ServiceError::StageWrittenByMismatch);
    }

    // 4. Canonical-bytes the record and verify the HMAC.
    let record_bytes = body
        .record
        .canonical_bytes()
        .map_err(|e| ServiceError::BadRequest(format!("canonical_bytes failed: {e}")))?;
    verify_kernel_hmac(&record_bytes, &supplied_hmac, &state.kernel_hmac_key)?;

    // 5. Frame the leaf payload (record bytes + raw HMAC) and append.
    let idempotency_key = body.record.record_idempotency_key();
    let leaf_payload = build_leaf_payload(&record_bytes, &supplied_hmac);

    let size_before = state.store.current_size().await?;
    let outcome = state
        .store
        .append(AppendInput {
            idempotency_key,
            payload: leaf_payload,
            occurred_at_epoch_seconds: body.record.occurred_at_epoch_seconds,
        })
        .await?;

    // 6. Update the wave-id index + per-leaf payload side map
    //    regardless of fresh/retry. Both helpers are idempotent.
    state
        .record_wave_session_leaf(&body.record.wave_id, outcome.leaf_index)
        .await;
    state
        .record_wave_session_payload(outcome.leaf_index, body.record.clone(), supplied_hmac)
        .await;

    let idempotent_replay = outcome.leaf_index < size_before;
    let status = if idempotent_replay {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };

    let resp = AppendWaveSessionResponse {
        idempotent_replay,
        leaf_hash_hex: hex::encode(outcome.leaf_hash),
        leaf_index: outcome.leaf_index,
        ok: true,
    };
    Ok((status, Json(resp)).into_response())
}

/// `GET /v1/wave/{wave_id}/verify`.
pub async fn verify_session(
    State(state): State<AppState>,
    Path(wave_id): Path<String>,
) -> Result<Response, ServiceError> {
    let wid = WaveId::new(wave_id.clone());
    let leaves = state.wave_session_leaves(&wid).await;
    if leaves.is_empty() {
        return Err(ServiceError::NotFound);
    }

    // Fetch every leaf payload and decode back to a (record, hmac)
    // pair. We assemble entries first so the canonical-pipeline-order
    // sort below operates on decoded records.
    let mut entries: Vec<WaveSessionChainEntry> = Vec::with_capacity(leaves.len());
    for leaf_idx in leaves {
        // Read the leaf metadata (we need its hash, but we use the
        // payload — which we have to recompute via the inclusion-proof
        // route's underlying mechanism). For now: hold the raw payload
        // alongside the metadata in the in-process index. Phase 2
        // (Postgres) will denormalize.
        //
        // The TransparencyStore trait does not expose `get_payload`
        // today (only `get_leaf` which returns `MerkleLeaf` —
        // metadata, not bytes). Phase 1 work-around: keep the raw
        // record + hmac in a side map so we can stream the chain.
        //
        // The side map is appended in lock-step with the store; it
        // does NOT serve as the source of truth (the leaf hash + the
        // Merkle root do). On cold start, Phase 2 will walk the
        // ledger and rebuild.
        let Some((record, hmac)) = state.lookup_wave_session_payload(leaf_idx).await else {
            return Err(ServiceError::Backend(format!(
                "wave-session payload missing for leaf {leaf_idx}"
            )));
        };
        entries.push(WaveSessionChainEntry {
            kernel_hmac_hex: hex::encode(hmac),
            leaf_index: leaf_idx,
            record,
        });
    }

    // Canonical pipeline order, then leaf-index tiebreaker.
    entries.sort_by(|a, b| {
        a.record
            .stage
            .cmp(&b.record.stage)
            .then(a.leaf_index.cmp(&b.leaf_index))
    });

    let records: Vec<WaveSessionRecord> =
        entries.iter().map(|e| e.record.clone()).collect();
    let all_required = all_required_stages_present(&records);

    let resp = VerifyWaveSessionResponse {
        all_required_stages_present: all_required,
        chain: entries,
        kernel_key_fingerprint_sha256: state.kernel_key_fingerprint_hex.clone(),
        ok: true,
        wave_id,
    };
    Ok((StatusCode::OK, Json(resp)).into_response())
}

/// Decode a hex string into exactly 32 bytes (re-implemented here to
/// avoid cross-module visibility tweaks; same as the impl in
/// `routes::append`).
fn hex_to_32(s: &str) -> Result<[u8; 32], ServiceError> {
    let raw = hex::decode(s.trim())
        .map_err(|e| ServiceError::BadRequest(format!("hex decode failed: {e}")))?;
    if raw.len() != 32 {
        return Err(ServiceError::BadRequest(format!(
            "expected 32-byte hex value, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{get, post};
    use axum::Router;
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt;
    use qorch_adapters::clock::SystemClock;
    use qorch_domain::safety::Clock;
    use qorch_domain::wave::context::WaveId;
    use qorch_domain::wave::gate_surface::GateSurface;
    use qorch_domain::wave::session_record::WaveSessionRecord;
    use qorch_domain::wave::stage::{WaveOutcome, WaveStage};
    use qorch_transparency_store::memory::MemoryTransparencyStore;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    fn fixture_state(hmac_key: &[u8]) -> AppState {
        let seed = [0x11u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let signing_pk = signing_key.verifying_key().to_bytes();
        let mut h = Sha256::new();
        h.update(signing_pk);
        let signing_fpr = hex::encode(h.finalize());
        let kernel_seed = [0x22u8; 32];
        let kernel_signing = SigningKey::from_bytes(&kernel_seed);
        let kernel_pk = kernel_signing.verifying_key().to_bytes();
        let mut h2 = Sha256::new();
        h2.update(kernel_pk);
        let kernel_fpr = hex::encode(h2.finalize());
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        AppState::new(
            Arc::new(MemoryTransparencyStore::new()),
            Arc::new(signing_key),
            signing_fpr,
            kernel_fpr,
            clock,
            "test-key".to_string(),
        )
        .with_kernel_hmac_key(hmac_key.to_vec())
    }

    fn router(state: AppState) -> Router {
        Router::new()
            .route("/v1/wave/session", post(append_session))
            .route("/v1/wave/{wave_id}/verify", get(verify_session))
            .with_state(state)
    }

    fn record(
        wave: &str,
        stage: WaveStage,
        sid: &str,
        outcome: WaveOutcome,
        gs: HashSet<GateSurface>,
        written_by: &str,
    ) -> WaveSessionRecord {
        WaveSessionRecord::new(
            WaveId::new(wave),
            "ARY-2181",
            stage,
            sid,
            outcome,
            "re-derived",
            gs,
            written_by,
            1_716_400_000,
        )
    }

    fn hmac_over(key: &[u8], record: &WaveSessionRecord) -> [u8; 32] {
        let bytes = record.canonical_bytes().unwrap();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
        mac.update(&bytes);
        let out = mac.finalize().into_bytes();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        a
    }

    fn body_for(state: &AppState, hmac: &[u8; 32], record: &WaveSessionRecord) -> Value {
        json!({
            "kernel_hmac_hex": hex::encode(hmac),
            "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
            "record": record,
        })
    }

    async fn post_json(router: &Router, body: Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/wave/session")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    async fn get_verify(router: &Router, wave_id: &str) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/v1/wave/{wave_id}/verify"))
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    #[tokio::test]
    async fn fresh_append_returns_201_and_index_zero() {
        let key = b"unit-test-hmac-key-32-bytes-pad!";
        let state = fixture_state(key);
        let router = router(state.clone());
        let r = record(
            "w1",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let h = hmac_over(key, &r);
        let (s, v) = post_json(&router, body_for(&state, &h, &r)).await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(v["leaf_index"], 0);
        assert_eq!(v["idempotent_replay"], false);
        assert_eq!(v["ok"], true);
    }

    #[tokio::test]
    async fn duplicate_returns_200_replay() {
        let key = b"unit-test-hmac-key-32-bytes-pad!";
        let state = fixture_state(key);
        let router = router(state.clone());
        let r = record(
            "w-dup",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let h = hmac_over(key, &r);
        let body = body_for(&state, &h, &r);
        let (s1, _) = post_json(&router, body.clone()).await;
        assert_eq!(s1, StatusCode::CREATED);
        let (s2, v2) = post_json(&router, body).await;
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(v2["idempotent_replay"], true);
        assert_eq!(v2["leaf_index"], 0);
    }

    #[tokio::test]
    async fn forged_hmac_returns_403() {
        let key = b"unit-test-hmac-key-32-bytes-pad!";
        let state = fixture_state(key);
        let router = router(state.clone());
        let r = record(
            "w-forged",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        // Attacker uses the wrong HMAC key.
        let wrong_h = hmac_over(b"WRONG-KEY-different-from-server", &r);
        let (s, v) = post_json(&router, body_for(&state, &wrong_h, &r)).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(v["reason"], "kernel_hmac_mismatch");
    }

    #[tokio::test]
    async fn forged_kernel_fingerprint_returns_403() {
        let key = b"unit-test-hmac-key-32-bytes-pad!";
        let state = fixture_state(key);
        let router = router(state.clone());
        let r = record(
            "w-fp",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let h = hmac_over(key, &r);
        let mut body = body_for(&state, &h, &r);
        body["kernel_key_fingerprint_sha256"] = Value::String(hex::encode([0xAB; 32]));
        let (s, v) = post_json(&router, body).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(v["reason"], "kernel_fingerprint_mismatch");
    }

    #[tokio::test]
    async fn stage_written_by_mismatch_returns_400() {
        let key = b"unit-test-hmac-key-32-bytes-pad!";
        let state = fixture_state(key);
        let router = router(state.clone());
        // `/test` writing a CLOSED record — refused.
        let r = record(
            "w-wb",
            WaveStage::Closed,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let h = hmac_over(key, &r);
        let (s, v) = post_json(&router, body_for(&state, &h, &r)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(v["reason"], "stage_written_by_mismatch");
    }

    #[tokio::test]
    async fn verify_returns_404_on_unknown_wave() {
        let key = b"unit-test-hmac-key-32-bytes-pad!";
        let state = fixture_state(key);
        let router = router(state.clone());
        let (s, _) = get_verify(&router, "no-such-wave").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn verify_returns_chain_in_canonical_order() {
        let key = b"unit-test-hmac-key-32-bytes-pad!";
        let state = fixture_state(key);
        let router = router(state.clone());

        let mut gs = HashSet::new();
        gs.insert(GateSurface::SafetyKernel);
        let stages = [
            (WaveStage::Closed, "cls-1", "/closeout"),
            (WaveStage::Tested, "adv-1", "/test"),
            (WaveStage::Accepted, "uat-1", "/user-acceptance"),
            (WaveStage::PurpleTeamed, "pt-1", "/purple-team"),
        ];
        // Append in a deliberately-out-of-order sequence.
        for (stage, sid, wb) in stages {
            let r = record("w-chain", stage, sid, WaveOutcome::Pass, gs.clone(), wb);
            let h = hmac_over(key, &r);
            let (s, _) = post_json(&router, body_for(&state, &h, &r)).await;
            assert_eq!(s, StatusCode::CREATED);
        }
        let (s, v) = get_verify(&router, "w-chain").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["all_required_stages_present"], true);
        let chain = v["chain"].as_array().unwrap();
        let stages_in_order: Vec<&str> = chain
            .iter()
            .map(|e| e["record"]["stage"].as_str().unwrap())
            .collect();
        assert_eq!(
            stages_in_order,
            vec!["TESTED", "PURPLE_TEAMED", "ACCEPTED", "CLOSED"]
        );
    }

    #[tokio::test]
    async fn verify_all_required_false_when_purple_team_missing_for_gate_surface() {
        let key = b"unit-test-hmac-key-32-bytes-pad!";
        let state = fixture_state(key);
        let router = router(state.clone());
        let mut gs = HashSet::new();
        gs.insert(GateSurface::SafetyKernel);
        // Tested has gate_surfaces non-empty; PURPLE_TEAMED omitted.
        for (stage, sid, wb, gs_local) in [
            (WaveStage::Tested, "adv", "/test", gs.clone()),
            (WaveStage::Accepted, "uat", "/user-acceptance", HashSet::new()),
            (WaveStage::Closed, "cls", "/closeout", HashSet::new()),
        ] {
            let r = record("w-missing-pt", stage, sid, WaveOutcome::Pass, gs_local, wb);
            let h = hmac_over(key, &r);
            let (s, _) = post_json(&router, body_for(&state, &h, &r)).await;
            assert_eq!(s, StatusCode::CREATED);
        }
        let (s, v) = get_verify(&router, "w-missing-pt").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["all_required_stages_present"], false);
    }

    #[tokio::test]
    async fn append_with_empty_gate_surfaces_for_purple_team_allowed() {
        // Spec requirement: append-stage consistency check for
        // PURPLE_TEAMED with empty gate_surfaces is permitted (the
        // chain-level all_required check is the one that flags it,
        // not the append-time validator).
        let key = b"unit-test-hmac-key-32-bytes-pad!";
        let state = fixture_state(key);
        let router = router(state.clone());
        let r = record(
            "w-pt-empty",
            WaveStage::PurpleTeamed,
            "pt-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/purple-team",
        );
        let h = hmac_over(key, &r);
        let (s, _) = post_json(&router, body_for(&state, &h, &r)).await;
        assert_eq!(s, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn forged_hmac_with_mutated_record_returns_403() {
        // Rule 8 adversarial — attacker mutates the record AFTER the
        // legitimate HMAC was computed. Constant-time verify_slice
        // must reject.
        let key = b"unit-test-hmac-key-32-bytes-pad!";
        let state = fixture_state(key);
        let router = router(state.clone());
        let r = record(
            "w-mut",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let h = hmac_over(key, &r);
        // Now mutate the record but keep the original HMAC.
        let mut mutated = r.clone();
        mutated.evidence = "tampered".to_string();
        let (s, v) = post_json(&router, body_for(&state, &h, &mutated)).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(v["reason"], "kernel_hmac_mismatch");
    }

    #[tokio::test]
    async fn invalid_hmac_hex_length_returns_400() {
        let key = b"unit-test-hmac-key-32-bytes-pad!";
        let state = fixture_state(key);
        let router = router(state.clone());
        let r = record(
            "w-bad-hex",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let h = hmac_over(key, &r);
        let mut body = body_for(&state, &h, &r);
        body["kernel_hmac_hex"] = Value::String("aabbcc".to_string()); // 3 bytes
        let (s, _) = post_json(&router, body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }
}
