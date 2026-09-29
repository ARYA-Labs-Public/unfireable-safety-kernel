//! internal-ref / ADR-016 — `POST /v1/audit/mcp` MCP-audit-record append.
//!
//! A THIRD typed append route on the same transparency-log service,
//! mirroring `POST /v1/wave/session` exactly but for an MCP audit
//! record. It does NOT touch the kernel-key-pinned `POST /v1/append`
//! (the MCP ledger is not the kernel and must not impersonate it) and
//! it reuses the SAME `transparency_store`, Merkle tree, STH signer, and
//! `/v1/verify` + `/v1/consistency` endpoints — zero new hash-chain
//! code.
//!
//! Differences from the wave-session route:
//!   - The record is supplied as opaque CANONICAL BYTES (hex), not a
//!     typed `WaveSessionRecord` — the t-log is record-type-agnostic.
//!   - The leaf is signed with a DEDICATED MCP-audit Ed25519 key
//!     (open-question 1: dedicated key so a compromise of the MCP server
//!     cannot forge wave-session or kernel leaves).
//!   - The leaf framing carries the 64-byte Ed25519 signature as the
//!     trailer (vs the wave-session route's 32-byte HMAC).
//!
//! internal-ref cross-check is preserved by construction: the returned
//! `leaf_hash_hex` is `SHA-256(0x00 || framed_payload)`, and the client
//! recomputes the same framing + leaf hash locally.

#![allow(clippy::bool_assert_comparison)]
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use sha2::{Digest, Sha256};

use qorch_transparency_store::AppendInput;

use crate::dto::{AppendMcpAuditRequest, AppendMcpAuditResponse};
use crate::error::ServiceError;
use crate::state::AppState;

/// Length-prefixed framing for an MCP-audit leaf: 8-byte big-endian
/// record length, then `canonical_bytes`, then the 64-byte raw Ed25519
/// signature. IDENTICAL in shape to the wave-session route's
/// `build_leaf_payload` except the trailer is a 64-byte signature (the
/// wave-session route trails a 32-byte HMAC). The leaf hash therefore
/// commits to BOTH the record content AND the signature.
///
/// Shared with the `POST /v1/audit/drift` route (`src/routes/drift.rs`).
pub(crate) fn build_audit_leaf_payload(
    record_bytes: &[u8],
    sig: &[u8; SIGNATURE_LENGTH],
) -> Vec<u8> {
    let n: u64 = u64::try_from(record_bytes.len()).unwrap_or(u64::MAX);
    let mut out = Vec::with_capacity(8 + record_bytes.len() + SIGNATURE_LENGTH);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(record_bytes);
    out.extend_from_slice(sig);
    out
}

/// Constant-time ASCII-hex equality (same shape as the wave-session
/// route's `constant_time_str_eq`). Local copy to avoid widening that
/// module's visibility.
fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `POST /v1/audit/mcp`.
///
/// 1. Refuse (503) if the service was started without a DEDICATED
///    MCP-audit Ed25519 fingerprint (`Ed25519NotConfigured`).
/// 2. Pin the caller-announced public key against the configured
///    MCP-audit fingerprint (constant-time; `Ed25519KeyFingerprintMismatch`
///    → 403). This is DISTINCT from the kernel + wave-session keys.
/// 3. Verify the Ed25519 signature over the decoded canonical bytes
///    (`Ed25519SignatureMismatch` → 403).
/// 4. Frame the leaf, append (idempotent on the supplied idempotency
///    key), return `{idempotent_replay, leaf_hash_hex, leaf_index, ok}`.
pub async fn append_mcp_audit(
    State(state): State<AppState>,
    Json(body): Json<AppendMcpAuditRequest>,
) -> Result<Response, ServiceError> {
    // 1. Dedicated MCP-audit key must be configured.
    let Some(expected_fpr) = state.mcp_audit_ed25519_key_fingerprint_hex.as_deref() else {
        return Err(ServiceError::Ed25519NotConfigured);
    };

    // 2. Decode + pin the announced public key.
    let announced_pk_raw = hex::decode(body.ed25519_public_key_hex.trim())
        .map_err(|e| ServiceError::BadRequest(format!("ed25519 pk hex decode: {e}")))?;
    if announced_pk_raw.len() != 32 {
        return Err(ServiceError::BadRequest(format!(
            "ed25519 public key must be 32 bytes, got {}",
            announced_pk_raw.len()
        )));
    }
    let announced_fpr = {
        let mut h = Sha256::new();
        h.update(&announced_pk_raw);
        hex::encode(h.finalize())
    };
    if !constant_time_str_eq(&announced_fpr, &expected_fpr.to_ascii_lowercase()) {
        return Err(ServiceError::Ed25519KeyFingerprintMismatch);
    }

    // 3. Decode the canonical bytes + signature, then verify.
    let record_bytes = hex::decode(body.canonical_bytes_hex.trim())
        .map_err(|e| ServiceError::BadRequest(format!("canonical_bytes hex decode: {e}")))?;
    if record_bytes.is_empty() {
        return Err(ServiceError::BadRequest("canonical_bytes empty".into()));
    }
    let sig_raw = hex::decode(body.ed25519_signature_hex.trim())
        .map_err(|e| ServiceError::BadRequest(format!("ed25519 sig hex decode: {e}")))?;
    if sig_raw.len() != SIGNATURE_LENGTH {
        return Err(ServiceError::BadRequest(format!(
            "ed25519 signature must be 64 bytes, got {}",
            sig_raw.len()
        )));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&announced_pk_raw);
    let mut sig_arr = [0u8; SIGNATURE_LENGTH];
    sig_arr.copy_from_slice(&sig_raw);

    let vk =
        VerifyingKey::from_bytes(&pk_arr).map_err(|_| ServiceError::Ed25519SignatureMismatch)?;
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify(&record_bytes, &signature)
        .map_err(|_| ServiceError::Ed25519SignatureMismatch)?;

    // 4. Frame + append (idempotent on the caller-supplied key).
    let idempotency_key = hex_to_32(&body.idempotency_key_hex)?;
    let leaf_payload = build_audit_leaf_payload(&record_bytes, &sig_arr);

    let outcome = state
        .store
        .append(AppendInput {
            idempotency_key,
            payload: leaf_payload,
            occurred_at_epoch_seconds: body.occurred_at_epoch_seconds,
        })
        .await?;

    // Atomic fresh-vs-replay from the store (internal-ref): a pre-append
    // size snapshot races under concurrent identical appends.
    let idempotent_replay = !outcome.created;
    let status = if idempotent_replay {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    let resp = AppendMcpAuditResponse {
        idempotent_replay,
        leaf_hash_hex: hex::encode(outcome.leaf_hash),
        leaf_index: outcome.leaf_index,
        ok: true,
    };
    Ok((status, Json(resp)).into_response())
}

/// Decode a hex string into exactly 32 bytes (same as the wave-session
/// route's local helper).
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
    use std::sync::Arc;

    use crate::clock::SystemClock;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{get, post};
    use axum::Router;
    use ed25519_dalek::{Signer, SigningKey};
    use http_body_util::BodyExt;
    use qorch_domain::mcp_audit::{CallerType, EventKind, McpAuditRecord, ToolClass};
    use qorch_domain::safety::Clock;
    use qorch_transparency_store::memory::MemoryTransparencyStore;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    /// Deterministic dedicated MCP-audit signing key (seed 0x99) so the
    /// fingerprint is stable across the test.
    fn mcp_audit_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x99u8; 32])
    }

    fn mcp_audit_fingerprint(sk: &SigningKey) -> String {
        let pk = sk.verifying_key().to_bytes();
        let mut h = Sha256::new();
        h.update(pk);
        hex::encode(h.finalize())
    }

    fn fixture_state_with_mcp_audit() -> (AppState, SigningKey) {
        let sth_seed = [0x11u8; 32];
        let sth_key = SigningKey::from_bytes(&sth_seed);
        let sth_pk = sth_key.verifying_key().to_bytes();
        let mut h = Sha256::new();
        h.update(sth_pk);
        let sth_fpr = hex::encode(h.finalize());
        let kernel_seed = [0x22u8; 32];
        let kernel_pk = SigningKey::from_bytes(&kernel_seed)
            .verifying_key()
            .to_bytes();
        let mut h2 = Sha256::new();
        h2.update(kernel_pk);
        let kernel_fpr = hex::encode(h2.finalize());
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

        let audit_sk = mcp_audit_signing_key();
        let audit_fpr = mcp_audit_fingerprint(&audit_sk);

        let state = AppState::new(
            Arc::new(MemoryTransparencyStore::new()),
            Arc::new(sth_key),
            sth_fpr,
            kernel_fpr,
            clock,
            "test-key".to_string(),
        )
        .with_mcp_audit_ed25519_fingerprint(audit_fpr);
        (state, audit_sk)
    }

    fn router(state: AppState) -> Router {
        Router::new()
            .route("/v1/audit/mcp", post(append_mcp_audit))
            .route("/v1/verify/{entry_id}", get(crate::routes::verify::verify))
            .with_state(state)
    }

    fn sample_record() -> McpAuditRecord {
        McpAuditRecord {
            args_fingerprint: "a".repeat(64),
            args_preview: None,
            authorizer_verdict: Some("allow".to_string()),
            caller_type: CallerType::HumanViaClaudeAi,
            completed_at_epoch_seconds: None,
            error_detail: None,
            event_kind: EventKind::Dispatch,
            event_id: "ev-route-1".to_string(),
            extension: None,
            job_id: "job-1".to_string(),
            parent_trace_id: None,
            principal: Some("client-x".to_string()),
            schema_version: 1,
            received_at_epoch_seconds: 1_716_400_000,
            result_pointer: None,
            result_fingerprint: None,
            resolved_route: Some("orchestrate_tool".to_string()),
            session_id: Some("sess-1".to_string()),
            sk_token_id: None,
            sk_verdict: None,
            source_ip_hash: Some("b".repeat(64)),
            source_ua_hash: Some("c".repeat(64)),
            status: None,
            subject_pseudonym: None,
            tool_class: ToolClass::Mutating,
            tool_name: "biotech_protein_fold".to_string(),
            tool_risk_tier: Some("A2".to_string()),
            trace_id: "tr-1".to_string(),
        }
    }

    fn idempotency_key(record: &McpAuditRecord) -> [u8; 32] {
        // SHA-256(schema_version || event_id) — the natural key.
        let mut h = Sha256::new();
        h.update(record.schema_version.to_le_bytes());
        h.update(record.event_id.as_bytes());
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }

    fn body_for(sk: &SigningKey, record: &McpAuditRecord) -> Value {
        let canonical = record.canonical_bytes(None).unwrap();
        let sig = sk.sign(&canonical);
        json!({
            "canonical_bytes_hex": hex::encode(&canonical),
            "ed25519_public_key_hex": hex::encode(sk.verifying_key().to_bytes()),
            "ed25519_signature_hex": hex::encode(sig.to_bytes()),
            "idempotency_key_hex": hex::encode(idempotency_key(record)),
            "occurred_at_epoch_seconds": record.received_at_epoch_seconds,
        })
    }

    async fn post_json(router: &Router, body: Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/audit/mcp")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    #[tokio::test]
    async fn fresh_append_returns_201_and_cross_checks_leaf_hash() {
        let (state, sk) = fixture_state_with_mcp_audit();
        let router = router(state);
        let r = sample_record();
        let body = body_for(&sk, &r);
        let (s, v) = post_json(&router, body).await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(v["leaf_index"], 0);
        assert_eq!(v["ok"], true);
        // leaf_hash_hex MUST equal SHA-256(0x00 || framed_payload).
        let canonical = r.canonical_bytes(None).unwrap();
        let sig = sk.sign(&canonical).to_bytes();
        let framed = build_audit_leaf_payload(&canonical, &sig);
        let expected = qorch_domain::transparency::leaf_hash(&framed);
        assert_eq!(v["leaf_hash_hex"], hex::encode(expected));
    }

    #[tokio::test]
    async fn duplicate_idempotency_key_returns_200_replay() {
        let (state, sk) = fixture_state_with_mcp_audit();
        let router = router(state);
        let r = sample_record();
        let body = body_for(&sk, &r);
        let (s1, _) = post_json(&router, body.clone()).await;
        assert_eq!(s1, StatusCode::CREATED);
        let (s2, v2) = post_json(&router, body).await;
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(v2["idempotent_replay"], true);
        assert_eq!(v2["leaf_index"], 0);
    }

    #[tokio::test]
    async fn inclusion_proof_verifies_for_appended_audit_leaf() {
        let (state, sk) = fixture_state_with_mcp_audit();
        let router = router(state);
        let r = sample_record();
        let (s, v) = post_json(&router, body_for(&sk, &r)).await;
        assert_eq!(s, StatusCode::CREATED);
        let idx = v["leaf_index"].as_u64().unwrap();
        // GET /v1/verify/{idx} must return a valid inclusion proof.
        let req = Request::builder()
            .method("GET")
            .uri(format!("/v1/verify/{idx}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_key_returns_403_fingerprint_mismatch() {
        // Adversarial (Rule 8): attacker signs with a DIFFERENT key and
        // announces that key. The dedicated-fingerprint pin must reject —
        // the MCP server's key is not the kernel's or wave-session's.
        let (state, _sk) = fixture_state_with_mcp_audit();
        let router = router(state);
        let r = sample_record();
        let attacker = SigningKey::from_bytes(&[0xAAu8; 32]);
        let (s, v) = post_json(&router, body_for(&attacker, &r)).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(v["reason"], "ed25519_key_fingerprint_mismatch");
    }

    #[tokio::test]
    async fn right_key_forged_signature_returns_403() {
        // Caller announces the RIGHT public key but sends a signature
        // minted by a different key. Fingerprint pin passes; verify fails.
        let (state, sk) = fixture_state_with_mcp_audit();
        let router = router(state);
        let r = sample_record();
        let canonical = r.canonical_bytes(None).unwrap();
        let attacker = SigningKey::from_bytes(&[0xBBu8; 32]);
        let bad_sig = attacker.sign(&canonical);
        let body = json!({
            "canonical_bytes_hex": hex::encode(&canonical),
            "ed25519_public_key_hex": hex::encode(sk.verifying_key().to_bytes()),
            "ed25519_signature_hex": hex::encode(bad_sig.to_bytes()),
            "idempotency_key_hex": hex::encode(idempotency_key(&r)),
            "occurred_at_epoch_seconds": r.received_at_epoch_seconds,
        });
        let (s, v) = post_json(&router, body).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(v["reason"], "ed25519_signature_mismatch");
    }

    #[tokio::test]
    async fn tampered_canonical_bytes_returns_403() {
        // Adversarial: attacker keeps a valid signature but mutates the
        // canonical bytes after signing. verify() over the mutated bytes
        // must fail.
        let (state, sk) = fixture_state_with_mcp_audit();
        let router = router(state);
        let r = sample_record();
        let canonical = r.canonical_bytes(None).unwrap();
        let sig = sk.sign(&canonical);
        let mut tampered = canonical.clone();
        tampered[0] ^= 0xFF;
        let body = json!({
            "canonical_bytes_hex": hex::encode(&tampered),
            "ed25519_public_key_hex": hex::encode(sk.verifying_key().to_bytes()),
            "ed25519_signature_hex": hex::encode(sig.to_bytes()),
            "idempotency_key_hex": hex::encode(idempotency_key(&r)),
            "occurred_at_epoch_seconds": r.received_at_epoch_seconds,
        });
        let (s, v) = post_json(&router, body).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(v["reason"], "ed25519_signature_mismatch");
    }

    #[tokio::test]
    async fn not_configured_returns_503() {
        // Service started WITHOUT a dedicated MCP-audit fingerprint.
        let sth_key = SigningKey::from_bytes(&[0x11u8; 32]);
        let sth_pk = sth_key.verifying_key().to_bytes();
        let mut h = Sha256::new();
        h.update(sth_pk);
        let sth_fpr = hex::encode(h.finalize());
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let state = AppState::new(
            Arc::new(MemoryTransparencyStore::new()),
            Arc::new(sth_key),
            sth_fpr,
            "deadbeef".to_string(),
            clock,
            "test-key".to_string(),
        ); // no .with_mcp_audit_ed25519_fingerprint
        let router = router(state);
        let sk = mcp_audit_signing_key();
        let r = sample_record();
        let (s, v) = post_json(&router, body_for(&sk, &r)).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(v["reason"], "ed25519_not_configured");
    }

    #[tokio::test]
    async fn audit_key_is_distinct_from_kernel_and_sth_keys() {
        // The dedicated MCP-audit fingerprint must NOT equal the STH
        // signing-key fingerprint or the kernel fingerprint — open-Q1.
        let (state, _sk) = fixture_state_with_mcp_audit();
        let audit_fpr = state.mcp_audit_ed25519_key_fingerprint_hex.clone().unwrap();
        assert_ne!(audit_fpr, state.signing_key_fingerprint_hex);
        assert_ne!(audit_fpr, state.kernel_key_fingerprint_hex);
    }
}
