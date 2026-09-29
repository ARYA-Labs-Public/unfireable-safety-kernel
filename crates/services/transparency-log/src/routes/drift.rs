//! A FOURTH typed append route on the same transparency-log service,
//! for Safety-Kernel image-drift events from the reconciler.
//! It mirrors `POST /v1/audit/mcp` and `POST /v1/wave/session` exactly but
//! uses a dedicated reconciler Ed25519 key.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use qorch_transparency_store::AppendInput;
use sha2::{Digest, Sha256};

use crate::{
    dto::{AppendReconcilerDriftRequest, AppendReconcilerDriftResponse},
    error::ServiceError,
    routes::audit_mcp::build_audit_leaf_payload,
    state::AppState,
};

pub async fn append_reconciler_drift(
    State(state): State<AppState>,
    Json(body): Json<AppendReconcilerDriftRequest>,
) -> Result<Response, ServiceError> {
    // 1. Dedicated reconciler-drift key must be configured.
    let Some(expected_fpr) = state
        .reconciler_drift_ed25519_key_fingerprint_hex
        .as_deref()
    else {
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

    let idempotent_replay = !outcome.created;
    let status = if idempotent_replay {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    let resp = AppendReconcilerDriftResponse {
        idempotent_replay,
        leaf_hash_hex: hex::encode(outcome.leaf_hash),
        leaf_index: outcome.leaf_index,
        ok: true,
    };
    Ok((status, Json(resp)).into_response())
}

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
mod tests {
    use std::sync::Arc;

    use ed25519_dalek::{Signer, SigningKey};
    use qorch_transparency_store::memory::MemoryTransparencyStore;

    use super::*;
    use crate::clock::SystemClock;
    use crate::dto::{AppendMcpAuditRequest, AppendMcpAuditResponse};
    use crate::routes::audit_mcp::append_mcp_audit;
    use qorch_domain::safety::Clock;

    fn keypair_from_seed(seed_byte: u8) -> (SigningKey, VerifyingKey, String, String) {
        let seed = [seed_byte; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        let pk_hex = hex::encode(vk.as_bytes());
        let mut h = Sha256::new();
        h.update(vk.as_bytes());
        let fpr_hex = hex::encode(h.finalize());
        (sk, vk, pk_hex, fpr_hex)
    }

    fn make_test_state(reconciler_fpr: Option<String>, mcp_fpr: Option<String>) -> AppState {
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

        let mut state = AppState::new(
            Arc::new(MemoryTransparencyStore::new()),
            Arc::new(sth_key),
            sth_fpr,
            kernel_fpr,
            clock,
            "test-key".to_string(),
        );
        if let Some(rfpr) = reconciler_fpr {
            state = state.with_reconciler_drift_ed25519_fingerprint(rfpr);
        }
        if let Some(mfpr) = mcp_fpr {
            state = state.with_mcp_audit_ed25519_fingerprint(mfpr);
        }
        state
    }

    #[tokio::test]
    async fn a_signed_drift_event_is_appended() {
        let (sk, _vk, pk_hex, fpr_hex) = keypair_from_seed(1);
        let state = make_test_state(Some(fpr_hex), None);

        let canonical_bytes = b"{\"event\":\"drift\",\"manifest\":\"v1\"}".to_vec();
        let sig = sk.sign(&canonical_bytes);
        let id_key = [7u8; 32];

        let req = AppendReconcilerDriftRequest {
            canonical_bytes_hex: hex::encode(&canonical_bytes),
            ed25519_public_key_hex: pk_hex,
            ed25519_signature_hex: hex::encode(sig.to_bytes()),
            idempotency_key_hex: hex::encode(id_key),
            occurred_at_epoch_seconds: 1700000000,
        };

        let resp = append_reconciler_drift(State(state), Json(req))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let framed = build_audit_leaf_payload(&canonical_bytes, &sig.to_bytes());
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(&framed);
        let expected_leaf_hash = hex::encode(hasher.finalize());

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: AppendReconcilerDriftResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert!(body.ok);
        assert!(!body.idempotent_replay);
        assert_eq!(body.leaf_hash_hex, expected_leaf_hash);
    }

    #[tokio::test]
    async fn replaying_the_same_event_is_idempotent() {
        let (sk, _vk, pk_hex, fpr_hex) = keypair_from_seed(2);
        let state = make_test_state(Some(fpr_hex), None);

        let canonical_bytes = b"{\"event\":\"drift_replay\"}".to_vec();
        let sig = sk.sign(&canonical_bytes);
        let id_key = [8u8; 32];

        let req = AppendReconcilerDriftRequest {
            canonical_bytes_hex: hex::encode(&canonical_bytes),
            ed25519_public_key_hex: pk_hex,
            ed25519_signature_hex: hex::encode(sig.to_bytes()),
            idempotency_key_hex: hex::encode(id_key),
            occurred_at_epoch_seconds: 1700000000,
        };

        let resp1 = append_reconciler_drift(State(state.clone()), Json(req.clone()))
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::CREATED);
        let body1: AppendReconcilerDriftResponse = serde_json::from_slice(
            &axum::body::to_bytes(resp1.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();

        let resp2 = append_reconciler_drift(State(state), Json(req))
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let body2: AppendReconcilerDriftResponse = serde_json::from_slice(
            &axum::body::to_bytes(resp2.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(body2.idempotent_replay);
        assert_eq!(body1.leaf_index, body2.leaf_index);
        assert_eq!(body1.leaf_hash_hex, body2.leaf_hash_hex);
    }

    #[tokio::test]
    async fn an_unconfigured_key_refuses() {
        let (sk, _vk, pk_hex, _fpr_hex) = keypair_from_seed(3);
        let state = make_test_state(None, None);

        let canonical_bytes = b"{\"event\":\"drift\"}".to_vec();
        let sig = sk.sign(&canonical_bytes);

        let req = AppendReconcilerDriftRequest {
            canonical_bytes_hex: hex::encode(&canonical_bytes),
            ed25519_public_key_hex: pk_hex,
            ed25519_signature_hex: hex::encode(sig.to_bytes()),
            idempotency_key_hex: hex::encode([9u8; 32]),
            occurred_at_epoch_seconds: 1700000000,
        };

        let err = append_reconciler_drift(State(state), Json(req))
            .await
            .unwrap_err();
        match err {
            ServiceError::Ed25519NotConfigured => {}
            other => panic!("expected Ed25519NotConfigured, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_key_that_is_not_the_pinned_one_refuses() {
        let (_sk_pinned, _vk_pinned, _pk_pinned_hex, fpr_pinned_hex) = keypair_from_seed(4);
        let (sk_other, _vk_other, pk_other_hex, _fpr_other_hex) = keypair_from_seed(5);
        let state = make_test_state(Some(fpr_pinned_hex), None);

        let canonical_bytes = b"{\"event\":\"drift\"}".to_vec();
        let sig = sk_other.sign(&canonical_bytes);

        let req = AppendReconcilerDriftRequest {
            canonical_bytes_hex: hex::encode(&canonical_bytes),
            ed25519_public_key_hex: pk_other_hex,
            ed25519_signature_hex: hex::encode(sig.to_bytes()),
            idempotency_key_hex: hex::encode([10u8; 32]),
            occurred_at_epoch_seconds: 1700000000,
        };

        let err = append_reconciler_drift(State(state), Json(req))
            .await
            .unwrap_err();
        match err {
            ServiceError::Ed25519KeyFingerprintMismatch => {}
            other => panic!("expected Ed25519KeyFingerprintMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_signature_over_different_bytes_refuses() {
        let (sk, _vk, pk_hex, fpr_hex) = keypair_from_seed(6);
        let state = make_test_state(Some(fpr_hex), None);

        let canonical_bytes = b"{\"event\":\"drift_a\"}".to_vec();
        let sig = sk.sign(&canonical_bytes);
        let other_bytes = b"{\"event\":\"drift_b\"}".to_vec();

        let req = AppendReconcilerDriftRequest {
            canonical_bytes_hex: hex::encode(&other_bytes),
            ed25519_public_key_hex: pk_hex,
            ed25519_signature_hex: hex::encode(sig.to_bytes()),
            idempotency_key_hex: hex::encode([11u8; 32]),
            occurred_at_epoch_seconds: 1700000000,
        };

        let err = append_reconciler_drift(State(state), Json(req))
            .await
            .unwrap_err();
        match err {
            ServiceError::Ed25519SignatureMismatch => {}
            other => panic!("expected Ed25519SignatureMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tampering_with_the_bytes_after_signing_refuses() {
        let (sk, _vk, pk_hex, fpr_hex) = keypair_from_seed(7);
        let state = make_test_state(Some(fpr_hex), None);

        let mut canonical_bytes = b"{\"event\":\"drift_original\"}".to_vec();
        let sig = sk.sign(&canonical_bytes);
        canonical_bytes[0] ^= 0xff;

        let req = AppendReconcilerDriftRequest {
            canonical_bytes_hex: hex::encode(&canonical_bytes),
            ed25519_public_key_hex: pk_hex,
            ed25519_signature_hex: hex::encode(sig.to_bytes()),
            idempotency_key_hex: hex::encode([12u8; 32]),
            occurred_at_epoch_seconds: 1700000000,
        };

        let err = append_reconciler_drift(State(state), Json(req))
            .await
            .unwrap_err();
        match err {
            ServiceError::Ed25519SignatureMismatch => {}
            other => panic!("expected Ed25519SignatureMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_mcp_audit_key_cannot_write_a_drift_leaf() {
        let (_drift_sk, _drift_vk, _drift_pk_hex, drift_fpr_hex) = keypair_from_seed(10);
        let (mcp_sk, _mcp_vk, mcp_pk_hex, mcp_fpr_hex) = keypair_from_seed(11);
        let state = make_test_state(Some(drift_fpr_hex), Some(mcp_fpr_hex));

        let canonical_bytes = b"{\"event\":\"drift_payload\"}".to_vec();
        let sig = mcp_sk.sign(&canonical_bytes);

        let req = AppendReconcilerDriftRequest {
            canonical_bytes_hex: hex::encode(&canonical_bytes),
            ed25519_public_key_hex: mcp_pk_hex,
            ed25519_signature_hex: hex::encode(sig.to_bytes()),
            idempotency_key_hex: hex::encode([13u8; 32]),
            occurred_at_epoch_seconds: 1700000000,
        };

        let err = append_reconciler_drift(State(state), Json(req))
            .await
            .unwrap_err();
        match err {
            ServiceError::Ed25519KeyFingerprintMismatch => {}
            other => panic!("expected Ed25519KeyFingerprintMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_drift_key_cannot_write_an_mcp_audit_leaf() {
        let (drift_sk, _drift_vk, drift_pk_hex, drift_fpr_hex) = keypair_from_seed(12);
        let (_mcp_sk, _mcp_vk, _mcp_pk_hex, mcp_fpr_hex) = keypair_from_seed(13);
        let state = make_test_state(Some(drift_fpr_hex), Some(mcp_fpr_hex));

        let canonical_bytes = b"{\"event\":\"mcp_payload\"}".to_vec();
        let sig = drift_sk.sign(&canonical_bytes);

        let req = AppendMcpAuditRequest {
            canonical_bytes_hex: hex::encode(&canonical_bytes),
            ed25519_public_key_hex: drift_pk_hex,
            ed25519_signature_hex: hex::encode(sig.to_bytes()),
            idempotency_key_hex: hex::encode([14u8; 32]),
            occurred_at_epoch_seconds: 1700000000,
        };

        let err = append_mcp_audit(State(state), Json(req)).await.unwrap_err();
        match err {
            ServiceError::Ed25519KeyFingerprintMismatch => {}
            other => panic!("expected Ed25519KeyFingerprintMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_two_routes_frame_leaves_identically() {
        let (drift_sk, _drift_vk, drift_pk_hex, drift_fpr_hex) = keypair_from_seed(20);

        let bytes = b"{\"shared\":\"content\"}";
        let drift_sig = drift_sk.sign(bytes);

        let dummy_sig = drift_sig.to_bytes();
        let drift_leaf = build_audit_leaf_payload(bytes, &dummy_sig);
        let mcp_leaf = build_audit_leaf_payload(bytes, &dummy_sig);
        assert_eq!(drift_leaf, mcp_leaf);

        let state_drift = make_test_state(Some(drift_fpr_hex.clone()), None);
        let req_drift = AppendReconcilerDriftRequest {
            canonical_bytes_hex: hex::encode(bytes),
            ed25519_public_key_hex: drift_pk_hex.clone(),
            ed25519_signature_hex: hex::encode(drift_sig.to_bytes()),
            idempotency_key_hex: hex::encode([22u8; 32]),
            occurred_at_epoch_seconds: 1700000000,
        };
        let resp_drift = append_reconciler_drift(State(state_drift), Json(req_drift))
            .await
            .unwrap();
        let body_drift: AppendReconcilerDriftResponse = serde_json::from_slice(
            &axum::body::to_bytes(resp_drift.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();

        let state_mcp = make_test_state(None, Some(drift_fpr_hex));
        let req_mcp = AppendMcpAuditRequest {
            canonical_bytes_hex: hex::encode(bytes),
            ed25519_public_key_hex: drift_pk_hex,
            ed25519_signature_hex: hex::encode(drift_sig.to_bytes()),
            idempotency_key_hex: hex::encode([23u8; 32]),
            occurred_at_epoch_seconds: 1700000000,
        };
        let resp_mcp = append_mcp_audit(State(state_mcp), Json(req_mcp))
            .await
            .unwrap();
        let body_mcp: AppendMcpAuditResponse = serde_json::from_slice(
            &axum::body::to_bytes(resp_mcp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();

        assert_eq!(body_drift.leaf_hash_hex, body_mcp.leaf_hash_hex);
    }

    #[tokio::test]
    async fn the_route_refuses_a_request_without_the_api_key() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let (sk, _vk, pk_hex, fpr_hex) = keypair_from_seed(30);
        let state = make_test_state(Some(fpr_hex), None);
        let app = crate::router::build_router(state);

        let canonical_bytes = b"{\"event\":\"drift_auth_check\"}".to_vec();
        let sig = sk.sign(&canonical_bytes);
        let id_key = [30u8; 32];

        let req_body = AppendReconcilerDriftRequest {
            canonical_bytes_hex: hex::encode(&canonical_bytes),
            ed25519_public_key_hex: pk_hex,
            ed25519_signature_hex: hex::encode(sig.to_bytes()),
            idempotency_key_hex: hex::encode(id_key),
            occurred_at_epoch_seconds: 1700000000,
        };
        let body_json = serde_json::to_vec(&req_body).unwrap();

        // 1. Without x-api-key -> 401 UNAUTHORIZED
        let req_unauthed = Request::builder()
            .method("POST")
            .uri("/v1/audit/drift")
            .header("content-type", "application/json")
            .body(Body::from(body_json.clone()))
            .unwrap();

        let resp_unauthed = app.clone().oneshot(req_unauthed).await.unwrap();
        assert_eq!(resp_unauthed.status(), StatusCode::UNAUTHORIZED);

        // 2. With x-api-key: "test-key" -> 201 CREATED
        let req_authed = Request::builder()
            .method("POST")
            .uri("/v1/audit/drift")
            .header("content-type", "application/json")
            .header("x-api-key", "test-key")
            .body(Body::from(body_json))
            .unwrap();

        let resp_authed = app.oneshot(req_authed).await.unwrap();
        assert_eq!(resp_authed.status(), StatusCode::CREATED);
    }
}
