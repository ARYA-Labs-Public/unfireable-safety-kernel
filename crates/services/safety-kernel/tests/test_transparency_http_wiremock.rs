//!   /test wave — real HTTP wiremock test for
//! `ReqwestTransparencyClient`.
//!
//! Step 5's kernel-side integration test (`authorize_transparency_log.rs`)
//! mocks the `TransparencyClient` trait, which skips the HTTP path
//! entirely. This file pins the contract from the OTHER side: the
//! production reqwest client points at a `wiremock::MockServer` and we
//! assert that every HTTP-shape failure mode maps to the expected
//! `TransparencyError` variant.
//!
//! Cases:
//!   * 201 with `idempotent_replay=false` ⇒ Ok(fresh insert)
//!   * 200 with `idempotent_replay=true`  ⇒ Ok(retry)
//!   * 400 ⇒ Rejected{400}
//!   * 401 ⇒ Rejected{401}
//!   * 403 ⇒ Rejected{403}
//!   * 422 ⇒ Rejected{422}
//!   * 500 ⇒ ServerError{500}
//!   * 502 ⇒ ServerError{502}
//!   * 503 ⇒ ServerError{503}
//!   * 409 ⇒ Conflict
//!   * malformed JSON body in a 2xx ⇒ Malformed
//!   * slow response > client timeout ⇒ Unreachable (timeout)
//!   * connection refused ⇒ Unreachable

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::similar_names, clippy::too_many_lines)]

use std::time::Duration;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use qorch_safety_kernel::transparency_client::{
    ReqwestTransparencyClient, TransparencyAppendInput, TransparencyClient, TransparencyError,
};

fn input() -> TransparencyAppendInput {
    TransparencyAppendInput {
        idempotency_key: [0xAB; 32],
        payload: b"test-token-bytes".to_vec(),
        occurred_at_epoch_seconds: 1_700_000_000,
    }
}

/// RFC-6962 leaf hash of the canonical `input()` payload, hex-encoded.
///: the kernel cross-verifies the t-log's `leaf_hash_hex`
/// against this locally-recomputed value, so 2xx happy-path mock
/// responses MUST carry the matching hash or they will surface as
/// `ProtocolViolation`.
fn input_leaf_hash_hex() -> String {
    hex::encode(qorch_domain::transparency::leaf_hash(b"test-token-bytes"))
}

async fn client_for(server: &MockServer, timeout: Duration) -> ReqwestTransparencyClient {
    ReqwestTransparencyClient::new(
        server.uri(),
        "test-api-key".to_string(),
        hex::encode([0u8; 32]),
        timeout,
    )
}

/// 201 Created with `idempotent_replay=false` — the fresh-insert path.
#[tokio::test]
async fn http_201_fresh_insert_returns_ok() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "entry_id": "42",
            "idempotent_replay": false,
            //: must match the kernel's locally-computed
            // RFC-6962 leaf hash or the request fails-closed.
            "leaf_hash_hex": input_leaf_hash_hex(),
            "leaf_index": 42,
            "ok": true,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_secs(2)).await;
    let outcome = client.append(input()).await.expect("201 must succeed");
    assert_eq!(outcome.leaf_index, 42);
    assert!(!outcome.idempotent_replay);
}

/// 200 OK with `idempotent_replay=true` — the retry path.
#[tokio::test]
async fn http_200_idempotent_replay_returns_ok() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "entry_id": "7",
            "idempotent_replay": true,
            //: must match the kernel's locally-computed
            // RFC-6962 leaf hash or the request fails-closed.
            "leaf_hash_hex": input_leaf_hash_hex(),
            "leaf_index": 7,
            "ok": true,
        })))
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_secs(2)).await;
    let outcome = client.append(input()).await.expect("200 must succeed");
    assert_eq!(outcome.leaf_index, 7);
    assert!(outcome.idempotent_replay);
}

/// 400 Bad Request → TransparencyError::Rejected{400}
#[tokio::test]
async fn http_400_yields_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_secs(2)).await;
    let err = client.append(input()).await.unwrap_err();
    match err {
        TransparencyError::Rejected { status_code,.. } => {
            assert_eq!(status_code, 400);
        }
        other => panic!("expected Rejected{{400}}, got {other:?}"),
    }
}

/// 401 Unauthorized → Rejected{401}
#[tokio::test]
async fn http_401_yields_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_secs(2)).await;
    let err = client.append(input()).await.unwrap_err();
    assert!(
        matches!(err, TransparencyError::Rejected { status_code: 401,.. }),
        "got {err:?}",
    );
    assert_eq!(err.kind(), "append_failed");
}

/// 403 Forbidden → Rejected{403}
#[tokio::test]
async fn http_403_yields_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_secs(2)).await;
    let err = client.append(input()).await.unwrap_err();
    assert!(
        matches!(err, TransparencyError::Rejected { status_code: 403,.. }),
        "got {err:?}",
    );
}

/// 422 Unprocessable Entity → Rejected{422}
#[tokio::test]
async fn http_422_yields_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(422))
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_secs(2)).await;
    let err = client.append(input()).await.unwrap_err();
    assert!(
        matches!(err, TransparencyError::Rejected { status_code: 422,.. }),
        "got {err:?}",
    );
}

/// 500 Internal Server Error → ServerError{500} (FAIL-CLOSED on kernel side)
#[tokio::test]
async fn http_500_yields_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(500).set_body_string("oops"))
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_secs(2)).await;
    let err = client.append(input()).await.unwrap_err();
    assert!(
        matches!(err, TransparencyError::ServerError { status_code: 500,.. }),
        "got {err:?}",
    );
    assert_eq!(err.kind(), "server_error");
}

/// 502 Bad Gateway → ServerError{502}
#[tokio::test]
async fn http_502_yields_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_secs(2)).await;
    let err = client.append(input()).await.unwrap_err();
    assert!(
        matches!(err, TransparencyError::ServerError { status_code: 502,.. }),
        "got {err:?}",
    );
}

/// 503 Service Unavailable → ServerError{503}
#[tokio::test]
async fn http_503_yields_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_secs(2)).await;
    let err = client.append(input()).await.unwrap_err();
    assert!(
        matches!(err, TransparencyError::ServerError { status_code: 503,.. }),
        "got {err:?}",
    );
}

/// 409 Conflict → TransparencyError::Conflict (kernel side treats as success).
#[tokio::test]
async fn http_409_yields_conflict() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
            "error": "conflict",
            "ok": false,
            "reason": "idempotency_payload_mismatch",
        })))
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_secs(2)).await;
    let err = client.append(input()).await.unwrap_err();
    assert!(matches!(err, TransparencyError::Conflict), "got {err:?}");
    assert_eq!(err.kind(), "conflict");
}

/// Malformed JSON body on a 2xx → TransparencyError::Malformed.
#[tokio::test]
async fn http_2xx_with_malformed_json_yields_malformed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string("{this-is-not-json"),
        )
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_secs(2)).await;
    let err = client.append(input()).await.unwrap_err();
    assert!(
        matches!(err, TransparencyError::Malformed {.. }),
        "expected Malformed, got {err:?}",
    );
    assert_eq!(err.kind(), "malformed_response");
}

/// Slow response that exceeds the client's per-request timeout MUST
/// surface as Unreachable (reqwest's timeout error is mapped there).
#[tokio::test]
async fn slow_response_exceeding_timeout_yields_unreachable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_millis(200)).await;
    let err = client.append(input()).await.unwrap_err();
    assert!(
        matches!(err, TransparencyError::Unreachable {.. }),
        "expected Unreachable, got {err:?}",
    );
    assert_eq!(err.kind(), "unreachable");
}

/// Connection refused (server never started) → Unreachable.
#[tokio::test]
async fn connection_refused_yields_unreachable() {
    let client = ReqwestTransparencyClient::new(
        "http://127.0.0.1:1".to_string(),
        "test-api-key".to_string(),
        hex::encode([0u8; 32]),
        Duration::from_millis(500),
    );
    let err = client.append(input()).await.unwrap_err();
    assert!(
        matches!(err, TransparencyError::Unreachable {.. }),
        "expected Unreachable, got {err:?}",
    );
}

/// Request body shape correctness — the wiremock receives a JSON
/// envelope whose `idempotency_key_hex` is 64 hex chars, the
/// `kernel_key_fingerprint_sha256` is the configured value, and
/// `token_b64` is the base64url-no-pad encoding of the input bytes.
/// We assert these via wiremock's body matcher to lock in the wire
/// shape — anyone refactoring the client must update this test too.
#[tokio::test]
async fn request_body_carries_required_fields_in_lex_order() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "idempotency_key_hex": hex::encode([0xABu8; 32]),
            "kernel_key_fingerprint_sha256": hex::encode([0u8; 32]),
            "occurred_at_epoch_seconds": 1_700_000_000_u64,
            "token_b64": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(b"test-token-bytes"),
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "entry_id": "0",
            "idempotent_replay": false,
            //: must match the kernel's locally-computed
            // RFC-6962 leaf hash or the request fails-closed.
            "leaf_hash_hex": input_leaf_hash_hex(),
            "leaf_index": 0_u64,
            "ok": true,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_secs(2)).await;
    client.append(input()).await.expect("body must match");

    // Mock asserts on Drop that exact-count expectations were met.
}

// Note: import for the body_json matcher's encoder.
#[allow(unused_imports)]
use base64::Engine as _;

///  /  Step 8 — t-log returns a 2xx with a
/// `leaf_hash_hex` that does NOT match the kernel's locally-computed
/// `SHA-256(0x00 || payload)`. The wire client MUST refuse and
/// surface `TransparencyError::ProtocolViolation`. This is the
/// upstream half of the kernel's existing fail-closed:
/// `routes/authorize.rs:Step 7.5` then synthesizes the 403 with
/// `transparency_error:protocol_violation`.
#[tokio::test]
async fn http_2xx_with_wrong_leaf_hash_yields_protocol_violation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "entry_id": "1",
            "idempotent_replay": false,
            // Deliberately divergent — NOT the leaf hash of
            // `b"test-token-bytes"`. The kernel's local re-hash will
            // not match, so the client must refuse.
            "leaf_hash_hex": hex::encode([0xDEu8; 32]),
            "leaf_index": 1,
            "ok": true,
        })))
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_secs(2)).await;
    let err = client.append(input()).await.unwrap_err();
    assert!(
        matches!(err, TransparencyError::ProtocolViolation(_)),
        "expected ProtocolViolation, got {err:?}",
    );
    assert_eq!(err.kind(), "protocol_violation");
}

///  /  Step 8 — non-hex `leaf_hash_hex` MUST also map
/// to `ProtocolViolation` (this is the same fail-closed class — the
/// t-log violated its wire contract).
#[tokio::test]
async fn http_2xx_with_non_hex_leaf_hash_yields_protocol_violation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "entry_id": "1",
            "idempotent_replay": false,
            "leaf_hash_hex": "not-hex-at-all-zzz",
            "leaf_index": 1,
            "ok": true,
        })))
        .mount(&server)
        .await;

    let client = client_for(&server, Duration::from_secs(2)).await;
    let err = client.append(input()).await.unwrap_err();
    assert!(
        matches!(err, TransparencyError::ProtocolViolation(_)),
        "expected ProtocolViolation, got {err:?}",
    );
}
