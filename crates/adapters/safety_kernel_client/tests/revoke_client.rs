//! Reaper / revoke-compute client-method tests.
//!
//! Stands a mock kernel up via `wiremock` and drives the four revoke
//! SDK methods (`mint_revoke`, `pending_revoke`, `ack_revoke`,
//! `restore_revoke`) against it. Two kinds of assertion:
//!
//! - Happy path: a well-shaped 200 (or 204) decodes into the shared DTO.
//! - FAIL-CLOSED path: transport failure / 5xx (incl. the mint 503
//!   `revoke_not_recorded`) / role-forbidden 403 REJECT with an `Err`,
//!   never a false-`Ok`.
//!
//! Each assertion is a structural enum-variant / value match — no
//! string-regex-as-evidence.
//!
//! Run with: `cargo test -p qorch-safety-kernel-client --test revoke_client`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::time::Duration;

use ed25519_dalek::SigningKey;
use qorch_domain::safety::revoke::{
    InstanceTarget, MintRevokeRequest, RestoreRequest, RevokeAckRequest,
};
use qorch_domain::safety::{CircuitConfig, Clock};
use qorch_safety_kernel_client::{
    CircuitBreaker, KernelClientError, KernelDecisionError, PinnedKeyVerifier, SafetyKernelClient,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Clone, Copy)]
struct FixedClock(f64);
impl Clock for FixedClock {
    fn now(&self) -> f64 {
        self.0
    }
}

/// Build a client with a tight breaker so the fail-closed trips are cheap.
fn build_client(base_url: String) -> SafetyKernelClient {
    let pinned = SigningKey::from_bytes(&[9u8; 32]);
    let verifier =
        PinnedKeyVerifier::from_pubkey_bytes(pinned.verifying_key().to_bytes()).expect("pubkey");
    let breaker = CircuitBreaker::new(
        CircuitConfig {
            failure_threshold: 2,
            cooldown_seconds: 30.0,
            call_timeout_seconds: 5.0,
        },
        Box::new(FixedClock(1_700_000_000.0)),
    );
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    SafetyKernelClient::new(
        http,
        base_url,
        "test-api-key".to_string(),
        breaker,
        verifier,
        Box::new(FixedClock(1_700_000_000.0)),
    )
}

fn sample_target() -> InstanceTarget {
    InstanceTarget {
        project: "example-project".to_string(),
        zone: "zone-a".to_string(),
        instance: "ai-worker-vm".to_string(),
    }
}

fn mint_request() -> MintRevokeRequest {
    // MintRevokeRequest is deserialize-only; parse one to construct it.
    serde_json::from_value(serde_json::json!({
        "target": sample_target(),
        "tier": "vm_stop",
        "trigger": "operator_emergency_stop",
        "reason": "e-stop",
    }))
    .expect("mint request")
}

// ---------------------------------------------------------------------------
// mint_revoke — happy path decodes SignedRevokeResponse.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mint_revoke_ok_decodes_signed_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/kernel/v1/revoke/compute"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true,
            "run_id": "revoke_test_1",
            "token": "payload_b64.sig_b64",
            "token_sha256": "a".repeat(64),
            "claims": { "action": "revoke_compute" },
        })))
        .mount(&server)
        .await;

    let client = build_client(server.uri());
    let resp = client.mint_revoke(&mint_request()).await.expect("mint ok");
    assert!(resp.ok);
    assert_eq!(resp.run_id, "revoke_test_1");
    assert_eq!(resp.token, "payload_b64.sig_b64");
}

// ---------------------------------------------------------------------------
// mint_revoke — 503 revoke_not_recorded is FAIL-CLOSED (Unavailable), not Ok.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mint_revoke_503_not_recorded_is_fail_closed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/kernel/v1/revoke/compute"))
        .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
            "error": "unavailable",
            "reason": "revoke_not_recorded",
        })))
        .mount(&server)
        .await;

    let client = build_client(server.uri());
    let result = client.mint_revoke(&mint_request()).await;
    match result {
        Err(KernelClientError::Decision(KernelDecisionError::Unavailable { reason })) => {
            assert!(
                reason.contains("503"),
                "reason should mention 503, got: {reason}"
            );
        }
        other => panic!("mint 503 MUST be Decision::Unavailable, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// mint_revoke — operator role-forbidden (403) rejects, never false-Ok.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mint_revoke_403_forbidden_rejects() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/kernel/v1/revoke/compute"))
        .respond_with(ResponseTemplate::new(403).set_body_string("caller_role_not_operator"))
        .mount(&server)
        .await;

    let client = build_client(server.uri());
    let result = client.mint_revoke(&mint_request()).await;
    assert!(
        matches!(result, Err(KernelClientError::Transport(_))),
        "403 forbidden MUST reject (Transport), got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// mint_revoke — connection refused is FAIL-CLOSED.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mint_revoke_unreachable_is_fail_closed() {
    // Port 1 is reliably connection-refused.
    let client = build_client("http://127.0.0.1:1".to_string());
    let result = client.mint_revoke(&mint_request()).await;
    assert!(
        matches!(
            result,
            Err(KernelClientError::Decision(
                KernelDecisionError::Unavailable { .. }
            ))
        ),
        "unreachable kernel MUST be Decision::Unavailable, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// pending_revoke — 200 with pending tokens decodes.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pending_revoke_200_decodes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kernel/v1/revoke/pending"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true,
            "pending": ["tok_a", "tok_b"],
        })))
        .mount(&server)
        .await;

    let client = build_client(server.uri());
    let resp = client
        .pending_revoke("ai-worker-vm")
        .await
        .expect("pending ok");
    assert_eq!(resp.pending, vec!["tok_a".to_string(), "tok_b".to_string()]);
}

// ---------------------------------------------------------------------------
// pending_revoke — 204 No Content maps to an empty queue, not an error.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pending_revoke_204_is_empty_not_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kernel/v1/revoke/pending"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let client = build_client(server.uri());
    let resp = client.pending_revoke("ai-worker-vm").await.expect("204 ok");
    assert!(resp.ok);
    assert!(resp.pending.is_empty(), "204 must yield an empty queue");
}

// ---------------------------------------------------------------------------
// pending_revoke — 5xx is FAIL-CLOSED.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pending_revoke_500_is_fail_closed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kernel/v1/revoke/pending"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = build_client(server.uri());
    let result = client.pending_revoke("ai-worker-vm").await;
    assert!(
        matches!(
            result,
            Err(KernelClientError::Decision(
                KernelDecisionError::Unavailable { .. }
            ))
        ),
        "pending 500 MUST be Decision::Unavailable, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// ack_revoke — 200 decodes RevokeAckResponse.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ack_revoke_200_decodes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/kernel/v1/revoke/ack"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true,
            "run_id": "revoke_test_1",
            "cleared": true,
        })))
        .mount(&server)
        .await;

    let client = build_client(server.uri());
    let req = RevokeAckRequest {
        run_id: "revoke_test_1".to_string(),
        outcome: "stopped".to_string(),
    };
    let resp = client.ack_revoke(&req).await.expect("ack ok");
    assert!(resp.cleared);
    assert_eq!(resp.run_id, "revoke_test_1");
}

// ---------------------------------------------------------------------------
// restore_revoke — 200 decodes; 503 is FAIL-CLOSED.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restore_revoke_200_decodes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/kernel/v1/revoke/restore"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true,
            "run_id": "restore_test_1",
            "token": "payload_b64.sig_b64",
            "token_sha256": "b".repeat(64),
            "claims": { "action": "revoke_restore" },
        })))
        .mount(&server)
        .await;

    let client = build_client(server.uri());
    let req = RestoreRequest {
        target: sample_target(),
        reason: Some("cleared".to_string()),
    };
    let resp = client.restore_revoke(&req).await.expect("restore ok");
    assert_eq!(resp.run_id, "restore_test_1");
}

#[tokio::test]
async fn restore_revoke_503_is_fail_closed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/kernel/v1/revoke/restore"))
        .respond_with(ResponseTemplate::new(503).set_body_string("revoke_not_recorded"))
        .mount(&server)
        .await;

    let client = build_client(server.uri());
    let req = RestoreRequest {
        target: sample_target(),
        reason: None,
    };
    let result = client.restore_revoke(&req).await;
    assert!(
        matches!(
            result,
            Err(KernelClientError::Decision(
                KernelDecisionError::Unavailable { .. }
            ))
        ),
        "restore 503 MUST be Decision::Unavailable, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Wire-shape check: the deserialize-only request DTOs serialize into the
// exact keys the kernel expects (target/tier/trigger/reason for mint).
// The mock asserts the body via a JSON matcher.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mint_revoke_sends_expected_wire_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/kernel/v1/revoke/compute"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "target": { "project": "example-project", "zone": "zone-a", "instance": "ai-worker-vm" },
            "tier": "vm_stop",
            "trigger": "operator_emergency_stop",
            "reason": "e-stop",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true,
            "run_id": "revoke_test_1",
            "token": "t.s",
            "token_sha256": "a".repeat(64),
            "claims": {},
        })))
        .mount(&server)
        .await;

    let client = build_client(server.uri());
    // If the body did not match the JSON matcher, wiremock returns no
    // mock → the client sees a non-2xx and this unwrap fails.
    client
        .mint_revoke(&mint_request())
        .await
        .expect("body matched + 200");
}
