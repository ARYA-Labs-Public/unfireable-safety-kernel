//!   — Adversarial test suite for the Safety Kernel
//! client SDK.
//!
//! This file is the **Rule 8 (adversarial-fixture)** gate for the
//! `/test` skill: every test below stands a mock kernel up via
//! `wiremock`, feeds the SDK a deliberately bad response shape, and
//! asserts the SDK REJECTS the call rather than treating it as
//! ALLOW. A "passing" test suite without these denials would be
//! malformed.
//!
//! Covers acceptance criteria AC5, AC6, and the AC2 forged-signature
//! defence:
//!
//! - **AC5**: HTTP 500 → `KernelClientError::Decision(Unavailable)`,
//!            never silent approve.
//! - **AC6**: kernel timeout → `KernelClientError::Decision(Unavailable)`
//!            within 5s, breaker trips after `failure_threshold`.
//! - **AC2 (forged-sig)**: kernel returns 200 + a signed-looking token
//!            signed by an attacker key → SDK MUST reject with
//!            `KernelClientError::Verification`.
//! - **Rule-8 belt-and-braces**: HTTP 4xx (non-403) → `Transport`
//!            error, never silently treated as ALLOW.
//!
//! Each assertion is a structural enum-variant match; no string-regex
//! evidence. Re-deriving the rejection in-process is the oracle (Rule 9).
//!
//! Run with: `cargo test -p qorch-safety-kernel-client --test adversarial`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use qorch_domain::safety::{
    sign_kernel_token, AuthorizeClaims, CircuitConfig, Clock, KERNEL_AUTHORIZE_AUD,
};
use qorch_safety_kernel_client::{
    AuthorizeRequest, CircuitBreaker, KernelClientError, KernelDecisionError, PinnedKeyVerifier,
    SafetyKernelClient,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Frozen test clock so token expiry windows are deterministic.
#[derive(Clone, Copy)]
struct FixedClock(f64);
impl Clock for FixedClock {
    fn now(&self) -> f64 {
        self.0
    }
}

/// Build a client whose pinned key matches `pinned_signing`. The
/// breaker config is intentionally tight (`failure_threshold: 2`,
/// short cooldown) so AC6 can observe the trip without burning real
/// wall-clock budget.
fn build_client(base_url: String, pinned_signing: &SigningKey) -> SafetyKernelClient {
    let pubkey = pinned_signing.verifying_key().to_bytes();
    let verifier = PinnedKeyVerifier::from_pubkey_bytes(pubkey).expect("valid pubkey");
    let breaker = CircuitBreaker::new(
        CircuitConfig {
            failure_threshold: 2,
            cooldown_seconds: 30.0,
            call_timeout_seconds: 5.0,
        },
        Box::new(FixedClock(1_700_000_000.0)),
    );
    let http = reqwest::Client::builder()
        // Tight per-request timeout — AC6 budget is 5s wall-clock.
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

fn sample_request() -> AuthorizeRequest {
    AuthorizeRequest {
        action: "sio_run_cycles".to_string(),
        params_fingerprint: "f".repeat(64),
        run_id: "run-adv-001".to_string(),
        subject: "worker".to_string(),
        traceparent: None,
    }
}

// ---------------------------------------------------------------------------
// AC5 — HTTP 500 must REJECT, never silent ALLOW.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ac5_kernel_500_caller_rejects_never_silently_approves() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/kernel/v1/authorize"))
        .respond_with(ResponseTemplate::new(500).set_body_string("kernel meltdown"))
        .mount(&server)
        .await;

    let pinned = SigningKey::from_bytes(&[9u8; 32]);
    let client = build_client(server.uri(), &pinned);

    let result = client.authorize(&sample_request()).await;

    match result {
        Err(KernelClientError::Decision(KernelDecisionError::Unavailable { reason })) => {
            // Structural assertion: the 500 reason is wired through to
            // the caller-visible error so debugging logs can locate it.
            // We are NOT regex-matching for "500" as evidence of pass;
            // the PASS condition is the Decision::Unavailable variant.
            assert!(
                reason.contains("500"),
                "Unavailable reason should mention the 500 status, got: {reason}"
            );
        }
        other => panic!(
            "AC5: kernel 500 MUST reject as Decision::Unavailable, got {other:?} \
             (silent approval would be a critical security failure)"
        ),
    }

    // Audit trail must have recorded one UNAVAILABLE entry — never ALLOW.
    let trail = client.audit_trail();
    assert_eq!(trail.len(), 1, "exactly one audit row");
    assert_eq!(trail[0].outcome, "UNAVAILABLE", "outcome must be UNAVAILABLE");
}

// ---------------------------------------------------------------------------
// AC6 — kernel timeout must fire breaker; total elapsed under 5s budget.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ac6_kernel_timeout_fires_breaker_within_budget() {
    let server = MockServer::start().await;
    // Configure the mock to delay 30 seconds — far longer than our
    // 5s per-request timeout.
    Mock::given(method("POST"))
        .and(path("/kernel/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;

    let pinned = SigningKey::from_bytes(&[11u8; 32]);
    let client = build_client(server.uri(), &pinned);

    // First call: should time out within the per-request budget.
    let start = Instant::now();
    let r1 = client.authorize(&sample_request()).await;
    let elapsed_1 = start.elapsed();
    assert!(
        elapsed_1 < Duration::from_secs(8),
        "first timeout must complete within ~5s + slack, took {elapsed_1:?}"
    );
    assert!(
        matches!(
            r1,
            Err(KernelClientError::Decision(KernelDecisionError::Unavailable {.. }))
        ),
        "first call MUST yield Decision::Unavailable, got {r1:?}"
    );

    // Second call: trips the breaker (threshold=2).
    let r2 = client.authorize(&sample_request()).await;
    assert!(
        matches!(
            r2,
            Err(KernelClientError::Decision(KernelDecisionError::Unavailable {.. }))
        ),
        "second call MUST yield Decision::Unavailable, got {r2:?}"
    );

    // Third call: breaker should now be OPEN and fail-closed
    // immediately (under 100ms — no network involved).
    let start3 = Instant::now();
    let r3 = client.authorize(&sample_request()).await;
    let elapsed_3 = start3.elapsed();
    assert!(
        elapsed_3 < Duration::from_millis(500),
        "breaker-open path MUST be fast (<500ms), took {elapsed_3:?}"
    );
    match r3 {
        Err(KernelClientError::Decision(KernelDecisionError::Unavailable { reason })) => {
            assert!(
                reason.contains("circuit") || reason.contains("breaker") || reason.contains("open"),
                "breaker-open reason should reference breaker state, got: {reason}"
            );
        }
        other => panic!("AC6: breaker MUST be Open after 2 timeouts, got {other:?}"),
    }

    // Total wall-clock budget check: 5s timeout + 5s timeout + sub-ms
    // breaker-open path → must complete in well under 15s.
    let total = start.elapsed();
    assert!(
        total < Duration::from_secs(15),
        "AC6 budget: all 3 calls must finish in <15s, took {total:?}"
    );

    // Audit trail must have three UNAVAILABLE entries.
    let trail = client.audit_trail();
    assert_eq!(trail.len(), 3);
    for (i, e) in trail.iter().enumerate() {
        assert_eq!(e.outcome, "UNAVAILABLE", "audit[{i}] outcome");
    }
}

// ---------------------------------------------------------------------------
// AC2 forged-signature defence — pinned key mismatch MUST reject.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn forged_signature_kernel_response_rejected_with_verification_error() {
    let server = MockServer::start().await;

    // Pinned key the client trusts.
    let pinned = SigningKey::from_bytes(&[13u8; 32]);
    // Attacker key the malicious kernel signs its forged ALLOW with.
    let attacker = SigningKey::from_bytes(&[42u8; 32]);

    // Build a structurally valid AuthorizeClaims and sign with the
    // attacker key.
    let now = 1_700_000_000.0;
    let claims = AuthorizeClaims {
        action: "sio_run_cycles".to_string(),
        aud: KERNEL_AUTHORIZE_AUD.to_string(),
        run_id: "run-adv-001".to_string(),
        subject: "worker".to_string(),
        params_fingerprint: "f".repeat(64),
        issued_at: now,
        expires_at: now + 300.0,
        nonce: "test-nonce-22-chars-".to_string(),
    };
    let forged_token = sign_kernel_token(&claims, &attacker);

    // Mock kernel returns 200 with a signed-but-attacker-keyed token.
    let response_body = serde_json::json!({
        "token": forged_token,
        "token_sha256": "ignored",
        "ok": true,
        "claims": {}
    });
    Mock::given(method("POST"))
        .and(path("/kernel/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
        .mount(&server)
        .await;

    let client = build_client(server.uri(), &pinned);
    let result = client.authorize(&sample_request()).await;

    // PASS condition: Verification error, NEVER an ALLOW.
    match result {
        Err(KernelClientError::Verification(_)) => {
            // good — pinned-key check refused the substituted kernel.
        }
        Ok(_) => panic!(
            "CRITICAL: forged-signature response MUST be refused. \
             Accepting an attacker-signed ALLOW defeats the pinned-key \
             defence ( AC9 /  AC2 R)."
        ),
        other => panic!(
            "forged-sig response MUST yield Verification error, got {other:?}"
        ),
    }

    // Audit trail entry must be VERIFICATION_FAILED — not ALLOW.
    let trail = client.audit_trail();
    assert_eq!(trail.len(), 1);
    assert_eq!(
        trail[0].outcome, "VERIFICATION_FAILED",
        "forged-sig audit row must be VERIFICATION_FAILED, not ALLOW"
    );
}

// ---------------------------------------------------------------------------
// Rule-8 belt-and-braces — 4xx non-403 is Transport, never silent ALLOW.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kernel_400_bad_request_yields_transport_error_never_allow() {
    // A 400 from the kernel is contract drift (not a DENY, not an
    // ALLOW). The SDK surfaces it as `Transport` so the caller knows
    // the operation did NOT succeed.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/kernel/v1/authorize"))
        .respond_with(ResponseTemplate::new(400).set_body_string("missing field"))
        .mount(&server)
        .await;

    let pinned = SigningKey::from_bytes(&[17u8; 32]);
    let client = build_client(server.uri(), &pinned);
    let result = client.authorize(&sample_request()).await;

    match result {
        Err(KernelClientError::Transport(detail)) => {
            assert!(
                detail.contains("400"),
                "Transport error should reference the 400 status, got: {detail}"
            );
        }
        Ok(_) => panic!("400 MUST NOT be treated as ALLOW"),
        other => panic!("400 should yield Transport, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// AC5 sibling — kernel 403 is an AUTHORITATIVE DENY (distinct from Unavailable)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kernel_403_forbidden_returns_authoritative_deny_not_unavailable() {
    // 403 from the kernel is the documented DENY shape. This is the
    // CONTROL test for the adversarial suite: the SDK can distinguish
    // "kernel refused" from "kernel unreachable" — both are still
    // FAIL-CLOSED for the caller, but only Unavailable opens the breaker.
    use qorch_domain::safety::KernelDecision;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/kernel/v1/authorize"))
        .respond_with(ResponseTemplate::new(403).set_body_string("denied: policy refused"))
        .mount(&server)
        .await;

    let pinned = SigningKey::from_bytes(&[19u8; 32]);
    let client = build_client(server.uri(), &pinned);
    let result = client.authorize(&sample_request()).await;

    match result {
        Ok(KernelDecision::Deny { reason }) => {
            assert!(
                reason.contains("denied") || reason.contains("policy"),
                "deny reason should be propagated, got: {reason}"
            );
        }
        Ok(KernelDecision::Allow {.. }) => {
            panic!("CRITICAL: 403 MUST NOT yield Allow")
        }
        other => panic!("403 should yield Deny, got {other:?}"),
    }

    // Audit trail entry must be DENY.
    let trail = client.audit_trail();
    assert_eq!(trail.len(), 1);
    assert_eq!(trail[0].outcome, "DENY");
}

// ---------------------------------------------------------------------------
// AC5 sibling — transport-level connection refused trips Unavailable.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unreachable_kernel_yields_unavailable_not_silent_approve() {
    // Wire the SDK to a port that is intentionally closed. The dial
    // should refuse, the SDK should surface Unavailable, and the
    // breaker should trip on the second consecutive failure.
    let pinned = SigningKey::from_bytes(&[23u8; 32]);
    // 127.0.0.1:1 is reliably closed on every Linux host (privileged
    // port that no service can bind to without root).
    let client = build_client("http://127.0.0.1:1".to_string(), &pinned);

    let r = client.authorize(&sample_request()).await;
    assert!(
        matches!(
            r,
            Err(KernelClientError::Decision(KernelDecisionError::Unavailable {.. }))
        ),
        "unreachable kernel MUST yield Decision::Unavailable, got {r:?}"
    );
}
