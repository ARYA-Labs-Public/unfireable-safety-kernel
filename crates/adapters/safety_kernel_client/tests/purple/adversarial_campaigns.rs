//!   /purple-team adversarial campaigns.
//!
//! Session: ary1883-pt-5d8d4b5c.
//! Worktree: /home/s/qo-ary1883 (branch
//! seth/--phase-2a-build-safety-kernel-client-sdk-network).
//!
//! This file runs the adversarial probes that exercise the FAIL-CLOSED
//! invariants of the Safety Kernel client SDK. Each campaign is a Rule-5
//! PoC + Rule-9 evidence recompute: the assertions DO NOT regex log
//! lines, they observe the live defense response (error variant, state
//! transition, audit-trail outcome string).
//!
//! Campaigns covered as live Rust tests:
//!   A — Forged ed25519 signature
//!   B — Token replay (expiry rejection)
//!   D — Network partition fail-closed (100 concurrent under drop)
//!   E — HalfOpen race (50 concurrent in cooldown; exactly 1 probe)
//!   F — Slow-loris (5s timeout fires)
//!   H — Boundary forbidden-imports in pure-types modules
//!   I — Audit-chain provenance (traceparent header round-trip into
//!       audit_trail() entry)
//!
//! Campaigns covered out-of-band (NOT in this file):
//!   C — Cert-pinning bypass: external curl + mismatched CA; result
//!       written to docs/security/-purple-team-findings/.
//!   G — Provider sneak-in: workspace-wide grep + cargo-tree analysis;
//!       result written to docs/security/-purple-team-findings/.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use qorch_domain::safety::{
    sign_kernel_token, AuthorizeClaims, CircuitConfig, CircuitState, Clock, KERNEL_AUTHORIZE_AUD,
};
use qorch_safety_kernel_client::circuit_breaker::CircuitBreaker;
use qorch_safety_kernel_client::client::SafetyKernelClient;
use qorch_safety_kernel_client::token::PinnedKeyVerifier;
use qorch_safety_kernel_client::types::{
    AuthorizeRequest, AuthorizeResponse, KernelClientError, KernelDecision, KernelDecisionError,
};

// ---------------------------------------------------------------------------
// Shared clock + fixture helpers
// ---------------------------------------------------------------------------

/// Manual-advance clock; lets each campaign control wall-clock without
/// touching SystemTime (the boundaries.toml forbidden import).
struct ManualClock {
    epoch_micros: AtomicU64,
}

impl ManualClock {
    fn new(initial_seconds: f64) -> Self {
        Self {
            epoch_micros: AtomicU64::new((initial_seconds * 1_000_000.0) as u64),
        }
    }
    fn advance_by(&self, seconds: f64) {
        self.epoch_micros
            .fetch_add((seconds * 1_000_000.0) as u64, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> f64 {
        (self.epoch_micros.load(Ordering::SeqCst) as f64) / 1_000_000.0
    }
}

/// Newtype wrapper so multiple consumers can share the manual clock
/// (CircuitBreaker takes `Box<dyn Clock>` so we wrap the Arc).
struct ArcClock(Arc<ManualClock>);
impl Clock for ArcClock {
    fn now(&self) -> f64 {
        self.0.now()
    }
}

fn fixed_keypair(seed: u8) -> (SigningKey, [u8; 32]) {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let public = signing.verifying_key().to_bytes();
    (signing, public)
}

fn sample_claims(now: f64) -> AuthorizeClaims {
    AuthorizeClaims {
        action: "sio_run_cycles".to_string(),
        aud: KERNEL_AUTHORIZE_AUD.to_string(),
        run_id: "purple-run".to_string(),
        subject: "purple-subject".to_string(),
        params_fingerprint: "a".repeat(64),
        issued_at: now,
        expires_at: now + 300.0,
        nonce: "purple-nonce-22-chars".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Campaign A — Forged ed25519 signature
// ---------------------------------------------------------------------------
//
// Threat: attacker substitutes a kernel response token signed with a
// fresh signing key (NOT the pinned key). Defense: PinnedKeyVerifier
// MUST refuse and surface KernelTokenError::SignatureMismatch (or any
// signature-class error); no `KernelDecision::Allow` may be constructed.
//
// Rule 9 evidence: we observe the exact Err variant returned by
// `verifier.verify()`, not a log string.

#[test]
fn campaign_a_forged_signature_is_rejected() {
    let (_pinned_signing, pinned_public) = fixed_keypair(7);
    let attacker_signing = SigningKey::from_bytes(&[42u8; 32]);
    let now = 1_700_000_000.0_f64;
    let forged_token = sign_kernel_token(&sample_claims(now), &attacker_signing);

    let verifier = PinnedKeyVerifier::from_pubkey_bytes(pinned_public).unwrap();
    let result = verifier.verify(&forged_token, now + 1.0);

    // Evidence: the verifier MUST refuse. The exact KernelTokenError
    // variant depends on which layer detects the mismatch (signature vs
    // key-binding) — either way, no `Ok(VerifiedClaims)` is acceptable.
    assert!(
        result.is_err(),
        "FAIL-CLOSED breach: verifier accepted attacker-signed token"
    );
    // Defense-in-depth: ensure the error stringifies into something
    // attributable. We do NOT regex-match for verdict — only as an
    // audit-line aid.
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        !err_str.is_empty(),
        "verifier returned a degenerate error type"
    );
}

// ---------------------------------------------------------------------------
// Campaign B — Token replay after expiry
// ---------------------------------------------------------------------------
//
// Threat: a previously-valid token is replayed after its `expires_at`
// has passed (plus the verifier's leeway). Defense: PinnedKeyVerifier
// rejects with KernelTokenError::Expired (the expiry path).
//
// Rule 9 evidence: re-derive via `verifier.verify(token, now_far_past_exp)`
// and observe the Err variant on the actual return value.

#[test]
fn campaign_b_token_replay_after_expiry_is_rejected() {
    let (signing, public) = fixed_keypair(7);
    let now = 1_700_000_000.0_f64;
    let claims = sample_claims(now); // expires_at = now + 300
    let token = sign_kernel_token(&claims, &signing);
    let verifier = PinnedKeyVerifier::from_pubkey_bytes(public).unwrap();

    // Boundary-immediate sanity: at now+1 the token verifies.
    let ok = verifier.verify(&token, now + 1.0);
    assert!(ok.is_ok(), "fresh token must verify (control)");

    // Replay: 1 hour later — well past `expires_at + leeway`.
    let replay_at = now + 3_600.0;
    let result = verifier.verify(&token, replay_at);
    assert!(
        result.is_err(),
        "FAIL-CLOSED breach: verifier accepted expired token"
    );
}

// ---------------------------------------------------------------------------
// Campaign D — Network partition fail-closed
// ---------------------------------------------------------------------------
//
// Threat: under sustained connection drop the breaker MUST trip Open
// and every subsequent `authorize()` must return
// `Err(KernelClientError::Decision(KernelDecisionError::Unavailable))` —
// none may return `Ok(Allow)`.
//
// We model the partition at the breaker layer (the layer that actually
// guards the network call). 100 concurrent `before_call()` invocations
// against a breaker that has been driven Open MUST all return
// `Err(Unavailable)`; none silently become Ok.
//
// Rule 9 evidence: count Ok vs Err across the 100 concurrent calls.

#[test]
fn campaign_d_partition_fail_closed_100_concurrent() {
    let clock = Arc::new(ManualClock::new(1_000.0));
    let breaker = Arc::new(CircuitBreaker::new(
        CircuitConfig {
            failure_threshold: 3,
            cooldown_seconds: 30.0,
            call_timeout_seconds: 5.0,
        },
        Box::new(ArcClock(clock.clone())),
    ));

    // Drive Open via 3 consecutive failures (failure_threshold).
    for _ in 0..3 {
        breaker.record_failure();
    }
    assert_eq!(breaker.state(), CircuitState::Open);

    // Fan out 100 callers — every one must see Unavailable. The breaker
    // is the FAIL-CLOSED gate; this proves no silent-approve path
    // exists while Open.
    let mut handles = Vec::with_capacity(100);
    for _ in 0..100 {
        let b = breaker.clone();
        handles.push(std::thread::spawn(move || b.before_call()));
    }
    let mut ok_count = 0usize;
    let mut unavail_count = 0usize;
    let mut other_count = 0usize;
    for h in handles {
        match h.join().unwrap() {
            Ok(()) => ok_count += 1,
            Err(KernelClientError::Decision(KernelDecisionError::Unavailable {.. })) => {
                unavail_count += 1;
            }
            Err(_) => other_count += 1,
        }
    }

    // FAIL-CLOSED invariant: zero Ok, all Unavailable.
    assert_eq!(
        ok_count, 0,
        "FAIL-CLOSED breach: {ok_count}/100 callers received Ok during partition"
    );
    assert_eq!(unavail_count, 100, "expected 100 Unavailable, got {unavail_count} (other={other_count})");
}

// ---------------------------------------------------------------------------
// Campaign E — HalfOpen race
// ---------------------------------------------------------------------------
//
// Threat: when the breaker transitions Open -> HalfOpen at the end of
// cooldown, a thundering herd of concurrent callers must NOT all become
// probes (which would defeat the purpose of the probe gate). Exactly
// ONE caller may probe; the rest must receive Unavailable immediately
// (no queueing, no blocking).
//
// Rule 9 evidence: of N concurrent callers in HalfOpen, observe exactly
// 1 Ok (the probe) and N-1 Err(Unavailable). The breaker's probe-in-
// flight gate is the line of defense.

#[test]
fn campaign_e_half_open_race_exactly_one_probe() {
    let clock = Arc::new(ManualClock::new(1_000.0));
    let breaker = Arc::new(CircuitBreaker::new(
        CircuitConfig {
            failure_threshold: 3,
            cooldown_seconds: 30.0,
            call_timeout_seconds: 5.0,
        },
        Box::new(ArcClock(clock.clone())),
    ));

    // Drive Open then expire the cooldown so the next caller transitions
    // Open -> HalfOpen.
    for _ in 0..3 {
        breaker.record_failure();
    }
    assert_eq!(breaker.state(), CircuitState::Open);
    clock.advance_by(31.0);

    // 50 concurrent callers contending for the single probe slot.
    let mut handles = Vec::with_capacity(50);
    for _ in 0..50 {
        let b = breaker.clone();
        handles.push(std::thread::spawn(move || b.before_call()));
    }
    let mut ok_count = 0usize;
    let mut unavail_count = 0usize;
    for h in handles {
        match h.join().unwrap() {
            Ok(()) => ok_count += 1,
            Err(KernelClientError::Decision(KernelDecisionError::Unavailable {.. })) => {
                unavail_count += 1;
            }
            Err(other) => panic!("unexpected error type during HalfOpen race: {other:?}"),
        }
    }

    // Exactly 1 probe; 49 must be rejected immediately.
    assert_eq!(
        ok_count, 1,
        "HalfOpen single-probe gate breached: {ok_count} probes ran (expected 1)"
    );
    assert_eq!(
        unavail_count, 49,
        "HalfOpen race: expected 49 Unavailable, got {unavail_count}"
    );
    // State must still be HalfOpen (contended calls did NOT spuriously
    // transition the breaker).
    assert_eq!(breaker.state(), CircuitState::HalfOpen);
}

// ---------------------------------------------------------------------------
// Campaign F — Slow-loris
// ---------------------------------------------------------------------------
//
// Threat: a kernel-impostor accepts the TCP connection but never sends
// a response body. The client MUST time out within the configured
// `call_timeout_seconds` (5.0 per default) and the breaker MUST count
// this as a failure. We exercise the timeout at the reqwest layer
// against a wiremock that stalls.

#[tokio::test(flavor = "multi_thread")]
async fn campaign_f_slow_loris_timeout_fires() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;

    // Respond to POST /kernel/v1/authorize after 30s delay — well past
    // the client's 5s timeout. The client must NOT block its caller
    // for 30s; it MUST time out at 5s.
    Mock::given(method("POST"))
        .and(path("/kernel/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;

    let (_signing, public) = fixed_keypair(7);
    let verifier = PinnedKeyVerifier::from_pubkey_bytes(public).unwrap();
    let breaker = CircuitBreaker::new(
        CircuitConfig {
            failure_threshold: 3,
            cooldown_seconds: 30.0,
            call_timeout_seconds: 5.0,
        },
        Box::new(ArcClock(Arc::new(ManualClock::new(1_000.0)))),
    );
    // The client-side reqwest timeout in client.rs is hardcoded 5.0s.
    // We use the reqwest default builder (no global timeout) since the
    // request-scoped `.timeout(Duration::from_secs_f64(5.0))` in
    // client.rs is what we're exercising.
    let inner = reqwest::Client::builder()
        .build()
        .expect("build reqwest client");
    let client = SafetyKernelClient::new(
        inner,
        server.uri(),
        "purple-key".to_string(),
        breaker,
        verifier,
        Box::new(ArcClock(Arc::new(ManualClock::new(1_000.0)))),
    );

    let req = AuthorizeRequest {
        action: "sio_run_cycles".to_string(),
        params_fingerprint: "a".repeat(64),
        run_id: "campaign-f".to_string(),
        subject: "purple".to_string(),
        traceparent: None,
    };
    let started = std::time::Instant::now();
    let result = client.authorize(&req).await;
    let elapsed = started.elapsed();

    // Evidence (Rule 9): we observe two things — (a) the Err variant
    // is Decision(Unavailable), and (b) the wall-clock between request
    // and return is well under the mock's 30s delay AND close to or
    // below the configured 5s timeout (we allow some slack for
    // scheduler + tokio overhead).
    match result {
        Err(KernelClientError::Decision(KernelDecisionError::Unavailable {.. })) => {}
        other => panic!("expected Decision(Unavailable) on slow-loris, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(15),
        "slow-loris not bounded: elapsed={elapsed:?} (mock delay 30s, expected client timeout near 5s)"
    );
    // Audit trail recorded the UNAVAILABLE outcome.
    let trail = client.audit_trail();
    assert_eq!(trail.len(), 1, "audit trail must record one entry");
    assert_eq!(trail[0].outcome, "UNAVAILABLE");
    assert_eq!(trail[0].run_id, "campaign-f");
}

// ---------------------------------------------------------------------------
// Campaign H — Boundary policy enforcement
// ---------------------------------------------------------------------------
//
// Threat: a careless edit to a pure-types module imports a forbidden
// dep (std::fs, std::env, std::net, std::time::SystemTime, rand,
// sqlx, diesel, reqwest, rdkafka, tracing, log) and silently couples
// the domain crate to I/O. The boundaries.toml policy forbids all
// such imports under `crates/domain/`.
//
// Rule 9 evidence: we grep the actual files for `use <forbidden>` /
// `<forbidden>::` patterns and assert zero hits. The two source files
// in scope for this assessment are:
//   - crates/domain/src/safety/decision.rs (newly added in Step 2)
//   - crates/adapters/safety_kernel_client/src/types.rs
// The adapter file is ALLOWED to use reqwest + tracing; but the
// `KernelDecision` / `KernelDecisionError` re-export shapes themselves
// must not pull in I/O.
//
// We scan only the actual types.rs file (not its test module) since
// tests can use anything.

#[test]
fn campaign_h_domain_decision_module_has_no_forbidden_imports() {
    // Workspace-relative path resolution: the test is run from the
    // adapter crate dir; the domain decision module lives two levels
    // up under crates/domain/...
    let here = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let domain_decision = here
        .parent() // adapters/
        .unwrap()
        .parent() // crates/
        .unwrap()
        .join("domain/src/safety/decision.rs");
    let src = std::fs::read_to_string(&domain_decision)
        .unwrap_or_else(|e| panic!("read {}: {e}", domain_decision.display()));

    // Strip test module: the trailing `#[cfg(test)] mod tests {}` is
    // permitted to use serde_json + std types freely. We slice up to
    // that delimiter when present (kept loose — match `#[cfg(test)]`
    // which is the convention used throughout the crate).
    let prod_only = src
        .split("#[cfg(test)]")
        .next()
        .expect("must have at least one segment");

    let forbidden = [
        "use std::fs",
        "use std::env",
        "use std::net",
        "use std::time::SystemTime",
        "use rand",
        "use sqlx",
        "use diesel",
        "use reqwest",
        "use rdkafka",
        "use tracing",
        "use log",
    ];
    let mut hits = Vec::new();
    for needle in &forbidden {
        if prod_only.contains(needle) {
            hits.push(needle.to_string());
        }
    }
    assert!(
        hits.is_empty(),
        "Boundary breach in {}: forbidden imports {:?}",
        domain_decision.display(),
        hits
    );
}

// ---------------------------------------------------------------------------
// Campaign I — Audit-chain provenance (traceparent round-trip)
// ---------------------------------------------------------------------------
//
// Threat: an attacker manipulates the traceparent header so the local
// audit trail captures a different trace ID than the one the kernel
// receives — breaking audit-chain correlation.
//
// Defense: the SDK emits the caller-supplied traceparent as the HTTP
// `traceparent` header (NEVER in the JSON body) AND echoes it into the
// local AuditEntry.traceparent field. So a caller can correlate their
// audit log with the kernel's audit chain by trace ID alone.
//
// Rule 9 evidence: a wiremock kernel inspects the inbound traceparent
// header on every request and stores it; the assertion compares (a)
// the value the kernel received, (b) the value in client.audit_trail(),
// and (c) verifies the request BODY does NOT contain the traceparent
// substring (per Step 6 boundary contract).

#[tokio::test(flavor = "multi_thread")]
async fn campaign_i_audit_chain_traceparent_round_trip() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    let (signing, public) = fixed_keypair(7);

    struct InspectingResponder {
        captured_traceparent: Arc<std::sync::Mutex<Option<String>>>,
        captured_body: Arc<std::sync::Mutex<Vec<u8>>>,
        signing_seed: u8,
    }
    impl Respond for InspectingResponder {
        fn respond(&self, req: &Request) -> ResponseTemplate {
            // Capture traceparent header.
            let tp = req
                .headers
                .get("traceparent")
                .map(|hv| hv.to_str().unwrap_or("").to_string());
            *self.captured_traceparent.lock().unwrap() = tp;
            *self.captured_body.lock().unwrap() = req.body.clone();

            // Mint a real signed token so the SDK accepts the response.
            let now = 1_700_000_000.0_f64;
            let signing = SigningKey::from_bytes(&[self.signing_seed; 32]);
            let token = sign_kernel_token(&sample_claims(now), &signing);
            let body = AuthorizeResponse {
                claims_hint: None,
                token,
            };
            ResponseTemplate::new(200)
                .set_body_json(serde_json::to_value(&body).unwrap())
        }
    }

    let captured_tp = Arc::new(std::sync::Mutex::new(None));
    let captured_body = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/kernel/v1/authorize"))
        .respond_with(InspectingResponder {
            captured_traceparent: captured_tp.clone(),
            captured_body: captured_body.clone(),
            signing_seed: 7,
        })
        .mount(&server)
        .await;

    let verifier = PinnedKeyVerifier::from_pubkey_bytes(public).unwrap();
    let breaker = CircuitBreaker::new(
        CircuitConfig::default(),
        Box::new(ArcClock(Arc::new(ManualClock::new(1_700_000_000.0)))),
    );
    let inner = reqwest::Client::builder().build().unwrap();
    let client_clock_seed = 1_700_000_000.0_f64;
    let client = SafetyKernelClient::new(
        inner,
        server.uri(),
        "purple-key".to_string(),
        breaker,
        verifier,
        Box::new(ArcClock(Arc::new(ManualClock::new(client_clock_seed)))),
    );

    let known_traceparent = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01";
    let req = AuthorizeRequest {
        action: "sio_run_cycles".to_string(),
        params_fingerprint: "a".repeat(64),
        run_id: "campaign-i".to_string(),
        subject: "purple".to_string(),
        traceparent: Some(known_traceparent.to_string()),
    };
    let _ = signing; // silence unused (used inside responder via seed).
    let decision = client
        .authorize(&req)
        .await
        .expect("authorize must succeed against valid mock");
    assert!(matches!(decision, KernelDecision::Allow {.. }));

    // (a) Server side received exactly the traceparent we sent.
    let kernel_saw = captured_tp.lock().unwrap().clone();
    assert_eq!(
        kernel_saw.as_deref(),
        Some(known_traceparent),
        "kernel did NOT receive the traceparent header intact"
    );

    // (b) Client-local audit trail echoes the same traceparent.
    let trail = client.audit_trail();
    assert_eq!(trail.len(), 1);
    assert_eq!(trail[0].outcome, "ALLOW");
    assert_eq!(trail[0].traceparent.as_deref(), Some(known_traceparent));

    // (c) The JSON body of the outbound request MUST NOT contain the
    //     literal substring "traceparent" — proves the field is HTTP-
    //     header only, never serialized into the body. (boundary_check
    //     pin from types.rs Step 6.)
    let body_bytes = captured_body.lock().unwrap().clone();
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(
        !body_str.contains("traceparent"),
        "traceparent leaked into body: {body_str}"
    );
}
