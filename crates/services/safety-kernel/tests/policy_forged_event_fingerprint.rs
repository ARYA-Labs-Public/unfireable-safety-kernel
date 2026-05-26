//! Adversarial fixture — forged `event_fingerprint` MUST be rejected
//! ( slice 2, watchdog class `forged_event_fingerprint_rejected`).
//!
//! Threat model ( reflection-style attack via fingerprint
//! mutation): a worker process with a valid x-api-key sends an
//! authorize body where `event_fingerprint` does NOT equal the
//! canonical SHA-256 of
//! `(event_kind, module_path, caller_subject, caller_run_id)`. The
//! attacker's goal is to either:
//!
//!   1. Cause the audit chain to record an event_fingerprint that
//!      cannot be re-derived (forensic dodge); or
//!   2. Bypass the registry lookup by submitting a fingerprint that
//!      matches a previously-allowed module_path while the body fields
//!      target a different module.
//!
//! The slice-2 handler MUST defeat this by recomputing the fingerprint
//! server-side and rejecting on mismatch BEFORE any IPC, registry
//! lookup, signing, or audit-chain write. Rejection MUST be 400 with
//! `error=invalid_request` + `reason=event_fingerprint_invalid`.
//!
//! All assertions in this file demand REJECTION (Rule 8 evidence over
//! labels). A passing test means the gate held; a failing test means
//! the gate dropped and the slice-1 watchdog deferral was premature.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown, clippy::needless_pass_by_value)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    middleware::from_fn,
    Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use qorch_adapters::clock::SystemClock;
use qorch_adapters::nonce::OsRngNonceSource;
use qorch_adapters::policy_engine_client::PolicyEngineClient;
use qorch_domain::safety::{params_fingerprint, Clock, NonceSource};
use qorch_safety_kernel::auth::CallerRole;
use qorch_safety_kernel::routes;
use qorch_safety_kernel::settings::Settings;
use qorch_safety_kernel::state::AppState;

// ============================================================================
// Test fixture — `Router` with the policy sub-router under an injected
// `CallerRole(worker)`. The IPC socket is intentionally non-existent;
// the slice-2 handler's fingerprint check fires BEFORE any IPC, so the
// failure mode under attack here never reaches the sidecar — that's the
// whole point of the defense.
// ============================================================================

fn test_settings() -> Settings {
    let zero_seed_b64 = URL_SAFE_NO_PAD.encode([0u8; 32]);
    Settings {
        env: "dev".to_string(),
        db_backend: "sqlite".to_string(),
        db_path: ".qorch/test_audit.sqlite3".to_string(),
        pg_dsn: None,
        auth_mode: "api_key".to_string(),
        api_key_worker: Some("test-worker-key".to_string()),
        api_key_api: Some("test-api-key".to_string()),
        api_key_operator: Some("test-operator-key".to_string()),
        signing_key_b64: zero_seed_b64.clone(),
        audit_pepper_b64: zero_seed_b64,
        default_token_ttl_s: 60,
        max_token_ttl_s: 300,
        approval_token_ttl_s: 365 * 24 * 60 * 60,
        build_version: "test-forged-fp".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        policy_sock_path: PathBuf::from("/tmp/qorch-test-nonexistent-forged-fp.sock"),
        //  Addendum 2a §2 — TLS fields. In-process tests
        // never bind, so tls_enable=false matches dev-default Settings.
        tls_cert_path: None,
        tls_key_path: None,
        tls_client_ca_path: None,
        tls_sni: "safety-kernel-rust.internal".to_string(),
        tls_enable: false,
        transparency_enabled: false,
        transparency_log_url: None,
        transparency_log_api_key: None,
        transparency_log_timeout_seconds: 2.0,
        transparency_log_client_cert_path: None,
        transparency_log_client_key_path: None,
    }
}

fn test_state() -> AppState {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let pk_raw = verifying_key.to_bytes();
    let pk_b64 = URL_SAFE_NO_PAD.encode(pk_raw);
    let mut h = Sha256::new();
    h.update(pk_raw);
    let pk_fpr = hex::encode(h.finalize());

    let clock_arc: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let started_at = clock_arc.now();
    let nonce_arc: Arc<dyn NonceSource> = Arc::new(OsRngNonceSource::new());

    AppState {
        settings: Arc::new(test_settings()),
        signing_key: Arc::new(signing_key),
        public_key_b64: pk_b64,
        public_key_fingerprint: pk_fpr,
        audit_pepper: Arc::new(vec![0u8; 32]),
        started_at,
        clock: clock_arc,
        nonce: nonce_arc,
        policy_client: Arc::new(PolicyEngineClient::new(PathBuf::from(
            "/tmp/qorch-test-nonexistent-forged-fp.sock",
        ))),
        transparency_client: None,
    }
}

fn policy_router() -> Router {
    let state = test_state();
    Router::new()
        .merge(routes::policy::router())
        .layer(from_fn(
            |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
                req.extensions_mut()
                    .insert(CallerRole("worker".to_string()));
                next.run(req).await
            },
        ))
        .with_state(state)
}

async fn oneshot(app: Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app.oneshot(req).await.expect("router oneshot");
    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec();
    (status, body)
}

/// Build the canonical event fingerprint for a given quadruple — mirrors
/// the kernel's `recompute_event_fingerprint` in
/// `routes/policy/authorize.rs`. We use this to seed valid bodies and
/// then perturb them to forge the fingerprint mismatch.
fn canonical_fp(
    event_kind: &str,
    module_path: &str,
    caller_subject: &str,
    caller_run_id: &str,
) -> String {
    let canonical = json!({
        "event_kind": event_kind,
        "module_path": module_path,
        "caller_subject": caller_subject,
        "caller_run_id": caller_run_id,
    });
    params_fingerprint(&canonical)
}

/// Build a `POST /policy/module/authorize` request with the supplied
/// fingerprint, no api-key (the test fixture injects CallerRole(worker)).
fn authorize_request(body: Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/policy/module/authorize")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

// ============================================================================
// HAPPY PATH (control) — a body with the CORRECT fingerprint crosses the
// step-3 gate. The handler then attempts IPC to the (non-existent)
// sidecar and 503s. The point of this control: prove the gate is at
// step 3, not earlier, so the adversarial assertions below mean what
// they claim.
// ============================================================================

#[tokio::test]
async fn correct_fingerprint_passes_step_3_and_proceeds_to_ipc() {
    let body = json!({
        "event_kind": "import",
        "module_path": "pkg.mod",
        "caller_subject": "worker",
        "caller_run_id": "run-1",
        "event_fingerprint": canonical_fp("import", "pkg.mod", "worker", "run-1"),
    });
    let (status, body_bytes) = oneshot(policy_router(), authorize_request(body)).await;
    // Step 3 passed — handler attempted IPC against the non-existent
    // sidecar, mapping IpcConnect to 503 kernel_unavailable.
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "correct fingerprint should reach the IPC step; got {status}; body={}",
        String::from_utf8_lossy(&body_bytes),
    );
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        parsed.get("error").and_then(Value::as_str),
        Some("kernel_unavailable"),
        "503 body should carry error=kernel_unavailable; body={parsed}",
    );
}

// ============================================================================
// ADVERSARIAL — bit-flip in the fingerprint (one byte differs)
// ============================================================================

#[tokio::test]
async fn forged_fingerprint_bit_flip_is_rejected() {
    let canonical = canonical_fp("import", "pkg.mod", "worker", "run-1");
    // Flip a single byte (first hex digit). Any single bit flip makes
    // the fingerprint a different SHA-256, so the server-side recompute
    // will not match.
    let mut forged = canonical.clone();
    // Mutation: replace first char with a different hex digit. The
    // canonical fp starts with some byte; we flip to ensure mismatch.
    let first = forged.chars().next().unwrap();
    let new_first = if first == 'a' { 'b' } else { 'a' };
    forged.replace_range(0..1, &new_first.to_string());
    assert_ne!(forged, canonical);

    let body = json!({
        "event_kind": "import",
        "module_path": "pkg.mod",
        "caller_subject": "worker",
        "caller_run_id": "run-1",
        "event_fingerprint": forged,
    });
    let (status, body_bytes) = oneshot(policy_router(), authorize_request(body)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "forged fingerprint MUST be rejected with 400; got {status}; body={}",
        String::from_utf8_lossy(&body_bytes),
    );
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        parsed.get("ok"),
        Some(&Value::Bool(false)),
        "rejection body MUST carry ok=false; body={parsed}",
    );
    assert_eq!(
        parsed.get("error").and_then(Value::as_str),
        Some("invalid_request"),
        "rejection error MUST be invalid_request; body={parsed}",
    );
    assert_eq!(
        parsed.get("reason").and_then(Value::as_str),
        Some("event_fingerprint_invalid"),
        "rejection reason MUST be event_fingerprint_invalid; body={parsed}",
    );
}

// ============================================================================
// ADVERSARIAL — confused-deputy attack: fingerprint of a DIFFERENT
// module_path while the body fields target this one. Without server-side
// recompute, the attacker could submit a fingerprint they pre-computed
// for `pkg.allowed.mod` while the body claims `pkg.secret.mod` and the
// registry would mistakenly bind the allowed policy to the secret path.
// ============================================================================

#[tokio::test]
async fn confused_deputy_fingerprint_from_different_module_is_rejected() {
    // Pre-compute the fp for an "allowed" tuple.
    let confused_fp = canonical_fp("import", "pkg.allowed.mod", "worker", "run-1");

    // Now submit a body targeting a different module_path but carrying
    // the allowed-mod fingerprint. Without server-side recompute the
    // registry lookup would be against `pkg.secret.mod` while the audit
    // record would say `pkg.allowed.mod` — the worst kind of split.
    let body = json!({
        "event_kind": "import",
        "module_path": "pkg.secret.mod",
        "caller_subject": "worker",
        "caller_run_id": "run-1",
        "event_fingerprint": confused_fp,
    });
    let (status, body_bytes) = oneshot(policy_router(), authorize_request(body)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "confused-deputy fingerprint MUST be rejected; got {status}; body={}",
        String::from_utf8_lossy(&body_bytes),
    );
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        parsed.get("reason").and_then(Value::as_str),
        Some("event_fingerprint_invalid"),
    );
}

// ============================================================================
// ADVERSARIAL — fingerprint format is correct shape (64-hex) but doesn't
// match ANY canonical input. This tests that the format-level gate
// (step 2) is NOT the only defense — step 3's recompute also has to
// fire for the all-zeros classic.
// ============================================================================

#[tokio::test]
async fn well_formed_but_wrong_fingerprint_is_rejected() {
    // All-zero 64-hex is well-formed per step 2 but matches no
    // (event_kind, module_path, caller_subject, caller_run_id) tuple.
    let body = json!({
        "event_kind": "import",
        "module_path": "pkg.mod",
        "caller_subject": "worker",
        "caller_run_id": "run-1",
        "event_fingerprint": "0".repeat(64),
    });
    let (status, body_bytes) = oneshot(policy_router(), authorize_request(body)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "all-zero fingerprint MUST be rejected at step 3 (recompute); got {status}",
    );
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        parsed.get("reason").and_then(Value::as_str),
        Some("event_fingerprint_invalid"),
        "the rejection reason for all-zero MUST be the step-3 recompute mismatch, \
         NOT the step-2 format check — a step-2 trigger would emit \
         event_fingerprint_format. body={parsed}",
    );
}

// ============================================================================
// ADVERSARIAL — malformed fingerprint (uppercase / wrong length / non-hex)
// is rejected at step 2. We test this so the slice-2 watchdog assertion
// isn't conflating the two reasons.
// ============================================================================

#[tokio::test]
async fn malformed_fingerprint_format_is_rejected_at_step_2() {
    // Uppercase hex — fails the lowercase-only regex.
    let body = json!({
        "event_kind": "import",
        "module_path": "pkg.mod",
        "caller_subject": "worker",
        "caller_run_id": "run-1",
        "event_fingerprint": "A".repeat(64),
    });
    let (status, body_bytes) = oneshot(policy_router(), authorize_request(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let parsed: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        parsed.get("reason").and_then(Value::as_str),
        Some("event_fingerprint_format"),
        "uppercase fingerprint MUST be rejected with event_fingerprint_format, \
         not event_fingerprint_invalid; body={parsed}",
    );
}
