//! Positive-control auth coverage for the `/policy/*` slice-1 routes
//! (, ). This file is the sibling of
//! `policy_routes_scaffold.rs` — that one exercises the routes WITHOUT
//! auth middleware (route-shape gates), this one exercises them WITH
//! auth middleware (key-checking gates).
//!
//! Why both files: the scaffold tests need a free-standing
//! `Router<()>` so axum's method/body-shape behavior is asserted in
//! isolation from the kernel's API-key middleware. The auth tests
//! need a `Router<AppState>` plus the real `auth::auth_layer` so the
//! 401-without-key and 401-with-wrong-key contract is asserted on
//! the SAME handler bytes that production runs. Both files exist to
//! catch the missed-attack vector M2 identified in the PR #367
//! purple-team review (slice-1 policy routes shipped without an auth
//! positive control; nothing prevented a future scaffold revert from
//! silently dropping the middleware on `/policy/*`).
//!
//!  handlers still return 501 — the goal of THIS file is the
//! middleware gate, not the handler logic. The "valid-key → 501"
//! test pins TODAY's contract: with a valid worker key, traffic
//! reaches the scaffold handler and gets the slice-1 `not_implemented`
//! body.  MUST update that assertion to `200 / 403 / 503` once
//! the real authorization path lands; the 401-without-key and
//! 401-with-wrong-key assertions stay green forever.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::too_many_lines)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use tower::ServiceExt; // for `oneshot`

use qorch_adapters::clock::SystemClock;
use qorch_adapters::nonce::OsRngNonceSource;
use qorch_adapters::policy_engine_client::PolicyEngineClient;
use qorch_domain::safety::{Clock, NonceSource};
use qorch_safety_kernel::auth;
use qorch_safety_kernel::routes;
use qorch_safety_kernel::settings::Settings;
use qorch_safety_kernel::state::AppState;

// =============================================================================
// Per-test API keys
// =============================================================================
//
// Hardcoded test values — slice 1 settings forbid empty keys at load
// time, so we always pass concrete non-empty strings here. None of these
// match any production key (they include `test-` prefix + a long random
// nonce so they cannot collide with a real `.env` value by accident).

const TEST_WORKER_KEY: &str = "test-worker-key-policy-auth-aa42";
const TEST_API_KEY: &str = "test-api-key-policy-auth-bb73";
const TEST_OPERATOR_KEY: &str = "test-operator-key-policy-auth-cc91";
const BOGUS_KEY: &str = "bogus-key-value-12345";

// =============================================================================
// Test fixture — `Router<()>` carrying the policy sub-router with auth
// =============================================================================
//
// Mirrors `main.rs` line-by-line for the layers that gate `/policy/*`:
// the policy sub-router merged in, the auth middleware wrapped via
// `from_fn_with_state(state, auth_layer)`, then `.with_state(state)`.
//
// We do NOT mount the body-limit layer or trace layer here — they are
// orthogonal to the auth gate.  may want to add a body-limit
// positive control; that's a separate file.

/// Build a minimal `Settings` with the test API keys baked in. None of
/// the secret-bearing fields (signing key, audit pepper) need to be
/// real — auth never inspects them and the handlers return 501 before
/// they would be used.
fn test_settings() -> Settings {
    // A 32-byte all-zero seed is valid for `SigningKey::from_bytes`;
    // we never sign anything in this file. Same for the audit pepper.
    let zero_seed_b64 = URL_SAFE_NO_PAD.encode([0u8; 32]);

    Settings {
        env: "dev".to_string(),
        db_backend: "sqlite".to_string(),
        db_path: ".qorch/test_audit.sqlite3".to_string(),
        pg_dsn: None,
        auth_mode: "api_key".to_string(),
        api_key_worker: Some(TEST_WORKER_KEY.to_string()),
        api_key_api: Some(TEST_API_KEY.to_string()),
        api_key_operator: Some(TEST_OPERATOR_KEY.to_string()),
        signing_key_b64: zero_seed_b64.clone(),
        key_backend: qorch_safety_kernel::key_backend::KeyBackendKind::Env,
        key_gcp_project: None,
        key_gcp_secret: None,
        key_gcp_secret_version: "latest".to_string(),
        audit_pepper_b64: zero_seed_b64,
        default_token_ttl_s: 60,
        max_token_ttl_s: 300,
        approval_token_ttl_s: 365 * 24 * 60 * 60,
        build_version: "test-policy-auth".to_string(),
        // The auth-layer doesn't bind a socket; this path is never
        // touched by 401 / 501 paths.
        listen_addr: "127.0.0.1:0".to_string(),
        policy_sock_path: PathBuf::from("/tmp/qorch-test-nonexistent.sock"),
        //  Addendum 2a §2 — TLS dual-ingress fields. The
        // in-process router tests never bind a socket; tls_enable=false
        // and all paths None matches the dev-default Settings shape.
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

/// Build an `AppState` suitable for in-process router exercise. The
/// `signing_key` and `audit_pepper` use throwaway randomness — handlers
/// return 501 before they're ever consumed; auth never reads them.
fn test_state() -> AppState {
    // Throwaway signing seed so we don't even load the all-zero one
    // from settings — that field is just a parity-of-shape detail.
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
        // PolicyEngineClient does not connect at construction time; it
        // only opens the socket on the first IPC call. Slice-1 stub
        // handlers return 501 BEFORE any IPC, so this never connects.
        policy_client: Arc::new(PolicyEngineClient::new(PathBuf::from(
            "/tmp/qorch-test-nonexistent.sock",
        ))),
        transparency_client: None,
    }
}

/// Build the same `Router` shape the binary builds for `/policy/*`:
/// the policy sub-router merged with the auth middleware wrapped via
/// `from_fn_with_state(state, auth_layer)`, then `.with_state(state)`.
///
/// We intentionally do NOT mount the kernel's `/kernel/v1/*` routes —
/// the auth-layer behavior is identical regardless of which mount-point
/// the request hits (it short-circuits public paths by URL only). The
/// only public paths are `/health`, `/kernel/v1/health`,
/// `/kernel/v1/public_key`; nothing under `/policy/*` is public. Less
/// surface = a cleaner test.
fn auth_protected_router() -> Router {
    let state = test_state();
    Router::new()
        .merge(routes::policy::router())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::auth_layer,
        ))
        .with_state(state)
}

/// Fire one request through the in-process router and return
/// (`status`, `body_bytes`). Panics on transport / encoding errors —
/// this is a test helper, not production code.
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

/// A syntactically valid `ModuleAuthorizeRequest` body — what the
/// slice-2 handler will eventually parse.  ignores the body and
/// returns 501 regardless; we still send a well-formed one so we never
/// false-pass through a JSON-extractor rejection that returns the
/// "right" code for the wrong reason.
const VALID_AUTHORIZE_BODY: &str = r#"{
    "event_kind":"import",
    "module_path":"pkg.mod",
    "caller_subject":"worker",
    "caller_run_id":"run-1",
    "event_fingerprint":"0000000000000000000000000000000000000000000000000000000000000000"
}"#;

// =============================================================================
// 1. No `x-api-key` → 401 (the M2 gate)
// =============================================================================
//
// Closes finding M2 against PR #367: the slice-1 scaffold mounted
// `/policy/*` and the scaffold tests asserted 501 for any caller,
// but no test pinned the wire-level "no key → 401" contract. Without
// this, a future refactor that drops the middleware off `/policy/*`
// would silently green the existing test suite. THIS test breaks if
// that ever happens.

/// `POST /policy/module/authorize` with no `x-api-key` → 401.
// Gate: auth middleware MUST 401 unauthenticated requests on the FROZEN
// authorize endpoint. Slice-2 MUST keep this assertion green.
#[tokio::test]
async fn policy_authorize_returns_401_without_x_api_key() {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/policy/module/authorize")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(VALID_AUTHORIZE_BODY))
        .expect("build request");
    let (status, body) = oneshot(auth_protected_router(), req).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "authorize without x-api-key MUST 401; got {status}; body={}",
        String::from_utf8_lossy(&body),
    );
    // Body should be the standard kernel ErrorResponse with the
    // `unauthorized` machine code (matches `auth.rs:147-149`).
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).expect("401 body must be JSON ErrorResponse");
    assert_eq!(parsed.get("ok"), Some(&serde_json::Value::Bool(false)));
    assert_eq!(
        parsed.get("error").and_then(serde_json::Value::as_str),
        Some("unauthorized"),
    );
}

/// `POST /policy/module/register` with no `x-api-key` → 401. Pinned for
/// the draft endpoints too — the M2 finding was about the whole
/// `/policy/*` mount, not just authorize.
// Gate: draft endpoint auth MUST be enforced; slice 2 keeps this green
// even as the handler returns 200/4xx on a real shape.
#[tokio::test]
async fn policy_register_returns_401_without_x_api_key() {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/policy/module/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .expect("build request");
    let (status, body) = oneshot(auth_protected_router(), req).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "register without x-api-key MUST 401; got {status}; body={}",
        String::from_utf8_lossy(&body),
    );
}

// =============================================================================
// 2. Wrong `x-api-key` → 401
// =============================================================================
//
// Constant-time compare can still leak by `is_empty()` short-circuit if
// the supplied key matches the empty-string check. We feed a clearly
// non-empty bogus key to exercise the full match path.

/// `POST /policy/module/authorize` with a wrong `x-api-key` → 401.
// Gate: middleware MUST refuse a non-matching key.  keeps green.
#[tokio::test]
async fn policy_authorize_returns_401_with_wrong_x_api_key() {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/policy/module/authorize")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-api-key", BOGUS_KEY)
        .body(Body::from(VALID_AUTHORIZE_BODY))
        .expect("build request");
    let (status, body) = oneshot(auth_protected_router(), req).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "authorize with wrong x-api-key MUST 401; got {status}; body={}",
        String::from_utf8_lossy(&body),
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).expect("401 body must be JSON ErrorResponse");
    assert_eq!(
        parsed.get("error").and_then(serde_json::Value::as_str),
        Some("unauthorized"),
    );
}

// =============================================================================
// 3. Valid worker key → reaches the handler (501 today)
// =============================================================================
//
// THIS test is the slice-1 positive-control contract: with a valid
// worker key the auth layer passes the request through to the scaffold
// handler, which returns 501 with the slice-1 marker body.
// MUST update this expectation to 200 (allow) / 403 (deny) /
// 503 (kernel-unavailable) when the real authorize path lands. The
// 401-without-key and 401-with-wrong-key assertions above are
// permanent; this one is intentionally fragile so slice 2 can't
// silently land without touching the auth-control suite.

/// `POST /policy/module/authorize` with a valid worker key reaches the
/// slice-2 handler.  handler performs body validation; since
/// the test request body has a placeholder `event_fingerprint` (all
/// zeros) that doesn't match the recomputed canonical fingerprint,
/// the handler MUST return 400 `event_fingerprint_invalid`. Either
/// way — 400 here proves traffic crossed the auth boundary and
/// reached the handler logic.
// Gate: auth middleware MUST forward authenticated traffic; slice-2
// handler then rejects the placeholder fingerprint with 400.
#[tokio::test]
async fn policy_authorize_reaches_handler_with_valid_worker_key() {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/policy/module/authorize")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-api-key", TEST_WORKER_KEY)
        .body(Body::from(VALID_AUTHORIZE_BODY))
        .expect("build request");
    let (status, body) = oneshot(auth_protected_router(), req).await;
    // Slice-2 handler rejects the placeholder all-zeros fingerprint
    // with 400 `event_fingerprint_invalid` (the recomputed value
    // never matches all-zeros for ANY combination of event_kind /
    // module_path / caller_subject / caller_run_id). This proves the
    // request reached the handler; any 401 here would indicate the
    // auth middleware dropped.
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "valid worker key should reach the slice-2 handler, which \
         400s on the placeholder fingerprint; got {status}; body={}",
        String::from_utf8_lossy(&body),
    );
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("400 body must be JSON");
    assert_eq!(
        parsed.get("ok"),
        Some(&serde_json::Value::Bool(false)),
        "400 body should carry ok=false; body={parsed}",
    );
    assert_eq!(
        parsed.get("error").and_then(serde_json::Value::as_str),
        Some("invalid_request"),
        "400 body should carry error=invalid_request; body={parsed}",
    );
    assert_eq!(
        parsed.get("reason").and_then(serde_json::Value::as_str),
        Some("event_fingerprint_invalid"),
        "400 reason should be event_fingerprint_invalid; body={parsed}",
    );
}
