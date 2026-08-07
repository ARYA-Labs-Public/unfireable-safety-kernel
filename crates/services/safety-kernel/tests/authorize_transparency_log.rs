//!   Step 5 — kernel-side transparency-log fail-CLOSED
//! integration tests.
//!
//! Four scenarios per the brief:
//!   1. T-log returns 200 → authorize() returns 200 + signed token.
//!   2. T-log returns 500 → authorize() returns 403 +
//!      `transparency_error:server_error` (fail-CLOSED).
//!   3. T-log timeouts → authorize() returns 403 +
//!      `transparency_error:timeout` (fail-CLOSED).
//!   4. T-log returns 409 → authorize() returns 200 (idempotent retry
//!      treated as success).
//!
//! Test harness:
//!   - A minimal Rust mock policy sidecar bound to a tempfile Unix
//!     socket; it always returns an allow decision so we reach the
//!     transparency-log block of the authorize handler.
//!   - A custom `MockTransparencyClient` trait impl that yields the
//!     scripted outcome.
//!   - The kernel's real `routes::authorize::authorize` handler driven
//!     via `tower::ServiceExt::oneshot`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::similar_names, clippy::too_many_lines)]
#![allow(clippy::doc_markdown, clippy::doc_lazy_continuation)]
#![allow(clippy::needless_pass_by_value)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    routing::post,
    Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tower::ServiceExt;

use qorch_adapters::clock::SystemClock;
use qorch_adapters::nonce::OsRngNonceSource;
use qorch_adapters::policy_engine_client::PolicyEngineClient;
use qorch_domain::safety::{Clock, NonceSource};
use qorch_safety_kernel::auth::CallerRole;
use qorch_safety_kernel::routes;
use qorch_safety_kernel::settings::Settings;
use qorch_safety_kernel::state::AppState;
use qorch_safety_kernel::transparency_client::{
    TransparencyAppendInput, TransparencyAppendOutcome, TransparencyClient, TransparencyError,
};

// ---------------------------------------------------------------------------
// Mock transparency-log client
// ---------------------------------------------------------------------------

/// What a `MockTransparencyClient` instance should do on `append`.
#[derive(Debug, Clone)]
enum MockBehavior {
    Ok,
    ServerError,
    Conflict,
    SlowSleep(Duration),
    ///: trait-level surface for the new `ProtocolViolation`
    /// error (the wire client emits this when the t-log returns a
    /// divergent `leaf_hash_hex`; the trait mock simply returns the
    /// pre-mapped error so we can assert the kernel's authorize
    /// handler synthesizes the right deny reason).
    ProtocolViolation,
}

#[derive(Debug, Clone)]
struct MockTransparencyClient {
    behavior: MockBehavior,
}

#[async_trait]
impl TransparencyClient for MockTransparencyClient {
    async fn append(
        &self,
        _input: TransparencyAppendInput,
    ) -> Result<TransparencyAppendOutcome, TransparencyError> {
        match &self.behavior {
            MockBehavior::Ok => Ok(TransparencyAppendOutcome {
                leaf_index: 42,
                idempotent_replay: false,
            }),
            MockBehavior::ServerError => Err(TransparencyError::ServerError {
                status_code: 500,
                detail: "synthetic 500".into(),
            }),
            MockBehavior::Conflict => Err(TransparencyError::Conflict),
            MockBehavior::SlowSleep(d) => {
                tokio::time::sleep(*d).await;
                Ok(TransparencyAppendOutcome {
                    leaf_index: 0,
                    idempotent_replay: false,
                })
            }
            MockBehavior::ProtocolViolation => Err(TransparencyError::ProtocolViolation(
                "synthetic leaf_hash mismatch (test fixture)".into(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal Rust mock policy sidecar
// ---------------------------------------------------------------------------

/// Bind a Unix socket at `path` and respond to every connection with
/// `{"ok": true, "request_id": "<echo>", "decision": {"allowed": true,
/// "reason": "test_allow", "metadata": {}}}` for `op=authorize` and
/// `{"ok": true, "request_id": "<echo>", "entry": {...}}` for
/// `op=audit_append`. Single-line newline-delimited JSON, matching
/// the production protocol (`crates/adapters/src/policy_engine_client.rs`).
fn spawn_mock_sidecar(path: PathBuf) -> JoinHandle<()> {
    let listener = UnixListener::bind(&path).expect("bind unix socket");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(handle_conn(stream));
        }
    })
}

async fn handle_conn(stream: tokio::net::UnixStream) {
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_err() || line.is_empty() {
        return;
    }
    let envelope: Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(_) => return,
    };
    let request_id = envelope
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let op = envelope
        .get("op")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let resp = match op.as_str() {
        "authorize" => json!({
            "ok": true,
            "request_id": request_id,
            "decision": {"allowed": true, "reason": "test_allow", "metadata": {}}
        }),
        "audit_append" => json!({
            "ok": true,
            "request_id": request_id,
            "entry": {"hash": "deadbeef", "chain_index": 1}
        }),
        _ => json!({"ok": false, "request_id": request_id, "error": "unknown_op"}),
    };
    let mut out = serde_json::to_string(&resp).unwrap();
    out.push('\n');
    let _ = write_half.write_all(out.as_bytes()).await;
    let _ = write_half.flush().await;
}

// ---------------------------------------------------------------------------
// AppState fixture
// ---------------------------------------------------------------------------

fn test_settings(sock: PathBuf) -> Settings {
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
        key_backend: qorch_safety_kernel::key_backend::KeyBackendKind::Env,
        key_gcp_project: None,
        key_gcp_secret: None,
        key_gcp_secret_version: "latest".to_string(),
        audit_pepper_b64: zero_seed_b64,
        default_token_ttl_s: 60,
        max_token_ttl_s: 300,
        approval_token_ttl_s: 365 * 24 * 60 * 60,
        build_version: "test-tlog-int".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        policy_sock_path: sock,
        tls_cert_path: None,
        tls_key_path: None,
        tls_client_ca_path: None,
        tls_sni: "safety-kernel-rust.internal".to_string(),
        tls_enable: false,
        transparency_enabled: true,
        transparency_log_url: Some("http://mock".to_string()),
        transparency_log_api_key: Some("mock-key".to_string()),
        transparency_log_timeout_seconds: 0.5,
        transparency_log_client_cert_path: None,
        transparency_log_client_key_path: None,
    }
}

fn build_state(behavior: MockBehavior, sock: PathBuf, timeout_s: f64) -> AppState {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let pk_raw = signing_key.verifying_key().to_bytes();
    let pk_b64 = URL_SAFE_NO_PAD.encode(pk_raw);
    let mut h = Sha256::new();
    h.update(pk_raw);
    let pk_fpr = hex::encode(h.finalize());

    let clock_arc: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let started_at = clock_arc.now();
    let nonce_arc: Arc<dyn NonceSource> = Arc::new(OsRngNonceSource::new());

    let mut settings = test_settings(sock.clone());
    settings.transparency_log_timeout_seconds = timeout_s;

    let tlog: Arc<dyn TransparencyClient> = Arc::new(MockTransparencyClient { behavior });

    AppState {
        settings: Arc::new(settings),
        signing_key: Arc::new(signing_key),
        public_key_b64: pk_b64,
        public_key_fingerprint: pk_fpr,
        audit_pepper: Arc::new(vec![0u8; 32]),
        started_at,
        clock: clock_arc,
        nonce: nonce_arc,
        policy_client: Arc::new(PolicyEngineClient::new(sock)),
        transparency_client: Some(tlog),
    }
}

/// Build an authorize-only router with the auth layer bypassed and
/// `CallerRole(worker)` injected on every request — same shim used
/// by `policy_routes_scaffold.rs`.
fn router(state: AppState) -> Router {
    use axum::middleware::from_fn;
    Router::new()
        .route("/kernel/v1/authorize", post(routes::authorize::authorize))
        .layer(from_fn(
            |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
                req.extensions_mut()
                    .insert(CallerRole("worker".to_string()));
                next.run(req).await
            },
        ))
        .with_state(state)
}

fn authorize_body() -> Value {
    json!({
        "action": "sio_run_cycles",
        "run_id": "test-run-id",
        "subject": "ignored-untrusted-subject",
        "params_fingerprint": "deadbeef",
        "ttl_s": 60,
    })
}

async fn post_json(router: Router, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/kernel/v1/authorize")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Build a fresh tempdir + spawn a mock sidecar bound to a tempfile.
async fn fresh_sidecar() -> (TempDir, PathBuf, JoinHandle<()>) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("sidecar.sock");
    let handle = spawn_mock_sidecar(sock.clone());
    // Give the listener a moment to be ready.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (dir, sock, handle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn authorize_with_transparency_log_succeeds() {
    let (_dir, sock, _h) = fresh_sidecar().await;
    let state = build_state(MockBehavior::Ok, sock, 2.0);
    let router = router(state);
    let (status, v) = post_json(router, authorize_body()).await;
    assert_eq!(status, StatusCode::OK, "body={v:?}");
    assert_eq!(v["ok"], true);
    assert!(v["token"].is_string());
    assert!(v["token_sha256"].is_string());
}

#[tokio::test]
async fn authorize_transparency_500_fails_closed() {
    let (_dir, sock, _h) = fresh_sidecar().await;
    let state = build_state(MockBehavior::ServerError, sock, 2.0);
    let router = router(state);
    let (status, v) = post_json(router, authorize_body()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={v:?}");
    assert_eq!(v["error"], "denied");
    assert_eq!(v["reason"], "transparency_error:server_error");
}

#[tokio::test]
async fn authorize_transparency_timeout_fails_closed() {
    let (_dir, sock, _h) = fresh_sidecar().await;
    // Mock sleeps 1s; settings timeout is 0.1s ⇒ tokio::time::timeout fires.
    let state = build_state(MockBehavior::SlowSleep(Duration::from_secs(1)), sock, 0.1);
    let router = router(state);
    let (status, v) = post_json(router, authorize_body()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={v:?}");
    assert_eq!(v["error"], "denied");
    assert_eq!(v["reason"], "transparency_error:timeout");
}

#[tokio::test]
async fn authorize_transparency_409_treated_as_success() {
    let (_dir, sock, _h) = fresh_sidecar().await;
    let state = build_state(MockBehavior::Conflict, sock, 2.0);
    let router = router(state);
    let (status, v) = post_json(router, authorize_body()).await;
    assert_eq!(status, StatusCode::OK, "body={v:?}");
    assert_eq!(v["ok"], true);
    assert!(v["token"].is_string());
}

///  /  Step 8 — when the t-log returns a 2xx with a
/// divergent `leaf_hash_hex`, the wire-level
/// `ReqwestTransparencyClient::append` maps that to
/// `TransparencyError::ProtocolViolation(...)`. The kernel's authorize
/// handler MUST surface this as a 403 with
/// `transparency_error:protocol_violation` (fail-CLOSED, same shape as
/// every other transparency_error variant).
#[tokio::test]
async fn authorize_transparency_returns_wrong_leaf_hash_fails_closed() {
    let (_dir, sock, _h) = fresh_sidecar().await;
    let state = build_state(MockBehavior::ProtocolViolation, sock, 2.0);
    let router = router(state);
    let (status, v) = post_json(router, authorize_body()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={v:?}");
    assert_eq!(v["error"], "denied");
    assert_eq!(v["reason"], "transparency_error:protocol_violation");
}
