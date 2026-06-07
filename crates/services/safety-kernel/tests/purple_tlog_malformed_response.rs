//!   — Purple-Team adversarial tests for the kernel
//! fail-closed transparency-log integration ().
//!
//! Campaigns:
//!   C1 — T-log returns 200 with malformed JSON body
//!        (TransparencyError::Malformed). Kernel MUST deny.
//!   C2 — T-log returns 200 with a `leaf_hash_hex` that does not
//!        correspond to the kernel's local SHA-256 of its own token
//!        bytes. HISTORICALLY: kernel accepted (gap recorded as
//!        ). RESOLUTION ( Step 8): the wire client
//!        now cross-verifies and surfaces `ProtocolViolation`, which
//!        the authorize handler maps to a 403 with
//!        `transparency_error:protocol_violation`. The trait-level
//!        mock in this file does NOT exercise the wire path, so the
//!        snapshot below remains "200" — wire-level coverage lives in
//!        `tests/test_transparency_http_wiremock.rs::
//!        http_2xx_with_wrong_leaf_hash_yields_protocol_violation`
//!        and the e2e in `authorize_transparency_log.rs::
//!        authorize_transparency_returns_wrong_leaf_hash_fails_closed`.
//!   C3 — Concurrent storm: 100 simultaneous authorize() calls
//!        against a slow t-log (1s sleep, kernel timeout 0.1s).
//!        EVERY response MUST be a fail-closed 403 — zero allow
//!        slip-through.
//!
//! Topology: reuse the existing `MockTransparencyClient` shape from
//! `tests/authorize_transparency_log.rs` (no production wire change
//! introduced for the assessment) and add new behaviors that simulate
//! `Malformed` responses + a programmable `OkWithLeafHash` path.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::similar_names, clippy::too_many_lines)]
#![allow(clippy::doc_markdown, clippy::doc_lazy_continuation)]
#![allow(clippy::needless_pass_by_value)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
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
// Adversarial transparency-log client variants
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)] // `Ok` is held for parity with the existing
                    // `MockBehavior` shape in `authorize_transparency_log.rs` and to
                    // document the available test surface; the success path is already
                    // exercised by `authorize_with_transparency_log_succeeds` in that
                    // file, so we don't repeat it here.
enum PurpleBehavior {
    /// 2xx but the response body did not parse → Malformed.
    Malformed,
    /// 2xx happy path — returned to the kernel as Ok.
    Ok,
    /// 2xx with a leaf_hash_hex that does NOT correspond to the
    /// kernel's local SHA-256 of the token bytes. Currently NOT
    /// checked by the kernel — we capture this as a defense gap.
    OkWithMismatchedLeafHash,
    /// Slow sleep — used to test concurrent fail-closed under
    /// kernel-side timeout pressure.
    SlowSleep(Duration),
}

/// Atomic counter of how many times `append` was called — used by C3
/// to assert the per-request slip-through count is exactly zero.
#[derive(Debug)]
struct PurpleTransparencyClient {
    behavior: PurpleBehavior,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl TransparencyClient for PurpleTransparencyClient {
    async fn append(
        &self,
        _input: TransparencyAppendInput,
    ) -> Result<TransparencyAppendOutcome, TransparencyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.behavior {
            PurpleBehavior::Malformed => Err(TransparencyError::Malformed {
                detail: "synthetic malformed JSON body (purple-team fixture)".into(),
            }),
            PurpleBehavior::Ok | PurpleBehavior::OkWithMismatchedLeafHash => {
                Ok(TransparencyAppendOutcome {
                    leaf_index: 7,
                    idempotent_replay: false,
                })
            }
            PurpleBehavior::SlowSleep(d) => {
                tokio::time::sleep(*d).await;
                Ok(TransparencyAppendOutcome {
                    leaf_index: 0,
                    idempotent_replay: false,
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Mock policy sidecar — copied from authorize_transparency_log.rs
// ---------------------------------------------------------------------------

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
        db_path: ".qorch/purple_audit.sqlite3".to_string(),
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
        build_version: "test-purple".to_string(),
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
        transparency_log_timeout_seconds: 2.0,
        transparency_log_client_cert_path: None,
        transparency_log_client_key_path: None,
    }
}

fn build_state(
    behavior: PurpleBehavior,
    sock: PathBuf,
    timeout_s: f64,
) -> (AppState, Arc<AtomicUsize>) {
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

    let calls = Arc::new(AtomicUsize::new(0));
    let tlog: Arc<dyn TransparencyClient> = Arc::new(PurpleTransparencyClient {
        behavior,
        calls: calls.clone(),
    });

    let state = AppState {
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
    };
    (state, calls)
}

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
        "run_id": "test-run-purple",
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

async fn fresh_sidecar() -> (TempDir, PathBuf, JoinHandle<()>) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("sidecar.sock");
    let handle = spawn_mock_sidecar(sock.clone());
    tokio::time::sleep(Duration::from_millis(50)).await;
    (dir, sock, handle)
}

// ---------------------------------------------------------------------------
// C1 — Malformed JSON body on 200 MUST fail-closed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn purple_c1_tlog_malformed_response_fails_closed() {
    let (_dir, sock, _h) = fresh_sidecar().await;
    let (state, _calls) = build_state(PurpleBehavior::Malformed, sock, 2.0);
    let router = router(state);
    let (status, v) = post_json(router, authorize_body()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={v:?}");
    assert_eq!(v["error"], "denied");
    assert_eq!(
        v["reason"], "transparency_error:malformed_response",
        "kernel must surface the malformed-response variant in the deny reason",
    );
}

// ---------------------------------------------------------------------------
// C2 — Defense-gap CLOSED (,  Step 8): the wire client
// now cross-verifies `leaf_hash_hex` and surfaces `ProtocolViolation`
// on divergence, which the authorize handler maps to 403 +
// `transparency_error:protocol_violation`.
//
// This trait-level mock returns `Ok(...)` directly without going
// through the wire client, so the cross-check does not fire here.
// Wire-level coverage lives in `tests/test_transparency_http_wiremock.rs::
// http_2xx_with_wrong_leaf_hash_yields_protocol_violation` and the
// end-to-end mapping in `tests/authorize_transparency_log.rs::
// authorize_transparency_returns_wrong_leaf_hash_fails_closed`.
//
// We keep this test as a contract-snapshot of the trait surface:
// changing the trait so that mismatched leaf_hash is observable
// (e.g. by returning a richer outcome that includes the returned
// hash) would require updating this test to assert the new shape.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn purple_c2_trait_mock_does_not_exercise_wire_cross_check_snapshot() {
    let (_dir, sock, _h) = fresh_sidecar().await;
    let (state, _calls) = build_state(PurpleBehavior::OkWithMismatchedLeafHash, sock, 2.0);
    let router = router(state);
    let (status, v) = post_json(router, authorize_body()).await;
    // Trait-level snapshot: the mock returns `Ok(...)` without going
    // through the wire path that performs the cross-check, so
    // the authorize handler sees a clean success. Wire-level coverage
    // for the cross-check lives in the wiremock test referenced in the
    // module docstring above.
    assert_eq!(
        status,
        StatusCode::OK,
        "trait-mock snapshot: wire-level leaf_hash cross-check is exercised in test_transparency_http_wiremock.rs::http_2xx_with_wrong_leaf_hash_yields_protocol_violation; this trait-mock path bypasses the wire. body={v:?}"
    );
}

// ---------------------------------------------------------------------------
// C3 — Concurrent storm: 100 authorize calls against a slow t-log
// (1s sleep) with the kernel timeout pinned to 0.1s. Every response
// MUST be 403 (fail-closed). Zero allow-slip-through.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn purple_c3_concurrent_slow_tlog_all_fail_closed() {
    const STORM: usize = 100;
    let (_dir, sock, _h) = fresh_sidecar().await;
    let (state, calls) = build_state(PurpleBehavior::SlowSleep(Duration::from_secs(1)), sock, 0.1);

    // Spawn STORM concurrent in-process requests against the same
    // router. We clone the router (`Arc<Router>` semantics) per task.
    let mut handles = Vec::with_capacity(STORM);
    for i in 0..STORM {
        let r = router(state.clone());
        let body = json!({
            "action": "sio_run_cycles",
            "run_id": format!("storm-{i:03}"),
            "subject": "ignored",
            "params_fingerprint": "deadbeef",
            "ttl_s": 60,
        });
        let h = tokio::spawn(async move {
            let (s, v) = post_json(r, body).await;
            (s, v)
        });
        handles.push(h);
    }

    let mut allows = 0usize;
    let mut denies = 0usize;
    let mut other = Vec::<u16>::new();
    for h in handles {
        let (status, v) = h.await.unwrap();
        if status == StatusCode::OK && v["ok"] == true {
            allows += 1;
        } else if status == StatusCode::FORBIDDEN && v["reason"] == "transparency_error:timeout" {
            denies += 1;
        } else {
            other.push(status.as_u16());
        }
    }

    assert_eq!(
        allows, 0,
        "ZERO allow slip-through under concurrent slow-tlog (got {allows}); fail-closed contract broken",
    );
    assert_eq!(
        denies, STORM,
        "all {STORM} responses must be fail-closed timeout denies; got denies={denies} other={other:?}",
    );
    // Sanity — the mock client was hit STORM times.
    assert_eq!(
        calls.load(Ordering::SeqCst),
        STORM,
        "t-log mock should have been invoked once per request",
    );
}
