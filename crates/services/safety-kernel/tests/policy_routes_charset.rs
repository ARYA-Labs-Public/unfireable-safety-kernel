//! Adversarial fixture — slice-3 PT-L1 canonical `module_path`
//! charset (ADR-018 §2.5, ARY-2028).
//!
//! All four `/policy/*` endpoints MUST reject `module_path` values
//! outside the canonical charset `^[a-zA-Z0-9_.]+$` OR `^[0-9a-f]{64}$`
//! (length ≤ 256) with HTTP 400 + `reason: "module_path_invalid_charset"`.
//!
//! This is the Rule-8 adversarial suite for PT-L1: every test below
//! sends a deliberately-malformed `module_path` and asserts the
//! handler rejects it BEFORE any IPC call — proven by the route
//! returning 400 in-process without a sidecar wired up.
//!
//! Symmetric coverage:
//!   * `POST /policy/module/register`         — `body.module_path`
//!   * `POST /policy/module/authorize`        — `body.module_path`
//!   * `GET  /policy/module/{module_path}/status` — URL path segment
//!   * `POST /policy/audit-event`             — `metadata.module_path`
//!
//! Hyphen handling is its own test (slice-2 status route accepted `-`;
//! slice-3 rejects it across all four endpoints). The backward-compat
//! caveat is documented in `qorch_domain::safety::policy::validation`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::too_many_lines)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
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
use qorch_domain::safety::{Clock, NonceSource};
use qorch_safety_kernel::routes;
use qorch_safety_kernel::settings::Settings;
use qorch_safety_kernel::state::AppState;

// =============================================================================
// Test fixture — same minimal AppState pattern used in
// `policy_routes_scaffold.rs`. Auth middleware is bypassed; a tiny
// shim injects `CallerRole("worker")` so the charset check (which
// runs AFTER role check) is what we exercise.
// =============================================================================

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
        build_version: "test-policy-charset".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        // Non-existent socket — the handlers' charset check runs
        // BEFORE the IPC call, so we never reach the sidecar.
        policy_sock_path: PathBuf::from("/tmp/qorch-test-nonexistent-charset.sock"),
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
            "/tmp/qorch-test-nonexistent-charset.sock",
        ))),
    }
}

fn policy_router() -> Router {
    use axum::middleware::from_fn;
    use qorch_safety_kernel::auth::CallerRole;

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

fn json_req(method: Method, path: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("build json request")
}

/// Parse the response body as JSON; assert it's an object with the
/// expected `reason` field. Returns the parsed value.
fn assert_reason(body_bytes: &[u8], expected_reason: &str) {
    let parsed: Value = serde_json::from_slice(body_bytes).expect("response body is JSON");
    let reason = parsed
        .get("reason")
        .and_then(Value::as_str)
        .expect("response body has `reason` field");
    assert_eq!(
        reason, expected_reason,
        "expected reason={expected_reason}; got body={parsed}",
    );
}

// Adversarial `module_path` inputs — every value here is OUTSIDE the
// canonical `^[a-zA-Z0-9_.]+$` charset. Length-256 boundary cases live
// in the domain unit test (`crates/domain/.../validation.rs`).
//
// Each comment names the threat class the string represents.
const ADVERSARIAL_MODULE_PATHS: &[&str] = &[
    "foo/bar",              // path traversal — slash
    "foo-bar",              // hyphen (rejected slice-3)
    "foo bar",              // space
    "foo;DROP TABLE users", // SQL-injection-shaped
    "foo:bar",              // colon
    "foo,bar",              // comma
    "foo(bar)",             // parens
    "foo[bar]",             // brackets
    "foo\\bar",             // backslash
    "../etc/passwd",        // path traversal — relative
    "café",                 // non-ASCII (latin-1)
    "module\u{200B}x",      // zero-width unicode space
    "module\nfoo",          // newline
    "module\tfoo",          // tab
    "\"quoted\"",           // quotes
    "foo`bar",              // backtick
    "foo!bar",              // exclamation
    "foo@bar",              // at-sign
    "foo#bar",              // hash
    "foo$bar",              // dollar
    "foo%bar",              // percent
    "foo^bar",              // caret
    "foo&bar",              // ampersand
    "foo*bar",              // asterisk
    "foo+bar",              // plus
    "foo=bar",              // equals
    "foo<bar>",             // angle brackets
];

// =============================================================================
// 1. POST /policy/module/register — rejects malformed module_path
// =============================================================================

#[tokio::test]
async fn register_rejects_malformed_module_path() {
    for bad in ADVERSARIAL_MODULE_PATHS {
        let body = json!({
            "module_path": bad,
            "required_patterns_regex_set": ["^pkg\\."],
            "caller_subject": "test-worker",
        });
        let (status, resp_body) = oneshot(
            policy_router(),
            json_req(Method::POST, "/policy/module/register", &body),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "register MUST reject malformed module_path {bad:?} with 400 (got {status})",
        );
        assert_reason(&resp_body, "module_path_invalid_charset");
    }
}

#[tokio::test]
async fn register_rejects_oversized_module_path() {
    let oversize = "a".repeat(257);
    let body = json!({
        "module_path": oversize,
        "required_patterns_regex_set": ["^pkg\\."],
        "caller_subject": "test-worker",
    });
    let (status, resp_body) = oneshot(
        policy_router(),
        json_req(Method::POST, "/policy/module/register", &body),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_reason(&resp_body, "module_path_invalid_charset");
}

#[tokio::test]
async fn register_rejects_empty_module_path() {
    let body = json!({
        "module_path": "",
        "required_patterns_regex_set": ["^pkg\\."],
        "caller_subject": "test-worker",
    });
    let (status, resp_body) = oneshot(
        policy_router(),
        json_req(Method::POST, "/policy/module/register", &body),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_reason(&resp_body, "module_path_invalid_charset");
}

// =============================================================================
// 2. POST /policy/module/authorize — rejects malformed module_path
// =============================================================================

#[tokio::test]
async fn authorize_rejects_malformed_module_path() {
    for bad in ADVERSARIAL_MODULE_PATHS {
        // We don't bother computing a valid fingerprint here — the
        // charset check runs BEFORE the fingerprint check. If the
        // route emitted `event_fingerprint_*` reason then ordering
        // would be wrong and the test fails the assert_reason call.
        let body = json!({
            "event_kind": "import",
            "module_path": bad,
            "caller_subject": "test-worker",
            "caller_run_id": "run-1",
            "event_fingerprint": "0".repeat(64),
        });
        let (status, resp_body) = oneshot(
            policy_router(),
            json_req(Method::POST, "/policy/module/authorize", &body),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "authorize MUST reject malformed module_path {bad:?} with 400 (got {status})",
        );
        assert_reason(&resp_body, "module_path_invalid_charset");
    }
}

// =============================================================================
// 3. GET /policy/module/{module_path}/status — rejects malformed path
// =============================================================================

#[tokio::test]
async fn status_rejects_hyphenated_module_path_slice3() {
    // Slice-2 accepted hyphens at this endpoint; slice-3 rejects them.
    // This is the backward-compat breaking change documented in the
    // domain `validation.rs` preamble.
    let (status, resp_body) = oneshot(
        policy_router(),
        Request::builder()
            .method(Method::GET)
            .uri("/policy/module/foo-bar/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_reason(&resp_body, "module_path_invalid_charset");
}

#[tokio::test]
async fn status_rejects_url_encoded_malformed_paths() {
    // axum URL-decodes Path<String> automatically. A %2F-encoded slash
    // in the URL decodes to `/` which the canonical charset rejects.
    // Note: axum may treat literal `/` in the URL as a route separator,
    // so we use URL-encoded forms here to ensure axum decodes them as
    // path-segment content.
    let encoded_bads: &[&str] = &[
        "/policy/module/foo%20bar/status",       // space
        "/policy/module/foo%3Bbar/status",       // semicolon
        "/policy/module/foo%2Fbar/status",       // slash
        "/policy/module/foo%5Cbar/status",       // backslash
        "/policy/module/foo%21bar/status",       // exclamation
        "/policy/module/caf%C3%A9/status",       // non-ASCII
        "/policy/module/foo%E2%80%8Bbar/status", // ZWSP
    ];
    for path in encoded_bads {
        let (status, _) = oneshot(
            policy_router(),
            Request::builder()
                .method(Method::GET)
                .uri(*path)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "status MUST reject {path}, got {status}",
        );
    }
}

#[tokio::test]
async fn status_accepts_canonical_dotted_name_and_hex() {
    // Sanity check — valid charset gets PAST the charset gate. The
    // request will eventually 503 because the sidecar socket doesn't
    // exist, but the route returns 503 (sidecar unreachable), NOT 400
    // (charset rejected). This is the test that proves the validator
    // doesn't false-positive on legitimate input.
    let (status, _) = oneshot(
        policy_router(),
        Request::builder()
            .method(Method::GET)
            .uri("/policy/module/pkg.mod/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "valid charset should pass the gate and 503 on the missing sidecar",
    );

    let hex_path = "/policy/module/".to_string() + &"a".repeat(64) + "/status";
    let (status, _) = oneshot(
        policy_router(),
        Request::builder()
            .method(Method::GET)
            .uri(&hex_path)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "sha256-hex form should pass the gate and 503 on missing sidecar",
    );
}

// =============================================================================
// 4. POST /policy/audit-event — rejects malformed metadata.module_path
// =============================================================================

#[tokio::test]
async fn audit_event_rejects_malformed_metadata_module_path() {
    for bad in ADVERSARIAL_MODULE_PATHS {
        let body = json!({
            "event_kind": "hook_install_violation",
            "subject": "test-worker",
            "metadata": {
                "module_path": bad,
            },
        });
        let (status, resp_body) = oneshot(
            policy_router(),
            json_req(Method::POST, "/policy/audit-event", &body),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "audit-event MUST reject malformed metadata.module_path {bad:?} (got {status})",
        );
        assert_reason(&resp_body, "module_path_invalid_charset");
    }
}

#[tokio::test]
async fn audit_event_ignores_module_path_when_not_string() {
    // metadata.module_path = 42 (an int) is structurally weird but
    // not a charset violation — the route doesn't validate it. The
    // request will fall through to the IPC call and 502 (no sidecar).
    let body = json!({
        "event_kind": "hook_install_violation",
        "subject": "test-worker",
        "metadata": {
            "module_path": 42,
        },
    });
    let (status, _) = oneshot(
        policy_router(),
        json_req(Method::POST, "/policy/audit-event", &body),
    )
    .await;
    // Either 502 (sidecar IPC failed) or 400 (Json deserialization
    // failed) is acceptable here — what we're asserting is that the
    // route does NOT return the charset-violation 400 for a non-string.
    if status == StatusCode::BAD_REQUEST {
        // If 400, the reason should NOT be the charset reason.
        let resp_bytes = oneshot(
            policy_router(),
            json_req(
                Method::POST,
                "/policy/audit-event",
                &json!({
                    "event_kind": "hook_install_violation",
                    "subject": "test-worker",
                    "metadata": { "module_path": 42 },
                }),
            ),
        )
        .await
        .1;
        let parsed: Value = serde_json::from_slice(&resp_bytes).unwrap_or(Value::Null);
        if let Some(reason) = parsed.get("reason").and_then(Value::as_str) {
            assert_ne!(reason, "module_path_invalid_charset");
        }
    }
}

#[tokio::test]
async fn audit_event_without_metadata_passes_gate() {
    // No metadata — charset check is skipped entirely.
    let body = json!({
        "event_kind": "hook_install_violation",
        "subject": "test-worker",
    });
    let (status, _) = oneshot(
        policy_router(),
        json_req(Method::POST, "/policy/audit-event", &body),
    )
    .await;
    // 502 because the IPC fails on the non-existent socket.
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "no metadata should pass charset gate and 502 on missing sidecar",
    );
}

// =============================================================================
// 5. Wire-reason string is the canonical PT-L1 value
// =============================================================================

#[tokio::test]
async fn wire_reason_string_is_pt_l1_canonical() {
    // Pin the exact wire string so downstream verifiers and SREs can
    // grep / alert on it.
    let body = json!({
        "module_path": "foo-bar", // hyphen — slice-3 rejects
        "required_patterns_regex_set": ["^pkg\\."],
        "caller_subject": "test-worker",
    });
    let (status, resp_body) = oneshot(
        policy_router(),
        json_req(Method::POST, "/policy/module/register", &body),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let parsed: Value = serde_json::from_slice(&resp_body).unwrap();
    assert_eq!(parsed["error"], "invalid_request");
    assert_eq!(parsed["reason"], "module_path_invalid_charset");
    assert_eq!(parsed["ok"], false);
}
