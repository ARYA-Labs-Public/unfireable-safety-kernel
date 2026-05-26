//! Structural watchdog tests for the `/policy/*` slice-2 routes
//! (, ). This file complements
//! `policy_routes_auth.rs` (middleware/key gate) — here we exercise
//! the route-shape contract (allowed methods, OPTIONS non-5xx) and
//! the adversarial-suite coverage matrix that forces wave-2b to
//! shrink the deferred list as new fixture files land.
//!
//!  has flipped the four DEFERRED authorization-related test
//! classes to LANDED; the watchdog asserts `LANDED=10` /
//! `DEFERRED=1` so the only remaining deferral is the slice-5 perf
//! gate. The real-attack fixture tests live alongside in
//! `tests/policy_*.rs` (test 2b agent owns those).
//!
//! Real handlers now require `State<AppState>` + `Extension<CallerRole>`,
//! so the route fixture builds a minimal-but-real `AppState` using
//! the same mock pattern as `policy_routes_auth.rs`. The auth layer
//! is NOT mounted here — these tests are about route shape, not
//! middleware. The auth tests cover that gate.

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
use sha2::{Digest, Sha256};
use tower::ServiceExt; // for `oneshot`

use qorch_adapters::clock::SystemClock;
use qorch_adapters::nonce::OsRngNonceSource;
use qorch_adapters::policy_engine_client::PolicyEngineClient;
use qorch_domain::safety::{Clock, NonceSource};
use qorch_safety_kernel::routes;
use qorch_safety_kernel::settings::Settings;
use qorch_safety_kernel::state::AppState;

// =============================================================================
// Test fixture — `Router<()>` carrying the policy sub-router with AppState
// =============================================================================
//
// The new slice-2 handlers take `State<AppState>` + `Extension<CallerRole>`.
// We do NOT mount the auth middleware here — these tests target the
// route shape, not the middleware. To satisfy the Extension extractor
// we inject a `CallerRole` value via a tiny middleware that runs on
// every request (the equivalent of an "always-authenticated worker"
// shim, used ONLY for the route-shape tests).

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
        build_version: "test-policy-scaffold".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        // Use a non-existent socket path; the slice-2 handlers' IPC
        // call WILL fail with `IpcConnect`, which the handler maps to
        // 503. The shape tests below do NOT exercise the IPC path —
        // they exercise method matching, OPTIONS handling, and the
        // role-rejection short-circuit (which happens BEFORE IPC).
        policy_sock_path: PathBuf::from("/tmp/qorch-test-nonexistent-scaffold.sock"),
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
            "/tmp/qorch-test-nonexistent-scaffold.sock",
        ))),
        transparency_client: None,
    }
}

/// Build the policy sub-router with a `CallerRole(worker)` extension
/// injected on every request. We bypass the auth middleware entirely
/// so these tests exercise pure route shape — auth coverage lives in
/// `policy_routes_auth.rs`.
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

/// Fire one request through the in-process router and return
/// (`status`, `body_bytes`). Panics on transport/encoding errors —
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

/// Build a request with an arbitrary method, no body, no content-type.
fn empty_req(method: Method, path: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .expect("build request")
}

// =============================================================================
// 1. Wrong method → 405 Method Not Allowed
// =============================================================================

/// POST-only `register` rejects GET/PUT/DELETE/PATCH with 405.
#[tokio::test]
async fn register_rejects_non_post_methods() {
    for method in [Method::GET, Method::PUT, Method::DELETE, Method::PATCH] {
        let (status, _) = oneshot(
            policy_router(),
            empty_req(method.clone(), "/policy/module/register"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "register should 405 on {method:?}",
        );
    }
}

/// POST-only `authorize` rejects GET/PUT/DELETE/PATCH with 405.
#[tokio::test]
async fn authorize_rejects_non_post_methods() {
    for method in [Method::GET, Method::PUT, Method::DELETE, Method::PATCH] {
        let (status, _) = oneshot(
            policy_router(),
            empty_req(method.clone(), "/policy/module/authorize"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "authorize should 405 on {method:?}",
        );
    }
}

/// POST-only `audit-event` rejects GET/PUT/DELETE/PATCH with 405.
#[tokio::test]
async fn audit_event_rejects_non_post_methods() {
    for method in [Method::GET, Method::PUT, Method::DELETE, Method::PATCH] {
        let (status, _) = oneshot(
            policy_router(),
            empty_req(method.clone(), "/policy/audit-event"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "audit-event should 405 on {method:?}",
        );
    }
}

/// GET-only `status` rejects POST/PUT/DELETE/PATCH with 405.
#[tokio::test]
async fn status_rejects_non_get_methods() {
    for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
        let (status, _) = oneshot(
            policy_router(),
            empty_req(method.clone(), "/policy/module/pkg.mod/status"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "status should 405 on {method:?}",
        );
    }
}

/// OPTIONS on a known route must NOT 500 — axum 0.8 returns 405 by
/// default (no explicit CORS layer mounted on `/policy/*`).
#[tokio::test]
async fn options_does_not_500_on_any_policy_route() {
    for path in [
        "/policy/module/register",
        "/policy/module/authorize",
        "/policy/audit-event",
        "/policy/module/pkg.mod/status",
    ] {
        let (status, _) = oneshot(policy_router(), empty_req(Method::OPTIONS, path)).await;
        assert!(
            !status.is_server_error(),
            "OPTIONS on {path} returned server error {status}",
        );
    }
}

// =============================================================================
// 2. Adversarial-suite coverage matrix (watchdog)
// =============================================================================
//
//  flips 4 of 5 DEFERRED classes to LANDED. The watchdog is
// the fixed-length assertion below; the actual adversarial fixture
// files live alongside in `tests/policy_*.rs` and are owned by the
// wave-2b test agent.

/// Adversarial classes LANDED by slice 1 + slice 2 (10 total).
const LANDED: &[&str] = &[
    //  (route shape).
    "wrong_method_405",
    "options_does_not_500",
    "forbidden_imports_lint",
    //  (real handlers).
    "wrong_content_type_returns_415_or_400",
    "malformed_json_returns_400",
    "happy_path_returns_signed_decision",
    //  (adversarial — wave 2b test agent owns the fixture
    // files; the watchdog math here forces the engagement).
    "forged_event_fingerprint_rejected",
    "registry_bypass_attempt_denied",
    "audit_chain_replay_rejected",
    "signature_forgery_rejected",
];

/// Classes still deferred to a later slice.  perf gate is the
/// only remaining deferral.
const DEFERRED: &[(&str, &str)] = &[("performance_regression_p99", "slice_5")];

/// Adversarial fixture files that MUST exist on disk. Each one
/// corresponds to one or more `LANDED` class IDs above (slice-2
/// wave-2b deliverable The watchdog enforces both
/// the size invariant AND the on-disk presence of every fixture —
/// a future slice that empties one of these files without flipping
/// the matching LANDED entry will fail this watchdog.
const ADVERSARIAL_FIXTURE_FILES: &[&str] = &[
    // forged_event_fingerprint_rejected
    "tests/policy_forged_event_fingerprint.rs",
    // registry_bypass_attempt_denied + happy_path_returns_signed_decision
    "tests/policy_registry_bypass.rs",
    // audit_chain_replay_rejected (TTL + nonce uniqueness)
    "tests/policy_replay_within_ttl.rs",
    // signature_forgery_rejected
    "tests/policy_signature_forgery.rs",
    // Single-chain integrity covers audit_chain_replay's chain half.
    "tests/policy_audit_chain_integrity.rs",
];

#[test]
fn adversarial_suite_coverage_matrix_is_self_consistent() {
    // Hardcoded expected sizes — slice 2 lands exactly 10 / defers 1.
    // Any future slice that adds adversarial coverage MUST update both
    // lists in lockstep; the assertion is the watchdog.
    assert_eq!(
        LANDED.len(),
        10,
        "slice 2 lands exactly 10 adversarial classes (6 from slice 1 + 4 newly landed)",
    );
    assert_eq!(
        DEFERRED.len(),
        1,
        "slice 2 leaves exactly 1 deferred class (the slice-5 perf gate)",
    );

    // No overlap between landed and deferred.
    for (name, _) in DEFERRED {
        assert!(
            !LANDED.contains(name),
            "class {name} appears in BOTH landed and deferred — pick one",
        );
    }

    // Every deferred class names a real future slice.
    for (name, slice) in DEFERRED {
        assert!(
            matches!(*slice, "slice_2" | "slice_3" | "slice_5"),
            "class {name} deferred to unknown slice {slice}",
        );
    }

    // Every fixture file MUST exist on disk and be non-empty. This
    // catches the regression where a future slice flips a LANDED
    // entry but ships an empty test file — the watchdog math would
    // still pass but no real test would exist.
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for rel in ADVERSARIAL_FIXTURE_FILES {
        let path = manifest_dir.join(rel);
        let meta = std::fs::metadata(&path)
            .unwrap_or_else(|e| panic!("required adversarial fixture missing: {rel}: {e}"));
        assert!(
            meta.len() > 1024,
            "adversarial fixture {rel} is suspiciously small ({} bytes) — \
             a stub-only file would silently false-pass the watchdog",
            meta.len(),
        );
    }

    eprintln!(" adversarial-suite coverage matrix (slice 2):");
    eprintln!("  LANDED ({}):", LANDED.len());
    for name in LANDED {
        eprintln!("    + {name}");
    }
    eprintln!("  DEFERRED ({}):", DEFERRED.len());
    for (name, slice) in DEFERRED {
        eprintln!("    - {name} -> {slice}");
    }
    eprintln!("  FIXTURE FILES ({}):", ADVERSARIAL_FIXTURE_FILES.len());
    for rel in ADVERSARIAL_FIXTURE_FILES {
        eprintln!("    * {rel}");
    }
}
