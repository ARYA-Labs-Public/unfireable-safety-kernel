//! wiremock-backed integration tests for the reconciler's
//! `ManifestFetcher` + `TransparencyLogClient` HTTP paths
//! (,  Step 3).
//!
//! These tests live in `tests/` so they exercise the public crate
//! surface end-to-end through real reqwest clients pointed at a
//! `wiremock::MockServer`. The unit tests inside `reconciler.rs`
//! cover the algorithm logic itself; this file pins the HTTP-shape
//! invariants the reconciler depends on.

#![allow(
    // Test fixtures use deterministic small u64 epoch values that fit
    // losslessly in f64; cast lints are noise here.
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, SECRET_KEY_LENGTH};
use serde_json::Value;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use qorch_domain::safety::Clock;
use qorch_safety_kernel_reconciler::{
    AuditSink, DriftAuditEvent, HttpManifestFetcher, HttpTransparencyLogClient, Reconciler,
    ReconcilerConfig, RegistryClient, ReleaseManifest, TickOutcome,
    DEFAULT_MANIFEST_STALENESS_SECONDS,
};

/// Fixed clock so tests don't depend on wall-clock skew.
#[derive(Clone)]
struct FixedClock(f64);
impl Clock for FixedClock {
    fn now(&self) -> f64 {
        self.0
    }
}

/// Stub registry — pre-canned digest.
struct StubRegistry(String);
#[async_trait]
impl RegistryClient for StubRegistry {
    async fn fetch_running_digest(&self, _image_ref: &str) -> Result<String> {
        Ok(self.0.clone())
    }
}

/// Vec-backed audit sink.
#[derive(Default)]
struct VecAudit {
    events: Mutex<Vec<DriftAuditEvent>>,
}
#[async_trait]
impl AuditSink for VecAudit {
    async fn append(&self, event: &DriftAuditEvent) -> Result<()> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
}

fn test_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
    let seed = [7u8; SECRET_KEY_LENGTH];
    let s = SigningKey::from_bytes(&seed);
    let v = s.verifying_key();
    (s, v)
}

/// Mirror the canonical-bytes recipe inside `ReleaseManifest` so we
/// can sign and serialize a payload directly into a wiremock body.
/// The reconciler's `verify_manifest()` must agree byte-for-byte
/// with this construction.
fn signed_manifest_json(
    signing: &SigningKey,
    image: &str,
    digest: &str,
    issued_at: u64,
) -> String {
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    map.insert("digest".into(), Value::String(digest.into()));
    map.insert("image".into(), Value::String(image.into()));
    map.insert("issued_at".into(), Value::Number(issued_at.into()));
    map.insert("version".into(), Value::String("v0.1.0".into()));
    let canonical = serde_json::to_vec(&map).unwrap();
    let signature = signing.sign(&canonical);
    let manifest = ReleaseManifest {
        image: image.to_string(),
        digest: digest.to_string(),
        version: "v0.1.0".to_string(),
        issued_at,
        signature: B64.encode(signature.to_bytes()),
    };
    serde_json::to_string(&manifest).unwrap()
}

/// End-to-end: real reqwest clients fetch a wiremock-served manifest,
/// and the drift event is posted to a second wiremock endpoint.
#[tokio::test]
async fn drift_round_trip_with_real_http() {
    let (signing, verifying) = test_keypair();
    let now: u64 = 1_700_000_000;
    let image = "aryalabs/safety-kernel";
    let expected = "sha256:expected";
    let running = "sha256:running";
    let manifest_body = signed_manifest_json(&signing, image, expected, now);

    // Manifest server.
    let manifest_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/manifest"))
        .respond_with(ResponseTemplate::new(200).set_body_string(manifest_body))
        .mount(&manifest_server)
        .await;

    // Transparency-log server — must receive exactly one POST.
    let tlog_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"ok":true}"#))
        .expect(1)
        .mount(&tlog_server)
        .await;

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");

    let audit = Arc::new(VecAudit::default());

    let config = ReconcilerConfig {
        image_repository: image.to_string(),
        interval_seconds: 60,
        manifest_url: format!("{}/manifest", manifest_server.uri()),
        release_verifying_key: verifying,
        manifest_staleness_seconds: DEFAULT_MANIFEST_STALENESS_SECONDS,
        transparency_log_url: format!("{}/v1/append", tlog_server.uri()),
    };

    let r = Reconciler::new(
        config.clone(),
        Arc::new(FixedClock(now as f64)),
        Arc::new(StubRegistry(running.to_string())),
        Arc::new(HttpManifestFetcher::new(http.clone())),
        audit.clone(),
        Arc::new(HttpTransparencyLogClient::new(
            http,
            config.transparency_log_url.clone(),
        )),
    );

    let outcome = r.tick_once().await.expect("tick succeeds");
    assert!(
        matches!(outcome, TickOutcome::Drift {.. }),
        "expected Drift outcome, got {outcome:?}",
    );

    // Audit must capture the event.
    let snapshot = audit.events.lock().unwrap().clone();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].running_digest, running);
    assert_eq!(snapshot[0].expected_digest, expected);

    // Wiremock asserts on Drop that exact-count expectations were met
    // — if the transparency-log POST didn't fire, drop-time panics.
}

/// HTTP-layer counterpart to the in-file
/// `transparency_log_unavailable_does_not_block_polling`: a real
/// reqwest call to a server that 500s must NOT abort the tick.
#[tokio::test]
async fn http_transparency_log_500_does_not_block_polling() {
    let (signing, verifying) = test_keypair();
    let now: u64 = 1_700_000_000;
    let image = "aryalabs/safety-kernel";
    let expected = "sha256:expected";
    let running = "sha256:running";
    let manifest_body = signed_manifest_json(&signing, image, expected, now);

    let manifest_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/manifest"))
        .respond_with(ResponseTemplate::new(200).set_body_string(manifest_body))
        .mount(&manifest_server)
        .await;

    // Transparency-log server returns 500 — the HttpTransparencyLogClient
    // surfaces that as Err, which the reconciler must downgrade to WARN.
    let tlog_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/append"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&tlog_server)
        .await;

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");

    let audit = Arc::new(VecAudit::default());

    let config = ReconcilerConfig {
        image_repository: image.to_string(),
        interval_seconds: 60,
        manifest_url: format!("{}/manifest", manifest_server.uri()),
        release_verifying_key: verifying,
        manifest_staleness_seconds: DEFAULT_MANIFEST_STALENESS_SECONDS,
        transparency_log_url: format!("{}/v1/append", tlog_server.uri()),
    };

    let r = Reconciler::new(
        config.clone(),
        Arc::new(FixedClock(now as f64)),
        Arc::new(StubRegistry(running.to_string())),
        Arc::new(HttpManifestFetcher::new(http.clone())),
        audit.clone(),
        Arc::new(HttpTransparencyLogClient::new(
            http,
            config.transparency_log_url.clone(),
        )),
    );

    let outcome = r
        .tick_once()
        .await
        .expect("tick must not error even with 500 from t-log");
    assert!(
        matches!(outcome, TickOutcome::Drift {.. }),
        "drift must still be reported when t-log is 500",
    );
    // Local audit still captures it — the durable trail of last
    // resort.
    assert_eq!(audit.events.lock().unwrap().len(), 1);
}
