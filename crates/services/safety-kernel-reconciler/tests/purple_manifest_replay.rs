//!   — Purple-Team adversarial tests for the
//! reconciler signed-manifest verification path.
//!
//! Campaigns:
//!   D1 — Replay attack: old signed release manifest (issued_at
//!        N days ago, N > staleness threshold) MUST be rejected
//!        as `ExpiredManifest`. Counter-assertion: a fresh manifest
//!        for the same digest is accepted.
//!   D2 — Registry-MITM: the OCI registry returns a digest that
//!        differs from the manifest (drift). The reconciler MUST
//!        emit a Drift outcome AND a local audit event AND a
//!        transparency-log POST. A reconciler-side audit ledger
//!        captures the event independent of the t-log being
//!        reachable.
//!
//! Additional adversarial variants exercised:
//!   D2b — Attacker tampers the manifest signature byte → BadSignature
//!   D2c — Attacker tampers `digest` field after signing → BadSignature
//!         (signature covers digest)
//!   D2d — Attacker submits a manifest for a different image with a
//!         valid signature → ImageMismatch
//!
//! Topology: the reconciler exposes traits (`RegistryClient`,
//! `ManifestFetcher`, `AuditSink`, `TransparencyLogClient`); we plug
//! in vec-backed stubs and assert post-conditions on the snapshot.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::doc_markdown, clippy::doc_lazy_continuation)]

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};

use qorch_domain::safety::Clock;
use qorch_safety_kernel_reconciler::reconciler::{
    AuditSink, DriftAuditEvent, ManifestFetcher, ReconcileError, Reconciler, ReconcilerConfig,
    RegistryClient, ReleaseManifest, TickOutcome, TransparencyLogClient,
    DEFAULT_MANIFEST_STALENESS_SECONDS,
};

// ---------------------------------------------------------------------------
// Fixed-clock + vec-backed stubs (mirror the internal unit-test shapes
// since they're not pub-exported)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct FixedClock(f64);
impl Clock for FixedClock {
    fn now(&self) -> f64 {
        self.0
    }
}

struct StubRegistry(String);
#[async_trait]
impl RegistryClient for StubRegistry {
    async fn fetch_running_digest(&self, _image_ref: &str) -> Result<String> {
        Ok(self.0.clone())
    }
}

struct StubManifestFetcher(Vec<u8>);
#[async_trait]
impl ManifestFetcher for StubManifestFetcher {
    async fn fetch(&self, _url: &str) -> Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}

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
impl VecAudit {
    fn snapshot(&self) -> Vec<DriftAuditEvent> {
        self.events.lock().unwrap().clone()
    }
}

#[derive(Default)]
struct VecTlog {
    events: Mutex<Vec<DriftAuditEvent>>,
    fail: bool,
}
#[async_trait]
impl TransparencyLogClient for VecTlog {
    async fn post_drift_event(&self, event: &DriftAuditEvent) -> Result<()> {
        if self.fail {
            return Err(anyhow!("transparency-log unavailable (purple stub)"));
        }
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
}
impl VecTlog {
    fn snapshot(&self) -> Vec<DriftAuditEvent> {
        self.events.lock().unwrap().clone()
    }
    fn failing() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            fail: true,
        }
    }
}

fn test_keypair() -> (SigningKey, VerifyingKey) {
    let seed = [7u8; SECRET_KEY_LENGTH];
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

/// Helper: serialize a release manifest with a valid Ed25519 signature
/// over the canonical bytes. The signature is over
/// `{digest,image,issued_at,version}` lex-sorted.
fn build_signed_manifest(
    signing: &SigningKey,
    image: &str,
    digest: &str,
    issued_at: u64,
) -> Vec<u8> {
    use serde_json::Value;
    use std::collections::BTreeMap;

    let mut signed_payload: BTreeMap<String, Value> = BTreeMap::new();
    signed_payload.insert("digest".into(), Value::String(digest.to_string()));
    signed_payload.insert("image".into(), Value::String(image.to_string()));
    signed_payload.insert("issued_at".into(), Value::Number(issued_at.into()));
    signed_payload.insert("version".into(), Value::String("v0.1.0".to_string()));
    let canonical = serde_json::to_vec(&signed_payload).expect("canonicalize");

    let sig = signing.sign(&canonical);
    let manifest = ReleaseManifest {
        image: image.to_string(),
        digest: digest.to_string(),
        version: "v0.1.0".to_string(),
        issued_at,
        signature: B64.encode(sig.to_bytes()),
    };
    serde_json::to_vec(&manifest).expect("serialize manifest")
}

fn cfg(verifying: VerifyingKey, image: &str) -> ReconcilerConfig {
    ReconcilerConfig {
        image_repository: image.to_string(),
        interval_seconds: 60,
        manifest_url: "https://example.invalid/manifest".to_string(),
        release_verifying_key: verifying,
        manifest_staleness_seconds: DEFAULT_MANIFEST_STALENESS_SECONDS,
        transparency_log_url: "https://example.invalid/v1/append".to_string(),
    }
}

// ---------------------------------------------------------------------------
// D1 — Replay attack: 30-day-old signed manifest MUST be rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn purple_d1_30_day_old_manifest_rejected_as_expired() {
    let (signing, verifying) = test_keypair();
    let image = "aryalabs/safety-kernel";
    let digest = "sha256:aaaa";

    // Manifest was issued 30 days ago — well past the 7-day staleness
    // threshold. Attacker (or compromised CDN) replays it at the
    // reconciler.
    let issued_at: u64 = 1_700_000_000;
    let now: u64 = issued_at + 30 * 24 * 60 * 60;
    let manifest_bytes = build_signed_manifest(&signing, image, digest, issued_at);

    let audit = Arc::new(VecAudit::default());
    let tlog = Arc::new(VecTlog::default());
    let r = Reconciler::new(
        cfg(verifying, image),
        Arc::new(FixedClock(now as f64)),
        Arc::new(StubRegistry(digest.to_string())),
        Arc::new(StubManifestFetcher(manifest_bytes)),
        audit.clone(),
        tlog.clone(),
    );

    let err = r
        .tick_once()
        .await
        .expect_err("30-day-old manifest replay must be rejected");
    assert!(
        matches!(err, ReconcileError::ExpiredManifest {.. }),
        "expected ExpiredManifest, got {err:?}"
    );
    assert!(
        audit.snapshot().is_empty(),
        "no audit event on expired manifest (no drift decision was made)",
    );
    assert!(
        tlog.snapshot().is_empty(),
        "no transparency-log post on expired manifest",
    );

    // Counter-assertion: a FRESH manifest (issued_at == now) is
    // accepted and either Match or Drift depending on digest.
    let fresh_bytes = build_signed_manifest(&signing, image, digest, now);
    let r2 = Reconciler::new(
        cfg(verifying, image),
        Arc::new(FixedClock(now as f64)),
        Arc::new(StubRegistry(digest.to_string())),
        Arc::new(StubManifestFetcher(fresh_bytes)),
        Arc::new(VecAudit::default()),
        Arc::new(VecTlog::default()),
    );
    let outcome = r2.tick_once().await.expect("fresh manifest must verify");
    assert_eq!(outcome, TickOutcome::Match, "fresh same-digest must be Match");
}

// ---------------------------------------------------------------------------
// D2 — Registry-MITM: the registry returns a digest different from the
// signed manifest. The reconciler MUST detect drift, emit an audit
// event, and POST to the transparency log.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn purple_d2_registry_returns_different_digest_drift_detected() {
    let (signing, verifying) = test_keypair();
    let image = "aryalabs/safety-kernel";
    let expected = "sha256:legitimate-release-digest";
    let running = "sha256:ATTACKER-INJECTED-IMAGE";
    let now: u64 = 1_700_000_000;
    let manifest_bytes = build_signed_manifest(&signing, image, expected, now);

    let audit = Arc::new(VecAudit::default());
    let tlog = Arc::new(VecTlog::default());
    let r = Reconciler::new(
        cfg(verifying, image),
        Arc::new(FixedClock(now as f64)),
        Arc::new(StubRegistry(running.to_string())),
        Arc::new(StubManifestFetcher(manifest_bytes)),
        audit.clone(),
        tlog.clone(),
    );

    let outcome = r.tick_once().await.expect("tick must succeed");
    match outcome {
        TickOutcome::Drift {
            running: r1,
            expected: e1,
        } => {
            assert_eq!(r1, running);
            assert_eq!(e1, expected);
        }
        TickOutcome::Match => panic!("expected Drift, got Match"),
    }

    let snap = audit.snapshot();
    assert_eq!(snap.len(), 1, "exactly one audit event on drift");
    assert_eq!(snap[0].running_digest, running);
    assert_eq!(snap[0].expected_digest, expected);

    let tsnap = tlog.snapshot();
    assert_eq!(tsnap.len(), 1, "transparency-log MUST receive the drift POST");
    assert_eq!(tsnap[0], snap[0]);
}

// ---------------------------------------------------------------------------
// D2 follow-up: even when the transparency-log is unreachable, the
// local audit sink still captures the drift event. The reconciler is
// designed to keep polling even if the t-log is down (independent
// peer, not fail-closed). This documents that the drift signal is
// durable in TWO places (local audit + t-log), not just one.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn purple_d2_tlog_unreachable_drift_still_audited_locally() {
    let (signing, verifying) = test_keypair();
    let image = "aryalabs/safety-kernel";
    let expected = "sha256:legitimate";
    let running = "sha256:malicious";
    let now: u64 = 1_700_000_000;
    let manifest_bytes = build_signed_manifest(&signing, image, expected, now);

    let audit = Arc::new(VecAudit::default());
    let tlog = Arc::new(VecTlog::failing());
    let r = Reconciler::new(
        cfg(verifying, image),
        Arc::new(FixedClock(now as f64)),
        Arc::new(StubRegistry(running.to_string())),
        Arc::new(StubManifestFetcher(manifest_bytes)),
        audit.clone(),
        tlog.clone(),
    );

    let outcome = r.tick_once().await.expect("tick must not error");
    assert!(matches!(outcome, TickOutcome::Drift {.. }));
    assert_eq!(audit.snapshot().len(), 1, "local audit must capture the drift");
    assert!(tlog.snapshot().is_empty(), "failing t-log records nothing");
}

// ---------------------------------------------------------------------------
// D2b — Manifest signature tamper (1-byte flip in signature bytes)
//        MUST be rejected as BadSignature
// ---------------------------------------------------------------------------

#[tokio::test]
async fn purple_d2b_signature_tamper_rejected() {
    let (signing, verifying) = test_keypair();
    let image = "aryalabs/safety-kernel";
    let digest = "sha256:aaaa";
    let now: u64 = 1_700_000_000;

    let mut bytes = build_signed_manifest(&signing, image, digest, now);
    // Parse, flip a sig byte, re-serialise.
    let mut manifest: ReleaseManifest = serde_json::from_slice(&bytes).unwrap();
    let mut sig_decoded = B64.decode(&manifest.signature).unwrap();
    sig_decoded[0] ^= 0xff;
    manifest.signature = B64.encode(&sig_decoded);
    bytes = serde_json::to_vec(&manifest).unwrap();

    let r = Reconciler::new(
        cfg(verifying, image),
        Arc::new(FixedClock(now as f64)),
        Arc::new(StubRegistry(digest.to_string())),
        Arc::new(StubManifestFetcher(bytes)),
        Arc::new(VecAudit::default()),
        Arc::new(VecTlog::default()),
    );

    let err = r.tick_once().await.expect_err("tampered sig must be rejected");
    assert!(matches!(err, ReconcileError::BadSignature));
}

// ---------------------------------------------------------------------------
// D2c — Manifest digest field tampered AFTER signing → BadSignature
//        (the signature covers the digest, so any post-sign edit
//        invalidates verification)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn purple_d2c_digest_field_tamper_post_signing_rejected() {
    let (signing, verifying) = test_keypair();
    let image = "aryalabs/safety-kernel";
    let digest = "sha256:legitimate";
    let now: u64 = 1_700_000_000;

    let mut bytes = build_signed_manifest(&signing, image, digest, now);
    let mut manifest: ReleaseManifest = serde_json::from_slice(&bytes).unwrap();
    // Attacker swaps the digest to point at THEIR image, keeps the
    // original (legitimate) signature.
    manifest.digest = "sha256:ATTACKER-INJECTED".to_string();
    bytes = serde_json::to_vec(&manifest).unwrap();

    let r = Reconciler::new(
        cfg(verifying, image),
        Arc::new(FixedClock(now as f64)),
        Arc::new(StubRegistry(digest.to_string())),
        Arc::new(StubManifestFetcher(bytes)),
        Arc::new(VecAudit::default()),
        Arc::new(VecTlog::default()),
    );

    let err = r.tick_once().await.expect_err("post-sign digest tamper must be rejected");
    assert!(matches!(err, ReconcileError::BadSignature));
}

// ---------------------------------------------------------------------------
// D2d — Wrong-image manifest replay: a valid signature for a different
//        image is REJECTED because the reconciler binds to a specific
//        image_repository. Stops a "manifest for image B replayed at
//        a reconciler watching image A" attack.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn purple_d2d_wrong_image_manifest_rejected_image_mismatch() {
    let (signing, verifying) = test_keypair();
    let configured = "aryalabs/safety-kernel";
    let manifest_image = "aryalabs/some-other-service";
    let digest = "sha256:aaaa";
    let now: u64 = 1_700_000_000;
    let bytes = build_signed_manifest(&signing, manifest_image, digest, now);

    let r = Reconciler::new(
        cfg(verifying, configured),
        Arc::new(FixedClock(now as f64)),
        Arc::new(StubRegistry(digest.to_string())),
        Arc::new(StubManifestFetcher(bytes)),
        Arc::new(VecAudit::default()),
        Arc::new(VecTlog::default()),
    );

    let err = r.tick_once().await.expect_err("wrong-image manifest must be rejected");
    assert!(matches!(err, ReconcileError::ImageMismatch {.. }));
}
