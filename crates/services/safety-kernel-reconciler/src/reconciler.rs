//! Reconciler core — running-image-vs-signed-manifest drift detector
//! (,  Step 3).
//!
//! 3-step algorithm:
//!
//!   1. Pull the running kernel image digest via `oci-distribution`'s
//!      direct registry query (HEAD on the manifest, `Docker-Content-
//!      Digest`). This avoids mounting the Docker socket on the
//!      reconciler — smaller attack surface than `bollard`-style
//!      runtime queries. If multiple kernel replicas are deployed,
//!      the reconciler samples one image-tag pair per tick; an
//!      operator who wants per-replica drift detection runs one
//!      reconciler instance per replica.
//!   2. Fetch the expected digest from a signed release manifest.
//!      Manifest is canonical JSON (lexicographic key order via
//!      `BTreeMap`, matching Addendum 2a §5) signed by
//!      a pinned Ed25519 verifying key passed in at construction.
//!   3. Compare. On drift: emit `tracing::error!` with structured
//!      fields, write a local audit-log entry, and POST to the
//!      transparency log via a small trait so callers (and tests)
//!      can substitute the transport.
//!
//! Boundary contract per `agent/boundaries.toml`: this crate is a
//! service, not domain. `reqwest::`, `tracing::`, `std::time::*`
//! etc. are allowed here. The domain crate must not import from
//! this module.
//!
//! Clock injection uses the `Clock` trait at
//! `crates/domain/src/safety/mod.rs:65` — `f64` epoch seconds per
//!  Appendix B. We truncate to u64 when constructing
//! the transparency-log payload, which is u64-keyed.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::{client::ClientConfig, Reference};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use qorch_domain::safety::Clock;

/// Maximum age of a signed release manifest, in seconds, before the
/// reconciler treats it as stale and refuses to make a drift decision.
/// 7 days mirrors the cosign rekor-staleness ceiling; the reconciler
/// is a continuously-running service, so a manifest older than this
/// either means publishing has been broken for a week (operator
/// problem, not a kernel-drift problem) or someone is replaying an
/// ancient manifest at us.
pub const DEFAULT_MANIFEST_STALENESS_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Default reconcile interval — 15 minutes 
pub const DEFAULT_INTERVAL_SECONDS: u64 = 900;

/// Configuration shared across `Reconciler` instances. Values come
/// from env in `main.rs`; no env reads happen inside this module
/// (testability + boundary cleanliness).
#[derive(Clone)]
pub struct ReconcilerConfig {
    /// Fully-qualified image reference (e.g.
    /// `aryalabs/safety-kernel:latest`). Parsed via
    /// `oci_distribution::Reference::try_from` at tick time.
    pub image_repository: String,

    /// How often the polling loop ticks, in seconds.
    pub interval_seconds: u64,

    /// HTTPS URL of the signed release manifest. Plain `http://` is
    /// permitted only when explicitly configured for local tests; the
    /// reconciler does NOT enforce a scheme here — the boundary check
    /// lives in `main.rs` where env is read.
    pub manifest_url: String,

    /// Ed25519 verifying key pinned to the release-signing identity.
    /// Constructed from `QORCH_RECONCILER_RELEASE_KEY_B64` in main.rs.
    pub release_verifying_key: VerifyingKey,

    /// Maximum age of a manifest `issued_at` before the reconciler
    /// rejects it as stale. Defaults to
    /// `DEFAULT_MANIFEST_STALENESS_SECONDS`.
    pub manifest_staleness_seconds: u64,

    /// URL of the transparency-log `/v1/append` endpoint. The default
    /// `TransparencyLogClient` impl posts drift events here; the
    /// trait can be swapped for testing.
    pub transparency_log_url: String,
}

/// Outcome of a single reconcile tick — used by `tick_once` so unit
/// tests can assert on the high-level decision without observing the
/// alert sink directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TickOutcome {
    /// Running digest matches expected; no action required.
    Match,
    /// Running digest != expected; drift alert was emitted.
    Drift {
        /// Digest pulled from the registry HEAD.
        running: String,
        /// Digest from the signed release manifest.
        expected: String,
    },
}

/// Wire-shape of the signed release manifest. Field ordering here is
/// purely for human readability; canonical serialization uses a
/// `BTreeMap<String, Value>` (lexicographic) so the signature is
/// stable across encoders.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseManifest {
    /// Image repository the digest applies to.
    pub image: String,
    /// Expected digest (`sha256:...` form).
    pub digest: String,
    /// Release version tag (e.g. `v0.1.4`).
    pub version: String,
    /// Wall-clock instant the manifest was issued (epoch seconds).
    pub issued_at: u64,
    /// Base64-encoded Ed25519 signature over the canonical JSON of the
    /// signed payload (`image`, `digest`, `version`, `issued_at`).
    pub signature: String,
}

impl ReleaseManifest {
    /// Build the canonical JSON byte sequence that the signature
    /// covers. Lexicographic key order, no trailing whitespace.
    ///
    /// Per Addendum 2a §5 we use `BTreeMap<String,
    /// Value>` rather than `serde_json` `preserve_order`, so the
    /// stability property is structural (`BTreeMap` iterates sorted)
    /// rather than encoder-feature-gated.
    fn canonical_signed_bytes(&self) -> Result<Vec<u8>> {
        let mut map: BTreeMap<String, Value> = BTreeMap::new();
        map.insert("digest".into(), Value::String(self.digest.clone()));
        map.insert("image".into(), Value::String(self.image.clone()));
        map.insert("issued_at".into(), Value::Number(self.issued_at.into()));
        map.insert("version".into(), Value::String(self.version.clone()));
        serde_json::to_vec(&map).context("serialize canonical manifest bytes")
    }
}

/// Errors that can short-circuit a reconcile tick. Each variant is
/// observable + distinguishable from the test suite.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    /// The OCI registry query failed (network, auth, parse).
    #[error("registry query failed: {0}")]
    Registry(String),

    /// The signed-manifest HTTP fetch failed.
    #[error("manifest fetch failed: {0}")]
    ManifestFetch(String),

    /// The manifest body failed to parse as JSON.
    #[error("manifest parse failed: {0}")]
    ManifestParse(String),

    /// The Ed25519 signature did not verify against the pinned key.
    /// FAIL-CLOSED: no drift decision is made when the signature is
    /// bad, because the manifest is untrusted.
    #[error("manifest signature did not verify with pinned key")]
    BadSignature,

    /// The manifest `issued_at` is older than
    /// `manifest_staleness_seconds` ago. FAIL-CLOSED: stale manifests
    /// are treated as un-decidable.
    #[error("manifest expired: issued {issued_at}s, now {now}s, max age {max_age}s")]
    ExpiredManifest {
        /// Manifest `issued_at` value.
        issued_at: u64,
        /// Current wall-clock time at the tick.
        now: u64,
        /// Configured staleness threshold.
        max_age: u64,
    },

    /// The manifest is correctly signed but refers to a different
    /// image than the one the reconciler is configured to watch.
    #[error("manifest image {manifest_image:?} != configured {configured:?}")]
    ImageMismatch {
        /// `image` field from the verified manifest.
        manifest_image: String,
        /// Image repository from `ReconcilerConfig::image_repository`.
        configured: String,
    },
}

/// Local audit-log sink for drift events. The default impl in
/// `main.rs` writes to a structured-log file; tests inject a vec-
/// backed sink.
///
/// Decoupled from the kernel's `policy_engine_client::AuditAppendRequest`
/// because the reconciler does NOT speak to the kernel's policy
/// engine — it only emits its own drift-event audit shape. The
/// transparency-log POST is the durable trail; this local log exists
/// for the case where the transparency-log itself is unreachable.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Append a single drift-event audit record. Implementations
    /// should treat I/O failures as warnings — the reconciler keeps
    /// polling regardless.
    async fn append(&self, event: &DriftAuditEvent) -> Result<()>;
}

/// Structured audit record emitted on every drift detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftAuditEvent {
    /// `sha256:...` of the digest currently running in the cluster.
    pub running_digest: String,
    /// `sha256:...` of the digest the signed release manifest
    /// commits to.
    pub expected_digest: String,
    /// Wall-clock instant the drift was detected (epoch seconds).
    pub detected_at_epoch_seconds: u64,
    /// `image` field from the verified manifest (for cross-checking).
    pub image_repository: String,
    /// `version` field from the verified manifest (release tag).
    pub manifest_version: String,
}

/// Transparency-log POST surface. Production binds this to a reqwest
/// client hitting `/v1/append`; tests inject a stub that fails so the
/// `transparency_log_unavailable_does_not_block_polling` case is
/// observable. Per ADR §6 the transparency-log /v1/append endpoint is
/// fail-CLOSED for kernel /authorize traffic — but the reconciler is
/// NOT an authorize caller and its drift events are independently
/// durable in the local audit sink; a transparency-log outage logs
/// WARN and continues polling.
#[async_trait]
pub trait TransparencyLogClient: Send + Sync {
    /// POST a drift event to the transparency-log. Returns Ok on
    /// successful append, Err otherwise. The reconciler converts
    /// Err into a `tracing::warn!` and continues.
    async fn post_drift_event(&self, event: &DriftAuditEvent) -> Result<()>;
}

/// OCI registry query surface — abstracted so unit tests can inject
/// a fixed running-digest without spinning up a real registry.
#[async_trait]
pub trait RegistryClient: Send + Sync {
    /// Fetch the manifest digest for `image_ref`. Returns the raw
    /// `sha256:...` string.
    async fn fetch_running_digest(&self, image_ref: &str) -> Result<String>;
}

/// Production `RegistryClient` backed by `oci_distribution::Client`.
///
/// Constructed lazily in `main.rs`; tests use a stub instead.
pub struct OciRegistryClient {
    inner: oci_distribution::Client,
}

impl OciRegistryClient {
    /// Default construction — HTTPS, no client certs, anonymous auth.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: oci_distribution::Client::new(ClientConfig::default()),
        }
    }
}

impl Default for OciRegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RegistryClient for OciRegistryClient {
    async fn fetch_running_digest(&self, image_ref: &str) -> Result<String> {
        let reference: Reference = image_ref
            .parse()
            .map_err(|e| anyhow!("invalid image reference {image_ref}: {e}"))?;
        self.inner
            .fetch_manifest_digest(&reference, &RegistryAuth::Anonymous)
            .await
            .map_err(|e| anyhow!("oci fetch_manifest_digest failed: {e}"))
    }
}

/// HTTP-backed transparency-log client. Posts the drift event as
/// JSON; treats any non-2xx response as Err so the reconciler logs
/// WARN and keeps polling.
pub struct HttpTransparencyLogClient {
    inner: reqwest::Client,
    endpoint: String,
}

impl HttpTransparencyLogClient {
    /// Construct from a pre-built reqwest client (so the caller picks
    /// the TLS config + connection pool) and the endpoint URL.
    #[must_use]
    pub fn new(inner: reqwest::Client, endpoint: String) -> Self {
        Self { inner, endpoint }
    }
}

#[async_trait]
impl TransparencyLogClient for HttpTransparencyLogClient {
    async fn post_drift_event(&self, event: &DriftAuditEvent) -> Result<()> {
        let resp = self
            .inner
            .post(&self.endpoint)
            .timeout(Duration::from_secs(5))
            .json(event)
            .send()
            .await
            .map_err(|e| anyhow!("transparency-log POST failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "transparency-log returned non-success: {}",
                resp.status()
            ));
        }
        Ok(())
    }
}

/// HTTP-backed manifest fetcher — the small seam that exists so the
/// wiremock test suite can stand up a mock manifest server without
/// reaching for live HTTPS.
#[async_trait]
pub trait ManifestFetcher: Send + Sync {
    /// GET the manifest at `url` and return the raw JSON bytes.
    async fn fetch(&self, url: &str) -> Result<Vec<u8>>;
}

/// Production `ManifestFetcher` — reqwest with a 5-second timeout
/// per fetch. Matches the `SafetyKernelClient`'s transport budget so
/// the reconciler's polling cadence stays predictable.
pub struct HttpManifestFetcher {
    inner: reqwest::Client,
}

impl HttpManifestFetcher {
    /// Construct from a pre-built reqwest client.
    #[must_use]
    pub fn new(inner: reqwest::Client) -> Self {
        Self { inner }
    }
}

impl Default for HttpManifestFetcher {
    fn default() -> Self {
        Self::new(reqwest::Client::new())
    }
}

#[async_trait]
impl ManifestFetcher for HttpManifestFetcher {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self
            .inner
            .get(url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| anyhow!("manifest GET failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(anyhow!("manifest GET returned {}", resp.status()));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| anyhow!("manifest body read failed: {e}"))
    }
}

/// The reconciler itself. Single-instance per running kernel
/// deployment; `Arc<Reconciler>` is safe to share across tasks.
pub struct Reconciler {
    config: ReconcilerConfig,
    clock: Arc<dyn Clock>,
    registry: Arc<dyn RegistryClient>,
    manifest_fetcher: Arc<dyn ManifestFetcher>,
    audit: Arc<dyn AuditSink>,
    transparency_log: Arc<dyn TransparencyLogClient>,
}

impl Reconciler {
    /// Construct a `Reconciler` from its collaborators. The arity is
    /// deliberate — every collaborator is a trait object so the test
    /// suite can substitute each independently.
    #[must_use]
    pub fn new(
        config: ReconcilerConfig,
        clock: Arc<dyn Clock>,
        registry: Arc<dyn RegistryClient>,
        manifest_fetcher: Arc<dyn ManifestFetcher>,
        audit: Arc<dyn AuditSink>,
        transparency_log: Arc<dyn TransparencyLogClient>,
    ) -> Self {
        Self {
            config,
            clock,
            registry,
            manifest_fetcher,
            audit,
            transparency_log,
        }
    }

    /// Run the reconciler forever — `interval_seconds` between ticks.
    /// `tick_once` errors are downgraded to `tracing::warn!` and the
    /// loop continues; the reconciler does not terminate on transient
    /// failure. A real terminate signal must come from the runtime
    /// (SIGTERM, container stop).
    ///
    /// # Errors
    ///
    /// Returns `Err` only if the polling loop's initial setup fails;
    /// per-tick errors do not propagate.
    pub async fn run_forever(self: Arc<Self>) -> Result<()> {
        let mut tick =
            tokio::time::interval(Duration::from_secs(self.config.interval_seconds.max(1)));
        // Skip the first immediate tick semantics — we want the first
        // reconcile to run right away on boot, then settle into the
        // configured cadence.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match self.tick_once().await {
                Ok(TickOutcome::Match) => {
                    tracing::info!(
                        target = "qorch.safety_kernel_reconciler",
                        outcome = "match",
                        "reconciler tick: running digest matches signed manifest",
                    );
                }
                Ok(TickOutcome::Drift { running, expected }) => {
                    tracing::warn!(
                        target = "qorch.safety_kernel_reconciler",
                        outcome = "drift",
                        running_digest = %running,
                        expected_digest = %expected,
                        "reconciler tick: drift detected (alert emitted)",
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        target = "qorch.safety_kernel_reconciler",
                        error = %err,
                        "reconciler tick failed; continuing to next interval",
                    );
                }
            }
        }
    }

    /// Execute one reconcile step. Public for unit tests + the
    /// equivalence harness.
    ///
    /// # Errors
    ///
    /// Returns `ReconcileError` for any failure that prevents a
    /// drift decision (bad signature, expired manifest, image
    /// mismatch, registry/HTTP errors). Successful reconciles
    /// (match OR drift) return `Ok(TickOutcome::*)`.
    pub async fn tick_once(&self) -> Result<TickOutcome, ReconcileError> {
        let running = self
            .registry
            .fetch_running_digest(&self.config.image_repository)
            .await
            .map_err(|e| ReconcileError::Registry(e.to_string()))?;

        let manifest_bytes = self
            .manifest_fetcher
            .fetch(&self.config.manifest_url)
            .await
            .map_err(|e| ReconcileError::ManifestFetch(e.to_string()))?;

        let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| ReconcileError::ManifestParse(e.to_string()))?;

        self.verify_manifest(&manifest)?;
        self.check_freshness(&manifest)?;
        self.check_image(&manifest)?;

        if running == manifest.digest {
            return Ok(TickOutcome::Match);
        }

        // Drift path — emit alert + audit + transparency-log post.
        let detected_at = now_epoch_seconds_u64(self.clock.now());
        let event = DriftAuditEvent {
            running_digest: running.clone(),
            expected_digest: manifest.digest.clone(),
            detected_at_epoch_seconds: detected_at,
            image_repository: manifest.image.clone(),
            manifest_version: manifest.version.clone(),
        };

        // Structured error log — the alerting backbone tails this.
        tracing::error!(
            target = "qorch.safety_kernel_reconciler",
            running_digest = %event.running_digest,
            expected_digest = %event.expected_digest,
            drift_detected_at_epoch_seconds = event.detected_at_epoch_seconds,
            image_repository = %event.image_repository,
            manifest_version = %event.manifest_version,
            "kernel image drift detected",
        );

        // Local audit — best-effort. A failure here does NOT block
        // the transparency-log POST.
        if let Err(audit_err) = self.audit.append(&event).await {
            tracing::warn!(
                target = "qorch.safety_kernel_reconciler",
                error = %audit_err,
                "drift audit append failed; continuing",
            );
        }

        // Transparency-log POST — also best-effort per ADR §6
        // (reconciler ≠ authorize integration; reconciler drift events
        // stay durable in the local audit even when the t-log is down).
        if let Err(tlog_err) = self.transparency_log.post_drift_event(&event).await {
            tracing::warn!(
                target = "qorch.safety_kernel_reconciler",
                error = %tlog_err,
                "transparency-log POST failed; drift event persisted locally only",
            );
        }

        Ok(TickOutcome::Drift {
            running,
            expected: manifest.digest,
        })
    }

    /// Verify the manifest's Ed25519 signature against the pinned key.
    fn verify_manifest(&self, manifest: &ReleaseManifest) -> Result<(), ReconcileError> {
        let canonical = manifest
            .canonical_signed_bytes()
            .map_err(|e| ReconcileError::ManifestParse(format!("canonicalization: {e}")))?;
        let sig_bytes = B64
            .decode(&manifest.signature)
            .map_err(|_| ReconcileError::BadSignature)?;
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ReconcileError::BadSignature)?;
        let signature = Signature::from_bytes(&sig_array);
        self.config
            .release_verifying_key
            .verify(&canonical, &signature)
            .map_err(|_| ReconcileError::BadSignature)?;
        Ok(())
    }

    /// Reject manifests older than `manifest_staleness_seconds`.
    fn check_freshness(&self, manifest: &ReleaseManifest) -> Result<(), ReconcileError> {
        let now = now_epoch_seconds_u64(self.clock.now());
        // Tolerate small forward clock skew (manifest issued slightly
        // in the future) by computing on absolute difference, but only
        // for the past direction. Future-dated manifests will simply
        // pass through here (they aren't "stale"); if a malicious
        // future-dated manifest got past signature verification, the
        // pinned-key compromise is the bigger problem.
        if now >= manifest.issued_at && now - manifest.issued_at > self.config.manifest_staleness_seconds {
            return Err(ReconcileError::ExpiredManifest {
                issued_at: manifest.issued_at,
                now,
                max_age: self.config.manifest_staleness_seconds,
            });
        }
        Ok(())
    }

    /// Reject manifests whose `image` field doesn't match the
    /// configured `image_repository` (tag-stripped comparison). This
    /// stops a valid manifest for image B from being replayed at a
    /// reconciler watching image A.
    fn check_image(&self, manifest: &ReleaseManifest) -> Result<(), ReconcileError> {
        let manifest_image = strip_tag(&manifest.image);
        let configured = strip_tag(&self.config.image_repository);
        if manifest_image == configured {
            Ok(())
        } else {
            Err(ReconcileError::ImageMismatch {
                manifest_image: manifest_image.to_string(),
                configured: configured.to_string(),
            })
        }
    }
}

/// Strip everything from the first `:` onward — drops the tag (and
/// `@sha256:`-style digest references) so `aryalabs/safety-kernel:v1`
/// and `aryalabs/safety-kernel:v2` compare equal.
fn strip_tag(image: &str) -> &str {
    image.split_once(':').map_or(image, |(repo, _)| repo)
}

/// Convert `Clock::now()` (f64 epoch seconds) to u64 epoch seconds.
///
/// Saturating + sign-safe: negative or non-finite f64 floors to 0,
/// and values beyond `u64::MAX` saturate to `u64::MAX`. Real
/// wall-clock readings live in the safe `[0, 2^52]` range — the
/// guards exist to satisfy `clippy::cast_*` lints without
/// allow-listing the cast (audit signal: any cast here means we
/// genuinely thought about the boundary).
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn now_epoch_seconds_u64(now: f64) -> u64 {
    // `u64::MAX as f64` rounds to the nearest representable f64
    // (~1.8e19); that's exactly the boundary we want to compare
    // against. `cast_precision_loss` is the desired behaviour.
    let max_as_f64 = u64::MAX as f64;
    if !now.is_finite() || now <= 0.0 {
        0
    } else if now >= max_as_f64 {
        u64::MAX
    } else {
        now as u64
    }
}

// ---------------------------------------------------------------
// Unit tests live in the same file so they can reach the private
// helpers (`verify_manifest`, `check_freshness`, `check_image`). The
// wiremock-backed integration tests live in `tests/`.
// ---------------------------------------------------------------

#[cfg(test)]
#[allow(
    // Test fixtures use deterministic small u64 epoch values (~1.7e9)
    // that fit losslessly in f64. The cast is safe by construction;
    // allow-listing is preferable to wrapping every literal in a
    // helper because the test code's intent stays readable.
    clippy::cast_precision_loss,
    // Tests cast Vec lengths to usize comparisons — pedantic noise.
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
mod tests {
    use std::sync::Mutex;

    use ed25519_dalek::{Signer, SigningKey, SECRET_KEY_LENGTH};

    use super::*;

    /// Deterministic clock for unit tests.
    #[derive(Clone)]
    struct FixedClock(pub f64);
    impl Clock for FixedClock {
        fn now(&self) -> f64 {
            self.0
        }
    }

    /// Stub registry — returns a pre-canned digest.
    struct StubRegistry(pub String);
    #[async_trait]
    impl RegistryClient for StubRegistry {
        async fn fetch_running_digest(&self, _image_ref: &str) -> Result<String> {
            Ok(self.0.clone())
        }
    }

    /// Stub manifest fetcher — returns a pre-canned byte sequence.
    struct StubManifestFetcher(pub Vec<u8>);
    #[async_trait]
    impl ManifestFetcher for StubManifestFetcher {
        async fn fetch(&self, _url: &str) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    /// Vec-backed audit sink — exposes a snapshot for assertions.
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

    /// Vec-backed transparency-log client.
    #[derive(Default)]
    struct VecTlog {
        events: Mutex<Vec<DriftAuditEvent>>,
        fail: bool,
    }
    #[async_trait]
    impl TransparencyLogClient for VecTlog {
        async fn post_drift_event(&self, event: &DriftAuditEvent) -> Result<()> {
            if self.fail {
                return Err(anyhow!("transparency-log unavailable (stub)"));
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

    /// Deterministic Ed25519 keypair for tests. The 32-byte seed is
    /// fixed so the test never depends on a thread-RNG state.
    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let seed = [7u8; SECRET_KEY_LENGTH];
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    /// Build a manifest payload + a valid signature over its canonical
    /// bytes. Returns the JSON-serialized manifest.
    fn build_signed_manifest(
        signing: &SigningKey,
        image: &str,
        digest: &str,
        issued_at: u64,
    ) -> Vec<u8> {
        let mut manifest = ReleaseManifest {
            image: image.to_string(),
            digest: digest.to_string(),
            version: "v0.1.0".to_string(),
            issued_at,
            // Placeholder; we sign canonical_signed_bytes() of a
            // signature-free payload, then fill the field in.
            signature: String::new(),
        };
        let canonical = manifest.canonical_signed_bytes().expect("canonicalize");
        let sig = signing.sign(&canonical);
        manifest.signature = B64.encode(sig.to_bytes());
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

    #[tokio::test]
    async fn match_no_drift_no_alert() {
        let (signing, verifying) = test_keypair();
        let now: u64 = 1_700_000_000;
        let image = "aryalabs/safety-kernel";
        let digest = "sha256:aaaa";
        let manifest_bytes = build_signed_manifest(&signing, image, digest, now);

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

        let outcome = r.tick_once().await.expect("tick should succeed");
        assert_eq!(outcome, TickOutcome::Match);
        assert!(
            audit.snapshot().is_empty(),
            "no audit event should be emitted on match"
        );
        assert!(
            tlog.snapshot().is_empty(),
            "no transparency-log event should be emitted on match"
        );
    }

    #[tokio::test]
    async fn drift_detected_within_one_tick() {
        let (signing, verifying) = test_keypair();
        let now: u64 = 1_700_000_000;
        let image = "aryalabs/safety-kernel";
        let expected = "sha256:expected";
        let running = "sha256:running";
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

        let outcome = r.tick_once().await.expect("tick should succeed");
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

        let audit_snapshot = audit.snapshot();
        assert_eq!(audit_snapshot.len(), 1, "exactly one audit event on drift");
        assert_eq!(audit_snapshot[0].running_digest, running);
        assert_eq!(audit_snapshot[0].expected_digest, expected);
        assert_eq!(audit_snapshot[0].detected_at_epoch_seconds, now);

        let tlog_snapshot = tlog.snapshot();
        assert_eq!(
            tlog_snapshot.len(),
            1,
            "exactly one transparency-log post on drift"
        );
        assert_eq!(tlog_snapshot[0], audit_snapshot[0]);
    }

    #[tokio::test]
    async fn bad_signature_rejected() {
        let (signing, verifying) = test_keypair();
        let now: u64 = 1_700_000_000;
        let image = "aryalabs/safety-kernel";
        let digest = "sha256:aaaa";
        // Build a valid manifest, then tamper with the digest AFTER
        // signing — the signature now covers different bytes.
        let mut bytes = build_signed_manifest(&signing, image, digest, now);
        // Crude byte mutation: flip a byte in the digest portion of
        // the JSON; the signature is over canonical_signed_bytes()
        // which would no longer match.
        let mut manifest: ReleaseManifest =
            serde_json::from_slice(&bytes).expect("parse valid manifest");
        manifest.digest = "sha256:tampered".to_string();
        bytes = serde_json::to_vec(&manifest).unwrap();

        let audit = Arc::new(VecAudit::default());
        let tlog = Arc::new(VecTlog::default());
        let r = Reconciler::new(
            cfg(verifying, image),
            Arc::new(FixedClock(now as f64)),
            Arc::new(StubRegistry(digest.to_string())),
            Arc::new(StubManifestFetcher(bytes)),
            audit.clone(),
            tlog.clone(),
        );

        let err = r.tick_once().await.expect_err("should reject bad sig");
        assert!(matches!(err, ReconcileError::BadSignature));
        assert!(
            audit.snapshot().is_empty(),
            "no audit on signature failure (no decision was made)",
        );
        assert!(
            tlog.snapshot().is_empty(),
            "no transparency-log post on signature failure",
        );
    }

    #[tokio::test]
    async fn expired_manifest_rejected() {
        let (signing, verifying) = test_keypair();
        let issued_at: u64 = 1_700_000_000;
        // now is 8 days later — past the 7-day default staleness.
        let now: u64 = issued_at + 8 * 24 * 60 * 60;
        let image = "aryalabs/safety-kernel";
        let digest = "sha256:aaaa";
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

        let err = r.tick_once().await.expect_err("should reject expired");
        assert!(matches!(err, ReconcileError::ExpiredManifest {.. }));
        assert!(audit.snapshot().is_empty());
        assert!(tlog.snapshot().is_empty());
    }

    #[tokio::test]
    async fn transparency_log_unavailable_does_not_block_polling() {
        // Drift case + failing transparency-log: tick_once still
        // returns Ok(Drift), audit sink still receives the event,
        // and the failure is logged but does NOT propagate.
        let (signing, verifying) = test_keypair();
        let now: u64 = 1_700_000_000;
        let image = "aryalabs/safety-kernel";
        let expected = "sha256:expected";
        let running = "sha256:running";
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

        // Critical assertion: the reconciler's tick does NOT panic
        // and does NOT return Err — it returns Drift, proving the
        // reconciler is decoupled from the transparency-log's
        // fail-closed policy.
        let outcome = r.tick_once().await.expect("tick must not error");
        assert!(
            matches!(outcome, TickOutcome::Drift {.. }),
            "expected Drift outcome even with transparency-log down",
        );
        assert_eq!(
            audit.snapshot().len(),
            1,
            "local audit event must still be appended even when transparency-log is down",
        );
        assert!(
            tlog.snapshot().is_empty(),
            "failing transparency-log records nothing (failure path)",
        );
    }

    #[tokio::test]
    async fn image_mismatch_rejected() {
        // Even with a valid signature + fresh manifest, if the
        // manifest's `image` field disagrees with our configured
        // image_repository the reconciler refuses to make a drift
        // decision — stops a manifest replay from one image being
        // matched against another image's running digest.
        let (signing, verifying) = test_keypair();
        let now: u64 = 1_700_000_000;
        let configured = "aryalabs/safety-kernel";
        let manifest_image = "aryalabs/some-other-service";
        let digest = "sha256:aaaa";
        let manifest_bytes = build_signed_manifest(&signing, manifest_image, digest, now);

        let audit = Arc::new(VecAudit::default());
        let tlog = Arc::new(VecTlog::default());
        let r = Reconciler::new(
            cfg(verifying, configured),
            Arc::new(FixedClock(now as f64)),
            Arc::new(StubRegistry(digest.to_string())),
            Arc::new(StubManifestFetcher(manifest_bytes)),
            audit.clone(),
            tlog.clone(),
        );

        let err = r
            .tick_once()
            .await
            .expect_err("should reject image mismatch");
        assert!(matches!(err, ReconcileError::ImageMismatch {.. }));
        assert!(audit.snapshot().is_empty());
        assert!(tlog.snapshot().is_empty());
    }
}
