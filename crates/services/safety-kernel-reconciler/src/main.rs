//! Safety Kernel reconciler service — running-image-vs-manifest drift
//! detector (,  Step 3).
//!
//! Step 3 wires the binary entry point: read env (NO env reads inside
//! the algorithm), construct the production adapters
//! (`OciRegistryClient`, `HttpManifestFetcher`, `HttpTransparencyLogClient`,
//! a local `SystemClock`, a `FileAuditSink`), and hand them to
//! `Reconciler::run_forever`.
//!
//! Env contract:
//!   `QORCH_RECONCILER_IMAGE`                   image reference (repo[:tag])
//!   `QORCH_RECONCILER_MANIFEST_URL`            HTTPS URL of signed manifest
//!   `QORCH_RECONCILER_TRANSPARENCY_LOG_URL`    HTTPS URL of t-log /v1/append
//!   `QORCH_RECONCILER_RELEASE_KEY_B64`         base64(32-byte Ed25519 pub key)
//!   `QORCH_RECONCILER_INTERVAL_SECONDS`        optional (default 900)
//!   `QORCH_RECONCILER_MANIFEST_MAX_AGE_SECONDS`  optional (default 7d)
//!   `QORCH_RECONCILER_AUDIT_LOG_PATH`          optional (default./reconciler-audit.log)

#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use qorch_domain::safety::Clock;
use qorch_safety_kernel_reconciler::{
    AuditSink, DriftAuditEvent, HttpManifestFetcher, HttpTransparencyLogClient, OciRegistryClient,
    Reconciler, ReconcilerConfig, DEFAULT_INTERVAL_SECONDS, DEFAULT_MANIFEST_STALENESS_SECONDS,
};

/// Production `Clock` — wall-clock as f64 epoch seconds. Mirrors
/// `crates/adapters/src/clock.rs::SystemClock` but kept local so the
/// reconciler crate doesn't have to pull in the full adapters crate
/// just for a single `now()` reader.
#[derive(Debug, Default, Clone, Copy)]
struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64())
    }
}

/// File-backed audit sink — one JSON line per drift event. The
/// reconciler's primary durable trail is the transparency-log; this
/// sink exists for the case where the transparency-log itself is
/// unreachable. JSON-lines so the file is greppable.
struct FileAuditSink {
    inner: Mutex<tokio::fs::File>,
}

impl FileAuditSink {
    async fn open(path: &PathBuf) -> Result<Self> {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .with_context(|| format!("open audit log at {}", path.display()))?;
        Ok(Self {
            inner: Mutex::new(file),
        })
    }
}

#[async_trait]
impl AuditSink for FileAuditSink {
    async fn append(&self, event: &DriftAuditEvent) -> Result<()> {
        let mut line = serde_json::to_vec(event).context("serialize drift event")?;
        line.push(b'\n');
        let mut g = self.inner.lock().await;
        g.write_all(&line)
            .await
            .context("write drift event to audit log")?;
        g.flush().await.context("flush audit log")?;
        Ok(())
    }
}

fn read_env_or_err(key: &str) -> Result<String> {
    env::var(key).map_err(|_| anyhow!("missing required env var {key}"))
}

fn read_env_or_default(key: &str, default_value: u64) -> Result<u64> {
    match env::var(key) {
        Ok(v) => v
            .parse::<u64>()
            .map_err(|e| anyhow!("env {key} must be u64: {e}")),
        Err(_) => Ok(default_value),
    }
}

fn load_verifying_key() -> Result<VerifyingKey> {
    let b64 = read_env_or_err("QORCH_RECONCILER_RELEASE_KEY_B64")?;
    let bytes = B64
        .decode(b64.trim())
        .context("QORCH_RECONCILER_RELEASE_KEY_B64 must be base64")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("QORCH_RECONCILER_RELEASE_KEY_B64 must decode to 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| anyhow!("invalid Ed25519 verifying key: {e}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Same `RUST_LOG`-driven layer the kernel uses, so the reconciler's
    // logs land in the same observability pipeline.
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer())
        .init();

    let config = ReconcilerConfig {
        image_repository: read_env_or_err("QORCH_RECONCILER_IMAGE")?,
        interval_seconds: read_env_or_default(
            "QORCH_RECONCILER_INTERVAL_SECONDS",
            DEFAULT_INTERVAL_SECONDS,
        )?,
        manifest_url: read_env_or_err("QORCH_RECONCILER_MANIFEST_URL")?,
        release_verifying_key: load_verifying_key()?,
        manifest_staleness_seconds: read_env_or_default(
            "QORCH_RECONCILER_MANIFEST_MAX_AGE_SECONDS",
            DEFAULT_MANIFEST_STALENESS_SECONDS,
        )?,
        transparency_log_url: read_env_or_err("QORCH_RECONCILER_TRANSPARENCY_LOG_URL")?,
    };

    let audit_log_path: PathBuf = env::var("QORCH_RECONCILER_AUDIT_LOG_PATH")
        .unwrap_or_else(|_| "./reconciler-audit.log".to_string())
        .into();

    tracing::info!(
        target = "qorch.safety_kernel_reconciler",
        step = "step-3",
        adr = "adr-014-phase-3",
        linear = "",
        image = %config.image_repository,
        interval_seconds = config.interval_seconds,
        manifest_url = %config.manifest_url,
        transparency_log_url = %config.transparency_log_url,
        audit_log_path = %audit_log_path.display(),
        "reconciler: starting polling loop",
    );

    // Shared HTTP client for the manifest fetcher + transparency-log
    // poster. Reusing a single client gets us connection pooling and
    // the workspace's pinned `rustls-tls` config (no OpenSSL).
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("build reqwest client")?;

    let reconciler = Reconciler::new(
        config.clone(),
        Arc::new(SystemClock),
        Arc::new(OciRegistryClient::new()),
        Arc::new(HttpManifestFetcher::new(http.clone())),
        Arc::new(FileAuditSink::open(&audit_log_path).await?),
        Arc::new(HttpTransparencyLogClient::new(
            http,
            config.transparency_log_url.clone(),
        )),
    );

    Arc::new(reconciler).run_forever().await
}
