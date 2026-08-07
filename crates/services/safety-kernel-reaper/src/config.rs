//! Env-driven Reaper configuration.
//!
//! SAFETY defaults: `REAPER_ARMED` defaults to `false`, and there is no default
//! target instance — the Reaper refuses to start armed without an explicitly
//! configured scratch target, and never hardcodes a live agent VM.
//!
//! Secrets are read from the env by NAME (the `reaper` API key), never
//! hardcoded — the boot path hydrates the env from the secret store upstream.

use qorch_domain::safety::InstanceTarget;

use crate::executor::ProtectedCoord;

/// Fully-resolved Reaper configuration.
#[derive(Debug, Clone)]
pub struct ReaperConfig {
    /// Kernel HTTP root, e.g. `https://kernel:9000`.
    pub kernel_url: String,
    /// The `reaper` API key VALUE (already read from the env var named by
    /// `REAPER_API_KEY_ENV`). Never logged.
    pub reaper_api_key: String,
    /// Pinned verifying-key bytes (32) — loaded from hex or a file at deploy.
    pub pinned_pubkey: [u8; 32],
    /// The instance the Reaper watches + fail-closed-stops. In mock/scratch
    /// mode this is the disposable scratch instance.
    pub target: InstanceTarget,
    /// Poll cadence (seconds).
    pub poll_interval_s: f64,
    /// How long the kernel may be unreachable before failing closed.
    pub liveness_deadline_s: f64,
    /// Whether the cloud executor is armed. Default false. Only the operator
    /// flips this.
    pub armed: bool,
    /// The scratch instance the armed executor may touch (never the agent VM).
    pub scratch: Option<InstanceTarget>,
    /// Operator-configured protected instances the executor must NEVER
    /// stop/start (`REAPER_PROTECTED_INSTANCES`, comma-separated
    /// `project/instance`). This is in ADDITION to the Reaper's own host, which
    /// is self-identified from the metadata server at startup.
    pub protected_instances: Vec<ProtectedCoord>,
    /// Transparency-log root for kill-records (`None` = skip recording).
    pub tlog_url: Option<String>,
    /// Transparency-log API key value (`None` unless `tlog_url` set).
    pub tlog_api_key: Option<String>,
    /// Path to the kernel's server CA/cert PEM to PIN the kernel connection.
    /// When `Some`, the Reaper trusts ONLY this CA for the kernel TLS
    /// handshake, so a MITM / lying kernel presenting a public-CA cert cannot
    /// suppress a kill by returning an empty pending list. When `None`, the
    /// connection falls back to the platform WebPKI roots and the boot path
    /// logs a loud LIVE-ARMING-PREREQUISITE warning.
    pub kernel_ca_path: Option<String>,
}

/// Errors resolving config from the environment.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required env var was missing or empty.
    #[error("missing required config: {0}")]
    Missing(String),
    /// The pinned key could not be decoded/read.
    #[error("invalid pinned verifying key: {0}")]
    PinnedKey(String),
    /// A protected-instance entry was malformed (expected `project/instance`).
    #[error("invalid REAPER_PROTECTED_INSTANCES entry: {0}")]
    ProtectedEntry(String),
    /// Armed without a scratch target — refused (never default to the agent VM).
    #[error("REAPER_ARMED=true but no scratch target configured; refusing to arm")]
    ArmedWithoutScratch,
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Load the 32-byte pinned key from `REAPER_PINNED_KEY_HEX` or, failing that, a
/// hex file at `REAPER_PINNED_KEY_PATH`.
fn load_pinned_key() -> Result<[u8; 32], ConfigError> {
    let hex_str = if let Some(h) = env_nonempty("REAPER_PINNED_KEY_HEX") {
        h
    } else if let Some(path) = env_nonempty("REAPER_PINNED_KEY_PATH") {
        std::fs::read_to_string(&path)
            .map_err(|e| ConfigError::PinnedKey(format!("read {path}: {e}")))?
    } else {
        return Err(ConfigError::Missing(
            "REAPER_PINNED_KEY_HEX or REAPER_PINNED_KEY_PATH".to_string(),
        ));
    };
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| ConfigError::PinnedKey(format!("hex decode: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ConfigError::PinnedKey(format!("expected 32 bytes, got {}", bytes.len())))?;
    Ok(arr)
}

/// Parse `REAPER_PROTECTED_INSTANCES` — a comma-separated list of
/// `project/instance` coordinates the executor must never act on.
fn parse_protected_instances() -> Result<Vec<ProtectedCoord>, ConfigError> {
    let Some(raw) = env_nonempty("REAPER_PROTECTED_INSTANCES") else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.splitn(2, '/');
        let project = parts.next().unwrap_or("").trim();
        let instance = parts.next().unwrap_or("").trim();
        if project.is_empty() || instance.is_empty() {
            return Err(ConfigError::ProtectedEntry(format!(
                "{entry:?} (expected project/instance)"
            )));
        }
        out.push(ProtectedCoord::new(project, instance));
    }
    Ok(out)
}

fn parse_f64(key: &str, default: f64) -> f64 {
    env_nonempty(key)
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(default)
}

impl ReaperConfig {
    /// Resolve config from the process environment.
    ///
    /// # Errors
    ///
    /// Returns `Err` if a required field is missing, the pinned key is
    /// unreadable, a protected-instance entry is malformed, or `REAPER_ARMED=true`
    /// without a scratch target.
    pub fn from_env() -> Result<Self, ConfigError> {
        let kernel_url = env_nonempty("REAPER_KERNEL_URL")
            .ok_or_else(|| ConfigError::Missing("REAPER_KERNEL_URL".to_string()))?;

        // The reaper API key is read by NAME (default the worker-key sibling
        // name), never hardcoded.
        let key_env = env_nonempty("REAPER_API_KEY_ENV")
            .unwrap_or_else(|| "QORCH_KERNEL_API_KEY_REAPER".to_string());
        let reaper_api_key = env_nonempty(&key_env)
            .ok_or_else(|| ConfigError::Missing(format!("{key_env} (reaper API key)")))?;

        let pinned_pubkey = load_pinned_key()?;

        let target = InstanceTarget {
            project: env_nonempty("REAPER_TARGET_PROJECT")
                .ok_or_else(|| ConfigError::Missing("REAPER_TARGET_PROJECT".to_string()))?,
            zone: env_nonempty("REAPER_TARGET_ZONE")
                .ok_or_else(|| ConfigError::Missing("REAPER_TARGET_ZONE".to_string()))?,
            instance: env_nonempty("REAPER_TARGET_INSTANCE")
                .ok_or_else(|| ConfigError::Missing("REAPER_TARGET_INSTANCE".to_string()))?,
        };

        let armed = env_nonempty("REAPER_ARMED")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let scratch = match (
            env_nonempty("REAPER_SCRATCH_PROJECT"),
            env_nonempty("REAPER_SCRATCH_ZONE"),
            env_nonempty("REAPER_SCRATCH_INSTANCE"),
        ) {
            (Some(project), Some(zone), Some(instance)) => Some(InstanceTarget {
                project,
                zone,
                instance,
            }),
            _ => None,
        };

        if armed && scratch.is_none() {
            return Err(ConfigError::ArmedWithoutScratch);
        }

        let protected_instances = parse_protected_instances()?;

        let tlog_url = env_nonempty("REAPER_TLOG_URL");
        let tlog_api_key = tlog_url.as_ref().and_then(|_| {
            let name = env_nonempty("REAPER_TLOG_API_KEY_ENV")
                .unwrap_or_else(|| "QORCH_TRANSPARENCY_API_KEY".to_string());
            env_nonempty(&name)
        });

        Ok(Self {
            kernel_url,
            reaper_api_key,
            pinned_pubkey,
            target,
            poll_interval_s: parse_f64("REAPER_POLL_INTERVAL_S", 15.0),
            liveness_deadline_s: parse_f64("REAPER_LIVENESS_DEADLINE_S", 300.0),
            armed,
            scratch,
            protected_instances,
            tlog_url,
            tlog_api_key,
            kernel_ca_path: env_nonempty("REAPER_KERNEL_CA_PATH"),
        })
    }
}
