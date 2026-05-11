//! Env-driven settings layer — mirrors `apps/safety_kernel/config.py`.
//!
//! Per ADR-014 Slice 1, the Rust binary owns the HTTP boundary and
//! Ed25519 signing. The DB lives in the Python policy sidecar, so all
//! `db_*` and `pg_dsn` fields here are forwarded as opaque strings (or
//! ignored) — the Rust binary does NOT touch the DB directly in
//! Slice 1. They are kept on the struct for parity with Python and so
//! the Slice 1b port (Rust takes over audit) is a drop-in.
//!
//! Required-secrets policy (matches `config.py:65-71`):
//! - `QORCH_KERNEL_SIGNING_KEY_B64` — fail-closed in all envs
//! - `QORCH_KERNEL_AUDIT_PEPPER_B64` — fail-closed in all envs
//! - `QORCH_KERNEL_API_KEY_WORKER` — fail-closed in all envs
//! - `QORCH_KERNEL_API_KEY_API` — fail-closed in all envs
//! - `QORCH_KERNEL_API_KEY_OPERATOR` — required only when `env == prod`
//!   (mirrors `middleware.py:48-58`)

use std::env;
use std::path::PathBuf;

use anyhow::{anyhow, Result};

/// Default path to the policy sidecar's Unix-domain socket.
const DEFAULT_POLICY_SOCK: &str = "/var/run/qorch/safety_policy.sock";

/// Default container-internal listen address. Host port 9001 is
/// mapped to this in `docker-compose.yml`.
const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:9000";

/// Process-level Safety Kernel configuration. Built once at startup
/// from the environment and held inside `AppState` for the lifetime
/// of the process.
#[allow(dead_code)] // db_* + pg_dsn are parity fields (Slice 1b will read them)
#[derive(Debug, Clone)]
pub struct Settings {
    /// `dev` | `staging` | `prod`. Drives the operator-key requirement.
    pub env: String,

    /// `postgres` | `sqlite` — opaque, forwarded to the sidecar.
    pub db_backend: String,

    /// Path used by the sqlite backend — forwarded to the sidecar.
    pub db_path: String,

    /// Postgres DSN — forwarded to the sidecar (Slice 1 does not
    /// connect from Rust).
    pub pg_dsn: Option<String>,

    /// `none` | `api_key` | `jwt` — Slice 1 supports `api_key` only.
    pub auth_mode: String,

    /// Per-role API keys.
    pub api_key_worker: Option<String>,
    pub api_key_api: Option<String>,
    pub api_key_operator: Option<String>,

    /// Ed25519 signing key (32-byte seed, base64url; padded or
    /// unpadded both accepted at decode time).
    pub signing_key_b64: String,

    /// HMAC-SHA256 audit pepper (base64url; padded or unpadded).
    pub audit_pepper_b64: String,

    /// TTL clamp window in seconds.
    pub default_token_ttl_s: i64,
    pub max_token_ttl_s: i64,
    pub approval_token_ttl_s: i64,

    /// `QORCH_KERNEL_BUILD_VERSION` (default `"0.0.0-dev"`). Echoed
    /// in `/health.version`.
    pub build_version: String,

    /// `host:port` axum binds to (default `0.0.0.0:9000`).
    pub listen_addr: String,

    /// Path to the Python policy sidecar's Unix socket.
    pub policy_sock_path: PathBuf,
}

impl Settings {
    /// Build a `Settings` by reading the environment.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any fail-closed required secret is missing
    /// (matches Python `apps/safety_kernel/config.py:76-80` +
    /// `middleware.py:48-58`).
    pub fn from_env() -> Result<Self> {
        let env_v = env::var("QORCH_ENV").unwrap_or_else(|_| "dev".to_string());
        let env_lower = env_v.to_ascii_lowercase();

        let db_backend = env::var("QORCH_KERNEL_DB_BACKEND")
            .or_else(|_| env::var("QORCH_DB_BACKEND"))
            .unwrap_or_else(|_| "postgres".to_string())
            .to_ascii_lowercase();
        let db_path = env::var("QORCH_KERNEL_DB_PATH")
            .unwrap_or_else(|_| ".qorch/kernel_audit.sqlite3".to_string());
        let pg_dsn = env::var("QORCH_KERNEL_PG_DSN")
            .ok()
            .or_else(|| env::var("QORCH_PG_DSN_CONTAINER").ok())
            .or_else(|| env::var("QORCH_PG_DSN_HOST").ok())
            .or_else(|| env::var("QORCH_PG_DSN").ok())
            .or_else(|| env::var("DATABASE_URL").ok());

        let auth_mode = env::var("QORCH_KERNEL_AUTH_MODE")
            .unwrap_or_else(|_| "api_key".to_string())
            .to_ascii_lowercase();

        // Fail-closed required secrets (all envs).
        let signing_key_b64 = env::var("QORCH_KERNEL_SIGNING_KEY_B64")
            .map_err(|_| anyhow!("missing QORCH_KERNEL_SIGNING_KEY_B64"))?
            .trim()
            .to_string();
        if signing_key_b64.is_empty() {
            return Err(anyhow!("missing QORCH_KERNEL_SIGNING_KEY_B64"));
        }

        let audit_pepper_b64 = env::var("QORCH_KERNEL_AUDIT_PEPPER_B64")
            .map_err(|_| anyhow!("missing QORCH_KERNEL_AUDIT_PEPPER_B64"))?
            .trim()
            .to_string();
        if audit_pepper_b64.is_empty() {
            return Err(anyhow!("missing QORCH_KERNEL_AUDIT_PEPPER_B64"));
        }

        let api_key_worker = env::var("QORCH_KERNEL_API_KEY_WORKER")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let api_key_api = env::var("QORCH_KERNEL_API_KEY_API")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let api_key_operator = env::var("QORCH_KERNEL_API_KEY_OPERATOR")
            .ok()
            .filter(|v| !v.trim().is_empty());

        if api_key_worker.is_none() {
            return Err(anyhow!("missing QORCH_KERNEL_API_KEY_WORKER"));
        }
        if api_key_api.is_none() {
            return Err(anyhow!("missing QORCH_KERNEL_API_KEY_API"));
        }
        // Operator key is required only in prod (matches Python
        // middleware §middleware.py:48-58 default-deny shape).
        if matches!(env_lower.as_str(), "prod" | "production") && api_key_operator.is_none() {
            return Err(anyhow!(
                "missing QORCH_KERNEL_API_KEY_OPERATOR (required in prod)"
            ));
        }

        // TTLs (matches Python defaults from `config.py:82-86`).
        let default_token_ttl_s = env::var("QORCH_KERNEL_TOKEN_TTL_S")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(60)
            .max(1);
        let max_token_ttl_s = env::var("QORCH_KERNEL_MAX_TOKEN_TTL_S")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(300)
            .max(1);
        let approval_token_ttl_s = env::var("QORCH_KERNEL_APPROVAL_TOKEN_TTL_S")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(365 * 24 * 60 * 60)
            .max(60);

        let build_version =
            env::var("QORCH_KERNEL_BUILD_VERSION").unwrap_or_else(|_| "0.0.0-dev".to_string());

        let listen_addr = env::var("QORCH_KERNEL_LISTEN_ADDR")
            .unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string());
        let policy_sock_path = PathBuf::from(
            env::var("QORCH_KERNEL_POLICY_SOCK")
                .unwrap_or_else(|_| DEFAULT_POLICY_SOCK.to_string()),
        );

        Ok(Self {
            env: env_lower,
            db_backend,
            db_path,
            pg_dsn,
            auth_mode,
            api_key_worker,
            api_key_api,
            api_key_operator,
            signing_key_b64,
            audit_pepper_b64,
            default_token_ttl_s,
            max_token_ttl_s,
            approval_token_ttl_s,
            build_version,
            listen_addr,
            policy_sock_path,
        })
    }
}
