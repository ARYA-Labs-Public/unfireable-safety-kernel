//! Env-driven settings for the transparency-log service (
//!  §3,  Step 5).
//!
//! Required-secrets policy:
//! - `QORCH_TRANSPARENCY_SIGNING_KEY_B64` — fail-closed in all envs
//! - `QORCH_TRANSPARENCY_KERNEL_VERIFYING_KEY_B64` — fail-closed in
//!   all envs. Binds the ledger to ONE kernel.
//! - `QORCH_TRANSPARENCY_API_KEY` — fail-closed in `prod`. Optional in
//!   `dev` for ergonomics (the middleware still rejects empty keys
//!   when QORCH_ENV != dev).
//!
//! Optional:
//! - `QORCH_TRANSPARENCY_DB_URL` — Postgres DSN. When unset the
//!   service boots with the in-memory store (dev only). The bin emits
//!   a WARN at startup if DB_URL is unset and `env != dev`.
//! - `QORCH_TRANSPARENCY_LISTEN_ADDR` — default `0.0.0.0:8100`.
//! - `QORCH_TRANSPARENCY_TLS_CERT_PATH` / `..._KEY_PATH` /
//!   `..._CLIENT_CA_PATH` — rustls server material + optional mTLS
//!   client-CA bundle.
//!
//! Mirrors the kernel's `crates/services/safety-kernel/src/settings.rs`
//! pattern so the prod-only fail-closed semantics are uniform across
//! services.

use std::env;
use std::path::PathBuf;

use anyhow::{anyhow, Result};

/// Default container-internal listen address. Host port 8102 maps to
/// this in `docker-compose.yml`.
const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8100";

/// Frozen, env-driven configuration. Built once at startup and held
/// inside `AppState` (or its caller) for the lifetime of the process.
#[derive(Debug, Clone)]
pub struct Settings {
    /// `dev` | `staging` | `prod`. Drives the prod-only fail-closed
    /// checks (TLS required, api_key required, db_url required).
    pub env: String,

    /// `host:port` axum binds to.
    pub listen_addr: String,

    /// Optional Postgres DSN. `None` ⇒ in-memory store (dev only).
    pub db_url: Option<String>,

    /// Base64url-no-pad of the 32-byte Ed25519 seed used to sign STHs.
    pub signing_key_b64: String,

    /// Base64url-no-pad of the kernel's raw 32-byte Ed25519 public key.
    /// Pinned at startup so `POST /v1/append` rejects payloads whose
    /// `kernel_key_fingerprint_sha256` does not match this key.
    pub kernel_verifying_key_b64: String,

    /// Shared-secret `x-api-key` value. Empty string ⇒ dev-only no-auth.
    pub api_key: String,

    // Rustls server material.
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    /// Optional client-CA bundle for mTLS. When `Some(_)` the listener
    /// requires the caller (kernel) to present a client certificate
    /// chain-of-trust matching this CA bundle.
    pub tls_client_ca_path: Option<PathBuf>,

    /// Derived: `tls_cert_path.is_some() && tls_key_path.is_some()`.
    pub tls_enable: bool,
}

impl Settings {
    /// Build a `Settings` by reading the environment.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any fail-closed required secret is missing.
    pub fn from_env() -> Result<Self> {
        let env_v = env::var("QORCH_ENV").unwrap_or_else(|_| "dev".to_string());
        let env_lower = env_v.to_ascii_lowercase();
        let is_prod = matches!(env_lower.as_str(), "prod" | "production");

        let listen_addr = env::var("QORCH_TRANSPARENCY_LISTEN_ADDR")
            .unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string());

        let db_url = env::var("QORCH_TRANSPARENCY_DB_URL")
            .ok()
            .filter(|v| !v.trim().is_empty());

        let signing_key_b64 = env::var("QORCH_TRANSPARENCY_SIGNING_KEY_B64")
            .map_err(|_| anyhow!("missing QORCH_TRANSPARENCY_SIGNING_KEY_B64"))?
            .trim()
            .to_string();
        if signing_key_b64.is_empty() {
            return Err(anyhow!("missing QORCH_TRANSPARENCY_SIGNING_KEY_B64"));
        }

        let kernel_verifying_key_b64 = env::var("QORCH_TRANSPARENCY_KERNEL_VERIFYING_KEY_B64")
            .map_err(|_| anyhow!("missing QORCH_TRANSPARENCY_KERNEL_VERIFYING_KEY_B64"))?
            .trim()
            .to_string();
        if kernel_verifying_key_b64.is_empty() {
            return Err(anyhow!(
                "missing QORCH_TRANSPARENCY_KERNEL_VERIFYING_KEY_B64"
            ));
        }

        let api_key = env::var("QORCH_TRANSPARENCY_API_KEY")
            .unwrap_or_default()
            .trim()
            .to_string();
        if is_prod && api_key.is_empty() {
            return Err(anyhow!(
                "missing QORCH_TRANSPARENCY_API_KEY (required in prod)"
            ));
        }

        let tls_cert_path = env::var("QORCH_TRANSPARENCY_TLS_CERT_PATH")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from);
        let tls_key_path = env::var("QORCH_TRANSPARENCY_TLS_KEY_PATH")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from);
        let tls_client_ca_path = env::var("QORCH_TRANSPARENCY_TLS_CLIENT_CA_PATH")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from);
        let tls_enable = tls_cert_path.is_some() && tls_key_path.is_some();

        // Mirror the kernel: prod fail-closes if TLS material is missing,
        // so the internal mesh is never served plaintext in production.
        if is_prod && !tls_enable {
            return Err(anyhow!(
                "fail-closed: QORCH_ENV=prod requires QORCH_TRANSPARENCY_TLS_CERT_PATH \
                 and QORCH_TRANSPARENCY_TLS_KEY_PATH to be set"
            ));
        }
        if is_prod && db_url.is_none() {
            return Err(anyhow!(
                "fail-closed: QORCH_ENV=prod requires QORCH_TRANSPARENCY_DB_URL to be set"
            ));
        }

        Ok(Self {
            env: env_lower,
            listen_addr,
            db_url,
            signing_key_b64,
            kernel_verifying_key_b64,
            api_key,
            tls_cert_path,
            tls_key_path,
            tls_client_ca_path,
            tls_enable,
        })
    }

    /// True when running in a production environment.
    #[must_use]
    pub fn is_prod(&self) -> bool {
        matches!(self.env.as_str(), "prod" | "production")
    }
}
