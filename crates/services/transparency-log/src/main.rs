//! Transparency-log HTTP service binary (,
//!  Step 5).
//!
//! Binds the four endpoints on internal port 8100 (host port 8102
//! per `docker-compose.yml`; 8101 reserved for the optional 
//! Rekor proxy). Wires:
//!
//!   - `GET  /health`               (public liveness probe)
//!   - `POST /v1/append`            (x-api-key)
//!   - `GET  /v1/verify/:entry_id`  (x-api-key)
//!   - `GET  /v1/sth`               (x-api-key)
//!   - `GET  /v1/consistency`       (x-api-key)
//!
//! Storage backend:
//!   * `QORCH_TRANSPARENCY_DB_URL=postgres://…` → `PgTransparencyStore`
//!     with migrations applied on boot.
//!   * unset → `MemoryTransparencyStore` (dev only; Settings.rs
//!     fail-closes in prod when DB_URL is missing).
//!
//! TLS: server-side rustls via the same `axum-server` + `ring` pattern
//! the safety-kernel uses. mTLS optional via
//! `QORCH_TRANSPARENCY_TLS_CLIENT_CA_PATH`.

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown, clippy::too_many_lines)]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use qorch_adapters::clock::SystemClock;
use qorch_domain::safety::Clock;
use qorch_transparency_log::router::build_router;
use qorch_transparency_log::settings::Settings;
use qorch_transparency_log::state::AppState;
use qorch_transparency_log::tls;
use qorch_transparency_store::{
    memory::MemoryTransparencyStore, postgres::PgTransparencyStore, TransparencyStore,
};

fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.trim().trim_end_matches('='))
        .with_context(|| "base64url decode failed")
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer().compact())
        .init();

    let settings = Settings::from_env().context("settings.from_env")?;
    info!(
        env = %settings.env,
        listen = %settings.listen_addr,
        tls = settings.tls_enable,
        db_backend = if settings.db_url.is_some() { "postgres" } else { "memory" },
        "qorch-transparency-log starting"
    );

    // Decode the STH signing key (32-byte seed).
    let signing_seed = b64url_decode(&settings.signing_key_b64)?;
    if signing_seed.len() != 32 {
        return Err(anyhow!(
            "signing key seed must be 32 bytes, got {}",
            signing_seed.len()
        ));
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&signing_seed);
    let signing_key = SigningKey::from_bytes(&seed_arr);
    let signing_pk = signing_key.verifying_key().to_bytes();
    let signing_key_fingerprint_hex = {
        let mut h = Sha256::new();
        h.update(signing_pk);
        hex::encode(h.finalize())
    };

    // Decode the pinned kernel verifying key (32-byte raw public key).
    let kernel_pk_bytes = b64url_decode(&settings.kernel_verifying_key_b64)?;
    if kernel_pk_bytes.len() != 32 {
        return Err(anyhow!(
            "kernel verifying key must be 32 bytes, got {}",
            kernel_pk_bytes.len()
        ));
    }
    let kernel_key_fingerprint_hex = {
        let mut h = Sha256::new();
        h.update(&kernel_pk_bytes);
        hex::encode(h.finalize())
    };

    // Build the storage adapter.
    let store: Arc<dyn TransparencyStore> = if let Some(dsn) = settings.db_url.as_ref() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(16)
            .connect(dsn)
            .await
            .with_context(|| format!("connect to {dsn}"))?;
        // Apply migrations from the adapter crate's `migrations/` dir.
        sqlx::migrate!("../../adapters/transparency_store/migrations")
            .run(&pool)
            .await
            .context("apply transparency_store migrations")?;
        Arc::new(PgTransparencyStore::new(pool))
    } else {
        warn!(
            target = "qorch.transparency_log",
            env = %settings.env,
            "no QORCH_TRANSPARENCY_DB_URL set — using in-memory store (dev only)",
        );
        Arc::new(MemoryTransparencyStore::new())
    };

    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    let app_state = AppState::new(
        store,
        Arc::new(signing_key),
        signing_key_fingerprint_hex,
        kernel_key_fingerprint_hex,
        clock,
        settings.api_key.clone(),
    );

    let router = build_router(app_state);

    let listen_sock: SocketAddr = settings
        .listen_addr
        .parse()
        .with_context(|| format!("parse listen addr {}", settings.listen_addr))?;

    if settings.tls_enable {
        let cert_path = settings
            .tls_cert_path
            .as_ref()
            .ok_or_else(|| anyhow!("tls_enable=true but tls_cert_path is None"))?;
        let key_path = settings
            .tls_key_path
            .as_ref()
            .ok_or_else(|| anyhow!("tls_enable=true but tls_key_path is None"))?;
        let client_ca = settings.tls_client_ca_path.as_deref();

        let _ = rustls::crypto::ring::default_provider().install_default();

        let rustls_config = tls::build_server_config(cert_path, key_path, client_ca)
            .context("build rustls server config")?;

        info!(
            addr = %settings.listen_addr,
            mtls = client_ca.is_some(),
            "qorch-transparency-log listening (rustls)"
        );

        axum_server::bind_rustls(listen_sock, rustls_config)
            .serve(router.into_make_service())
            .await
            .context("axum_server bind_rustls serve")?;
    } else {
        warn!(
            addr = %settings.listen_addr,
            "qorch-transparency-log listening (plaintext — no TLS env vars set)"
        );
        let listener = tokio::net::TcpListener::bind(&settings.listen_addr)
            .await
            .with_context(|| format!("bind {}", settings.listen_addr))?;
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("axum serve")?;
    }

    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal;
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        let Ok(mut s) = signal::unix::signal(signal::unix::SignalKind::terminate()) else {
            return;
        };
        let _ = s.recv().await;
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
}
