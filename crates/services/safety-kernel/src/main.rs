//! Safety Kernel HTTP service — Rust port (ADR-014 Slice 1, internal-ref).
//!
//! W2: axum service + 6 endpoints + Unix-socket policy IPC.
//!
//! Wires:
//!   * `GET  /health`                              (public)
//!   * `GET  /kernel/v1/health`                    (public)
//!   * `GET  /kernel/v1/public_key`                (public)
//!   * `POST /kernel/v1/authorize`                 (worker | api)
//!   * `POST /kernel/v1/approvals/{id}/approve`    (operator)
//!   * `POST /kernel/v1/approvals/{id}/reject`     (operator)
//!
//! Policy decisions and audit-chain writes are forwarded over Unix
//! socket to the Python policy sidecar (Slice 1 boundary). See
//! `docs/adr/adr-014-slice-1-equivalence.md` §3 / §4.

#![forbid(unsafe_code)]

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use axum::{
    routing::{get, post},
    Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod auth;
mod dto;
mod routes;
mod settings;
mod state;

use qorch_adapters::clock::SystemClock;
use qorch_adapters::nonce::OsRngNonceSource;
use qorch_adapters::policy_engine_client::PolicyEngineClient;
use qorch_domain::safety::Clock;

use crate::settings::Settings;
use crate::state::AppState;

// 1 MiB request body limit — matches FastAPI / starlette default (per
// ADR §G5 of the Adversarial gate).
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Decode a base64url string accepting both padded and unpadded
/// inputs — mirrors Python `_b64url_decode`
/// (`packages/core/safety_tokens.py:71-80`).
fn b64url_decode_padded_or_unpadded(s: &str) -> Result<Vec<u8>> {
    let trimmed = s.trim();
    // Try unpadded first (the production canonical form), then fall
    // back to padded (legacy / human-input).
    URL_SAFE_NO_PAD
        .decode(trimmed.trim_end_matches('='))
        .with_context(|| "base64url decode failed")
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logging — `RUST_LOG` overrides; default INFO.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().compact())
        .init();

    let settings = Settings::from_env()?;
    info!(
        env = %settings.env,
        listen = %settings.listen_addr,
        sock = %settings.policy_sock_path.display(),
        version = %settings.build_version,
        "qorch-safety-kernel starting"
    );

    // Decode signing key (32-byte seed).
    let signing_seed_bytes = b64url_decode_padded_or_unpadded(&settings.signing_key_b64)?;
    if signing_seed_bytes.len() != 32 {
        return Err(anyhow!(
            "signing key seed must be 32 bytes, got {}",
            signing_seed_bytes.len()
        ));
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&signing_seed_bytes);
    let signing_key = SigningKey::from_bytes(&seed_arr);
    let verifying_key = signing_key.verifying_key();
    let public_key_raw = verifying_key.to_bytes();

    // Public-key b64 (URL_SAFE_NO_PAD over raw 32 bytes).
    let public_key_b64 = URL_SAFE_NO_PAD.encode(public_key_raw);

    // Public-key fingerprint = sha256_hex of raw 32 bytes.
    let pk_digest = {
        let mut h = Sha256::new();
        h.update(public_key_raw);
        h.finalize()
    };
    let public_key_fingerprint = hex::encode(pk_digest);

    // Audit pepper bytes.
    let audit_pepper = b64url_decode_padded_or_unpadded(&settings.audit_pepper_b64)?;

    // Clock + Nonce + PolicyEngineClient adapters.
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let nonce: Arc<dyn qorch_domain::safety::NonceSource> = Arc::new(OsRngNonceSource::new());
    let policy_sock_canon = match std::fs::canonicalize(&settings.policy_sock_path) {
        Ok(p) => p,
        Err(e) => {
            // The socket may not exist yet at startup; do NOT fail-fast
            // here. Log and accept the configured path — the first
            // IPC call will surface a real error.
            tracing::warn!(
                path = %settings.policy_sock_path.display(),
                err = %e,
                "policy socket not canonicalizable at startup (will retry on first call)"
            );
            settings.policy_sock_path.clone()
        }
    };
    let policy_client = Arc::new(PolicyEngineClient::new(policy_sock_canon));

    let started_at = clock.now();

    let app_state = AppState {
        settings: Arc::new(settings.clone()),
        signing_key: Arc::new(signing_key),
        public_key_b64,
        public_key_fingerprint,
        audit_pepper: Arc::new(audit_pepper),
        started_at,
        clock,
        nonce,
        policy_client,
    };

    // Router. Auth layer applies to every route except the public
    // ones (the layer itself short-circuits public paths internally).
    let router = Router::new()
        .route("/health", get(routes::meta::health))
        .route("/kernel/v1/health", get(routes::meta::health))
        .route("/kernel/v1/public_key", get(routes::meta::public_key))
        .route("/kernel/v1/authorize", post(routes::authorize::authorize))
        .route(
            "/kernel/v1/approvals/{item_id}/approve",
            post(routes::approvals::approve),
        )
        .route(
            "/kernel/v1/approvals/{item_id}/reject",
            post(routes::approvals::reject),
        )
        // ADR-018 (internal-ref) — `/policy/*` slice-1 scaffold (501s).
        .merge(routes::policy::router())
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth::auth_layer,
        ))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(&settings.listen_addr)
        .await
        .with_context(|| format!("bind {}", settings.listen_addr))?;
    info!(addr = %settings.listen_addr, "qorch-safety-kernel listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum serve")?;

    info!("qorch-safety-kernel shutting down cleanly");
    Ok(())
}

/// Wait for SIGINT or SIGTERM so the runtime can drain in-flight
/// requests cleanly.
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
