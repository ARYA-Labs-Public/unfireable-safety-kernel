//! Safety Kernel HTTP service — Rust port (, ).
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
//! socket to the Python policy sidecar ( boundary). See
//! `docs/adr/adr-014-slice-1-equivalence.md` §3 / §4.

#![forbid(unsafe_code)]
#![allow(clippy::too_many_lines)]

use std::net::SocketAddr;
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
use tracing::{info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod auth;
mod dto;
mod key_backend;
mod routes;
mod settings;
mod state;
mod tls;
mod transparency_client;

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

    // Resolve the signing seed via the configured key backend
    // (env|gcp). For managed backends this performs the live secret
    // fetch now that the tokio runtime is up (Step-14R / ARY-1886).
    let signing_key_b64 = key_backend::resolve_signing_key_b64(&settings)
        .await
        .context("resolving Ed25519 signing seed from key backend")?;
    info!(
        backend = %settings.key_backend.as_str(),
        "signing-key backend resolved"
    );

    // Decode signing key (32-byte seed).
    let signing_seed_bytes = b64url_decode_padded_or_unpadded(&signing_key_b64)?;
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

    //  — build the optional transparency-log client.
    // Settings::from_env already failed closed in prod; here we just
    // honor the boolean and config. Empty url / key ⇒ None (the
    // helper handles both). In prod with the flag set, `None` here
    // means an unreachable config bug — we panic so it doesn't ship.
    let transparency_client = if settings.transparency_enabled {
        let c = crate::transparency_client::build_optional_client(
            true,
            settings.transparency_log_url.as_deref(),
            settings.transparency_log_api_key.as_deref(),
            &public_key_fingerprint,
            std::time::Duration::from_secs_f64(settings.transparency_log_timeout_seconds),
            settings.transparency_log_client_cert_path.as_deref(),
            settings.transparency_log_client_key_path.as_deref(),
        )?;
        if settings.is_prod() && c.is_none() {
            return Err(anyhow!(
                "fail-closed: transparency_enabled=true in prod but no \
                 transparency-log client could be built (URL/key missing)"
            ));
        }
        c
    } else {
        None
    };

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
        transparency_client,
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
        //  — `/policy/*` slice-1 scaffold (501s).
        .merge(routes::policy::router())
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth::auth_layer,
        ))
        .with_state(app_state);

    //  Addendum 2a §2 — dual-ingress bind.
    //
    // When `QORCH_KERNEL_TLS_CERT` + `QORCH_KERNEL_TLS_KEY` are set, the
    // kernel binary terminates rustls itself. nginx remains the outer
    // edge for external callers; the rustls listener is a SECOND
    // ingress for in-cluster Rust callers.
    //
    // Prod fail-closed: if env=prod and TLS env vars are missing, log
    // and exit non-zero so we never quietly serve plaintext to the
    // internal mesh in production.
    if settings.is_prod() && !settings.tls_enable {
        return Err(anyhow!(
            "fail-closed: QORCH_ENV=prod requires QORCH_KERNEL_TLS_CERT \
             and QORCH_KERNEL_TLS_KEY to be set ( Addendum 2a §2)"
        ));
    }

    let listen_sock: SocketAddr = settings
        .listen_addr
        .parse()
        .with_context(|| format!("parse listen addr {}", settings.listen_addr))?;

    if settings.tls_enable {
        // SAFETY: tls_enable is true ⇒ both paths are Some(_).
        let cert_path = settings
            .tls_cert_path
            .as_ref()
            .ok_or_else(|| anyhow!("tls_enable=true but tls_cert_path is None"))?;
        let key_path = settings
            .tls_key_path
            .as_ref()
            .ok_or_else(|| anyhow!("tls_enable=true but tls_key_path is None"))?;
        let client_ca = settings.tls_client_ca_path.as_deref();

        // Install ring as the rustls crypto provider exactly once per
        // process. Repeat installs error; we only care about the first
        // success, hence `let _ =...`.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let rustls_config = tls::build_server_config(cert_path, key_path, client_ca)
            .context("build rustls server config")?;

        info!(
            addr = %settings.listen_addr,
            mtls = client_ca.is_some(),
            sni = %settings.tls_sni,
            "qorch-safety-kernel listening (rustls)"
        );

        axum_server::bind_rustls(listen_sock, rustls_config)
            .serve(router.into_make_service())
            .await
            .context("axum_server bind_rustls serve")?;
    } else {
        // Dev/test fallback — plaintext. Warn once so it's obvious in
        // logs that mTLS is OFF.
        warn!(
            addr = %settings.listen_addr,
            "qorch-safety-kernel listening (plaintext — no TLS env vars set)"
        );
        let listener = tokio::net::TcpListener::bind(&settings.listen_addr)
            .await
            .with_context(|| format!("bind {}", settings.listen_addr))?;

        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("axum serve")?;
    }

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
