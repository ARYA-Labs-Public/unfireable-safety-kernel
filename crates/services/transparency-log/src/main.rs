//! Transparency-log HTTP service binary (ADR-014 Phase 3 §3,
//! internal-ref Step 5).
//!
//! Binds the four endpoints on internal port 8100 (host port 8102
//! per `docker-compose.yml`; 8101 reserved for the optional internal-ref
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

use qorch_domain::safety::Clock;
use qorch_transparency_log::clock::SystemClock;
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

    let mut app_state = AppState::new(
        store,
        Arc::new(signing_key),
        signing_key_fingerprint_hex,
        kernel_key_fingerprint_hex,
        clock,
        settings.api_key.clone(),
    );

    // internal-ref — install the wave-session-detail sqlite side-table.
    // Persistent path when configured; in-memory fallback otherwise
    // (dev / smoke tests). The transparency-log ledger remains the
    // durable source-of-truth either way.
    {
        use qorch_transparency_log::wave_session_detail::SideTable;
        let side_table = if let Some(path) = settings.wave_session_detail_sqlite_path.as_ref() {
            info!(
                target = "qorch.transparency_log",
                path = %path.display(),
                "internal-ref: opening persistent wave_session_detail sqlite side-table",
            );
            SideTable::open(path).context("opening wave_session_detail sqlite")?
        } else {
            warn!(
                target = "qorch.transparency_log",
                "internal-ref: QORCH_TRANSPARENCY_WAVE_DETAIL_SQLITE_PATH unset — \
                 wave-session-detail denorm runs in-memory (dev only)"
            );
            SideTable::in_memory().context("opening in-memory wave_session_detail sqlite")?
        };
        app_state = app_state.with_wave_session_detail_store(Arc::new(side_table));
    }

    // internal-ref — install the shared kernel HMAC key for the wave-session
    // HMAC path (legacy internal-ref contract) when provisioned. Decoded
    // base64url-no-pad; must be exactly 32 bytes. When unset, the
    // wave-session HMAC path stays closed (empty key); the Ed25519 path is
    // unaffected. This is what lets ceremony writers holding the same key
    // produce a verifiable `kernel_hmac_hex` over a record's canonical bytes.
    if let Some(hmac_b64) = settings.kernel_hmac_key_b64.as_deref() {
        let hmac_key = b64url_decode(hmac_b64)?;
        if hmac_key.len() != 32 {
            return Err(anyhow!(
                "kernel HMAC key must be 32 bytes, got {}",
                hmac_key.len()
            ));
        }
        app_state = app_state.with_kernel_hmac_key(hmac_key);
        info!(
            target = "qorch.transparency_log",
            "internal-ref: installed shared kernel HMAC key (wave-session HMAC path enabled)",
        );
    }

    // internal-ref — install the transparency-log's asymmetric (Ed25519)
    // signing keypair if configured. Production fail-closes in
    // `Settings::from_env`; here we just decode + install. The
    // `generated_at_epoch_seconds` is sourced from the wall clock at
    // install time when the seed is env-injected (we don't know the
    // operator's actual mint time).
    if let Some(priv_hex) = settings.transparency_log_ed25519_private_hex.as_deref() {
        let seed_raw = hex::decode(priv_hex.trim())
            .context("hex-decode QORCH_TRANSPARENCY_LOG_ED25519_PRIVATE")?;
        if seed_raw.len() != 32 {
            return Err(anyhow!(
                "QORCH_TRANSPARENCY_LOG_ED25519_PRIVATE must be 32 bytes hex \
                 (64 chars); got {} bytes",
                seed_raw.len()
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_raw);
        let tl_signing = SigningKey::from_bytes(&seed);
        let generated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        app_state = app_state.with_transparency_ed25519_keypair(tl_signing, generated_at);
        info!(
            target = "qorch.transparency_log",
            "internal-ref: transparency-log Ed25519 signing keypair installed"
        );
    } else {
        warn!(
            target = "qorch.transparency_log",
            "internal-ref: QORCH_TRANSPARENCY_LOG_ED25519_PRIVATE unset — \
             /v1/keys/transparency and signature_type=ed25519 will 503 \
             (HMAC-only mode; legacy compat)"
        );
    }

    // internal-ref — install the dedicated MCP-audit Ed25519 fingerprint so
    // `POST /v1/audit/mcp` accepts properly-signed leaves. The route only
    // verifies + PINS this public key's SHA-256 fingerprint (it never
    // signs — the MCP-audit sweeper holds the matching private key), so
    // we compute the fingerprint from the configured PUBLIC key. When
    // unset the route stays at `503 ed25519_not_configured` (Settings
    // fail-closes this case in prod, mirroring internal-ref). This does NOT
    // touch the kernel-pinned `/v1/append` key.
    if let Some(pub_hex) = settings.mcp_audit_ed25519_public_hex.as_deref() {
        let pk_raw = hex::decode(pub_hex.trim())
            .context("hex-decode QORCH_TRANSPARENCY_MCP_AUDIT_ED25519_PUBLIC")?;
        if pk_raw.len() != 32 {
            return Err(anyhow!(
                "QORCH_TRANSPARENCY_MCP_AUDIT_ED25519_PUBLIC must be 32 bytes hex \
                 (64 chars); got {} bytes",
                pk_raw.len()
            ));
        }
        let mcp_audit_fingerprint_hex = {
            let mut h = Sha256::new();
            h.update(&pk_raw);
            hex::encode(h.finalize())
        };
        app_state = app_state.with_mcp_audit_ed25519_fingerprint(mcp_audit_fingerprint_hex);
        info!(
            target = "qorch.transparency_log",
            "internal-ref: MCP-audit Ed25519 fingerprint installed; POST /v1/audit/mcp active"
        );
    } else {
        warn!(
            target = "qorch.transparency_log",
            "internal-ref: QORCH_TRANSPARENCY_MCP_AUDIT_ED25519_PUBLIC unset — \
             POST /v1/audit/mcp will 503 (ed25519_not_configured; dev-only — \
             Settings fail-closes this in prod)"
        );
    }

    // internal-ref — install the dedicated reconciler-drift Ed25519 fingerprint so
    // reconciler drift appends accept properly-signed leaves. The route only
    // verifies + PINS this public key's SHA-256 fingerprint (it never
    // signs — the drift reconciler holds the matching private key), so
    // we compute the fingerprint from the configured PUBLIC key. When
    // unset the route stays at `503 ed25519_not_configured`. This does NOT
    // touch the kernel-pinned `/v1/append` key.
    if let Some(pub_hex) = settings.reconciler_drift_ed25519_public_hex.as_deref() {
        let pk_raw = hex::decode(pub_hex.trim())
            .context("hex-decode QORCH_TRANSPARENCY_RECONCILER_DRIFT_ED25519_PUBLIC")?;
        if pk_raw.len() != 32 {
            return Err(anyhow!(
                "QORCH_TRANSPARENCY_RECONCILER_DRIFT_ED25519_PUBLIC must be 32 bytes hex \
                 (64 chars); got {} bytes",
                pk_raw.len()
            ));
        }
        let reconciler_drift_fingerprint_hex = {
            let mut h = Sha256::new();
            h.update(&pk_raw);
            hex::encode(h.finalize())
        };
        info!(
            target = "qorch.transparency_log",
            fingerprint = %reconciler_drift_fingerprint_hex,
            "internal-ref: reconciler-drift Ed25519 fingerprint pinned; drift append active"
        );
        app_state =
            app_state.with_reconciler_drift_ed25519_fingerprint(reconciler_drift_fingerprint_hex);
    } else {
        warn!(
            target = "qorch.transparency_log",
            "internal-ref: QORCH_TRANSPARENCY_RECONCILER_DRIFT_ED25519_PUBLIC unset — \
             reconciler-drift append will 503 (ed25519_not_configured)"
        );
    }

    // internal-ref — install per-skill (per-stage) HMAC `x-api-key` table
    // when any `QORCH_TRANSPARENCY_KEY_*` env var is set. None ⇒
    // legacy single-shared-key path (back-compat); the bin warns at
    // startup so operators can see which mode is active.
    if let Some(per_skill_keys) = settings.per_skill_keys.clone() {
        info!(
            target = "qorch.transparency_log",
            stages_with_keys = per_skill_keys.len(),
            "internal-ref: per-skill HMAC x-api-key table installed"
        );
        app_state = app_state.with_per_skill_keys(per_skill_keys);
    } else {
        warn!(
            target = "qorch.transparency_log",
            "internal-ref: per-skill HMAC keys NOT configured — \
             /v1/wave/session falls through to legacy single-shared-key mode"
        );
    }

    // internal-ref durability — rebuild the in-process wave-session index
    // from the durable ledger BEFORE serving, so `GET /v1/wave/{id}/verify`
    // survives a restart. Without this, a restart empties the index and
    // every prior wave verifies as 404, which (under the tlog-required
    // flip) would brick release commits on any tlog restart. Fail-soft:
    // a reconstruction error is logged and serving continues (verify
    // degrades to re-append-to-recover, same as pre-internal-ref behavior),
    // never a boot abort.
    match qorch_transparency_log::routes::wave_session::reconstruct_wave_sessions_from_ledger(
        &app_state,
    )
    .await
    {
        Ok(recovered) => info!(
            target = "qorch.transparency_log",
            recovered_wave_leaves = recovered,
            "internal-ref: reconstructed wave-session index from ledger on boot"
        ),
        Err(e) => warn!(
            target = "qorch.transparency_log",
            error = %e,
            "internal-ref: wave-session index reconstruction failed; \
             prior waves may verify 404 until re-appended"
        ),
    }

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
