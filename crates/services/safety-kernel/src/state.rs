//! Process-level Safety Kernel state — what the axum router holds.
//!
//! Built once in `main.rs` from `Settings::from_env()` and passed to
//! every route handler via `axum::extract::State<AppState>`. Includes
//! the signing key, the public-key fingerprint (hex sha256 of raw
//! public-key bytes), the audit pepper bytes, the production `Clock`
//! and `NonceSource` adapters, and the `PolicyEngineClient`.

use std::sync::Arc;

use ed25519_dalek::SigningKey;

use qorch_adapters::policy_engine_client::PolicyEngineClient;
use qorch_domain::safety::{Clock, NonceSource};

use crate::settings::Settings;

/// Process-level state shared by every handler.
#[allow(dead_code)] // audit_pepper is held for Slice 1b (Rust takes over audit hash).
#[derive(Clone)]
pub struct AppState {
    /// Frozen, env-driven configuration.
    pub settings: Arc<Settings>,
    /// Ed25519 private key wrapped in `Arc` so handlers can pass it
    /// to `sign_kernel_token` without cloning the key bytes.
    pub signing_key: Arc<SigningKey>,
    /// Base64url-no-pad of the raw 32-byte Ed25519 public key.
    pub public_key_b64: String,
    /// Hex sha256 of the raw 32-byte Ed25519 public key.
    pub public_key_fingerprint: String,
    /// HMAC pepper bytes for audit-record hashing (forwarded to the
    /// sidecar; Slice 1 doesn't HMAC in Rust).
    pub audit_pepper: Arc<Vec<u8>>,
    /// Wall-clock at process start (for `/health.uptime_s`).
    pub started_at: f64,
    /// Production `Clock` adapter — `SystemClock`.
    pub clock: Arc<dyn Clock>,
    /// Production `NonceSource` adapter — `OsRngNonceSource`.
    pub nonce: Arc<dyn NonceSource>,
    /// Unix-socket policy IPC client.
    pub policy_client: Arc<PolicyEngineClient>,
}
