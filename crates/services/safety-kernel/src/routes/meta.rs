//! Public meta endpoints — `/health`, `/kernel/v1/health`,
//! `/kernel/v1/public_key`. None require auth.
//!
//! Mirrors `apps/safety_kernel/routes/meta.py` after the §5.3 patch.

use axum::{extract::State, Json};

use crate::dto::{HealthResponse, PublicKeyResponse};
use crate::state::AppState;

/// `GET /health` and `GET /kernel/v1/health` — same handler.
///
/// Per ADR-014 Slice 1 §5.3, the response shape is `{ok, version,
/// uptime_s}` with all three fields always present. Both paths
/// return identical bodies.
pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let now = state.clock.now();
    let started = state.started_at;
    // Use saturating subtraction to avoid the (very unlikely) negative
    // uptime if the clock was set backwards between handler instances.
    let uptime_s = (now - started).max(0.0);
    Json(HealthResponse {
        ok: true,
        version: state.settings.build_version.clone(),
        uptime_s,
    })
}

/// `GET /kernel/v1/public_key` — emits `{ok, algorithm, public_key_b64,
/// public_key_fingerprint}`.
///
/// The schema only declares the latter two fields, but Python emits
/// `ok` and `algorithm` too — Rust matches Python wire (ADR-014 Slice 1
/// §10 inconsistency note 2).
pub async fn public_key(State(state): State<AppState>) -> Json<PublicKeyResponse> {
    Json(PublicKeyResponse {
        ok: true,
        algorithm: "Ed25519".to_string(),
        public_key_b64: state.public_key_b64.clone(),
        public_key_fingerprint: state.public_key_fingerprint.clone(),
    })
}
