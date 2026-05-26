//! Router builder for the transparency-log service ( Step 5).
//!
//! Centralised in one function so the bin and the integration tests
//! share the exact route table + middleware stack. Wires:
//!
//!   - `GET  /health`               (public)
//!   - `POST /v1/append`            (x-api-key)
//!   - `GET  /v1/verify/:entry_id`  (x-api-key)
//!   - `GET  /v1/sth`               (x-api-key)
//!   - `GET  /v1/consistency`       (x-api-key)

use axum::routing::{get, post};
use axum::Router;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::auth::auth_layer;
use crate::routes::{
    append::append,
    consistency::consistency,
    sth::sth,
    verify::verify,
    wave_session::{append_session as wave_session_append, verify_session as wave_session_verify},
};
use crate::state::AppState;

/// 1 MiB request body limit — matches the safety-kernel's setting so
/// upstream nginx limits are consistent across services.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Build the full router for the transparency-log service.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(crate::routes::health))
        .route("/v1/append", post(append))
        .route("/v1/verify/{entry_id}", get(verify))
        .route("/v1/sth", get(sth))
        .route("/v1/consistency", get(consistency))
        //: wave-session-record routes.
        .route("/v1/wave/session", post(wave_session_append))
        .route("/v1/wave/{wave_id}/verify", get(wave_session_verify))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_layer,
        ))
        .with_state(state)
}
