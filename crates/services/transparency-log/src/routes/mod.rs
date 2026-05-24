//! HTTP route handlers for the transparency-log service (ADR-014
//! Phase 3 §3, ARY-1885 Step 5).
//!
//! One file per endpoint. The `health` route is in this module to keep
//! the trivial liveness handler co-located with the dispatch table.

pub mod append;
pub mod consistency;
pub mod sth;
pub mod verify;
pub mod wave_session;

use axum::extract::State;
use axum::Json;

use crate::dto::HealthResponse;
use crate::error::ServiceError;
use crate::state::AppState;

/// `GET /health` — liveness check. Public (no `x-api-key`). Includes
/// the current tree size so operator dashboards can chart growth
/// without a separate `/v1/sth` hit.
pub async fn health(
    State(state): State<AppState>,
) -> Result<Json<HealthResponse>, ServiceError> {
    let tree_size = state.store.current_size().await?;
    Ok(Json(HealthResponse { ok: true, tree_size }))
}
