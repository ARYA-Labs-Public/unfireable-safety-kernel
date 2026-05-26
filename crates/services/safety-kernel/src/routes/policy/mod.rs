//! `/policy/*` route group —  scaffold (, ).
//!
//! Mounts four endpoints, every one returning `501 Not Implemented`:
//!
//!   * `POST /policy/module/register`            (`register.rs`)
//!   * `POST /policy/module/authorize`           (`authorize.rs`)
//!   * `POST /policy/audit-event`                (`audit_event.rs`)
//!   * `GET  /policy/module/{module_path}/status` (`status.rs`)
//!
//! Real authorization, registry lookup, signed-decision minting, and
//! audit-chain writes land in slice 2. See  §"Slice plan" for
//! the full milestone list and §"What slice 1 does NOT do" for the
//! explicit guarantee these handlers refuse production traffic.

use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

pub mod audit_event;
pub mod authorize;
pub mod register;
pub mod status;

/// Build the `/policy/*` sub-router. Wired into the main axum app in
/// `main.rs` with one line — keeps the policy surface entirely
/// self-contained so future slices can iterate without touching the
/// kernel entrypoint.
///
/// `Router` is itself `#[must_use]` upstream, so this function has no
/// redundant attribute.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/policy/module/register", post(register::register))
        .route("/policy/module/authorize", post(authorize::authorize))
        .route("/policy/audit-event", post(audit_event::audit_event))
        .route("/policy/module/{module_path}/status", get(status::status))
}
