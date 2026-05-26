//! Reference axum application demonstrating
//! `qorch-safety-kernel-middleware` (  sub-deliverable
//! 2c-rust).
//!
//! See `lib.rs` for the routes + handlers. This file is just the
//! tokio entry point so the binary stays minimal and integration
//! tests can re-use `build_app` from the library surface.
//!
//! Run:
//!
//! ```bash
//! cargo run -p reference_app_rs
//! ```
//!
//! Then:
//!
//! ```bash
//! curl -i http://127.0.0.1:8088/public/hello
//! curl -i -X POST http://127.0.0.1:8088/gated/run \
//!   -H 'x-run-id: r1' -H 'x-subject: worker' -d '{}'
//! ```

use reference_app_rs::{build_app, build_dev_client};

/// Bind address — overridable via `REFERENCE_APP_RS_ADDR`.
const DEFAULT_BIND: &str = "127.0.0.1:8088";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::try_init().ok();

    let app = build_app(build_dev_client());

    let bind = std::env::var("REFERENCE_APP_RS_ADDR")
        .unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(bind = %bind, "reference_app_rs listening");
    axum::serve(listener, app).await?;
    Ok(())
}
