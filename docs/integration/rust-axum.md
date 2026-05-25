# Axum integration

How to wire the Rust client SDK into an axum service as a `tower::Layer`,
so every request to a gated route is authorized by the Safety Kernel
before it reaches your handler.

This is **seam 2 of four** for Rust services — see
[architecture.md § four defense seams](../architecture.md#the-four-defense-seams) for the full picture.

## Add the dependency

```toml
[dependencies]
safety-kernel-client = "0.1"
axum = "0.7"
tower = "0.4"
tokio = { version = "1", features = ["full"] }
```

## Wire the layer

```rust
use axum::{Router, routing::post};
use safety_kernel_client::{SafetyKernelLayer, SafetyKernelConfig};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let layer = SafetyKernelLayer::new(SafetyKernelConfig {
        kernel_url: "http://localhost:9000".into(),
        worker_api_key: std::env::var("KERNEL_WORKER_KEY").unwrap(),
        operator_pubkey_hex: std::env::var("KERNEL_OPERATOR_PUBKEY").unwrap(),
        request_timeout: Duration::from_millis(500),
        circuit_breaker_failure_threshold: 3,
        circuit_breaker_open_duration: Duration::from_secs(10),
    });

    let app = Router::new()
        .route("/api/v1/write/thing", post(write_thing))
        .route("/api/v1/execute/op",  post(execute_op))
        .layer(layer)
        // Health endpoint mounted OUTSIDE the gated layer
        .route("/health", axum::routing::get(|| async { "ok" }));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

The layer implements `tower::Layer<S>` and produces a `Service` that
issues an `authorize` call before delegating to the inner service.
Decisions are awaited on the request path — keep `request_timeout`
short.

## Circuit-breaker behaviour

The layer wraps every outbound call in a fail-closed circuit breaker.
Three states:

- **Closed** — normal operation, every request hits the kernel.
- **Open** — opened after `failure_threshold` consecutive failures.
  Every gated request returns `503 Service Unavailable` immediately,
  without touching the kernel. Stays open for `open_duration`.
- **Half-open** — after the cooldown, a single probe request is sent.
  On success the breaker closes; on failure it re-opens.

The breaker **never** falls back to `ALLOW`. See
[`circuit-breaker.md`](circuit-breaker.md) for tuning.

## Per-route opt-out

Mount opt-out routes outside the `.layer()` call, as shown above for
`/health`. The layer only sees requests routed through it; routes
attached after the `.layer()` invocation are gated, routes attached
before or on a sibling `Router` are not.

For more granular control within a single router, use
`Router::merge` to compose a gated sub-router with an ungated one:

```rust
let gated = Router::new()
    .route("/api/v1/write/thing", post(write_thing))
    .layer(layer);

let ungated = Router::new()
    .route("/health",  axum::routing::get(|| async { "ok" }))
    .route("/metrics", axum::routing::get(metrics_handler));

let app = Router::new().merge(gated).merge(ungated);
```

Treat the ungated router as a **policy surface**. Review it on every
audit.

## Verify it works

The contract to test is: unreachable kernel must yield `503`, never `200`.

```rust
#[tokio::test]
async fn denies_when_kernel_unreachable() {
    let layer = SafetyKernelLayer::new(SafetyKernelConfig {
        // Port 1 is reliably refused
        kernel_url: "http://127.0.0.1:1".into(),
        worker_api_key: "test".into(),
        operator_pubkey_hex: "00".repeat(32),
        request_timeout: Duration::from_millis(100),
        ..Default::default()
    });

    let app = Router::new()
        .route("/api/v1/write/x", post(|| async { "ok" }))
        .layer(layer);

    let resp = app
        .oneshot(Request::builder()
            .method("POST")
            .uri("/api/v1/write/x")
            .body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}
```

If that test ever produces `200`, the layer is mis-wired or the
breaker is configured fail-open — fix before shipping.
