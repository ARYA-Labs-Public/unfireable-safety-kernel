# Axum integration

How to gate an axum service through the Safety Kernel with a
`tower::Layer`, so every request to a `Gated` route is authorized before
it reaches your handler.

The ready-made middleware ships as the **`qorch-safety-kernel-middleware`**
crate (a `tower::Layer` called `SafetyLayer`), built on the
`qorch-safety-kernel-client` SDK. You get a real, tested layer, not a
snippet to copy, and it is fail-closed by construction: on a `Gated`
route, any error from the SDK short-circuits the request — it never
auto-allows.

This is **seam 2 of four** for Rust services — see
[architecture.md § four defense seams](../architecture.md#the-four-defense-seams) for the full picture.

## Add the dependency

```toml
[dependencies]
qorch-safety-kernel-middleware = "0.1"
qorch-safety-kernel-client = "0.1"
axum = "0.8"
tower = "0.5"
tokio = { version = "1", features = ["full"] }
```

## Wire the layer

`SafetyLayer::new` takes two things: the SDK client (shared as
`Arc<dyn SafetyKernelClientTrait>` — the production impl is
`SafetyKernelClient` from `qorch-safety-kernel-client`, which owns the
reqwest client, the pinned-key Ed25519 verifier, and the fail-closed
circuit breaker), and a policy resolver that maps `(method, path)` to a
tier. `StaticPolicy::from_routes` is the simplest resolver.

```rust
use std::sync::Arc;

use axum::{http::Method, routing::post, Router};
use qorch_safety_kernel_client::SafetyKernelClient;
use qorch_safety_kernel_middleware::{
    MiddlewarePolicy, SafetyLayer, StaticPolicy,
};

#[tokio::main]
async fn main() {
    // 1. Build the SDK client once, at boot (see the client SDK docs for
    //    the exact constructor — it pins the kernel's Ed25519 public key
    //    and owns the circuit breaker). Share it behind the trait object.
    let client = Arc::new(build_safety_kernel_client());

    // 2. Declare which routes are Gated. Anything not listed defaults to
    //    Unrestricted (see the caveat below) — list every gated route.
    let policy = Arc::new(StaticPolicy::from_routes([
        (Method::POST, "/api/v1/write/thing".to_string(), MiddlewarePolicy::Gated),
        (Method::POST, "/api/v1/execute/op".to_string(),  MiddlewarePolicy::Gated),
    ]));

    let layer = SafetyLayer::new(client, policy);

    let app = Router::new()
        .route("/api/v1/write/thing", post(write_thing))
        .route("/api/v1/execute/op",  post(execute_op))
        .route("/health", axum::routing::get(|| async { "ok" }))
        .layer(layer);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

To control how the `AuthorizeRequest` body is built from a request
(`action` / `subject` / `params_fingerprint`), supply your own extractor
with `SafetyLayer::new(client, policy).with_extractor(Arc::new(my_extractor))`
(`RequestClaimsExtractor`); the default extractor is used otherwise.

## Policy tiers

`MiddlewarePolicyResolver` maps each request to one of three tiers:

| Tier | Kernel call | On failure |
|---|---|---|
| `Unrestricted` | none | n/a — passes through |
| `Supervised` | best-effort, fire-and-forget | log only, never blocks |
| `Gated` | synchronous, fail-closed | 503 (Unavailable) / 403 (Denied or forged token) |

Only `Gated` routes can reject a request. **`StaticPolicy` defaults to
`Unrestricted` on a miss** — safe-by-default for static assets, but it
means a forgotten `Gated` registration silently leaves a route ungated.
Treat the route list as a policy surface and verify it on every audit.

## Fail-closed contract

On a `Gated` route the inner handler runs on **exactly one** outcome: a
verified `Allow`. Any `Err` from the SDK — kernel unreachable, timeout,
breaker open, a denied decision, or a forged/wrong-key token — is
converted by `MiddlewareError` into a 503 or 403 and the handler is never
reached. The breaker never falls back to `ALLOW`. See
[`circuit-breaker.md`](circuit-breaker.md) for tuning.

On a successful `Gated` authorization the layer attaches a `SafetyToken`
request extension, so a downstream handler can prove the middleware
actually ran (the defence against a direct-dispatch bypass). The crate's
`tests/adversarial.rs` re-derives the fail-closed property structurally.

## Reaper / revoke-compute client usage

The same `SafetyKernelClient` carries the four coercive-shutdown methods,
mirroring the `/kernel/v1/revoke/*` endpoints. They share the client's
circuit breaker + error taxonomy, and are fail-closed: any transport
error, timeout, 5xx (including the mint path's `503 revoke_not_recorded`),
or decode drift returns `Err`, never a false-`Ok`.

```rust
use qorch_safety_kernel_client::{
    InstanceTarget, MintRevokeRequest, RestoreRequest, RevokeAckRequest, SafetyKernelClient,
};

async fn reap(client: &SafetyKernelClient) -> anyhow::Result<()> {
    // Operator mints a signed revoke-compute decision.
    let mint: MintRevokeRequest = serde_json::from_value(serde_json::json!({
        "target": { "project": "my-project", "zone": "zone-a", "instance": "agent-vm-1" },
        "tier": "vm_stop",
        "trigger": "operator_emergency_stop",
        "reason": "manual e-stop",
    }))?;
    let signed = client.mint_revoke(&mint).await?; // Err on 503 (not recorded)

    // Reaper pulls pending signed decisions for an instance (204 -> empty).
    let pending = client.pending_revoke("agent-vm-1").await?;
    for _token in &pending.pending {
        // verify + execute the reclaim out-of-band, then ack:
    }

    // Reaper acks execution so the kernel clears the queue entry.
    client
        .ack_revoke(&RevokeAckRequest {
            run_id: signed.run_id.clone(),
            outcome: "stopped".to_string(),
        })
        .await?;

    // Operator restores a stopped agent VM.
    let _restored = client
        .restore_revoke(&RestoreRequest {
            target: InstanceTarget {
                project: "my-project".to_string(),
                zone: "zone-a".to_string(),
                instance: "agent-vm-1".to_string(),
            },
            reason: Some("incident cleared".to_string()),
        })
        .await?;
    Ok(())
}
```

The tokens returned by `mint_revoke` / `restore_revoke` are opaque to the
minting caller; the reaper re-verifies each pulled token's Ed25519
signature and audience before acting on it.
