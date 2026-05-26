//! Library surface of the reference app — exposes `build_app` and
//! `build_dev_client` so integration tests can construct the app
//! without spinning up a TCP listener.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::sync::Arc;

use axum::extract::Extension;
use axum::http::{Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use qorch_domain::safety::VerifiedClaims;
use qorch_safety_kernel_client::KernelDecision;
use qorch_safety_kernel_middleware::{
    MiddlewarePolicy, MockSafetyKernelClient, SafetyKernelClientTrait, SafetyLayer, SafetyToken,
    StaticPolicy,
};
use serde_json::json;

/// Build the axum `Router` with `SafetyLayer` applied. Exposed so
/// integration tests can construct the app without a network listener.
pub fn build_app(client: Arc<dyn SafetyKernelClientTrait>) -> Router {
    let policy = Arc::new(StaticPolicy::from_routes([
        (
            Method::GET,
            "/public/hello".into(),
            MiddlewarePolicy::Unrestricted,
        ),
        (Method::POST, "/gated/run".into(), MiddlewarePolicy::Gated),
    ]));

    let layer = SafetyLayer::new(client, policy);

    Router::new()
        .route("/public/hello", get(public_hello))
        .route("/gated/run", post(gated_run))
        .layer(layer)
}

/// Build a local-dev client. ALLOWs every well-formed request by
/// minting a synthetic `KernelDecision::Allow` with a pre-populated
/// `VerifiedClaims`. The dev mock does NOT perform signature
/// verification — production deployments swap in the real SDK.
#[must_use]
pub fn build_dev_client() -> Arc<dyn SafetyKernelClientTrait> {
    Arc::new(MockSafetyKernelClient::new(|req| {
        let mut claims = std::collections::BTreeMap::new();
        claims.insert(
            "action".to_string(),
            serde_json::Value::String(req.action.clone()),
        );
        claims.insert(
            "subject".to_string(),
            serde_json::Value::String(req.subject.clone()),
        );
        claims.insert(
            "run_id".to_string(),
            serde_json::Value::String(req.run_id.clone()),
        );
        let verified = VerifiedClaims {
            token: "dev-mock-token".to_string(),
            claims,
            signature_b64: String::new(),
        };
        Ok(KernelDecision::Allow {
            token: "dev-mock-token".to_string(),
            claims: verified,
        })
    }))
}

/// `GET /public/hello` — Unrestricted route. Middleware skipped.
async fn public_hello() -> impl IntoResponse {
    Json(json!({"ok": true, "message": "hello"}))
}

/// `POST /gated/run` — Gated route. The middleware attaches a
/// `SafetyToken` extension on successful authorize; the handler
/// asserts its presence as the structural defence against fixture #6
/// ("bypass-attempt-direct"). If the extension is missing, return
/// 403 — the handler MUST refuse to operate when the middleware was
/// somehow bypassed.
async fn gated_run(
    token: Option<Extension<SafetyToken>>,
    body: Option<Json<serde_json::Value>>,
) -> impl IntoResponse {
    let Some(Extension(tok)) = token else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "ok": false,
                "error": "missing_safety_token",
                "reason": "handler invoked without SafetyLayer attestation",
            })),
        )
            .into_response();
    };
    let body_val = body.map(|Json(v)| v).unwrap_or(json!({}));
    Json(json!({
        "ok": true,
        "echo": body_val,
        "safety_token_action": tok
            .claims
            .claims
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    }))
    .into_response()
}
