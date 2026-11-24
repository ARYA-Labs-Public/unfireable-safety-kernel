//! Every tier that calls the kernel fails closed, and an unregistered
//! route is gated. `Supervised` used to make a fire-and-forget call and
//! let the request through on a DENY or an unreachable kernel; these
//! tests pin that it no longer can.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::routing::post;
use axum::Router;
use qorch_safety_kernel_client::{KernelClientError, KernelDecision, KernelDecisionError};
use qorch_safety_kernel_middleware::{
    MiddlewarePolicy, MockSafetyKernelClient, SafetyKernelClientTrait, SafetyLayer, StaticPolicy,
};
use tower::ServiceExt;

/// The app with `/sup` supervised and `/unlisted` not in the policy table.
/// `hits` counts how often a handler ran.
fn app(client: Arc<dyn SafetyKernelClientTrait>, hits: Arc<AtomicUsize>) -> Router {
    let policy = Arc::new(StaticPolicy::from_routes([(
        Method::POST,
        "/sup".into(),
        MiddlewarePolicy::Supervised,
    )]));
    let (h1, h2) = (Arc::clone(&hits), hits);
    Router::new()
        .route(
            "/sup",
            post(move || async move {
                h1.fetch_add(1, Ordering::SeqCst);
                "ok"
            }),
        )
        .route(
            "/unlisted",
            post(move || async move {
                h2.fetch_add(1, Ordering::SeqCst);
                "ok"
            }),
        )
        .layer(SafetyLayer::new(client, policy))
}

fn post_to(path: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("x-run-id", "run-tier")
        .header("x-subject", "worker")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"k":"v"}"#))
        .unwrap()
}

fn denying() -> Arc<dyn SafetyKernelClientTrait> {
    Arc::new(MockSafetyKernelClient::new(|_| {
        Ok(KernelDecision::Deny {
            reason: "policy_says_no".to_string(),
        })
    }))
}

fn unavailable() -> Arc<dyn SafetyKernelClientTrait> {
    Arc::new(MockSafetyKernelClient::new(|_| {
        Err(KernelClientError::Decision(
            KernelDecisionError::Unavailable {
                reason: "kernel_down".to_string(),
            },
        ))
    }))
}

async fn status(client: Arc<dyn SafetyKernelClientTrait>, path: &str) -> (StatusCode, usize) {
    let hits = Arc::new(AtomicUsize::new(0));
    let resp = app(client, Arc::clone(&hits))
        .oneshot(post_to(path))
        .await
        .unwrap();
    (resp.status(), hits.load(Ordering::SeqCst))
}

#[tokio::test]
async fn supervised_deny_is_403_and_the_handler_never_runs() {
    let (s, hits) = status(denying(), "/sup").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(hits, 0, "a denied supervised request reached the handler");
}

#[tokio::test]
async fn supervised_unavailable_is_503_and_the_handler_never_runs() {
    let (s, hits) = status(unavailable(), "/sup").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        hits, 0,
        "a supervised request went through with the kernel down"
    );
}

#[tokio::test]
async fn unregistered_route_is_gated_not_let_through() {
    let (s, hits) = status(unavailable(), "/unlisted").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(hits, 0, "an unregistered route bypassed the kernel");
    let (s, hits) = status(denying(), "/unlisted").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(hits, 0);
}
