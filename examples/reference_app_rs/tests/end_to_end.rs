//! End-to-end integration tests for the reference Rust app.
//!
//! These tests build the same `Router` the binary serves but route
//! requests in-process via `ServiceExt::oneshot`. The SK client is a
//! stub (the `MockSafetyKernelClient` from the middleware crate) so
//! no real kernel is needed.
//!
//! Per AC13 (R): "reference app runs against
//! real kernel; tests pass in CI". This file ships the in-process
//! variant; the live-kernel variant lives behind `--ignored` and is
//! exercised by the `/test` wave's docker-compose harness.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use qorch_domain::safety::VerifiedClaims;
use qorch_safety_kernel_client::{KernelClientError, KernelDecision, KernelDecisionError};
use qorch_safety_kernel_middleware::{MockSafetyKernelClient, SafetyKernelClientTrait};
use reference_app_rs::{build_app, build_dev_client};
use tower::ServiceExt;

async fn collect(resp: axum::response::Response) -> (StatusCode, String) {
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn public_get() -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri("/public/hello")
        .body(Body::empty())
        .unwrap()
}

fn gated_post_well_formed() -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/gated/run")
        .header("x-run-id", "run-it")
        .header("x-subject", "worker")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"k":"v"}"#))
        .unwrap()
}

// -----------------------------------------------------------------
// Happy path against the dev client (ALLOWs everything).
// -----------------------------------------------------------------

#[tokio::test]
async fn dev_client_allows_public_route() {
    let app = build_app(build_dev_client());
    let resp = app.oneshot(public_get()).await.unwrap();
    let (status, body) = collect(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("hello"));
}

#[tokio::test]
async fn dev_client_allows_gated_route_when_headers_present() {
    let app = build_app(build_dev_client());
    let resp = app.oneshot(gated_post_well_formed()).await.unwrap();
    let (status, body) = collect(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("POST:/gated/run"));
    assert!(body.contains("\"echo\""));
}

// -----------------------------------------------------------------
// Stub client refuses → app surfaces a 403.
// -----------------------------------------------------------------

fn stub_denying() -> Arc<dyn SafetyKernelClientTrait> {
    Arc::new(MockSafetyKernelClient::new(|_| {
        Ok(KernelDecision::Deny {
            reason: "policy_says_no".to_string(),
        })
    }))
}

#[tokio::test]
async fn deny_propagates_to_403() {
    let app = build_app(stub_denying());
    let resp = app.oneshot(gated_post_well_formed()).await.unwrap();
    let (status, body) = collect(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("denied"));
    assert!(body.contains("policy_says_no"));
}

// -----------------------------------------------------------------
// Stub client unreachable → app surfaces a 503.
// -----------------------------------------------------------------

fn stub_unavailable() -> Arc<dyn SafetyKernelClientTrait> {
    Arc::new(MockSafetyKernelClient::new(|_| {
        Err(KernelClientError::Decision(
            KernelDecisionError::Unavailable {
                reason: "ref_app_e2e_unavailable".to_string(),
            },
        ))
    }))
}

#[tokio::test]
async fn unavailable_propagates_to_503() {
    let app = build_app(stub_unavailable());
    let resp = app.oneshot(gated_post_well_formed()).await.unwrap();
    let (status, body) = collect(resp).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("kernel_unavailable"));
}

// -----------------------------------------------------------------
// Missing headers on a gated route → 400.
// -----------------------------------------------------------------

#[tokio::test]
async fn missing_run_id_yields_400() {
    let app = build_app(build_dev_client());
    let req = Request::builder()
        .method(Method::POST)
        .uri("/gated/run")
        // intentionally no x-run-id
        .header("x-subject", "worker")
        .body(Body::from("{}"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let (status, body) = collect(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("x-run-id"));
}

// -----------------------------------------------------------------
// Custom stub that explicitly attests a Verified claim — proves the
// downstream handler sees the SafetyToken extension produced by the
// middleware (Rule 9, re-derived in-process).
// -----------------------------------------------------------------

#[tokio::test]
async fn handler_sees_safety_token_action() {
    let client = Arc::new(MockSafetyKernelClient::new(|req| {
        let mut claims = std::collections::BTreeMap::new();
        claims.insert(
            "action".to_string(),
            serde_json::Value::String(req.action.clone()),
        );
        claims.insert(
            "subject".to_string(),
            serde_json::Value::String(req.subject.clone()),
        );
        let verified = VerifiedClaims {
            token: "tok".to_string(),
            claims,
            signature_b64: String::new(),
        };
        Ok(KernelDecision::Allow {
            token: "tok".to_string(),
            claims: verified,
        })
    }));
    let app = build_app(client);
    let resp = app.oneshot(gated_post_well_formed()).await.unwrap();
    let (status, body) = collect(resp).await;
    assert_eq!(status, StatusCode::OK);
    // The handler echoes back `safety_token_action`, which is the
    // `action` claim from the verified token. Confirms the middleware
    // attached the extension and the handler read it.
    assert!(
        body.contains("\"safety_token_action\":\"POST:/gated/run\""),
        "body: {body}"
    );
}
