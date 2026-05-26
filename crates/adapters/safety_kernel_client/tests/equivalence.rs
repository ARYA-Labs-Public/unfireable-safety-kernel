//! AC7 — golden-fixture equivalence test.
//!
//! Per Addendum 2a §7 (drift finding A, user-approved
//! 2026-05-22): the Python `sdk.py` cannot be byte-equivalent with the
//! Rust client because the two SDKs target different routes / auth
//! shapes. The reinterpreted AC7 instead pins the Rust client's
//! serialized request body + headers against the five fixtures at
//! `tests/fixtures/equivalence/`. Any drift here is a wire-contract
//! break.
//!
//! What this test covers (Step 4 — Developer #4):
//! - `AuthorizeRequest` serializes byte-exact to the body string in
//!   `authorize_rsi.json` and `authorize_inference.json`. Specifically:
//!   * lexicographic field order (`action`, `params_fingerprint`,
//!     `run_id`, `subject`),
//!   * no `traceparent` in the body (it goes on the header line).
//! - The fixture JSON files parse as well-formed shape — each has
//!   `method`, `path`, `headers`, `body`.
//!
//! Header equivalence (full ordered map compare against
//! `headers` in the fixture) is exercised by `boundary_check.rs` /
//! `traceparent.rs` (Step 6). This file only validates the body
//! serialization — that is the AC7 surface this developer owns.

use std::collections::BTreeMap;
use std::fs;

use qorch_safety_kernel_client::AuthorizeRequest;
use serde::Deserialize;

/// Minimal fixture envelope. Lex-sorted fields (per ADR §5 rule 1).
#[derive(Deserialize)]
struct Fixture {
    body: String,
    headers: BTreeMap<String, String>,
    method: String,
    path: String,
}

fn fixture_path(name: &str) -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push("equivalence");
    p.push(name);
    p
}

fn load(name: &str) -> Fixture {
    let s = fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|e| panic!("read fixture {name}: {e}"));
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse fixture {name}: {e}"))
}

#[test]
fn fixture_authorize_rsi_body_matches_rust_serialization() {
    // Build the exact request the fixture pins. traceparent lives on
    // the header, so it is `Some(...)` here (so the test also asserts
    // skip_serializing_if works — the body MUST NOT contain it).
    let req = AuthorizeRequest {
        action: "sio_run_cycles".to_string(),
        params_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            .to_string(),
        run_id: "run-rsi-001".to_string(),
        subject: "worker".to_string(),
        traceparent: Some("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01".to_string()),
    };
    let serialized = serde_json::to_string(&req).expect("serialize");

    let fx = load("authorize_rsi.json");
    assert_eq!(fx.method, "POST");
    assert_eq!(fx.path, "/kernel/v1/authorize");
    assert_eq!(
        serialized, fx.body,
        "AuthorizeRequest body must byte-match the fixture"
    );
    // The body MUST NOT contain traceparent — header-only field.
    assert!(
        !serialized.contains("traceparent"),
        "traceparent must NOT appear in the JSON body"
    );
}

#[test]
fn fixture_authorize_inference_body_matches_rust_serialization() {
    let req = AuthorizeRequest {
        action: "inference_dispatch".to_string(),
        params_fingerprint: "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"
            .to_string(),
        run_id: "run-inf-002".to_string(),
        subject: "worker".to_string(),
        traceparent: Some("00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-01".to_string()),
    };
    let serialized = serde_json::to_string(&req).expect("serialize");

    let fx = load("authorize_inference.json");
    assert_eq!(fx.method, "POST");
    assert_eq!(fx.path, "/kernel/v1/authorize");
    assert_eq!(
        serialized, fx.body,
        "AuthorizeRequest body must byte-match the inference fixture"
    );
}

#[test]
fn fixture_health_is_a_bodyless_get() {
    let fx = load("health.json");
    assert_eq!(fx.method, "GET");
    assert_eq!(fx.path, "/kernel/v1/health");
    assert_eq!(fx.body, "");
    assert!(fx.headers.contains_key("x-api-key"));
}

#[test]
fn fixture_public_key_is_a_bodyless_get() {
    let fx = load("public_key.json");
    assert_eq!(fx.method, "GET");
    assert_eq!(fx.path, "/kernel/v1/public_key");
    assert_eq!(fx.body, "");
    assert!(fx.headers.contains_key("x-api-key"));
}

#[test]
fn fixture_authorize_headers_are_lowercase_lex_sorted() {
    // ADR §5 rule 6 — headers are sorted lower-case BTreeMap. Verify
    // the fixture preserves this so boundary_check.rs (Step 6) can
    // rely on lex order when diffing the live request headers.
    let fx = load("authorize_rsi.json");
    let keys: Vec<&String> = fx.headers.keys().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "headers must already be lex-sorted in fixture");
    for k in &keys {
        assert_eq!(k.as_str(), &k.to_lowercase(), "header key {k} must be lowercase");
    }
}
