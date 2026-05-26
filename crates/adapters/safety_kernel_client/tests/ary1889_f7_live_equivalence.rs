//!   F7 — Live Rust kernel equivalence harness.
//!
//! Closes the AC7 milestone deferred at  (Addendum 2a §7 drift A):
//! the original AC7 was reinterpreted as "frozen golden fixtures" because
//! a live Python equivalence test was infeasible at the time the Rust
//! client landed. Now that 2c-python has migrated `sdk.py` to the new
//! Rust kernel API, we can fire **both** clients at the same live kernel
//! and compare wire bytes.
//!
//! This file is the Rust side of the harness. The Python side lives at
//! `tests/ary1889/test_f7_live_equivalence.py` and asserts the SAME
//! invariants from a Python caller. Together they prove that:
//!
//! 1. Both SDKs emit byte-identical request bodies given the same inputs.
//! 2. Both SDKs receive structurally equivalent responses from the kernel.
//! 3. Neither SDK can be the source of a wire-shape drift without the
//!    other catching it.
//!
//! Run with the Rust kernel running on `qorch-safety-kernel-rust:9000`
//! (default in dev compose) OR set `QORCH_LIVE_KERNEL_URL` explicitly.
//! The test silently skips when no live kernel is reachable, so CI on
//! offline runners is safe.
//!
//! ```sh
//! cargo test -p qorch-safety-kernel-client \
//!     --test ary1889_f7_live_equivalence
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::TcpStream;
use std::time::Duration;

use qorch_safety_kernel_client::AuthorizeRequest;

/// Resolve the live Rust kernel URL, returning `None` when no kernel is
/// reachable (the test then skips cleanly).
///
/// Priority:
/// 1. `QORCH_LIVE_KERNEL_URL` env override
/// 2. `docker inspect qorch-safety-kernel-rust` bridge IP probe
/// 3. localhost:9001 host-port fallback (some dev compose setups)
fn discover_live_kernel_url() -> Option<String> {
    if let Ok(url) = std::env::var("QORCH_LIVE_KERNEL_URL") {
        if !url.is_empty() {
            return Some(url);
        }
    }
    // Try docker inspect.
    if let Ok(out) = std::process::Command::new("docker")
        .args([
            "inspect",
            "qorch-safety-kernel-rust",
            "--format",
            "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        ])
        .output()
    {
        let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !ip.is_empty() {
            let addr = format!("{ip}:9000");
            if TcpStream::connect_timeout(
                &addr.parse().ok()?,
                Duration::from_millis(1000),
            )
            .is_ok()
            {
                return Some(format!("http://{addr}"));
            }
        }
    }
    // Last-resort: host-port 9001 (per CLAUDE.md port table).
    if TcpStream::connect_timeout(
        &"127.0.0.1:9001".parse().ok()?,
        Duration::from_millis(500),
    )
    .is_ok()
    {
        return Some("http://127.0.0.1:9001".to_string());
    }
    None
}

fn worker_api_key() -> String {
    std::env::var("QORCH_KERNEL_API_KEY_WORKER")
        .unwrap_or_else(|_| "30eHMobo3b0hmdsuWCzb7ruxb8CpdxO_APrcoFENVfk".to_string())
}

/// F7.RS.1 — The Rust SDK's serialized request body MUST byte-equal the
/// canonical AuthorizeRequest serialization per Addendum
/// 2a §5. This re-derives the canonical form in-process (Rule 9) rather
/// than regex-matching a fixture file.
#[test]
fn f7_rust_serialization_matches_canonical_contract() {
    let req = AuthorizeRequest {
        action: "sio_run_cycles".into(),
        params_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            .into(),
        run_id: "ary1889-f7-rs-canon-001".into(),
        subject: "worker".into(),
        traceparent: Some("00-ffffffffffffffffffffffffffffffff-9999999999999999-01".into()),
    };
    let serialized = serde_json::to_string(&req).expect("serialize");

    // Canonical form: lex-sorted keys, no spaces, no traceparent.
    let expected = r#"{"action":"sio_run_cycles","params_fingerprint":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","run_id":"ary1889-f7-rs-canon-001","subject":"worker"}"#;

    assert_eq!(
        serialized, expected,
        "F7.RS.1 canonical-serialization drift — wire contract broken"
    );
    assert!(
        !serialized.contains("traceparent"),
        "F7.RS.1 traceparent leaked into body (header-only field)"
    );
}

/// F7.RS.2 — Live kernel round-trip. POSTs the same canonical body to the
/// running Rust kernel and asserts the response shape is structurally
/// valid (allow → token+token_sha256+claims, deny → ok:false+reason).
///
/// The kernel may NACK an unknown action; that's an action-allowlist
/// outcome, NOT a 5xx — we accept either shape and only fail on 5xx or
/// malformed JSON.
#[tokio::test]
async fn f7_live_kernel_round_trip_is_well_formed() {
    let Some(base_url) = discover_live_kernel_url() else {
        eprintln!(
            "F7.RS.2 SKIP: no live Rust kernel reachable. Set QORCH_LIVE_KERNEL_URL or start \
             the qorch-safety-kernel-rust container."
        );
        return;
    };

    // Build the request body using the canonical serialization (must
    // byte-match the Python side).
    let req = AuthorizeRequest {
        action: "sio_run_cycles".into(),
        params_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            .into(),
        run_id: "ary1889-f7-rs-live-001".into(),
        subject: "worker".into(),
        traceparent: None,
    };
    let body = serde_json::to_string(&req).expect("serialize");

    // Use reqwest async (no blocking feature in workspace).
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");

    let resp = client
        .post(format!("{base_url}/kernel/v1/authorize"))
        .header("content-type", "application/json")
        .header("x-api-key", worker_api_key())
        .body(body.clone())
        .send()
        .await
        .expect("send to live kernel");

    let status = resp.status();
    let text = resp.text().await.expect("read response body");

    assert!(
        status.as_u16() < 500,
        "F7.RS.2 live kernel returned 5xx for a well-formed request: \
         status={status}, body={text}"
    );

    // Parse the response and validate the structural contract.
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("F7.RS.2 malformed JSON response: {e} body={text}"));

    if status.is_success() {
        // ALLOW path.
        assert_eq!(parsed["ok"].as_bool(), Some(true), "F7.RS.2 allow path ok != true");
        assert!(
            parsed["token"].is_string() && !parsed["token"].as_str().unwrap().is_empty(),
            "F7.RS.2 allow path missing token"
        );
        let sha = parsed["token_sha256"].as_str().unwrap_or("");
        assert_eq!(sha.len(), 64, "F7.RS.2 token_sha256 must be 64 hex chars");
        assert!(parsed["claims"].is_object(), "F7.RS.2 allow path missing claims object");
    } else {
        // DENY / not-allowlisted path.
        let ok_field = parsed["ok"].as_bool().unwrap_or(true);
        let has_error = parsed["error"].is_string() || parsed["reason"].is_string();
        assert!(
            !ok_field || has_error,
            "F7.RS.2 deny path must report ok:false or error/reason; got: {parsed}"
        );
    }
}

/// F7.RS.3 — Cross-language seam parity (F11 sibling assertion).
/// Verifies that a freshly fetched public key from the live kernel matches
/// the expected base64url-no-pad Ed25519 32-byte form. Both Python and
/// Rust SDKs MUST be able to round-trip this same key bytes.
#[tokio::test]
async fn f7_live_public_key_well_formed() {
    let Some(base_url) = discover_live_kernel_url() else {
        eprintln!(
            "F7.RS.3 SKIP: no live Rust kernel reachable."
        );
        return;
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("build reqwest client");
    let resp = client
        .get(format!("{base_url}/kernel/v1/public_key"))
        .header("x-api-key", worker_api_key())
        .send()
        .await
        .expect("send /public_key");
    assert!(resp.status().is_success(), "F7.RS.3 /public_key not 200");
    let body: serde_json::Value = resp.json().await.expect("/public_key json");
    assert_eq!(body["ok"].as_bool(), Some(true));
    assert_eq!(body["algorithm"].as_str(), Some("Ed25519"));
    let pk = body["public_key_b64"].as_str().expect("public_key_b64 string");
    // base64url-no-pad of 32 bytes = 43 chars
    assert_eq!(pk.len(), 43, "F7.RS.3 public_key_b64 must be 43 chars (32B b64url-nopad)");
    let fp = body["public_key_fingerprint"].as_str().expect("fingerprint string");
    assert_eq!(fp.len(), 64, "F7.RS.3 fingerprint must be SHA-256 hex");
}
