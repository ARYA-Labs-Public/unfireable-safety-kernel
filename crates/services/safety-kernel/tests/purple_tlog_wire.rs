//!   — Purple-Team wire-level tests for the kernel's
//! production `ReqwestTransparencyClient`.
//!
//! `purple_tlog_malformed_response.rs` covers the kernel's authorize
//! handler with a behaviorally-stubbed `TransparencyClient`. This file
//! complements that by exercising the PRODUCTION HTTP client against a
//! tiny inline TCP server that synthesises adversarial responses:
//!
//!   - C1-wire — 200 OK with non-JSON body  → Malformed
//!   - C1-wire — 200 OK with JSON of wrong  → Malformed
//!     shape (missing required fields)
//!   - C1-wire — 500 Internal Server Error → ServerError
//!   - C1-wire — 401 Unauthorized          → Rejected
//!   - C1-wire — 422 Unprocessable Entity  → Rejected
//!
//! No external mock crate. The server is a `std::net::TcpListener` in
//! a background thread answering one connection per scenario with a
//! hard-coded HTTP/1.1 response.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::similar_names)]
#![allow(clippy::doc_markdown, clippy::doc_lazy_continuation)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use qorch_safety_kernel::transparency_client::{
    ReqwestTransparencyClient, TransparencyAppendInput, TransparencyClient, TransparencyError,
};

/// Bind a TCP listener on 127.0.0.1:0 and answer the next accepted
/// connection with the literal `response` bytes (must be a full HTTP
/// response — caller supplies status line + headers + body). Returns
/// the bound port.
fn one_shot_server(response: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut socket, _addr) = listener.accept().expect("accept");
        // Drain the request — we don't validate it; the t-log client
        // sends a well-formed POST, and the test cares about the
        // response handling.
        let mut buf = [0u8; 4096];
        let _ = socket.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = socket.read(&mut buf);
        let _ = socket.write_all(response.as_bytes());
        let _ = socket.flush();
    });
    port
}

fn client_for(port: u16) -> ReqwestTransparencyClient {
    ReqwestTransparencyClient::new(
        format!("http://127.0.0.1:{port}"),
        "test-key".to_string(),
        hex::encode([0u8; 32]),
        Duration::from_secs(2),
    )
}

fn input() -> TransparencyAppendInput {
    TransparencyAppendInput {
        idempotency_key: [0x77u8; 32],
        payload: b"some-token-bytes".to_vec(),
        occurred_at_epoch_seconds: 1_700_000_000,
    }
}

// ---------------------------------------------------------------------------
// C1-wire — 200 OK + non-JSON body → Malformed
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn purple_c1wire_200_with_junk_body_yields_malformed() {
    let port = one_shot_server(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 23\r\n\r\nthis is not JSON at all",
    );
    let client = client_for(port);
    let err = client.append(input()).await.unwrap_err();
    assert!(
        matches!(err, TransparencyError::Malformed {.. }),
        "expected Malformed, got {err:?}"
    );
    // Stable kind string for synth-deny mapping.
    assert_eq!(err.kind(), "malformed_response");
}

// ---------------------------------------------------------------------------
// C1-wire — 200 OK + JSON body with wrong schema → Malformed
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn purple_c1wire_200_with_wrong_schema_yields_malformed() {
    // JSON body is valid JSON but missing the required `entry_id`,
    // `idempotent_replay`, `leaf_hash_hex`, `leaf_index`, `ok` fields.
    let body = r#"{"unrelated":"field"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let response_static: &'static str = Box::leak(response.into_boxed_str());
    let port = one_shot_server(response_static);
    let client = client_for(port);
    let err = client.append(input()).await.unwrap_err();
    assert!(
        matches!(err, TransparencyError::Malformed {.. }),
        "expected Malformed for wrong-schema body, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// C1-wire — 500 → ServerError (kind = "server_error")
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn purple_c1wire_500_yields_server_error() {
    let port = one_shot_server(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 14\r\n\r\nsynthetic 500\n",
    );
    let client = client_for(port);
    let err = client.append(input()).await.unwrap_err();
    assert!(matches!(err, TransparencyError::ServerError {.. }), "got {err:?}");
    assert_eq!(err.kind(), "server_error");
}

// ---------------------------------------------------------------------------
// C1-wire — 401 → Rejected (kind = "append_failed"). Verifies the
// kernel's deny path maps to a non-OK reason on auth failures from the
// t-log, not to a fall-through-allow.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn purple_c1wire_401_yields_rejected() {
    let port = one_shot_server(
        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 11\r\n\r\nbad api key",
    );
    let client = client_for(port);
    let err = client.append(input()).await.unwrap_err();
    assert!(matches!(err, TransparencyError::Rejected { status_code: 401,.. }), "got {err:?}");
    assert_eq!(err.kind(), "append_failed");
}

// ---------------------------------------------------------------------------
// C1-wire — 422 → Rejected (kind = "append_failed").
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn purple_c1wire_422_yields_rejected() {
    let port = one_shot_server(
        "HTTP/1.1 422 Unprocessable Entity\r\nContent-Length: 14\r\n\r\nbad body shape",
    );
    let client = client_for(port);
    let err = client.append(input()).await.unwrap_err();
    assert!(matches!(err, TransparencyError::Rejected { status_code: 422,.. }), "got {err:?}");
    assert_eq!(err.kind(), "append_failed");
}
