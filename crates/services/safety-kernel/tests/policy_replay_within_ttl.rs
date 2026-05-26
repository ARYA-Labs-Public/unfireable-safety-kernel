//! Adversarial fixture — replay attack within TTL window
//! ( slice 2, watchdog class `audit_chain_replay_rejected`).
//!
//! ## Threat model
//!
//! A worker captures a signed `module_authorize` token `T1` issued at
//! time `t0` with `exp = t0 + 60s` (default TTL). The
//! attacker:
//!
//!   - **Variant A — token reuse outside TTL:** waits 60+ seconds and
//!     replays T1 against the kernel's `verify_kernel_token`. Defense:
//!     `verify_kernel_token` rejects via `KernelTokenError::Expired`.
//!   - **Variant B — duplicate authorize call:** issues a second
//!     `POST /policy/module/authorize` with the same
//!     `(event_kind, module_path, caller_subject, caller_run_id)` → same
//!     event_fingerprint. The kernel produces a **new** token T2 with
//!     a fresh nonce + fresh times. T2 is NOT a copy of T1; T1's
//!     signature does NOT verify against T2's payload bytes. The audit
//!     chain records BOTH decisions (each gets its own
//!     `policy_authorize_allow` chain entry) so forensics can see the
//!     duplicate event pair.
//!
//! Per the slice-2 handler intentionally does NOT maintain a
//! request-level deduplication cache — the cryptographic defense is
//! `exp`-bounded validity + per-token nonce uniqueness. Slice 5b is the
//! only authorized addition of a decision cache (`exp`-bounded only,
//! and gated on a measured p99 failure in slice 5).
//!
//! ## Why this fixture covers the watchdog class
//!
//! `audit_chain_replay_rejected` per covers the threat where
//! a captured signed decision is replayed across the kernel boundary.
//! The defense is split across three primitives that we exercise here:
//!
//!   1. `exp`-bounded validity (this file, `replayed_token_after_exp_*`).
//!   2. Per-token nonce uniqueness (this file, `repeat_authorize_*`).
//!   3. Audit-chain single-chain ordering (in
//!      `policy_audit_chain_integrity.rs`, NOT this file).
//!
//! All assertions demand REJECTION of replay (Rule 8).
//!
//! Marked `#[ignore]` because it spawns the Python sidecar subprocess +
//! Rust kernel binary. Run with:
//!
//! ```bash
//! cargo test -p qorch-safety-kernel --test policy_replay_within_ttl -- --ignored
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::too_many_lines)]
#![allow(
    clippy::doc_markdown,
    clippy::single_match_else,
    clippy::manual_let_else
)]

mod common;

use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use serde_json::{json, Value};

use qorch_domain::safety::{params_fingerprint, verify_kernel_token, KernelTokenError};

fn canonical_fp(ek: &str, mp: &str, cs: &str, crid: &str) -> String {
    let canonical = json!({
        "event_kind": ek,
        "module_path": mp,
        "caller_subject": cs,
        "caller_run_id": crid,
    });
    params_fingerprint(&canonical)
}

fn authorize_body(ek: &str, mp: &str, cs: &str, crid: &str) -> Value {
    json!({
        "event_kind": ek,
        "module_path": mp,
        "caller_subject": cs,
        "caller_run_id": crid,
        "event_fingerprint": canonical_fp(ek, mp, cs, crid),
    })
}

async fn with_live_stack<F, Fut>(test: F)
where
    F: FnOnce(reqwest::Client, String) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if !common::have_python3() {
        eprintln!("python3 not on PATH — skipping");
        return;
    }
    let root = common::workspace_root();
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("sk.sock");
    let signing_key_b64 = common::fresh_seed_b64();
    let audit_pepper_b64 = common::fresh_seed_b64();

    let mut sidecar = match common::spawn_sidecar(&root, &sock_path) {
        Some(c) => c,
        None => {
            eprintln!("sidecar failed to start — skipping");
            return;
        }
    };

    let bin = match common::build_kernel_binary(&root) {
        Ok(p) => p,
        Err(e) => {
            let _ = sidecar.kill();
            panic!("{e}");
        }
    };

    let port = common::pick_free_port();
    let listen_addr = format!("127.0.0.1:{port}");
    let mut kernel = match common::spawn_kernel(
        &bin,
        &listen_addr,
        &sock_path,
        &signing_key_b64,
        &audit_pepper_b64,
    )
    .await
    {
        Some(c) => c,
        None => {
            let _ = sidecar.kill();
            panic!("kernel binary did not become ready in 10s");
        }
    };

    let url = format!("http://{listen_addr}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    test(client, url).await;

    let _ = kernel.kill();
    let _ = sidecar.kill();
    let _ = kernel.wait();
    let _ = sidecar.wait();
    drop(tmp);
    let _ = signing_key_b64;
    let _ = audit_pepper_b64;
}

/// Fetch the kernel's public key for token verification.
async fn fetch_public_key(client: &reqwest::Client, url: &str) -> VerifyingKey {
    let r = client
        .get(format!("{url}/kernel/v1/public_key"))
        .send()
        .await
        .unwrap();
    let body: Value = r.json().await.unwrap();
    let pk_b64 = body
        .get("public_key_b64")
        .and_then(Value::as_str)
        .expect("public_key_b64");
    let pk_raw = URL_SAFE_NO_PAD.decode(pk_b64).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pk_raw);
    VerifyingKey::from_bytes(&arr).unwrap()
}

/// Pre-register so the authorize call returns allow + a signed token.
async fn register(client: &reqwest::Client, url: &str, module_path: &str) {
    let r = client
        .post(format!("{url}/policy/module/register"))
        .header("x-api-key", "test-worker-key")
        .json(&json!({
            "module_path": module_path,
            "required_patterns_regex_set": ["^pkg\\."],
            "caller_subject": "worker",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "register failed");
}

/// Call authorize and pull the signed token from the response.
async fn authorize(
    client: &reqwest::Client,
    url: &str,
    module_path: &str,
    run_id: &str,
) -> (Value, String) {
    let r = client
        .post(format!("{url}/policy/module/authorize"))
        .header("x-api-key", "test-worker-key")
        .json(&authorize_body("import", module_path, "worker", run_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "authorize must succeed for this test");
    let body: Value = r.json().await.unwrap();
    let token = body
        .get("token")
        .and_then(Value::as_str)
        .expect("token in body")
        .to_string();
    (body, token)
}

// ============================================================================
// VARIANT A — Token reuse OUTSIDE TTL window MUST be rejected as expired.
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns python3 sidecar + cargo build; run with --ignored"]
async fn token_replay_after_exp_is_rejected_as_expired() {
    with_live_stack(|client, url| async move {
        register(&client, &url, "pkg.alpha").await;
        let (body, token) = authorize(&client, &url, "pkg.alpha", "run-A").await;

        // Pull the claims to discover `expires_at`.
        let claims = body.get("claims").expect("claims");
        let exp = claims
            .get("expires_at")
            .and_then(Value::as_f64)
            .expect("expires_at f64");

        let pk = fetch_public_key(&client, &url).await;

        // Sanity: token verifies right now (just past `iat`).
        let iat = claims.get("issued_at").and_then(Value::as_f64).unwrap();
        let now_ok = iat + 0.5;
        verify_kernel_token(&token, &pk, now_ok, 5.0, None).expect("token must verify within TTL");

        // Simulate replay AT a clock that is past `exp + leeway`. We
        // pass `now = exp + 10.0` so even with leeway up to 5.0 the
        // token is past its window.
        let now_replay = exp + 10.0;
        let err = verify_kernel_token(&token, &pk, now_replay, 5.0, None)
            .expect_err("replayed token MUST be rejected as expired");
        assert!(
            matches!(err, KernelTokenError::Expired(_)),
            "rejection MUST be Expired, got {err:?}",
        );
    })
    .await;
}

// ============================================================================
// VARIANT B — Duplicate authorize call produces a NEW token with a
//             different nonce. Replaying T1 against T2's claims fails.
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns python3 sidecar + cargo build; run with --ignored"]
async fn repeat_authorize_mints_new_token_with_fresh_nonce() {
    with_live_stack(|client, url| async move {
        register(&client, &url, "pkg.beta").await;
        // First authorize → T1.
        let (body1, token1) = authorize(&client, &url, "pkg.beta", "run-B").await;
        // Tiny delay so `iat` differs at f64 precision; not strictly
        // required for the nonce-uniqueness assert.
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Second authorize, same canonical event → T2.
        let (body2, token2) = authorize(&client, &url, "pkg.beta", "run-B").await;

        // T1 and T2 must be DIFFERENT compact tokens.
        assert_ne!(
            token1, token2,
            "duplicate authorize calls MUST produce different tokens; \
             a sidecar that returned a cached signed envelope would be \
             a replay-cache implementation that we have NOT shipped",
        );

        // The nonce slot MUST differ between T1 and T2 (the kernel's
        // per-token nonce is from `state.nonce.nonce_b64()`).
        let nonce1 = body1
            .get("claims")
            .and_then(|c| c.get("nonce"))
            .and_then(Value::as_str)
            .expect("nonce1");
        let nonce2 = body2
            .get("claims")
            .and_then(|c| c.get("nonce"))
            .and_then(Value::as_str)
            .expect("nonce2");
        assert_ne!(nonce1, nonce2, "each token MUST carry a fresh nonce");

        // Verify both tokens independently — both within their own
        // TTL windows — and assert each token's signature does NOT
        // verify against the OTHER token's compact form.
        let pk = fetch_public_key(&client, &url).await;
        let iat1 = body1
            .get("claims")
            .and_then(|c| c.get("issued_at"))
            .and_then(Value::as_f64)
            .unwrap();
        let iat2 = body2
            .get("claims")
            .and_then(|c| c.get("issued_at"))
            .and_then(Value::as_f64)
            .unwrap();
        verify_kernel_token(&token1, &pk, iat1 + 0.1, 5.0, None).expect("T1 must verify");
        verify_kernel_token(&token2, &pk, iat2 + 0.1, 5.0, None).expect("T2 must verify");

        // Cross-check: T1's signature is over T1's payload only — swap
        // payload + sig between tokens and verify both halves fail.
        let (payload1, sig1) = token1.split_once('.').unwrap();
        let (payload2, sig2) = token2.split_once('.').unwrap();
        let swapped1 = format!("{payload1}.{sig2}");
        let swapped2 = format!("{payload2}.{sig1}");
        let _ = verify_kernel_token(&swapped1, &pk, iat1 + 0.1, 5.0, None)
            .expect_err("payload1+sig2 MUST NOT verify");
        let _ = verify_kernel_token(&swapped2, &pk, iat2 + 0.1, 5.0, None)
            .expect_err("payload2+sig1 MUST NOT verify");
    })
    .await;
}

// ============================================================================
// VARIANT C — Audit chain records BOTH duplicate calls so forensics can
//             see the repeat. We assert via the status endpoint's
//             `recent_decisions` rather than reaching into the chain
//             directly (that's the audit-chain-integrity test's job).
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns python3 sidecar + cargo build; run with --ignored"]
async fn duplicate_authorize_calls_both_show_in_recent_decisions() {
    with_live_stack(|client, url| async move {
        register(&client, &url, "pkg.gamma").await;
        let _ = authorize(&client, &url, "pkg.gamma", "run-C").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = authorize(&client, &url, "pkg.gamma", "run-C").await;

        let r = client
            .get(format!("{url}/policy/module/pkg.gamma/status"))
            .header("x-api-key", "test-worker-key")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let body: Value = r.json().await.unwrap();
        let recent = body
            .get("recent_decisions")
            .and_then(Value::as_array)
            .expect("recent_decisions array");
        assert!(
            recent.len() >= 2,
            "audit chain MUST record BOTH duplicate authorize calls; \
             got recent_decisions.len()={}; body={body}",
            recent.len(),
        );
        // Both rows MUST be `allow` (we registered + matched pattern).
        for row in recent.iter().take(2) {
            assert_eq!(
                row.get("decision").and_then(Value::as_str),
                Some("allow"),
                "duplicate authorize MUST record allow rows; row={row}",
            );
        }
    })
    .await;
}
