//! Adversarial fixture — registry-bypass attack MUST be denied
//! (ARY-2028 slice 2, watchdog class `registry_bypass_attempt_denied`).
//!
//! Threat model: a worker process attempts to import / exec / compile
//! a module that the operator never registered. Two variants:
//!
//!   1. **Skip-registration**: the attacker calls `authorize` directly
//!      without ever calling `register`. Defense: sidecar returns
//!      `decision: deny, reason: module_not_registered`; kernel signs
//!      DENY claims, returns 403.
//!   2. **Path-confusion**: the attacker registers `pkg.allowed` but
//!      authorizes against `pkg.secret` (a path NOT in the registry).
//!      Defense: same as above — the lookup is by `module_path`, not
//!      by caller, so a registration for path A cannot leak permission
//!      to path B.
//!
//! Both variants assert REJECTION (Rule 8). The 403 must include
//! `decision: "deny"` + `reason: "module_not_registered"` in the
//! body — the audit chain MUST also record the deny event with
//! discriminator `policy_authorize_deny` (verified by the
//! audit-chain integrity test, not this file).
//!
//! Marked `#[ignore]` because it spawns the Python sidecar subprocess
//! against sqlite + the Rust kernel binary. Run with:
//!
//! ```bash
//! cargo test -p qorch-safety-kernel --test policy_registry_bypass -- --ignored
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

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use qorch_domain::safety::params_fingerprint;

/// Build the canonical event fingerprint for an authorize body.
fn canonical_fp(
    event_kind: &str,
    module_path: &str,
    caller_subject: &str,
    caller_run_id: &str,
) -> String {
    let canonical = json!({
        "event_kind": event_kind,
        "module_path": module_path,
        "caller_subject": caller_subject,
        "caller_run_id": caller_run_id,
    });
    params_fingerprint(&canonical)
}

/// Compose a full happy-path authorize body using the canonical fp.
fn authorize_body(
    event_kind: &str,
    module_path: &str,
    caller_subject: &str,
    caller_run_id: &str,
) -> Value {
    json!({
        "event_kind": event_kind,
        "module_path": module_path,
        "caller_subject": caller_subject,
        "caller_run_id": caller_run_id,
        "event_fingerprint": canonical_fp(event_kind, module_path, caller_subject, caller_run_id),
    })
}

// Test harness — spawns sidecar + kernel, runs the closure, tears down.
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

    // Run the test scenario.
    test(client, url).await;

    let _ = kernel.kill();
    let _ = sidecar.kill();
    let _ = kernel.wait();
    let _ = sidecar.wait();
    drop(tmp);
    let _ = signing_key_b64;
    let _ = audit_pepper_b64;
    // Silence "unused import" without removing it (the import is used
    // by the const evaluation pattern only).
    let _: [u8; 32] = {
        let mut h = Sha256::new();
        h.update([0u8; 32]);
        h.finalize().into()
    };
}

// ============================================================================
// VARIANT 1 — Skip registration: authorize a module that was never registered.
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns python3 sidecar + cargo build; run with --ignored"]
async fn authorize_without_register_is_denied() {
    with_live_stack(|client, url| async move {
        let body = authorize_body("import", "pkg.never_registered", "worker", "run-1");
        let r = client
            .post(format!("{url}/policy/module/authorize"))
            .header("x-api-key", "test-worker-key")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "unregistered module MUST 403");
        let parsed: Value = r.json().await.unwrap();
        assert_eq!(
            parsed.get("decision").and_then(Value::as_str),
            Some("deny"),
            "deny verdict expected; body={parsed}",
        );
        assert_eq!(
            parsed.get("reason").and_then(Value::as_str),
            Some("module_not_registered"),
            "reason MUST be module_not_registered; body={parsed}",
        );
        // The deny path MUST still mint a signed token — the audit
        // chain records the deny WITH a signed receipt so forensics
        // can prove the worker WAS told no, not merely that no
        // response was sent.
        assert!(
            parsed.get("token").and_then(Value::as_str).is_some(),
            "deny MUST sign a token so the worker has a cryptographic \
             record of the rejection; body={parsed}",
        );
    })
    .await;
}

// ============================================================================
// VARIANT 2 — Path confusion: register A, authorize against B.
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns python3 sidecar + cargo build; run with --ignored"]
async fn registered_path_does_not_leak_to_sibling_path() {
    with_live_stack(|client, url| async move {
        // Step 1: register pkg.allowed.module — registers an actively-
        // permissive pattern set.
        let r = client
            .post(format!("{url}/policy/module/register"))
            .header("x-api-key", "test-worker-key")
            .json(&json!({
                "module_path": "pkg.allowed.module",
                "required_patterns_regex_set": ["^pkg\\."],
                "caller_subject": "worker",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            201,
            "register MUST succeed for the allowed path",
        );

        // Step 2: authorize against pkg.secret.module (different path).
        // The registered set for pkg.allowed.module is NOT in scope.
        let body = authorize_body("import", "pkg.secret.module", "worker", "run-2");
        let r = client
            .post(format!("{url}/policy/module/authorize"))
            .header("x-api-key", "test-worker-key")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            403,
            "authorize on unregistered sibling path MUST 403",
        );
        let parsed: Value = r.json().await.unwrap();
        assert_eq!(
            parsed.get("reason").and_then(Value::as_str),
            Some("module_not_registered"),
            "reason MUST be module_not_registered (path-confused authorize \
             never reaches pattern evaluation); body={parsed}",
        );
    })
    .await;
}

// ============================================================================
// VARIANT 3 — Allowed path passes; this is the matching positive control
// so the rejection assertions above can't be a false-positive (e.g., the
// sidecar always denying due to a config bug).
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns python3 sidecar + cargo build; run with --ignored"]
async fn registered_path_authorize_succeeds_after_register() {
    with_live_stack(|client, url| async move {
        let r = client
            .post(format!("{url}/policy/module/register"))
            .header("x-api-key", "test-worker-key")
            .json(&json!({
                "module_path": "pkg.good.module",
                "required_patterns_regex_set": ["^pkg\\."],
                "caller_subject": "worker",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 201, "register MUST succeed");

        let body = authorize_body("import", "pkg.good.module", "worker", "run-3");
        let r = client
            .post(format!("{url}/policy/module/authorize"))
            .header("x-api-key", "test-worker-key")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            200,
            "registered + pattern-matching authorize MUST 200 — \
             without this positive control the deny assertions above \
             could be false positives caused by a sidecar config bug",
        );
        let parsed: Value = r.json().await.unwrap();
        assert_eq!(
            parsed.get("decision").and_then(Value::as_str),
            Some("allow"),
        );
    })
    .await;
}
