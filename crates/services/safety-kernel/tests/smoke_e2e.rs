//! End-to-end smoke test: spawn Python policy sidecar (mock mode),
//! spawn the Rust binary, hit the 6 endpoints with reqwest.
//!
//! This proves the whole stack works: TCP listener, axum routing,
//! middleware, body parsing, signing, IPC to the sidecar, public-key
//! response. Token validity is verified locally by reusing the
//! `qorch_domain::safety::verify_kernel_token` helper.
//!
//! Marked `#[ignore]` if Python 3 is not on PATH — the test relies on
//! `python3 -m apps.safety_kernel.policy_sidecar --mock`.
//!
//! Run with `cargo test -p qorch-safety-kernel --test smoke_e2e -- --ignored`.

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use qorch_domain::safety::{params_fingerprint, verify_kernel_token};

/// Discover the workspace root by walking up from the current crate
/// directory until we find `Cargo.toml` with `[workspace]`.
fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while p.pop() {
        let candidate = p.join("Cargo.toml");
        if candidate.exists() {
            if let Ok(contents) = std::fs::read_to_string(&candidate) {
                if contents.contains("[workspace]") {
                    return p;
                }
            }
        }
    }
    panic!("workspace root not found");
}

/// Probe whether `python3` is on PATH.
fn have_python3() -> bool {
    std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Bind a fresh TCP listener to a free port, return the port and
/// drop the listener so the Rust binary can bind it.
fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// Generate a fresh 32-byte signing seed + 32-byte audit pepper as
/// base64url-no-pad strings.
fn fresh_seed_b64() -> String {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

#[allow(clippy::too_many_lines)]
// Single end-to-end smoke; splitting hurts readability.
//
// Marked `#[ignore]`: this end-to-end smoke spawns the Python policy
// sidecar (`apps/safety_kernel/policy_sidecar.py`), which is not
// shipped in this public-extraction repo. The test is preserved for
// adopters who bring their own sidecar implementation. Run via:
//   cargo test -p qorch-safety-kernel --test smoke_e2e -- --ignored
#[ignore = "requires apps/safety_kernel/policy_sidecar.py — not shipped in the public extraction"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smoke_authorize_health_publickey() {
    if !have_python3() {
        eprintln!("python3 not on PATH — skipping smoke test");
        return;
    }

    let root = workspace_root();
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("sk.sock");

    // ------------------------------------------------------------------
    // 1. Spawn the Python sidecar in mock mode.
    // ------------------------------------------------------------------
    // Run as a path (not `-m`) so we don't pay the cost of importing
    // `apps/safety_kernel/__init__.py` (which pulls in FastAPI). We
    // still set PYTHONPATH so the script can `from apps.safety_kernel
    // import config / policy` lazily when it ever runs in non-mock
    // mode.
    let sidecar_script = root.join("apps/safety_kernel/policy_sidecar.py");
    let sidecar = std::process::Command::new("python3")
        .current_dir(&root)
        .env("PYTHONPATH", &root)
        .args([sidecar_script.to_str().unwrap(), "--mock", "--sock-path"])
        .arg(&sock_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut sidecar = match sidecar {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to spawn sidecar: {e}");
            return;
        }
    };

    // Wait up to 5s for the socket to appear.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock_path.exists() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if !sock_path.exists() {
        let _ = sidecar.kill();
        panic!("sidecar socket {sock_path:?} did not appear in 5s");
    }

    // ------------------------------------------------------------------
    // 2. Spawn the Rust binary on a free port.
    // ------------------------------------------------------------------
    let port = pick_free_port();
    let listen_addr = format!("127.0.0.1:{port}");
    let signing_key_b64 = fresh_seed_b64();
    let audit_pepper_b64 = fresh_seed_b64();

    // Build the binary first.
    let build = std::process::Command::new("cargo")
        .current_dir(&root)
        .args(["build", "-p", "qorch-safety-kernel"])
        .output();
    let build = match build {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            let _ = sidecar.kill();
            panic!("cargo build failed: {}", String::from_utf8_lossy(&o.stderr));
        }
        Err(e) => {
            let _ = sidecar.kill();
            panic!("cargo build spawn failed: {e}");
        }
    };
    drop(build);
    let bin_path = root.join("target/debug/qorch-safety-kernel");

    let server = std::process::Command::new(&bin_path)
        .env("QORCH_ENV", "dev")
        .env("QORCH_KERNEL_LISTEN_ADDR", &listen_addr)
        .env("QORCH_KERNEL_POLICY_SOCK", &sock_path)
        .env("QORCH_KERNEL_SIGNING_KEY_B64", &signing_key_b64)
        .env("QORCH_KERNEL_AUDIT_PEPPER_B64", &audit_pepper_b64)
        .env("QORCH_KERNEL_API_KEY_WORKER", "test-worker-key")
        .env("QORCH_KERNEL_API_KEY_API", "test-api-key")
        .env("QORCH_KERNEL_API_KEY_OPERATOR", "test-operator-key")
        .env("QORCH_KERNEL_BUILD_VERSION", "smoke-test-0.0.0")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut server = match server {
        Ok(c) => c,
        Err(e) => {
            let _ = sidecar.kill();
            panic!("failed to spawn server: {e}");
        }
    };

    // Wait for the listener to come up.
    let deadline = Instant::now() + Duration::from_secs(10);
    let url = format!("http://{listen_addr}");
    let client = reqwest::Client::new();
    let mut up = false;
    while Instant::now() < deadline {
        if let Ok(r) = client.get(format!("{url}/health")).send().await {
            if r.status().is_success() {
                up = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !up {
        let _ = server.kill();
        let _ = sidecar.kill();
        panic!("rust server did not become ready in 10s");
    }

    // ------------------------------------------------------------------
    // 3. Probe /health → expect {ok:true, version, uptime_s}.
    // ------------------------------------------------------------------
    let r = client.get(format!("{url}/health")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body.get("ok"), Some(&Value::Bool(true)));
    assert_eq!(
        body.get("version").and_then(Value::as_str),
        Some("smoke-test-0.0.0")
    );
    assert!(body.get("uptime_s").and_then(Value::as_f64).is_some());

    // ------------------------------------------------------------------
    // 4. Probe /kernel/v1/public_key → 4 keys.
    // ------------------------------------------------------------------
    let r = client
        .get(format!("{url}/kernel/v1/public_key"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let pk: Value = r.json().await.unwrap();
    assert_eq!(pk.get("ok"), Some(&Value::Bool(true)));
    assert_eq!(pk.get("algorithm").and_then(Value::as_str), Some("Ed25519"));
    let pk_b64 = pk
        .get("public_key_b64")
        .and_then(Value::as_str)
        .expect("public_key_b64");
    let pk_fpr = pk
        .get("public_key_fingerprint")
        .and_then(Value::as_str)
        .expect("public_key_fingerprint");
    let pk_raw = URL_SAFE_NO_PAD.decode(pk_b64).expect("decode pk");
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_raw);
    let verifying_key = VerifyingKey::from_bytes(&pk_arr).expect("verifying key");

    // Cross-check the fingerprint.
    let mut h = Sha256::new();
    h.update(pk_arr);
    assert_eq!(hex::encode(h.finalize()), pk_fpr);

    // ------------------------------------------------------------------
    // 5. /kernel/v1/authorize without x-api-key → 401.
    // ------------------------------------------------------------------
    let r = client
        .post(format!("{url}/kernel/v1/authorize"))
        .json(&json!({
            "action": "POST:/api/v1/chat",
            "run_id": "run_smoke",
            "subject": "client",
            "params_fingerprint": "deadbeef",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // ------------------------------------------------------------------
    // 6. /kernel/v1/authorize with worker key + matching params_fingerprint
    //    → 200, signed token verifies against the kernel public key.
    // ------------------------------------------------------------------
    let mut params = BTreeMap::new();
    params.insert("k".to_string(), Value::String("v".to_string()));
    let params_value = Value::Object(params.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
    let fp = params_fingerprint(&params_value);

    let r = client
        .post(format!("{url}/kernel/v1/authorize"))
        .header("x-api-key", "test-worker-key")
        .json(&json!({
            "action": "sio_run_cycles",
            "run_id": "run_smoke",
            "subject": "smoke-client",
            "params_fingerprint": fp,
            "params": params_value,
            "ttl_s": 60,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "authorize should succeed");
    let body: Value = r.json().await.unwrap();
    assert_eq!(body.get("ok"), Some(&Value::Bool(true)));
    let token = body
        .get("token")
        .and_then(Value::as_str)
        .expect("token in body");
    let claims = body.get("claims").expect("claims in body");

    // Verify the token using the fetched public key.
    let now = claims
        .get("issued_at")
        .and_then(Value::as_f64)
        .expect("issued_at f64");
    //  ( slice 5): the kernel now mints `aud=kernel/authorize`
    // on every `/kernel/v1/authorize` token. Verify with the matching
    // expected_aud to exercise the new cross-tenant replay defense.
    let verified = verify_kernel_token(
        token,
        &verifying_key,
        now + 1.0,
        5.0,
        Some(qorch_domain::safety::KERNEL_AUTHORIZE_AUD),
    )
    .expect("token must verify against kernel public key");
    // Subject in claims is the trusted caller_role, not body.subject.
    assert_eq!(
        verified.claims.get("subject").and_then(Value::as_str),
        Some("worker")
    );
    assert_eq!(
        verified.claims.get("action").and_then(Value::as_str),
        Some("sio_run_cycles")
    );

    // ------------------------------------------------------------------
    // 7. cleanup.
    // ------------------------------------------------------------------
    let _ = server.kill();
    let _ = sidecar.kill();
    let _ = server.wait();
    let _ = sidecar.wait();
    drop(tmp);
    let _ = (signing_key_b64, audit_pepper_b64);
    // Reference SigningKey to silence "unused import" if test layout
    // ever changes — we don't actually need the private key here.
    let _ = SigningKey::from_bytes(&[0u8; 32]);
}
