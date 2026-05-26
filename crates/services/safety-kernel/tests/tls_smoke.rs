//!   Step 3 — rustls dual-ingress smoke test.
//!
//! Spawns the kernel binary with self-signed TLS material, sends one
//! `GET /kernel/v1/health` over `reqwest` (rustls) trusting the test
//! CA, and asserts 200 + the expected `HealthResponse` shape. The
//! policy sidecar is NOT required for `/health` — that route only
//! reads `AppState`, no IPC.
//!
//! This test exercises the bind + handshake path, not the full
//! authorization stack (`smoke_e2e.rs` covers that for plaintext).
//! It is the minimum proof that `axum_server::bind_rustls` accepts
//! our PEM material and serves the existing axum router.
//!
//! Run with: `cargo test -p qorch-safety-kernel --test tls_smoke`.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

/// Walk up from `CARGO_MANIFEST_DIR` until a `Cargo.toml` with
/// `[workspace]` is found. Same helper pattern as `smoke_e2e.rs`.
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

/// Bind+drop trick to grab a free port for the kernel to claim.
fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// Fresh 32-byte signing seed / pepper as base64url-no-pad.
fn fresh_seed_b64() -> String {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Generate a self-signed CA + a server leaf cert with SAN
/// `DNS:localhost` so reqwest's SNI matches. Returns the CA-bundle
/// PEM (used by the client to trust the chain), the server cert PEM,
/// and the server private key PEM.
fn make_self_signed_chain() -> (String, String, String) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
    };

    // 1. CA cert.
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "qorch test CA");
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().expect("ca keypair");
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .expect("self-sign CA");
    let ca_pem = ca_cert.pem();

    // 2. Server leaf signed by the CA. SAN = DNS:localhost so the
    //    reqwest client (which connects to 127.0.0.1 with SNI
    //    "localhost") verifies cleanly without dancing with /etc/hosts.
    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    leaf_params.subject_alt_names = vec![SanType::DnsName(
        "localhost".try_into().expect("rfc1035 dns name"),
    )];
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().expect("leaf keypair");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("sign leaf");

    let leaf_pem = leaf_cert.pem();
    let leaf_key_pem = leaf_key.serialize_pem();

    (ca_pem, leaf_pem, leaf_key_pem)
}

/// Write `pem` to `path`. Convenience over the bag of `std::fs` calls.
fn write_pem(path: &Path, pem: &str) {
    std::fs::write(path, pem).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// Spawn the kernel binary with TLS env wired up. The Python sidecar
/// is NOT spawned — `/health` doesn't reach it. We pass an existing
/// but unconnected socket path so the canonicalize() warning is
/// silent in test output.
async fn spawn_kernel_tls(
    bin_path: &Path,
    listen_addr: &str,
    cert_path: &Path,
    key_path: &Path,
    sock_path: &Path,
    ca_pem: &str,
) -> Option<Child> {
    let signing_key_b64 = fresh_seed_b64();
    let audit_pepper_b64 = fresh_seed_b64();

    let mut child = std::process::Command::new(bin_path)
        .env("QORCH_ENV", "dev")
        .env("QORCH_KERNEL_LISTEN_ADDR", listen_addr)
        .env("QORCH_KERNEL_POLICY_SOCK", sock_path)
        .env("QORCH_KERNEL_SIGNING_KEY_B64", &signing_key_b64)
        .env("QORCH_KERNEL_AUDIT_PEPPER_B64", &audit_pepper_b64)
        .env("QORCH_KERNEL_API_KEY_WORKER", "test-worker-key")
        .env("QORCH_KERNEL_API_KEY_API", "test-api-key")
        .env("QORCH_KERNEL_API_KEY_OPERATOR", "test-operator-key")
        .env("QORCH_KERNEL_BUILD_VERSION", "tls-smoke-0.0.0")
        .env("QORCH_KERNEL_TLS_CERT", cert_path)
        .env("QORCH_KERNEL_TLS_KEY", key_path)
        // Intentionally NOT setting QORCH_KERNEL_CLIENT_CA_PEM — this
        // smoke proves TLS-only path. mTLS coverage lives in the
        // sibling adapter crate's `mtls_smoke.rs` (Step 4).
        .env("RUST_LOG", "warn")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    // Build a reqwest::Client that trusts the test CA. Connect to
    // `https://localhost:<port>/health` and wait for 200.
    let ca_cert = reqwest::Certificate::from_pem(ca_pem.as_bytes()).ok()?;
    let client = match reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        // Force the client to use rustls (matches server). reqwest's
        // default-features=false config in dev-deps already does this.
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            let _ = child.kill();
            return None;
        }
    };
    let url = format!("https://localhost:{}/health", port_of(listen_addr));
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(r) = client.get(&url).send().await {
            if r.status().is_success() {
                return Some(child);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = child.kill();
    None
}

/// Extract the port from a `host:port` string.
fn port_of(listen_addr: &str) -> u16 {
    listen_addr
        .rsplit(':')
        .next()
        .and_then(|s| s.parse().ok())
        .expect("listen addr port")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_health_handshake() {
    let root = workspace_root();
    let tmp = tempfile::tempdir().expect("tempdir");

    // 1. Generate the self-signed material.
    let (ca_pem, leaf_pem, leaf_key_pem) = make_self_signed_chain();
    let cert_path = tmp.path().join("server.crt");
    let key_path = tmp.path().join("server.key");
    write_pem(&cert_path, &leaf_pem);
    write_pem(&key_path, &leaf_key_pem);

    // 2. Pick a free port; build the binary (cached after first run).
    let port = pick_free_port();
    let listen_addr = format!("127.0.0.1:{port}");

    let build = std::process::Command::new("cargo")
        .current_dir(&root)
        .args(["build", "-p", "qorch-safety-kernel"])
        .output()
        .expect("cargo build spawn");
    if !build.status.success() {
        panic!("cargo build failed: {}", String::from_utf8_lossy(&build.stderr));
    }
    let bin_path = root.join("target/debug/qorch-safety-kernel");

    // Path that the kernel will `canonicalize()`; doesn't need to be a
    // live sidecar socket because /health never touches policy IPC.
    let sock_path = tmp.path().join("policy.sock");
    // Touch the file so canonicalize() succeeds (it requires the path
    // to exist; a dangling path is fine because we never connect).
    std::fs::write(&sock_path, b"").unwrap();

    // 3. Spawn the kernel with TLS env wired up.
    let server = spawn_kernel_tls(&bin_path, &listen_addr, &cert_path, &key_path, &sock_path, &ca_pem).await;
    let mut server = server.unwrap_or_else(|| {
        panic!("kernel did not come up on rustls listener https://{listen_addr}/health")
    });

    // 4. Hit /health one more time and assert the shape.
    let ca_cert = reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("ca pem");
    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .build()
        .expect("reqwest client");
    let url = format!("https://localhost:{port}/health");
    let resp = client.get(&url).send().await.expect("send /health");
    assert!(
        resp.status().is_success(),
        "expected 2xx from {url}, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("decode /health");
    assert_eq!(body["ok"], serde_json::Value::Bool(true), "ok field");
    assert_eq!(
        body["version"],
        serde_json::Value::String("tls-smoke-0.0.0".to_string()),
        "version field"
    );
    assert!(
        body.get("uptime_s")
            .and_then(serde_json::Value::as_f64)
            .is_some(),
        "uptime_s present + numeric"
    );

    let _ = server.kill();
    let _ = server.wait();
}
