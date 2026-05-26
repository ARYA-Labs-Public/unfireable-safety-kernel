//!   — mTLS smoke test (AC4 direct-rustls path).
//!
//! This test stands up a real rustls-backed HTTPS server in-process
//! that REQUIRES mTLS (client certificate verified against a known CA),
//! then dials it with a `reqwest::Client` constructed via the SDK's
//! own `make_client_config` factory. The PASS condition is a clean
//! TLS handshake + a 200 response from the server's `/kernel/v1/health`
//! route.
//!
//! Coverage:
//!
//! - **AC4 direct path**: `make_client_config()` produces a working
//!   rustls `ClientConfig` that:
//!     * trusts a custom CA bundle,
//!     * presents a client certificate signed by that CA,
//!     * negotiates TLS 1.3 with an axum-server running rustls
//!       `with_client_cert_verifier`.
//! - **Negative #1**: a client constructed with NO client cert is
//!   refused by the server (mTLS is actually enforced, not just TLS).
//! - **Negative #2**: a client constructed with an attacker-signed
//!   client cert (different CA) is refused.
//!
//! The Step 3 sibling test `crates/services/safety-kernel/tests/tls_smoke.rs`
//! covers the kernel binary spawn path; this file covers the SDK's
//! `mtls.rs` factory in isolation against an in-process server. The
//! two together prove AC4 across both layers (nginx-style ingress
//! handled by Step 3, direct-rustls handled here).
//!
//! Run with: `cargo test -p qorch-safety-kernel-client --test mtls_smoke`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use qorch_safety_kernel_client::mtls::make_client_config;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tempfile::TempDir;

const HEALTH_BODY: &str = r#"{"ok":true,"uptime_s":0.0,"version":"mtls-smoke-test"}"#;

/// Bind+drop trick to grab a free port.
fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// Self-signed CA used to sign both the server leaf and (in the happy
/// path) the client leaf. Holds the CA cert + key as PEM and the
/// rcgen parsed objects for further signing.
struct CaMaterial {
    ca_pem: String,
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
}

fn make_ca(common_name: &str) -> CaMaterial {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().expect("ca keypair");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
    let ca_pem = ca_cert.pem();
    CaMaterial {
        ca_pem,
        ca_cert,
        ca_key,
    }
}

/// Sign a server leaf certificate with SAN `DNS:localhost` so reqwest
/// (which connects to 127.0.0.1 with SNI "localhost") verifies cleanly.
fn make_server_leaf(ca: &CaMaterial) -> (String, String) {
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
        .signed_by(&leaf_key, &ca.ca_cert, &ca.ca_key)
        .expect("sign server leaf");
    (leaf_cert.pem(), leaf_key.serialize_pem())
}

/// Sign a client leaf certificate with `ClientAuth` EKU.
fn make_client_leaf(ca: &CaMaterial, common_name: &str) -> (String, String) {
    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let leaf_key = KeyPair::generate().expect("client keypair");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca.ca_cert, &ca.ca_key)
        .expect("sign client leaf");
    (leaf_cert.pem(), leaf_key.serialize_pem())
}

fn write_pem(p: &Path, pem: &str) {
    std::fs::write(p, pem).unwrap_or_else(|e| panic!("write {}: {e}", p.display()));
}

/// Build the server `RustlsConfig` requiring mTLS with `client_ca` as
/// the trust anchor. Models the production kernel's TLS setup.
fn build_server_config(
    server_cert_pem: &str,
    server_key_pem: &str,
    client_ca_pem: &str,
) -> RustlsConfig {
    // Server cert chain + private key.
    let mut cert_reader = server_cert_pem.as_bytes();
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("parse server cert");
    let mut key_reader = server_key_pem.as_bytes();
    let key = rustls_pemfile::private_key(&mut key_reader)
        .expect("parse server key io")
        .expect("server private key present");

    // Client CA trust store.
    let mut ca_reader = client_ca_pem.as_bytes();
    let cas: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("parse client ca");
    let mut roots = RootCertStore::empty();
    for c in cas {
        roots.add(c).expect("add ca");
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("client verifier");

    let server_cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .expect("server with_single_cert");

    RustlsConfig::from_config(Arc::new(server_cfg))
}

/// Spawn the in-process axum-server with rustls + mTLS. Returns the
/// bound address. The server task lives until the test process exits.
async fn spawn_server(rustls_cfg: RustlsConfig) -> SocketAddr {
    let port = pick_free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .expect("parse addr");

    let app = Router::new().route(
        "/kernel/v1/health",
        get(|| async {
            (
                axum::http::StatusCode::OK,
                [("content-type", "application/json")],
                HEALTH_BODY,
            )
        }),
    );

    tokio::spawn(async move {
        axum_server::bind_rustls(addr, rustls_cfg)
            .serve(app.into_make_service())
            .await
            .expect("server run");
    });

    // Give the server a moment to bind. axum-server does not surface a
    // "ready" signal; the SDK's connect will retry implicitly via the
    // top-level loop below.
    tokio::time::sleep(Duration::from_millis(200)).await;
    addr
}

/// Build a reqwest::Client from `make_client_config`. The `cert_dir`
/// holds the on-disk PEM files (mtls.rs reads from disk by contract).
fn make_reqwest_client_from_sdk_factory(
    cert_dir: &TempDir,
    client_cert_pem: &str,
    client_key_pem: &str,
    server_ca_pem: &str,
) -> reqwest::Client {
    let cert_path = cert_dir.path().join("client.crt");
    let key_path = cert_dir.path().join("client.key");
    let ca_path = cert_dir.path().join("server-ca.crt");
    write_pem(&cert_path, client_cert_pem);
    write_pem(&key_path, client_key_pem);
    write_pem(&ca_path, server_ca_pem);

    let client_config = make_client_config(&cert_path, &key_path, Some(&ca_path))
        .expect("SDK mtls factory MUST produce a valid ClientConfig");

    reqwest::Client::builder()
        .use_preconfigured_tls((*client_config).clone())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client")
}

// ---------------------------------------------------------------------------
// AC4 — happy path: SDK-factory client + valid mTLS = 200.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ac4_mtls_handshake_via_sdk_factory_returns_200() {
    // Single CA signs both the server leaf and the client leaf — the
    // simplest mTLS chain that exercises every code path in
    // make_client_config (cert load + key load + CA load).
    let ca = make_ca("qorch-test-ca");
    let (server_cert, server_key) = make_server_leaf(&ca);
    let (client_cert, client_key) = make_client_leaf(&ca, "qorch-test-client");

    let server_cfg = build_server_config(&server_cert, &server_key, &ca.ca_pem);
    let addr = spawn_server(server_cfg).await;

    let cert_dir = tempfile::tempdir().expect("tempdir");
    let client =
        make_reqwest_client_from_sdk_factory(&cert_dir, &client_cert, &client_key, &ca.ca_pem);

    let url = format!("https://localhost:{}/kernel/v1/health", addr.port());
    let resp = client.get(&url).send().await.expect("send https GET");
    assert!(
        resp.status().is_success(),
        "AC4: SDK-factory mTLS handshake MUST yield 2xx, got {}",
        resp.status()
    );
    let body = resp.text().await.expect("decode body");
    assert!(body.contains(r#""ok":true"#), "AC4: response body shape: {body}");
}

// ---------------------------------------------------------------------------
// Negative #1 — server REJECTS a client with NO certificate.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_server_rejects_client_without_cert() {
    let ca = make_ca("qorch-test-ca-2");
    let (server_cert, server_key) = make_server_leaf(&ca);
    let server_cfg = build_server_config(&server_cert, &server_key, &ca.ca_pem);
    let addr = spawn_server(server_cfg).await;

    // Plain reqwest client trusting the server CA but presenting NO
    // client cert.
    let ca_cert = reqwest::Certificate::from_pem(ca.ca_pem.as_bytes()).expect("ca pem");
    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest no-client-cert");

    let url = format!("https://localhost:{}/kernel/v1/health", addr.port());
    let r = client.get(&url).send().await;
    assert!(
        r.is_err(),
        "mTLS server MUST refuse a clientless handshake, got {r:?}"
    );
}

// ---------------------------------------------------------------------------
// Negative #2 — server REJECTS a client signed by a different CA.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_server_rejects_client_signed_by_attacker_ca() {
    // Server trusts ca_trusted only; we present a client cert signed
    // by ca_attacker — handshake MUST fail.
    let ca_trusted = make_ca("qorch-trusted-ca");
    let ca_attacker = make_ca("qorch-attacker-ca");
    let (server_cert, server_key) = make_server_leaf(&ca_trusted);
    let (atk_client_cert, atk_client_key) = make_client_leaf(&ca_attacker, "attacker");

    let server_cfg = build_server_config(&server_cert, &server_key, &ca_trusted.ca_pem);
    let addr = spawn_server(server_cfg).await;

    let cert_dir = tempfile::tempdir().expect("tempdir");
    let client = make_reqwest_client_from_sdk_factory(
        &cert_dir,
        &atk_client_cert,
        &atk_client_key,
        &ca_trusted.ca_pem,
    );

    let url = format!("https://localhost:{}/kernel/v1/health", addr.port());
    let r = client.get(&url).send().await;
    assert!(
        r.is_err(),
        "mTLS server MUST refuse attacker-CA-signed client, got {r:?}"
    );
}

// ---------------------------------------------------------------------------
// AC4 sibling — SDK factory rejects missing files (no panic / no silent Ok).
// ---------------------------------------------------------------------------

#[test]
fn ac4_sdk_factory_surfaces_missing_files_as_error() {
    // Belt-and-braces structural test: the factory MUST yield an
    // MtlsError, never panic, when a path is missing. The lib-level
    // test asserts the same property; this duplicates it at the
    // integration boundary so a future inlining of the factory cannot
    // regress this behaviour silently.
    let bad = PathBuf::from("/tmp/qorch-ary1883-mtls-smoke-nonexistent.pem");
    let r = make_client_config(&bad, &bad, None);
    assert!(r.is_err(), "missing files MUST yield Err, got Ok");
}
