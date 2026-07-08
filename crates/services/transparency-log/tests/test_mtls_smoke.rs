//!   /test wave — mTLS smoke test for
//! `tls::build_server_config`.
//!
//! Goals:
//!   1. `build_server_config(cert, key, None)` builds a RustlsConfig
//!      with `with_no_client_auth()` (the TLS-only path).
//!   2. `build_server_config(cert, key, Some(client_ca))` builds a
//!      RustlsConfig with the `WebPkiClientVerifier` set, i.e. the
//!      mTLS branch.
//!   3. The cert chain + private-key parsing accepts the rcgen-issued
//!      PKCS#8 PEM material we'd produce in prod.
//!   4. Negative case: passing a non-existent CA bundle, or a CA
//!      bundle with no certs, returns Err — the function never
//!      builds an mTLS verifier with empty trust roots.
//!
//! This stays in-process at the rustls config layer. Spawning an
//! axum-server bound to mTLS and driving a tokio-rustls client at it
//! would prove the same property but require a much heavier
//! dependency set (full hyper TLS termination + a custom rustls
//! client). The kernel-side `tls_smoke.rs` already exercises the
//! axum-server binding end-to-end for the TLS-only branch; the t-log
//! reuses the same axum-server, so the smoke property is the rustls
//! config the binding consumes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::similar_names)]

use std::path::PathBuf;

use tempfile::TempDir;

use qorch_transparency_log::tls::build_server_config;

/// Issue a self-signed CA + a server leaf signed by it. Returns
/// `(ca_pem, leaf_pem, leaf_key_pem)`.
fn issue_self_signed_chain() -> (String, String, String) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
    };

    // CA.
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "qorch t-log test CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().expect("ca keypair");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
    let ca_pem = ca_cert.pem();

    // Server leaf, SAN = localhost.
    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    leaf_params.subject_alt_names = vec![SanType::DnsName(
        "localhost".try_into().expect("rfc1035 dns"),
    )];
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().expect("leaf keypair");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
        .expect("sign leaf");

    (ca_pem, leaf_cert.pem(), leaf_key.serialize_pem())
}

/// Install the ring crypto provider once per test process. Tests
/// share the rustls global, so subsequent installs are no-ops.
fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn write_to(dir: &TempDir, name: &str, content: &str) -> PathBuf {
    let p = dir.path().join(name);
    std::fs::write(&p, content).expect("write pem");
    p
}

/// AC — TLS-only build path: build_server_config with `client_ca_path
/// = None` produces a usable RustlsConfig.
#[test]
fn build_server_config_tls_only_branch_ok() {
    install_provider();
    let (_ca_pem, leaf_pem, leaf_key_pem) = issue_self_signed_chain();
    let dir = TempDir::new().expect("tempdir");
    let cert = write_to(&dir, "leaf.pem", &leaf_pem);
    let key = write_to(&dir, "leaf.key", &leaf_key_pem);

    let cfg = build_server_config(&cert, &key, None);
    assert!(
        cfg.is_ok(),
        "TLS-only branch should build successfully: {:?}",
        cfg.err(),
    );
}

/// AC — mTLS build path: build_server_config with `client_ca_path =
/// Some(ca_bundle)` produces a usable RustlsConfig.
#[test]
fn build_server_config_mtls_branch_ok() {
    install_provider();
    let (ca_pem, leaf_pem, leaf_key_pem) = issue_self_signed_chain();
    let dir = TempDir::new().expect("tempdir");
    let cert = write_to(&dir, "leaf.pem", &leaf_pem);
    let key = write_to(&dir, "leaf.key", &leaf_key_pem);
    let ca = write_to(&dir, "ca.pem", &ca_pem);

    let cfg = build_server_config(&cert, &key, Some(&ca));
    assert!(
        cfg.is_ok(),
        "mTLS branch should build successfully: {:?}",
        cfg.err(),
    );
}

/// AC — empty client-CA bundle MUST fail. An mTLS server with no
/// trust roots would silently accept any client cert — the function
/// must refuse this footgun.
#[test]
fn build_server_config_empty_client_ca_rejected() {
    install_provider();
    let (_ca_pem, leaf_pem, leaf_key_pem) = issue_self_signed_chain();
    let dir = TempDir::new().expect("tempdir");
    let cert = write_to(&dir, "leaf.pem", &leaf_pem);
    let key = write_to(&dir, "leaf.key", &leaf_key_pem);
    let empty_ca = write_to(&dir, "ca.pem", ""); // empty PEM bundle

    let err = build_server_config(&cert, &key, Some(&empty_ca)).unwrap_err();
    let detail = format!("{err:#}");
    assert!(
        detail.contains("no CERTIFICATE PEM"),
        "expected 'no CERTIFICATE PEM' in error, got: {detail}",
    );
}

/// AC — missing cert file MUST fail with a wrapping context error
/// that names the path, so operator diagnostics aren't generic.
#[test]
fn build_server_config_missing_cert_fails_with_path_context() {
    install_provider();
    let dir = TempDir::new().expect("tempdir");
    let nonexistent_cert = dir.path().join("does-not-exist.pem");
    // We still need a valid key file because the cert load happens
    // first; this is just to prove cert IO error path.
    let (_ca_pem, _leaf_pem, leaf_key_pem) = issue_self_signed_chain();
    let key = write_to(&dir, "leaf.key", &leaf_key_pem);

    let err = build_server_config(&nonexistent_cert, &key, None).unwrap_err();
    let detail = format!("{err:#}");
    assert!(
        detail.contains("does-not-exist.pem"),
        "error context must name the bad path, got: {detail}",
    );
}

/// AC — malformed key file (not a valid PKCS#8 or RSA PEM) MUST fail
/// with a clear error.
#[test]
fn build_server_config_malformed_key_rejected() {
    install_provider();
    let (_ca_pem, leaf_pem, _leaf_key_pem) = issue_self_signed_chain();
    let dir = TempDir::new().expect("tempdir");
    let cert = write_to(&dir, "leaf.pem", &leaf_pem);
    let bad_key = write_to(&dir, "leaf.key", "not a real key");

    let err = build_server_config(&cert, &bad_key, None).unwrap_err();
    let detail = format!("{err:#}");
    assert!(
        detail.contains("PRIVATE KEY") || detail.contains("PKCS#8") || detail.contains("RSA"),
        "error must mention private-key issue, got: {detail}",
    );
}
