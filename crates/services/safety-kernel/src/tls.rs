//! Server-side rustls configuration for the dual-ingress kernel
//! ( Addendum 2a §2 —   Step 3).
//!
//! Builds a `axum_server::tls_rustls::RustlsConfig` from PEM files on
//! disk. When a client-CA bundle is provided, mTLS is enforced via
//! `rustls::server::WebPkiClientVerifier`. When it is absent, the
//! listener still requires TLS but does not request a client cert
//! (useful for dev / non-prod).
//!
//! Anti-pin: NO `native-tls`, NO `openssl-sys`. Crypto provider is
//! `rustls::crypto::ring` (installed in `main.rs`). The
//! `tls-rustls-no-provider` feature on `axum-server` lets us pick the
//! provider here instead of pulling `aws-lc-rs` via the default
//! `tls-rustls` feature.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};

/// Build the rustls `ServerConfig` and wrap it into the
/// `axum_server::tls_rustls::RustlsConfig` newtype consumed by
/// `axum_server::bind_rustls`.
///
/// `client_ca_path = None` ⇒ TLS only (no client cert verification).
/// `client_ca_path = Some(_)` ⇒ mTLS via `WebPkiClientVerifier`.
///
/// # Errors
///
/// Returns `Err` if the cert / key / CA files cannot be opened, are
/// not valid PEM, or rustls rejects the resulting material (e.g. cert
/// chain ↔ private key mismatch).
pub fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
) -> Result<RustlsConfig> {
    let cert_chain = load_cert_chain(cert_path)
        .with_context(|| format!("load cert chain {}", cert_path.display()))?;
    let key = load_private_key(key_path)
        .with_context(|| format!("load private key {}", key_path.display()))?;

    let server_config = if let Some(ca_path) = client_ca_path {
        let roots = load_client_ca_roots(ca_path)
            .with_context(|| format!("load client CA bundle {}", ca_path.display()))?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("build WebPkiClientVerifier")?;
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, key)
            .context("rustls with_single_cert (mTLS)")?
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .context("rustls with_single_cert (TLS-only)")?
    };

    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}

/// Read a PEM-encoded cert chain from disk into the rustls
/// `CertificateDer` list. Returns an error if the file is empty or
/// contains no PEM `CERTIFICATE` blocks.
fn load_cert_chain(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);
    let certs: Result<Vec<_>, _> = certs(&mut reader).collect();
    let certs = certs.context("parse cert PEM")?;
    if certs.is_empty() {
        return Err(anyhow!("no CERTIFICATE PEM blocks in {}", path.display()));
    }
    Ok(certs)
}

/// Read a PEM-encoded private key (PKCS#8 or RSA) from disk. Tries
/// PKCS#8 first (the modern default), then falls back to RSA. Errors
/// if neither produces a key.
fn load_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    // PKCS#8 attempt.
    {
        let f = File::open(path)?;
        let mut reader = BufReader::new(f);
        let pkcs8: Result<Vec<_>, _> = pkcs8_private_keys(&mut reader).collect();
        let pkcs8 = pkcs8.context("parse PKCS#8 key PEM")?;
        if let Some(k) = pkcs8.into_iter().next() {
            return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(k));
        }
    }
    // RSA fallback.
    {
        let f = File::open(path)?;
        let mut reader = BufReader::new(f);
        let rsa: Result<Vec<_>, _> = rsa_private_keys(&mut reader).collect();
        let rsa = rsa.context("parse RSA key PEM")?;
        if let Some(k) = rsa.into_iter().next() {
            return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(k));
        }
    }
    Err(anyhow!(
        "no PKCS#8 or RSA PRIVATE KEY block in {}",
        path.display()
    ))
}

/// Build a `RootCertStore` from a PEM bundle. Used to verify client
/// certificates in mTLS mode.
fn load_client_ca_roots(path: &Path) -> Result<RootCertStore> {
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);
    let cas: Result<Vec<_>, _> = certs(&mut reader).collect();
    let cas = cas.context("parse client-CA PEM")?;
    if cas.is_empty() {
        return Err(anyhow!(
            "no CERTIFICATE PEM blocks in client-CA bundle {}",
            path.display()
        ));
    }
    let mut roots = RootCertStore::empty();
    for c in cas {
        roots
            .add(c)
            .context("add client-CA to RootCertStore")?;
    }
    Ok(roots)
}
