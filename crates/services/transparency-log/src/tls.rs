//! Server-side rustls configuration for the transparency-log service
//! (,  Step 5).
//!
//! Identical pattern to `crates/services/safety-kernel/src/tls.rs` —
//! `axum-server` with `tls-rustls-no-provider`, `rustls::crypto::ring`
//! as the crypto provider, optional `WebPkiClientVerifier` for mTLS.
//! NO `aws-lc-rs`, NO `native-tls`, NO `openssl-sys` ( ban).

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};

/// Build the rustls `ServerConfig` and wrap it in `RustlsConfig`.
///
/// `client_ca_path = None` ⇒ TLS only (no client cert verification).
/// `client_ca_path = Some(_)` ⇒ mTLS via `WebPkiClientVerifier`.
///
/// # Errors
///
/// Returns `Err` if the cert / key / CA files cannot be opened, are
/// not valid PEM, or rustls rejects the resulting material.
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

fn load_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    {
        let f = File::open(path)?;
        let mut reader = BufReader::new(f);
        let pkcs8: Result<Vec<_>, _> = pkcs8_private_keys(&mut reader).collect();
        let pkcs8 = pkcs8.context("parse PKCS#8 key PEM")?;
        if let Some(k) = pkcs8.into_iter().next() {
            return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(k));
        }
    }
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
        roots.add(c).context("add client-CA to RootCertStore")?;
    }
    Ok(roots)
}
