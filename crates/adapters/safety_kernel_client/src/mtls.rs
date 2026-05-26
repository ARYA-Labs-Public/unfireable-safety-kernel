//! mTLS configuration factory for the Safety Kernel client.
//!
//! Per Migration Note Step 5R and Addendum
//! 2a §2 (anti-pin: rustls only, no native-tls), the adapter constructs
//! a `rustls::ClientConfig` from caller-supplied cert paths or in-memory
//! PEM bytes. Path resolution and env-var reading happen in the
//! **binding layer** (whoever owns the application boot) — this module
//! only consumes already-loaded paths/bytes so the test surface stays
//! deterministic and forbidden-import discipline is preserved at the
//! domain boundary.
//!
//! Two entry points:
//! - [`MtlsMaterial`] — in-memory PEM bytes constructor (legacy, kept
//!   for callers that load PEMs from a secret manager and never touch
//!   disk).
//! - [`make_client_config`] — path-based factory that reads the
//!   client certificate chain, the client private key, and an optional
//!   custom CA bundle from disk. Returns an `Arc<rustls::ClientConfig>`
//!   ready to plug into `reqwest::ClientBuilder::use_preconfigured_tls`.
//!
//! Production server-side wiring lives in
//! `crates/services/safety-kernel/src/auth.rs`.

use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use thiserror::Error;

/// Errors surfaced by the path-based mTLS factory. Distinct from the
/// adapter's main `KernelClientError` because mTLS setup happens at
/// boot, before any HTTP call — callers handle it during startup, not
/// on the request path.
#[derive(Debug, Error)]
pub enum MtlsError {
    /// PEM contained no client certificates.
    #[error("no client certificate found in PEM at {path}")]
    EmptyCertificateChain {
        /// Path the empty chain came from.
        path: String,
    },

    /// PEM contained no private key.
    #[error("no private key found in PEM at {path}")]
    EmptyPrivateKey {
        /// Path the empty key came from.
        path: String,
    },

    /// PEM parse error.
    #[error("invalid PEM at {path}: {detail}")]
    InvalidPem {
        /// Path the bad PEM came from.
        path: String,
        /// Human-readable parse error detail.
        detail: String,
    },

    /// Failed to read a PEM file from disk.
    #[error("failed to read PEM at {path}: {source}")]
    ReadFile {
        /// Path that failed to read.
        path: String,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// rustls config builder rejected the supplied materials.
    #[error("rustls configuration error: {0}")]
    RustlsConfig(String),
}

/// Container for client certificate + private key PEM bytes plus the
/// CA bundle the server presents. Caller loads these from whatever
/// secret backend they use (`gcp_secret_manager`, `aws_secrets_manager`,
/// PKCS#11 — see ).
#[derive(Debug, Clone)]
pub struct MtlsMaterial {
    /// PEM-encoded client certificate chain.
    pub client_cert_pem: Vec<u8>,
    /// PEM-encoded client private key (PKCS#8 or PKCS#1).
    pub client_key_pem: Vec<u8>,
    /// PEM-encoded CA bundle the server's cert chains to.
    pub server_ca_pem: Vec<u8>,
}

impl MtlsMaterial {
    /// Construct mTLS material from in-memory PEM bytes.
    /// The caller must redact `client_key_pem` from any logs.
    #[must_use]
    pub fn new(client_cert_pem: Vec<u8>, client_key_pem: Vec<u8>, server_ca_pem: Vec<u8>) -> Self {
        Self {
            client_cert_pem,
            client_key_pem,
            server_ca_pem,
        }
    }

    /// Length of the client cert PEM, useful for sanity checks at boot.
    #[must_use]
    pub fn client_cert_len(&self) -> usize {
        self.client_cert_pem.len()
    }
}

/// Build a `rustls::ClientConfig` from caller-supplied PEM paths.
///
/// `cert_path` and `key_path` are required (mTLS = client presents a
/// certificate). `ca_path` is OPTIONAL: when `Some`, the kernel's
/// server cert MUST chain to a CA in that bundle; when `None`, the
/// platform's WebPKI roots (via `webpki-roots`) are used.
///
/// This function **never** touches the environment. The caller passes
/// resolved paths — env-var lookup happens in the binding layer.
///
/// # Errors
///
/// Returns `MtlsError` if any file read fails, if the PEMs are
/// malformed, if they contain no certificates / no private key, or if
/// rustls rejects the constructed config.
pub fn make_client_config(
    cert_path: &Path,
    key_path: &Path,
    ca_path: Option<&Path>,
) -> Result<Arc<ClientConfig>, MtlsError> {
    // Ensure ring is installed as the default rustls crypto provider.
    // Idempotent — install_default returns Err if already installed,
    // which is fine for us (we accept whichever provider is active).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Load the client cert chain.
    let cert_bytes = read_pem(cert_path)?;
    let cert_chain = parse_cert_chain(&cert_bytes, cert_path)?;

    // Load the private key.
    let key_bytes = read_pem(key_path)?;
    let key = parse_private_key(&key_bytes, key_path)?;

    // Build the root store.
    let roots = if let Some(ca) = ca_path {
        let ca_bytes = read_pem(ca)?;
        let mut store = RootCertStore::empty();
        let mut cursor = Cursor::new(ca_bytes);
        let added = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| MtlsError::InvalidPem {
                path: ca.display().to_string(),
                detail: format!("CA parse: {e}"),
            })?;
        if added.is_empty() {
            return Err(MtlsError::EmptyCertificateChain {
                path: ca.display().to_string(),
            });
        }
        for c in added {
            store
                .add(c)
                .map_err(|e| MtlsError::RustlsConfig(format!("ca add: {e}")))?;
        }
        store
    } else {
        webpki_default_roots()
    };

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .map_err(|e| MtlsError::RustlsConfig(format!("client_auth_cert: {e}")))?;

    Ok(Arc::new(config))
}

fn read_pem(path: &Path) -> Result<Vec<u8>, MtlsError> {
    fs::read(path).map_err(|source| MtlsError::ReadFile {
        path: path.display().to_string(),
        source,
    })
}

fn parse_cert_chain(
    pem_bytes: &[u8],
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, MtlsError> {
    let mut cursor = Cursor::new(pem_bytes);
    let certs = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| MtlsError::InvalidPem {
            path: path.display().to_string(),
            detail: format!("cert parse: {e}"),
        })?;
    if certs.is_empty() {
        return Err(MtlsError::EmptyCertificateChain {
            path: path.display().to_string(),
        });
    }
    Ok(certs)
}

fn parse_private_key(
    pem_bytes: &[u8],
    path: &Path,
) -> Result<PrivateKeyDer<'static>, MtlsError> {
    let mut cursor = Cursor::new(pem_bytes);
    let key = rustls_pemfile::private_key(&mut cursor)
        .map_err(|e| MtlsError::InvalidPem {
            path: path.display().to_string(),
            detail: format!("key parse: {e}"),
        })?
        .ok_or_else(|| MtlsError::EmptyPrivateKey {
            path: path.display().to_string(),
        })?;
    Ok(key)
}

fn webpki_default_roots() -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn mtls_material_holds_caller_provided_bytes() {
        let m = MtlsMaterial::new(
            b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----".to_vec(),
            b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----".to_vec(),
            b"-----BEGIN CERTIFICATE-----\nca-fake\n-----END CERTIFICATE-----".to_vec(),
        );
        assert!(m.client_cert_len() > 0);
    }

    #[test]
    fn make_client_config_rejects_missing_files() {
        // Path that does not exist — must surface ReadFile, not panic.
        let bad = Path::new("/tmp/qorch-ary1883-nonexistent.pem");
        let result = make_client_config(bad, bad, None);
        match result {
            Err(MtlsError::ReadFile {.. }) => {}
            other => panic!("expected ReadFile error, got {other:?}"),
        }
    }

    #[test]
    fn make_client_config_rejects_empty_cert_pem() {
        // Write an empty file, point the factory at it — must yield
        // EmptyCertificateChain (NOT a panic, NOT a silent Ok).
        let dir = std::env::temp_dir();
        let cert = dir.join(format!(
            "qorch-ary1883-empty-cert-{}.pem",
            std::process::id()
        ));
        let key = dir.join(format!(
            "qorch-ary1883-empty-key-{}.pem",
            std::process::id()
        ));
        std::fs::write(&cert, b"").unwrap();
        std::fs::write(&key, b"").unwrap();
        let result = make_client_config(&cert, &key, None);
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
        match result {
            Err(MtlsError::EmptyCertificateChain {.. }) => {}
            other => panic!("expected EmptyCertificateChain, got {other:?}"),
        }
    }
}
