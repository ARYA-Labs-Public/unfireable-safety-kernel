// File-level allows: the docs use plain prose for service-level types
// (`api_key`, `kernel_key_fingerprint_sha256`, etc.) and the bullet
// lists in the module preamble are intentional bullets, not paragraphs.
#![allow(clippy::doc_markdown, clippy::doc_lazy_continuation)]

//! Outbound transparency-log client for the Safety Kernel (
//!  §6,  Step 5).
//!
//! The kernel POSTs every successful `kernel_authorize` decision to
//! the transparency-log service BEFORE returning the signed token to
//! the caller — fail-CLOSED per epic owner direction 2026-05-23.
//! See `routes/authorize.rs` for the call site.
//!
//! Two pieces live here:
//!   - [`TransparencyClient`] — trait used by `AppState`; routes hold
//!     `Option<Arc<dyn TransparencyClient>>` so existing tests that
//!     don't care about transparency can leave it `None`.
//!   - [`ReqwestTransparencyClient`] — production impl over `reqwest`
//!     + rustls. Lives here (not in `qorch-adapters`) because it's the
//!     kernel's private outbound dependency and we don't want to pull
//!     the kernel's `Settings` into a shared crate.
//!
//! The kernel maps the response space to four buckets:
//!   * 2xx `idempotent_replay=false` ⇒ success, fresh insert
//!   * 2xx `idempotent_replay=true`  ⇒ success, idempotent retry
//!   * 409 Conflict                  ⇒ idempotent retry of a different
//!     payload; the authorize handler folds 409 into success because
//!     the row already exists in the ledger
//!   * 4xx / 5xx / timeout / network ⇒ `Error`
//!
//! Per ADR §6 a retry of the SAME payload yields 200, not 409 —
//! `TransparencyError::Conflict` is therefore reserved for the rare
//! "kernel restarted and rolled forward an entry with a key collision"
//! case; the authorize handler still treats it as success because the
//! ledger has the row.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Pure input to the transparency-log append call. The kernel-side
/// wrapper derives the wire payload from this.
#[derive(Debug, Clone)]
pub struct TransparencyAppendInput {
    /// 32-byte idempotency fingerprint (kernel uses SHA-256 of the
    /// token bytes 
    pub idempotency_key: [u8; 32],
    /// Raw bytes the transparency-log will hash + persist as the
    /// leaf (RFC-6962 leaf hash = SHA-256(0x00 || payload)).
    pub payload: Vec<u8>,
    /// Kernel-asserted wall-clock instant the underlying decision was
    /// minted (seconds since the Unix epoch).
    pub occurred_at_epoch_seconds: u64,
}

/// Outcome of a successful append. Mirrors the wire DTO but omits
/// `entry_id` because the kernel uses `leaf_index` directly.
///
/// The kernel's authorize handler only checks `Result::Ok` — it does
/// not branch on the outcome fields. They are retained on the wire
/// for diagnostics + future audit-record enrichment.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct TransparencyAppendOutcome {
    /// 0-based ledger position assigned by the store.
    pub leaf_index: u64,
    /// True when the response surfaced an existing row (idempotent
    /// retry). False on a fresh insert.
    pub idempotent_replay: bool,
}

/// Errors surfaced by transparency-log calls. The kernel maps every
/// variant to fail-CLOSED — the only exception is
/// [`TransparencyError::Conflict`], which the authorize handler folds
/// into success (idempotent-retry success on a colliding key).
#[derive(Debug, Error)]
pub enum TransparencyError {
    /// Network error / DNS failure / TLS handshake failure.
    #[error("transparency-log unreachable: {detail}")]
    Unreachable {
        /// Diagnostic string, truncated to 300 chars.
        detail: String,
    },
    /// HTTP 4xx (other than 409).
    #[error("transparency-log rejected request: status={status_code} detail={detail}")]
    Rejected {
        /// Echoed status code.
        status_code: u16,
        /// Diagnostic string (response body), truncated to 300 chars.
        detail: String,
    },
    /// HTTP 5xx.
    #[error("transparency-log server error: status={status_code} detail={detail}")]
    ServerError {
        /// Echoed status code.
        status_code: u16,
        /// Diagnostic string, truncated to 300 chars.
        detail: String,
    },
    /// HTTP 409 Conflict — same idempotency key with a different
    /// payload. The kernel treats this as success (the row exists in
    /// the ledger; the divergence is a kernel bug, not a t-log fault).
    #[error("transparency-log idempotency conflict (existing row preserved)")]
    Conflict,
    /// Response shape did not match `AppendResponse`.
    #[error("transparency-log malformed response: {detail}")]
    Malformed {
        /// Diagnostic string, truncated to 300 chars.
        detail: String,
    },
    /// The t-log returned a 2xx with a `leaf_hash_hex` (or other
    /// protocol-level field) that diverges from what the kernel
    /// locally computed. Treated as evidence that the ledger is
    /// compromised or buggy — kernel fails CLOSED.  / 
    /// Step 8 defense-in-depth: catches a malicious or buggy t-log
    /// instance that stores leaf A but reports leaf B (future
    /// inclusion proofs would diverge silently otherwise).
    #[error("transparency-log protocol violation: {0}")]
    ProtocolViolation(String),
}

impl TransparencyError {
    /// Stable kind string for synth-deny reasons.
    /// Maps directly to the `transparency_error:<kind>` shape in
    /// `routes/authorize.rs`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            TransparencyError::Unreachable {.. } => "unreachable",
            TransparencyError::Rejected {.. } => "append_failed",
            TransparencyError::ServerError {.. } => "server_error",
            TransparencyError::Conflict => "conflict",
            TransparencyError::Malformed {.. } => "malformed_response",
            TransparencyError::ProtocolViolation(_) => "protocol_violation",
        }
    }

    /// Human-readable detail for log lines.
    #[must_use]
    pub fn detail(&self) -> String {
        format!("{self}")
    }
}

/// Trait the kernel's `AppState` holds (so route tests can mock it).
///
/// `#[async_trait]` is required because the `Arc<dyn …>` consumer
/// site needs a dyn-compatible vtable; bare `async fn` in traits is
/// not (yet) dyn-compatible in stable Rust 1.85.
#[async_trait]
pub trait TransparencyClient: Send + Sync {
    /// POST `/v1/append` with the given input. Returns the outcome on
    /// 2xx, [`TransparencyError::Conflict`] on 409, any other variant
    /// on failure.
    async fn append(
        &self,
        input: TransparencyAppendInput,
    ) -> Result<TransparencyAppendOutcome, TransparencyError>;
}

/// Production transparency-log client (`reqwest` + `rustls`).
#[derive(Debug, Clone)]
pub struct ReqwestTransparencyClient {
    base_url: String,
    api_key: String,
    kernel_key_fingerprint_hex: String,
    http: Client,
}

impl ReqwestTransparencyClient {
    /// Build a new client without a client certificate.
    ///
    /// `base_url` should be the t-log root, e.g.
    /// `https://transparency-log:8100`. `timeout` is per-request.
    ///
    /// # Panics
    ///
    /// Never — `Client::builder` always succeeds with the default
    /// rustls feature set. We fold the unlikely error back to
    /// `Client::new()` so a startup failure here doesn't propagate.
    #[must_use]
    pub fn new(
        base_url: String,
        api_key: String,
        kernel_key_fingerprint_hex: String,
        timeout: Duration,
    ) -> Self {
        let http = Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            base_url,
            api_key,
            kernel_key_fingerprint_hex,
            http,
        }
    }

    /// Build a new client with an mTLS client certificate identity.
    ///
    ///  /  Step 8: the kernel presents this identity
    /// when initiating the mTLS handshake to the transparency-log
    /// service. `cert_path` and `key_path` must both point at
    /// PEM-encoded files; their bytes are concatenated and fed to
    /// `reqwest::Identity::from_pem`. The resulting identity is
    /// installed on the underlying `reqwest::Client` so every outbound
    /// request carries the client cert.
    ///
    /// `rustls-tls` is the only TLS backend (per 
    /// Addendum 2a §2 — NO native-tls, NO aws-lc-rs). The workspace
    /// `reqwest` dep enables this feature.
    ///
    /// # Errors
    ///
    /// Returns `Err` if either PEM file cannot be read, or
    /// `reqwest::Identity::from_pem` rejects the concatenated bytes
    /// (malformed PEM, mismatched cert/key, etc.). The kernel's boot
    /// path treats this as a hard failure in prod.
    pub fn new_with_client_cert(
        base_url: String,
        api_key: String,
        kernel_key_fingerprint_hex: String,
        timeout: Duration,
        cert_path: &Path,
        key_path: &Path,
    ) -> anyhow::Result<Self> {
        let cert_bytes = std::fs::read(cert_path).map_err(|e| {
            anyhow::anyhow!(
                "failed to read transparency-log client cert at {}: {e}",
                cert_path.display()
            )
        })?;
        let key_bytes = std::fs::read(key_path).map_err(|e| {
            anyhow::anyhow!(
                "failed to read transparency-log client key at {}: {e}",
                key_path.display()
            )
        })?;
        let mut pem = Vec::with_capacity(cert_bytes.len() + 1 + key_bytes.len());
        pem.extend_from_slice(&cert_bytes);
        // Defensive: ensure a separator between cert and key so the
        // concatenation is still a well-formed PEM bundle even when
        // either file lacks a trailing newline.
        if !cert_bytes.ends_with(b"\n") {
            pem.push(b'\n');
        }
        pem.extend_from_slice(&key_bytes);

        let identity = reqwest::Identity::from_pem(&pem).map_err(|e| {
            anyhow::anyhow!(
                "failed to parse transparency-log client PEM identity (cert={}, key={}): {e}",
                cert_path.display(),
                key_path.display()
            )
        })?;

        let http = Client::builder()
            .timeout(timeout)
            .identity(identity)
            .build()
            .map_err(|e| {
                anyhow::anyhow!("failed to build reqwest::Client with mTLS identity: {e}")
            })?;
        Ok(Self {
            base_url,
            api_key,
            kernel_key_fingerprint_hex,
            http,
        })
    }
}

/// Wire shape for the request body; private to this module so the
/// public surface is the trait, not the HTTP envelope.
#[derive(Debug, Serialize)]
struct AppendBody<'a> {
    idempotency_key_hex: String,
    kernel_key_fingerprint_sha256: &'a str,
    occurred_at_epoch_seconds: u64,
    token_b64: String,
}

#[derive(Debug, Deserialize)]
struct AppendResponseBody {
    #[allow(dead_code)]
    entry_id: String,
    idempotent_replay: bool,
    /// Hex-encoded RFC-6962 leaf hash (`SHA-256(0x00 || payload)`) the
    /// t-log claims it stored.  added a kernel-side cross-check
    /// against the locally-computed hash; any mismatch raises a
    /// `ProtocolViolation` and fails CLOSED on the authorize path.
    leaf_hash_hex: String,
    leaf_index: u64,
    #[allow(dead_code)]
    ok: bool,
}

#[async_trait]
impl TransparencyClient for ReqwestTransparencyClient {
    async fn append(
        &self,
        input: TransparencyAppendInput,
    ) -> Result<TransparencyAppendOutcome, TransparencyError> {
        let url = format!("{}/v1/append", self.base_url.trim_end_matches('/'));
        let body = AppendBody {
            idempotency_key_hex: hex::encode(input.idempotency_key),
            kernel_key_fingerprint_sha256: &self.kernel_key_fingerprint_hex,
            occurred_at_epoch_seconds: input.occurred_at_epoch_seconds,
            token_b64: URL_SAFE_NO_PAD.encode(&input.payload),
        };
        let resp = self
            .http
            .post(&url)
            .header("x-api-key", &self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| TransparencyError::Unreachable {
                detail: truncate(&format!("{e}"), 300),
            })?;

        let status = resp.status();
        if status == reqwest::StatusCode::CONFLICT {
            return Err(TransparencyError::Conflict);
        }
        if status.is_success() {
            let parsed: AppendResponseBody =
                resp.json().await.map_err(|e| TransparencyError::Malformed {
                    detail: truncate(&format!("{e}"), 300),
                })?;
            //  /  Step 8 — cross-verify that the
            // returned leaf_hash_hex corresponds to the kernel's local
            // SHA-256(0x00 || payload). A divergence proves the t-log
            // is lying about what it stored — future inclusion proofs
            // would diverge silently otherwise. Fail-CLOSED.
            let expected = qorch_domain::transparency::leaf_hash(&input.payload);
            let returned = hex::decode(&parsed.leaf_hash_hex).map_err(|_| {
                TransparencyError::ProtocolViolation(format!(
                    "non-hex leaf_hash returned by t-log (got {} chars)",
                    parsed.leaf_hash_hex.len()
                ))
            })?;
            if expected[..] != returned[..] {
                return Err(TransparencyError::ProtocolViolation(format!(
                    "leaf_hash mismatch — t-log lied about what it stored \
                     (expected {}, got {})",
                    hex::encode(expected),
                    truncate(&parsed.leaf_hash_hex, 64),
                )));
            }
            return Ok(TransparencyAppendOutcome {
                leaf_index: parsed.leaf_index,
                idempotent_replay: parsed.idempotent_replay,
            });
        }

        let status_code = status.as_u16();
        let body_text = resp.text().await.unwrap_or_default();
        let detail = truncate(&body_text, 300);
        if status.is_server_error() {
            return Err(TransparencyError::ServerError {
                status_code,
                detail,
            });
        }
        Err(TransparencyError::Rejected {
            status_code,
            detail,
        })
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect()
}

/// Compute the idempotency key the kernel uses for `POST /v1/append`.
/// 
#[must_use]
pub fn idempotency_key_for_token(token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.finalize().into()
}

/// Convenience constructor used by `main.rs` to build the optional
/// production client from `Settings` env. Returns `None` when
/// transparency-log integration is disabled (`enabled=false`).
///
/// When BOTH `client_cert_path` and `client_key_path` are `Some`, the
/// client presents an mTLS identity on every outbound request
///. Either-side missing keeps the legacy x-api-key-only
/// behaviour — `Settings::from_env` already refuses to boot prod
/// without both paths set.
///
/// # Errors
///
/// Returns `Err` only when client-cert paths are present but the PEM
/// bytes fail to load (file missing, malformed PEM, mismatched
/// cert/key). The kernel's boot path treats this as a hard failure in
/// prod — the caller is `main.rs` which propagates the error.
pub fn build_optional_client(
    enabled: bool,
    url: Option<&str>,
    api_key: Option<&str>,
    kernel_key_fingerprint_hex: &str,
    timeout: Duration,
    client_cert_path: Option<&Path>,
    client_key_path: Option<&Path>,
) -> anyhow::Result<Option<Arc<dyn TransparencyClient>>> {
    if !enabled {
        return Ok(None);
    }
    let Some(url) = url else {
        return Ok(None);
    };
    let api_key = api_key.unwrap_or_default().to_string();
    if api_key.is_empty() {
        return Ok(None);
    }
    let client: Arc<dyn TransparencyClient> = match (client_cert_path, client_key_path) {
        (Some(cert), Some(key)) => Arc::new(ReqwestTransparencyClient::new_with_client_cert(
            url.to_string(),
            api_key,
            kernel_key_fingerprint_hex.to_string(),
            timeout,
            cert,
            key,
        )?),
        _ => Arc::new(ReqwestTransparencyClient::new(
            url.to_string(),
            api_key,
            kernel_key_fingerprint_hex.to_string(),
            timeout,
        )),
    };
    Ok(Some(client))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn idempotency_key_for_token_is_deterministic() {
        let k1 = idempotency_key_for_token("abc.def");
        let k2 = idempotency_key_for_token("abc.def");
        assert_eq!(k1, k2);
        let k3 = idempotency_key_for_token("abc.deg");
        assert_ne!(k1, k3);
    }

    #[test]
    fn transparency_error_kind_strings_are_stable() {
        let cases: Vec<(&'static str, TransparencyError)> = vec![
            (
                "unreachable",
                TransparencyError::Unreachable {
                    detail: "x".into(),
                },
            ),
            (
                "append_failed",
                TransparencyError::Rejected {
                    status_code: 400,
                    detail: "x".into(),
                },
            ),
            (
                "server_error",
                TransparencyError::ServerError {
                    status_code: 500,
                    detail: "x".into(),
                },
            ),
            ("conflict", TransparencyError::Conflict),
            (
                "malformed_response",
                TransparencyError::Malformed {
                    detail: "x".into(),
                },
            ),
            (
                "protocol_violation",
                TransparencyError::ProtocolViolation("x".into()),
            ),
        ];
        for (expected, err) in cases {
            assert_eq!(err.kind(), expected);
        }
    }

    #[tokio::test]
    async fn unreachable_url_yields_unreachable_error() {
        let client = ReqwestTransparencyClient::new(
            "http://127.0.0.1:1".to_string(),
            "test-key".to_string(),
            hex::encode([0u8; 32]),
            Duration::from_millis(200),
        );
        let err = client
            .append(TransparencyAppendInput {
                idempotency_key: [0u8; 32],
                payload: vec![1, 2, 3],
                occurred_at_epoch_seconds: 1,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, TransparencyError::Unreachable {.. }));
    }

    #[test]
    fn build_optional_client_disabled_returns_none() {
        let c = build_optional_client(
            false,
            Some("http://x"),
            Some("k"),
            "deadbeef",
            Duration::from_secs(2),
            None,
            None,
        )
        .unwrap();
        assert!(c.is_none());
    }

    #[test]
    fn build_optional_client_missing_url_returns_none() {
        let c = build_optional_client(
            true,
            None,
            Some("k"),
            "deadbeef",
            Duration::from_secs(2),
            None,
            None,
        )
        .unwrap();
        assert!(c.is_none());
    }

    #[test]
    fn build_optional_client_missing_api_key_returns_none() {
        let c = build_optional_client(
            true,
            Some("http://x"),
            Some(""),
            "deadbeef",
            Duration::from_secs(2),
            None,
            None,
        )
        .unwrap();
        assert!(c.is_none());
    }

    //  — mTLS identity loader tests.

    /// Writes a self-signed ED25519 cert + key pair to two temp files
    /// and returns their paths. Uses `rcgen` (already a dev-dep of this
    /// crate) so we don't pull a new dep for testing.
    fn write_self_signed_pem_pair() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        // rcgen is a dev-dependency; constructing a localhost cert is
        // sufficient — reqwest::Identity::from_pem only validates PEM
        // shape + key/cert binding, not chain trust.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed gen");
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("client.crt");
        let key_path = dir.path().join("client.key");
        std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
        (dir, cert_path, key_path)
    }

    #[test]
    fn client_builder_loads_pem_identity_pair_ok() {
        //  happy-path: a valid cert+key pair must build a
        // client successfully and the resulting client must be
        // identifiable as carrying an mTLS identity (the only
        // externally-visible signal is "the builder did not error").
        let (_dir, cert, key) = write_self_signed_pem_pair();
        let res = ReqwestTransparencyClient::new_with_client_cert(
            "https://t-log.internal:8100".to_string(),
            "test-api-key".to_string(),
            hex::encode([0u8; 32]),
            Duration::from_secs(2),
            &cert,
            &key,
        );
        assert!(
            res.is_ok(),
            "valid PEM cert+key pair must build: {:?}",
            res.err()
        );
    }

    #[test]
    fn client_builder_missing_cert_path_in_prod_errors() {
        //  fail-closed: pointing at a path that doesn't exist
        // must error rather than silently degrade to no-cert mode.
        let dir = tempfile::tempdir().expect("tempdir");
        let missing_cert = dir.path().join("definitely-not-there.crt");
        let missing_key = dir.path().join("definitely-not-there.key");
        let res = ReqwestTransparencyClient::new_with_client_cert(
            "https://t-log.internal:8100".to_string(),
            "test-api-key".to_string(),
            hex::encode([0u8; 32]),
            Duration::from_secs(2),
            &missing_cert,
            &missing_key,
        );
        assert!(res.is_err(), "missing cert path must error");
        let msg = format!("{:?}", res.err().unwrap());
        assert!(
            msg.contains("client cert") || msg.contains("client key"),
            "error must name the missing file role: {msg}"
        );
    }

    #[test]
    fn client_builder_malformed_pem_errors() {
        //  fail-closed: invalid PEM bytes must error at builder
        // time, not at first-request time.
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("bad.crt");
        let key_path = dir.path().join("bad.key");
        std::fs::write(&cert_path, b"this is not a PEM\n").unwrap();
        std::fs::write(&key_path, b"neither is this\n").unwrap();
        let res = ReqwestTransparencyClient::new_with_client_cert(
            "https://t-log.internal:8100".to_string(),
            "test-api-key".to_string(),
            hex::encode([0u8; 32]),
            Duration::from_secs(2),
            &cert_path,
            &key_path,
        );
        assert!(res.is_err(), "malformed PEM must error");
    }
}
