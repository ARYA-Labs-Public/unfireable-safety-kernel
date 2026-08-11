//! Kernel HTTP client — the Reaper's PULL + ACK surface.
//!
//! The Reaper polls `GET /kernel/v1/revoke/pending?instance=<agent-VM>` with
//! its `reaper` key and reports execution back via `POST /kernel/v1/revoke/ack`.
//! Both are consumed from the kernel-side committed routes; the DTOs
//! (`PendingRevokeResponse`, `RevokeAckRequest`) come from `qorch-domain`.

use async_trait::async_trait;
use qorch_domain::safety::PendingRevokeResponse;
use thiserror::Error;

/// Errors from the kernel pull/ack calls. `Unreachable` is the one the
/// liveness deadline watches: sustained `Unreachable` past the deadline drives
/// the fail-closed stop.
#[derive(Debug, Error)]
pub enum KernelClientError {
    /// Network error / DNS / TLS / timeout — the kernel could not be reached.
    #[error("kernel unreachable: {0}")]
    Unreachable(String),
    /// The kernel answered but with a non-success status (e.g. 401/403).
    #[error("kernel rejected request: status={status} detail={detail}")]
    Rejected {
        /// HTTP status code.
        status: u16,
        /// Truncated body.
        detail: String,
    },
    /// A 2xx body that did not parse as the expected DTO.
    #[error("kernel malformed response: {0}")]
    Malformed(String),
}

/// The result of a pending pull: the signed token(s) plus the kernel's
/// AUTHORITATIVE current grant generation for the queried instance. The Reaper
/// fences each pulled kill against `current_grant_generation` — a kill stamped
/// against an older generation was superseded by a restore and must not fire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingPull {
    /// The currently-pending signed token(s) for the instance.
    pub tokens: Vec<String>,
    /// The kernel's live grant generation for the queried instance (`0` when
    /// the queue is empty or the kernel does not report one).
    pub current_grant_generation: u64,
}

/// The pull/ack surface. Injected so the Reaper state machine is tested with a
/// mock and driven live by the reqwest impl.
#[async_trait]
pub trait KernelClient: Send + Sync {
    /// Pull the currently-pending signed kill token(s) for `instance`, together
    /// with the kernel's authoritative current grant generation. A 204 (empty
    /// queue) maps to an empty [`PendingPull`] (generation `0`).
    async fn pull_pending(&self, instance: &str) -> Result<PendingPull, KernelClientError>;
    /// Report execution of a kill so the kernel clears its pending entry.
    /// Fail-open on the kernel side (the Reaper's own tlog kill-record is the
    /// durable evidence), so an ack failure is logged, not fatal.
    async fn ack(&self, run_id: &str, outcome: &str) -> Result<(), KernelClientError>;
}

// ============================================================================
// ReqwestKernelClient — production HTTP client.
// ============================================================================

/// Production client over `reqwest` + rustls. Presents the `reaper` API key on
/// every call so the agent's `worker` key cannot even read the queue.
#[derive(Debug, Clone)]
pub struct ReqwestKernelClient {
    base_url: String,
    reaper_api_key: String,
    http: reqwest::Client,
}

impl ReqwestKernelClient {
    /// Build a client for `base_url` (kernel root, e.g. `https://kernel:9000`),
    /// authenticating with the `reaper` API key. `timeout` is per-request.
    ///
    /// NOTE: this constructor does NOT pin the kernel's server certificate —
    /// it trusts the platform WebPKI roots. For the kill-switch trust path use
    /// [`ReqwestKernelClient::with_pinned_ca`]; the unpinned path is a
    /// live-arming fallback only.
    #[must_use]
    pub fn new(base_url: String, reaper_api_key: String, timeout: std::time::Duration) -> Self {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            base_url,
            reaper_api_key,
            http,
        }
    }

    /// Build a client that PINS the kernel's server certificate to `ca_pem`.
    /// The Reaper trusts ONLY this CA for the kernel TLS handshake — the
    /// platform's built-in WebPKI roots are turned OFF — so a MITM or a
    /// substituted "lying kernel" presenting a public-CA-issued cert fails the
    /// handshake and can no longer suppress a kill by returning an empty
    /// pending list under an untrusted identity.
    ///
    /// `ca_pem` is the PEM bytes of the kernel's server cert (or its issuing
    /// CA), loaded by the binding layer from the config-provided
    /// `REAPER_KERNEL_CA_PATH`.
    ///
    /// # Errors
    ///
    /// Returns [`KernelClientError::Malformed`] if `ca_pem` is not a valid
    /// certificate PEM, and [`KernelClientError::Unreachable`] if the TLS
    /// client cannot be constructed from it — so a bad pin fails LOUD at boot
    /// rather than silently degrading to an unpinned connection.
    pub fn with_pinned_ca(
        base_url: String,
        reaper_api_key: String,
        timeout: std::time::Duration,
        ca_pem: &[u8],
    ) -> Result<Self, KernelClientError> {
        let ca = reqwest::Certificate::from_pem(ca_pem)
            .map_err(|e| KernelClientError::Malformed(format!("pinned kernel CA PEM: {e}")))?;
        let http = reqwest::Client::builder()
            .timeout(timeout)
            // Pin: drop the public roots and trust ONLY the kernel CA.
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .build()
            .map_err(|e| {
                KernelClientError::Unreachable(format!("build cert-pinned kernel client: {e}"))
            })?;
        Ok(Self {
            base_url,
            reaper_api_key,
            http,
        })
    }
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

#[async_trait]
impl KernelClient for ReqwestKernelClient {
    async fn pull_pending(&self, instance: &str) -> Result<PendingPull, KernelClientError> {
        let url = format!(
            "{}/kernel/v1/revoke/pending",
            self.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .get(&url)
            .header("x-api-key", &self.reaper_api_key)
            .query(&[("instance", instance)])
            .send()
            .await
            .map_err(|e| KernelClientError::Unreachable(truncate(&e.to_string(), 300)))?;

        let status = resp.status();
        if status == reqwest::StatusCode::NO_CONTENT {
            return Ok(PendingPull::default());
        }
        if !status.is_success() {
            let detail = truncate(&resp.text().await.unwrap_or_default(), 300);
            return Err(KernelClientError::Rejected {
                status: status.as_u16(),
                detail,
            });
        }
        let parsed: PendingRevokeResponse = resp
            .json()
            .await
            .map_err(|e| KernelClientError::Malformed(truncate(&e.to_string(), 300)))?;
        Ok(PendingPull {
            tokens: parsed.pending,
            current_grant_generation: parsed.current_grant_generation,
        })
    }

    async fn ack(&self, run_id: &str, outcome: &str) -> Result<(), KernelClientError> {
        let url = format!(
            "{}/kernel/v1/revoke/ack",
            self.base_url.trim_end_matches('/')
        );
        // The shared `RevokeAckRequest` DTO derives Deserialize only (it is the
        // kernel's REQUEST-parse type); we serialize the wire body by hand here
        // rather than widen the shared contract with a Serialize derive.
        let body = serde_json::json!({ "run_id": run_id, "outcome": outcome });
        let resp = self
            .http
            .post(&url)
            .header("x-api-key", &self.reaper_api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| KernelClientError::Unreachable(truncate(&e.to_string(), 300)))?;
        let status = resp.status();
        if !status.is_success() {
            let detail = truncate(&resp.text().await.unwrap_or_default(), 300);
            return Err(KernelClientError::Rejected {
                status: status.as_u16(),
                detail,
            });
        }
        Ok(())
    }
}
