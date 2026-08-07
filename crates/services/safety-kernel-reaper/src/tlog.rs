//! Kill-record transparency-log append. After executing a stop the Reaper
//! appends a kill-executed record to the SAME transparency log the kernel uses,
//! so every kill is audited + attributable (defends against "Kill-as-DoS").
//! This is the Reaper's durable evidence — the kernel-side ack
//! (`KernelClient::ack`) is only queue hygiene.

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use qorch_domain::safety::InstanceTarget;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::executor::StopOutcome;

/// A durable record of one executed revoke / restore. Serialized to JSON and
/// appended as the tlog leaf payload.
#[derive(Debug, Clone, Serialize)]
pub struct KillRecord {
    /// `"kill_executed"` or `"restore_executed"`.
    pub kind: String,
    /// The revocation / restore id.
    pub run_id: String,
    /// The per-decision nonce (bound into the seen-nonce store).
    pub nonce: String,
    /// sha256 of the executed decision token.
    pub token_sha256: String,
    /// Which instance was acted on.
    pub target: InstanceTarget,
    /// The executor outcome (instance / op id / prior state).
    pub outcome_instance: String,
    /// Op id returned by the executor.
    pub outcome_op_id: String,
    /// Prior state observed before the op.
    pub outcome_prev_state: String,
    /// Kernel-asserted wall-clock the record was minted (epoch seconds).
    pub occurred_at_epoch_seconds: u64,
}

impl KillRecord {
    /// Assemble a kill/restore record from the executed decision + outcome.
    #[must_use]
    pub fn new(
        kind: &str,
        run_id: &str,
        nonce: &str,
        token_sha256: &str,
        target: &InstanceTarget,
        outcome: &StopOutcome,
        occurred_at_epoch_seconds: u64,
    ) -> Self {
        Self {
            kind: kind.to_string(),
            run_id: run_id.to_string(),
            nonce: nonce.to_string(),
            token_sha256: token_sha256.to_string(),
            target: target.clone(),
            outcome_instance: outcome.instance.clone(),
            outcome_op_id: outcome.op_id.clone(),
            outcome_prev_state: outcome.prev_state.clone(),
            occurred_at_epoch_seconds,
        }
    }

    /// Canonical JSON bytes appended as the tlog leaf payload.
    #[must_use]
    pub fn payload_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// Errors from a kill-record append. Non-fatal at the Reaper's execute site
/// (the stop already happened); logged for durability follow-up.
#[derive(Debug, Error)]
pub enum KillRecorderError {
    /// Transport / server error appending the record.
    #[error("kill-record append failed: {0}")]
    Append(String),
}

/// The append surface, injected so the state machine tests use a mock.
#[async_trait]
pub trait KillRecorder: Send + Sync {
    /// Append `record` to the transparency log.
    async fn record(&self, record: &KillRecord) -> Result<(), KillRecorderError>;
}

// ============================================================================
// ReqwestKillRecorder — POST /v1/append to the transparency-log service.
// ============================================================================

/// Production recorder. Mirrors the kernel's `/v1/append` body shape
/// (idempotency key = sha256(payload); payload carried base64url).
#[derive(Debug, Clone)]
pub struct ReqwestKillRecorder {
    base_url: String,
    api_key: String,
    kernel_key_fingerprint_hex: String,
    http: reqwest::Client,
}

impl ReqwestKillRecorder {
    /// Build a recorder targeting the transparency-log root `base_url`.
    /// `kernel_key_fingerprint_hex` is the pinned verifying-key fingerprint
    /// (diagnostic; the Reaper never holds the signing key).
    #[must_use]
    pub fn new(
        base_url: String,
        api_key: String,
        kernel_key_fingerprint_hex: String,
        timeout: std::time::Duration,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            base_url,
            api_key,
            kernel_key_fingerprint_hex,
            http,
        }
    }
}

#[derive(Debug, Serialize)]
struct AppendBody {
    idempotency_key_hex: String,
    kernel_key_fingerprint_sha256: String,
    occurred_at_epoch_seconds: u64,
    token_b64: String,
}

#[async_trait]
impl KillRecorder for ReqwestKillRecorder {
    async fn record(&self, record: &KillRecord) -> Result<(), KillRecorderError> {
        let payload = record.payload_bytes();
        let idempotency_key: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&payload);
            h.finalize().into()
        };
        let body = AppendBody {
            idempotency_key_hex: hex::encode(idempotency_key),
            kernel_key_fingerprint_sha256: self.kernel_key_fingerprint_hex.clone(),
            occurred_at_epoch_seconds: record.occurred_at_epoch_seconds,
            token_b64: URL_SAFE_NO_PAD.encode(&payload),
        };
        let url = format!("{}/v1/append", self.base_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .header("x-api-key", &self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| KillRecorderError::Append(e.to_string()))?;
        let status = resp.status();
        // 2xx (fresh or idempotent replay) and 409 (existing row) both mean the
        // record is in the ledger — treat as success.
        if status.is_success() || status == reqwest::StatusCode::CONFLICT {
            return Ok(());
        }
        Err(KillRecorderError::Append(format!(
            "status={} body={}",
            status.as_u16(),
            resp.text()
                .await
                .unwrap_or_default()
                .chars()
                .take(200)
                .collect::<String>()
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn kill_record_payload_is_deterministic_json() {
        let target = InstanceTarget {
            project: "p".to_string(),
            zone: "z".to_string(),
            instance: "scratch-vm".to_string(),
        };
        let outcome = StopOutcome {
            instance: "scratch-vm".to_string(),
            op_id: "op-1".to_string(),
            prev_state: "RUNNING".to_string(),
        };
        let r = KillRecord::new(
            "kill_executed",
            "revoke_1",
            "nonce-1",
            "abc",
            &target,
            &outcome,
            42,
        );
        let a = r.payload_bytes();
        let b = r.payload_bytes();
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }
}
