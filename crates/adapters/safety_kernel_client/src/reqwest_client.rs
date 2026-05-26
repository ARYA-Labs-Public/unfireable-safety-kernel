//! Reqwest-based SK client adapter.
//!
//! Production impl of [`qorch_application::safety_kernel::SafetyKernelClient`]
//! for the dispatcher ( MED-2 remediation). POSTs an
//! `AuthorizeRequest` to the SK service's `/kernel/v1/authorize`
//! endpoint with the `x-api-key` header set from
//! `$QORCH_KERNEL_API_KEY_WORKER` per CLAUDE.md "Auth keys".
//!
//! The endpoint base URL is read from `$QORCH_SAFETY_KERNEL_URL`
//! (default `http://localhost:9000` matching CLAUDE.md "Port Mapping").

use std::time::Duration;

use async_trait::async_trait;
use qorch_application::safety_kernel::{
    AuthorizeClaimsRequest, AuthorizeOutcome, SafetyKernelClient, SafetyKernelError,
};
use reqwest::Client;
use serde::Deserialize;

/// Default request timeout — the SK service is supposed to be a
/// local-loopback hop; 5 s is generous. Overridden by
/// `$QORCH_SAFETY_KERNEL_TIMEOUT_MS`.
pub const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// Default base URL — matches `apps/safety_kernel/main.py`'s 9000
/// listen port.
pub const DEFAULT_BASE_URL: &str = "http://localhost:9000";

/// Configuration knobs read once at construction.
#[derive(Debug, Clone)]
pub struct ReqwestSafetyKernelConfig {
    /// Full base URL (without trailing slash) — `/kernel/v1/authorize`
    /// is appended.
    pub base_url: String,
    /// API key value for the `x-api-key` header. Caller-role mapping
    /// is the SK service's responsibility.
    pub api_key: String,
    /// Per-request timeout.
    pub timeout: Duration,
}

impl Default for ReqwestSafetyKernelConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.into(),
            api_key: String::new(),
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        }
    }
}

impl ReqwestSafetyKernelConfig {
    /// Build the config from environment variables. Returns `None` if
    /// the API key isn't configured — caller should treat that as the
    /// "SK not bootstrapped" path and degrade.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let api_key = std::env::var("QORCH_KERNEL_API_KEY_WORKER").ok()?;
        if api_key.is_empty() {
            return None;
        }
        let base_url = std::env::var("QORCH_SAFETY_KERNEL_URL")
            .unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
        let timeout_ms = std::env::var("QORCH_SAFETY_KERNEL_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TIMEOUT_MS);
        Some(Self {
            base_url,
            api_key,
            timeout: Duration::from_millis(timeout_ms),
        })
    }
}

/// Production SK client.
#[derive(Debug, Clone)]
pub struct ReqwestSafetyKernelClient {
    config: ReqwestSafetyKernelConfig,
    http: Client,
}

impl ReqwestSafetyKernelClient {
    /// Construct from a config. Panics only on `reqwest::Client::builder`
    /// failure (impossible in practice with default builder).
    #[must_use]
    pub fn new(config: ReqwestSafetyKernelConfig) -> Self {
        let http = Client::builder()
            .timeout(config.timeout)
            .build()
            .unwrap_or_else(|_| Client::new());
        Self { config, http }
    }
}

#[async_trait]
impl SafetyKernelClient for ReqwestSafetyKernelClient {
    async fn authorize(
        &self,
        claims: AuthorizeClaimsRequest,
    ) -> Result<AuthorizeOutcome, SafetyKernelError> {
        let url = format!(
            "{}/kernel/v1/authorize",
            self.config.base_url.trim_end_matches('/')
        );
        let response = self
            .http
            .post(&url)
            .header("x-api-key", &self.config.api_key)
            .json(&claims)
            .send()
            .await
            .map_err(|e| SafetyKernelError::Unreachable {
                detail: truncate(&format!("{e}"), 300),
            })?;

        let status = response.status();
        if status.is_success() {
            return response.json::<AuthorizeOutcome>().await.map_err(|e| {
                SafetyKernelError::MalformedResponse {
                    detail: truncate(&format!("{e}"), 300),
                }
            });
        }

        if status.is_client_error() {
            // 4xx → SK explicitly refused. Fail-closed signal.
            #[derive(Deserialize)]
            struct ErrorResponseBody {
                #[serde(default)]
                detail: Option<String>,
                #[serde(default)]
                reason: Option<String>,
            }
            let body: ErrorResponseBody = response.json().await.unwrap_or(ErrorResponseBody {
                detail: None,
                reason: None,
            });
            let detail = body
                .reason
                .or(body.detail)
                .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
            return Err(SafetyKernelError::PolicyRejected {
                status_code: status.as_u16(),
                detail: truncate(&detail, 300),
            });
        }

        // 5xx or other unexpected → treat as unreachable (fail-safe).
        Err(SafetyKernelError::Unreachable {
            detail: format!("unexpected status {}", status.as_u16()),
        })
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::{ReqwestSafetyKernelClient, ReqwestSafetyKernelConfig};
    use qorch_application::safety_kernel::{
        AuthorizeClaimsRequest, SafetyKernelClient, SafetyKernelError,
    };

    #[test]
    fn config_from_env_returns_none_when_api_key_missing() {
        // Unset the env vars for this test.
        let saved = std::env::var("QORCH_KERNEL_API_KEY_WORKER").ok();
        std::env::remove_var("QORCH_KERNEL_API_KEY_WORKER");
        assert!(ReqwestSafetyKernelConfig::from_env().is_none());
        // Restore.
        if let Some(v) = saved {
            std::env::set_var("QORCH_KERNEL_API_KEY_WORKER", v);
        }
    }

    #[tokio::test]
    async fn unreachable_sk_yields_unreachable_error() {
        // Point at an unused localhost port (no service listening).
        let cfg = ReqwestSafetyKernelConfig {
            base_url: "http://127.0.0.1:1".into(),
            api_key: "dev-key".into(),
            timeout: std::time::Duration::from_millis(500),
        };
        let client = ReqwestSafetyKernelClient::new(cfg);
        let claims = AuthorizeClaimsRequest {
            action: "ddi_atlas_exp2_run".into(),
            run_id: "test".into(),
            subject: "qorch-ddi-dispatch".into(),
            params_fingerprint: "deadbeef".into(),
            params: None,
            ttl_s: Some(60),
        };
        let result = client.authorize(claims).await;
        match result {
            Err(SafetyKernelError::Unreachable {.. }) => {}
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }
}
