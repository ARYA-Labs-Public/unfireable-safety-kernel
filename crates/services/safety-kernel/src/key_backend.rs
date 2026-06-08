//! Pluggable signing-key backend (Step-14R / ARY-1886 Phase-4).
//!
//! Historically the Safety Kernel's Ed25519 signing seed came ONLY from
//! the `QORCH_KERNEL_SIGNING_KEY_B64` environment variable. For
//! self-hosted / commodity-hardware production deployments that is a
//! liability: the raw 32-byte seed sits in the process environment where
//! anything that can read `/proc/<pid>/environ` (or a crashed-process
//! core dump) recovers the kernel's signing identity.
//!
//! This module introduces a `KERNEL_KEY_BACKEND` selector so the seed can
//! instead be fetched from a managed secret store at boot, while the env
//! var stays the zero-config default for dev/staging.
//!
//! ## Backends
//!
//! | value             | status        | notes                                   |
//! |-------------------|---------------|-----------------------------------------|
//! | `env` (default)   | implemented   | reads `QORCH_KERNEL_SIGNING_KEY_B64`. **Blocked when `QORCH_ENV=prod`** (fail-closed). |
//! | `gcp`             | implemented   | GCP Secret Manager via REST + metadata-server ADC token. |
//! | `aws`             | not yet       | tracked separately — see `docs/deployment/key-management.md`. |
//! | `azure`           | not yet       | tracked separately. |
//! | `pkcs11`          | not yet       | tracked separately (HSM). |
//! | `tpm`             | not yet       | tracked separately (TPM 2.0). |
//!
//! Selecting an unimplemented backend fails CLOSED with a pointer to the
//! tracking issue — it never silently falls back to the env var.
//!
//! ## GCP auth (least privilege)
//!
//! The `gcp` backend obtains an `OAuth2` access token from the GCE/GKE
//! metadata server (attached service account / Workload Identity), then
//! calls Secret Manager's `:access` REST endpoint. The kernel's service
//! account needs only `roles/secretmanager.secretAccessor` on the one
//! secret — it does NOT need write access. Seed *provisioning*
//! (generate-then-upload) is an operator/Terraform concern; see the
//! `safety-kernel-keygen` binary and `docs/deployment/key-management.md`.
//!
//! No new crates: this reuses the `reqwest` client already vendored for
//! the transparency-log path (rustls, no native-tls).

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::settings::Settings;

/// Which secret store the signing seed is fetched from at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBackendKind {
    /// `QORCH_KERNEL_SIGNING_KEY_B64` env var. Default; blocked in prod.
    Env,
    /// GCP Secret Manager (metadata-server ADC).
    Gcp,
    /// AWS Secrets Manager — not yet implemented.
    Aws,
    /// Azure Key Vault — not yet implemented.
    Azure,
    /// PKCS#11 HSM — not yet implemented.
    Pkcs11,
    /// TPM 2.0 — not yet implemented.
    Tpm,
}

impl KeyBackendKind {
    /// Parse the `KERNEL_KEY_BACKEND` value. Empty/unset ⇒ `Env`.
    ///
    /// # Errors
    /// Returns `Err` for an unrecognized backend name.
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "env" => Ok(Self::Env),
            "gcp" | "gcp_secret_manager" | "gcp-secret-manager" => Ok(Self::Gcp),
            "aws" | "aws_secrets_manager" | "aws-secrets-manager" => Ok(Self::Aws),
            "azure" | "azure_key_vault" | "azure-key-vault" => Ok(Self::Azure),
            "pkcs11" | "pkcs#11" | "hsm" => Ok(Self::Pkcs11),
            "tpm" | "tpm2" => Ok(Self::Tpm),
            other => Err(anyhow!(
                "unknown KERNEL_KEY_BACKEND '{other}' \
                 (expected one of: env|gcp|aws|azure|pkcs11|tpm)"
            )),
        }
    }

    /// Canonical lowercase name, for log lines and error messages.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Gcp => "gcp",
            Self::Aws => "aws",
            Self::Azure => "azure",
            Self::Pkcs11 => "pkcs11",
            Self::Tpm => "tpm",
        }
    }
}

/// Resolve the Ed25519 signing seed (base64url string) using the
/// configured backend. Called once at startup from `main`, after the
/// tokio runtime is live (the GCP path is async).
///
/// For `Env`, the value was already read + prod-blocked in
/// [`Settings::from_env`]; this just returns it. For `Gcp`, it performs
/// the live Secret Manager fetch.
///
/// # Errors
/// Returns `Err` if the backend is unimplemented, if required config is
/// missing, or if the remote fetch fails. The kernel MUST fail to boot in
/// that case (a kernel with no signing identity is not a kernel).
pub async fn resolve_signing_key_b64(settings: &Settings) -> Result<String> {
    match settings.key_backend {
        KeyBackendKind::Env => Ok(settings.signing_key_b64.clone()),
        KeyBackendKind::Gcp => {
            let project = settings
                .key_gcp_project
                .clone()
                .context("KERNEL_KEY_BACKEND=gcp requires KERNEL_KEY_GCP_PROJECT")?;
            let secret = settings
                .key_gcp_secret
                .clone()
                .context("KERNEL_KEY_BACKEND=gcp requires KERNEL_KEY_GCP_SECRET")?;
            fetch_gcp_secret(&project, &secret, &settings.key_gcp_secret_version).await
        }
        other => Err(anyhow!(
            "KERNEL_KEY_BACKEND={} is not implemented in this build; \
             see docs/deployment/key-management.md for the tracking issue. \
             Refusing to fall back to the env var (fail-closed).",
            other.as_str()
        )),
    }
}

/// Fetch a secret payload from GCP Secret Manager and return it as a
/// trimmed UTF-8 string (the stored base64url Ed25519 seed).
///
/// The Secret Manager `:access` response wraps the raw payload bytes in a
/// STANDARD-base64 `payload.data` field; we decode that one layer to
/// recover the seed string the operator stored.
async fn fetch_gcp_secret(project: &str, secret: &str, version: &str) -> Result<String> {
    let token = gcp_metadata_access_token().await?;
    let url = format!(
        "https://secretmanager.googleapis.com/v1/projects/{project}/secrets/{secret}/versions/{version}:access"
    );
    // Bounded timeout so a hung Secret Manager endpoint cannot stall boot
    // indefinitely (purple-team PT-3); a real error still fails closed.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("building reqwest client for GCP Secret Manager")?;
    let resp = client
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .context("GCP Secret Manager :access request failed")?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .context("reading GCP Secret Manager response body")?;
    if !status.is_success() {
        // Surface the GCP error verbatim (it names the missing IAM
        // permission, e.g. secretmanager.versions.access) but never the
        // token.
        return Err(anyhow!(
            "GCP Secret Manager returned {status} for secret '{secret}' \
             (version '{version}') in project '{project}': {body}"
        ));
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).context("parsing GCP Secret Manager JSON")?;
    let data_b64 = v
        .get("payload")
        .and_then(|p| p.get("data"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("GCP Secret Manager response missing payload.data"))?;
    let raw = STANDARD
        .decode(data_b64)
        .context("base64-decoding GCP Secret Manager payload.data")?;
    let seed_b64 = String::from_utf8(raw)
        .context("GCP secret payload is not valid UTF-8 (expected a base64url seed string)")?
        .trim()
        .to_string();
    if seed_b64.is_empty() {
        return Err(anyhow!(
            "GCP secret '{secret}' (version '{version}') is empty"
        ));
    }
    Ok(seed_b64)
}

/// Obtain an `OAuth2` access token from the GCE/GKE metadata server
/// (attached service account / Workload Identity). This is the canonical
/// ADC path for GCP-hosted workloads (GCE, GKE, Cloud Run).
///
/// Non-GCE ADC (service-account JSON key files) is intentionally NOT
/// supported in this slice — see `docs/deployment/key-management.md`.
async fn gcp_metadata_access_token() -> Result<String> {
    let url = "http://metadata.google.internal/computeMetadata/v1/\
               instance/service-accounts/default/token";
    // Short timeout: the metadata server is link-local; a hang here must
    // not stall boot (purple-team PT-3).
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .context("building reqwest client for GCP metadata server")?;
    let resp = client
        .get(url)
        .header("Metadata-Flavor", "Google")
        .send()
        .await
        .context(
            "GCP metadata-server token request failed \
             (is this running on GCE/GKE with an attached service account?)",
        )?;
    let status = resp.status();
    let body = resp.text().await.context("reading metadata token body")?;
    if !status.is_success() {
        return Err(anyhow!("GCP metadata server returned {status}: {body}"));
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).context("parsing metadata token JSON")?;
    v.get("access_token")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("metadata token response missing access_token"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_known_aliases() {
        assert_eq!(KeyBackendKind::parse("").unwrap(), KeyBackendKind::Env);
        assert_eq!(KeyBackendKind::parse("env").unwrap(), KeyBackendKind::Env);
        assert_eq!(KeyBackendKind::parse("GCP").unwrap(), KeyBackendKind::Gcp);
        assert_eq!(
            KeyBackendKind::parse("gcp_secret_manager").unwrap(),
            KeyBackendKind::Gcp
        );
        assert_eq!(KeyBackendKind::parse("aws").unwrap(), KeyBackendKind::Aws);
        assert_eq!(
            KeyBackendKind::parse("azure-key-vault").unwrap(),
            KeyBackendKind::Azure
        );
        assert_eq!(
            KeyBackendKind::parse("pkcs11").unwrap(),
            KeyBackendKind::Pkcs11
        );
        assert_eq!(KeyBackendKind::parse("tpm2").unwrap(), KeyBackendKind::Tpm);
    }

    #[test]
    fn parse_rejects_unknown() {
        assert!(KeyBackendKind::parse("vault").is_err());
        assert!(KeyBackendKind::parse("kms").is_err());
    }

    #[test]
    fn unimplemented_backends_report_canonical_names() {
        // The resolve path refuses these (fail-closed); the names must
        // stay stable for the error message + docs cross-reference.
        assert_eq!(KeyBackendKind::Aws.as_str(), "aws");
        assert_eq!(KeyBackendKind::Azure.as_str(), "azure");
        assert_eq!(KeyBackendKind::Pkcs11.as_str(), "pkcs11");
        assert_eq!(KeyBackendKind::Tpm.as_str(), "tpm");
    }
}
