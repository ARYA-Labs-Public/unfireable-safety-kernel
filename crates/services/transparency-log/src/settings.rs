//! Env-driven settings for the transparency-log service (ADR-014
//! Phase 3 §3, internal-ref Step 5).
//!
//! Required-secrets policy:
//! - `QORCH_TRANSPARENCY_SIGNING_KEY_B64` — fail-closed in all envs
//! - `QORCH_TRANSPARENCY_KERNEL_VERIFYING_KEY_B64` — fail-closed in
//!   all envs. Binds the ledger to ONE kernel.
//! - `QORCH_TRANSPARENCY_API_KEY` — fail-closed in `prod`. Optional in
//!   `dev` for ergonomics (the middleware still rejects empty keys
//!   when QORCH_ENV != dev).
//!
//! - `QORCH_TRANSPARENCY_MCP_AUDIT_ED25519_PUBLIC` — hex raw 32-byte
//!   Ed25519 public key whose SHA-256 fingerprint `POST /v1/audit/mcp`
//!   pins. Fail-closed in `prod` (internal-ref); unset in dev leaves the
//!   route at 503.
//!
//! Optional:
//! - `QORCH_TRANSPARENCY_DB_URL` — Postgres DSN. When unset the
//!   service boots with the in-memory store (dev only). The bin emits
//!   a WARN at startup if DB_URL is unset and `env != dev`.
//! - `QORCH_TRANSPARENCY_LISTEN_ADDR` — default `0.0.0.0:8100`.
//! - `QORCH_TRANSPARENCY_TLS_CERT_PATH` / `..._KEY_PATH` /
//!   `..._CLIENT_CA_PATH` — rustls server material + optional mTLS
//!   client-CA bundle.
//!
//! Mirrors the kernel's `crates/services/safety-kernel/src/settings.rs`
//! pattern so the prod-only fail-closed semantics are uniform across
//! services.

use std::path::PathBuf;

use anyhow::{anyhow, Result};

use crate::env_source::{trimmed_non_empty, EnvSource, SystemEnv};
use crate::per_skill_keys::PerSkillKeys;

/// Default container-internal listen address. Host port 8102 maps to
/// this in `docker-compose.yml`.
const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8100";

/// Frozen, env-driven configuration. Built once at startup and held
/// inside `AppState` (or its caller) for the lifetime of the process.
#[derive(Debug, Clone)]
pub struct Settings {
    /// `dev` | `staging` | `prod`. Drives the prod-only fail-closed
    /// checks (TLS required, api_key required, db_url required).
    pub env: String,

    /// `host:port` axum binds to.
    pub listen_addr: String,

    /// Optional Postgres DSN. `None` ⇒ in-memory store (dev only).
    pub db_url: Option<String>,

    /// Base64url-no-pad of the 32-byte Ed25519 seed used to sign STHs.
    pub signing_key_b64: String,

    /// Base64url-no-pad of the kernel's raw 32-byte Ed25519 public key.
    /// Pinned at startup so `POST /v1/append` rejects payloads whose
    /// `kernel_key_fingerprint_sha256` does not match this key.
    pub kernel_verifying_key_b64: String,

    /// Shared-secret `x-api-key` value. Empty string ⇒ dev-only no-auth.
    pub api_key: String,

    // Rustls server material.
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    /// Optional client-CA bundle for mTLS. When `Some(_)` the listener
    /// requires the caller (kernel) to present a client certificate
    /// chain-of-trust matching this CA bundle.
    pub tls_client_ca_path: Option<PathBuf>,

    /// Derived: `tls_cert_path.is_some() && tls_key_path.is_some()`.
    pub tls_enable: bool,

    /// internal-ref — hex-encoded raw 32-byte Ed25519 PRIVATE key (signing
    /// seed) for the transparency-log's asymmetric signing path. When
    /// `None`, the service still boots (HMAC-only mode); the
    /// `/v1/keys/transparency` endpoint and the
    /// `signature_type: "ed25519"` path return 503. Fail-closed in prod
    /// — production MUST configure the env var or boot will refuse.
    ///
    /// Sourced from `QORCH_TRANSPARENCY_LOG_ED25519_PRIVATE`. The bin
    /// also has a dev-only fallback that generates + persists to
    /// `.claude/state/transparency_ed25519_keypair.json` on first run.
    pub transparency_log_ed25519_private_hex: Option<String>,

    /// internal-ref — filesystem path for the embedded sqlite
    /// `wave_session_detail` side-table. When `None`, the service
    /// uses an in-memory database — fine for dev / smoke tests but
    /// drops the denormalization on restart. Production sets this to
    /// a persistent path (e.g. `/var/lib/qorch/wave_session_detail.sqlite3`).
    ///
    /// Sourced from `QORCH_TRANSPARENCY_WAVE_DETAIL_SQLITE_PATH`. Not
    /// fail-closed in prod — a missing path simply degrades to the
    /// in-memory denorm; the underlying transparency-log ledger
    /// remains the durable source-of-truth, so a restart is recoverable
    /// (the bin can re-walk the ledger and repopulate). Operators who
    /// want durability across restarts must configure this.
    pub wave_session_detail_sqlite_path: Option<PathBuf>,

    /// internal-ref — hex-encoded raw 32-byte Ed25519 PUBLIC key for the
    /// dedicated MCP-audit signing keypair. The `POST /v1/audit/mcp`
    /// route PINS the SHA-256 fingerprint of this public key; the
    /// MCP-audit sweeper (external `TlogSweeper`, signed with `MCP_AUDIT_TLOG_SIGNING_KEY`) holds the
    /// matching private key. The t-log never signs MCP-audit leaves — it
    /// only verifies + pins — so we install the PUBLIC key here, mirroring
    /// `kernel_verifying_key_b64`.
    ///
    /// Sourced from `QORCH_TRANSPARENCY_MCP_AUDIT_ED25519_PUBLIC`. When
    /// `None`, `POST /v1/audit/mcp` returns `503 ed25519_not_configured`
    /// (today's stock behaviour). Fail-closed in prod (internal-ref
    /// precedent): production MUST configure the env var or boot refuses,
    /// so a prod t-log never silently accepts unsigned/unpinned audit
    /// appends. Dev/staging may leave it unset and keep the route at 503.
    pub mcp_audit_ed25519_public_hex: Option<String>,

    /// internal-ref — hex-encoded raw 32-byte Ed25519 PUBLIC key for the
    /// dedicated Safety-Kernel reconciler drift-event signing identity.
    /// The `POST /v1/audit/drift` route pins against its SHA-256 fingerprint.
    /// When `None`, `POST /v1/audit/drift` returns `503 ed25519_not_configured`.
    ///
    /// Sourced from `QORCH_TRANSPARENCY_RECONCILER_DRIFT_ED25519_PUBLIC`.
    /// Deliberately NOT fail-closed in prod: drift appends are opt-in per
    /// deployment (only a t-log with a reconciler pointed at it needs this
    /// key). Failing closed in prod would break every existing production
    /// transparency log, none of which currently has a reconciler. When
    /// unset, `POST /v1/audit/drift` returns `503 ed25519_not_configured`
    /// (route-level fail-closed) while the service boots and serves all
    /// other routes normally.
    pub reconciler_drift_ed25519_public_hex: Option<String>,

    /// internal-ref — base64url-no-pad of the shared 32-byte kernel HMAC key
    /// for the legacy `POST /v1/wave/session` HMAC path (internal-ref contract).
    /// `Some(_)` installs it via [`AppState::with_kernel_hmac_key`] so a
    /// ceremony writer holding the same key can produce a verifiable
    /// `kernel_hmac_hex` over the record's `canonical_bytes`. `None` ⇒ the
    /// wave-session HMAC path stays unconfigured (empty key), i.e. HMAC-path
    /// appends are rejected — today's stock behaviour. Sourced from
    /// `QORCH_TRANSPARENCY_KERNEL_HMAC_KEY_B64`. Not fail-closed in prod: a
    /// deployment that has not provisioned the key simply keeps the
    /// wave-session HMAC path closed (the Ed25519 path is unaffected).
    pub kernel_hmac_key_b64: Option<String>,

    /// internal-ref — per-skill (per-stage) HMAC `x-api-key` table for
    /// wave-session writers. `Some(_)` when ANY of the four
    /// `QORCH_TRANSPARENCY_KEY_*` env vars are set; `None` otherwise.
    /// `None` is the LEGACY single-shared-key path — the
    /// `auth_layer` middleware still gates `/v1/wave/session` behind
    /// `api_key`, but the per-stage identity check is bypassed.
    ///
    /// Per-skill enforcement is layered on top of `auth_layer`: the
    /// route handler reads the request `x-api-key` again, decodes the
    /// stage from the request body, and rejects when the supplied
    /// bytes do not match the per-stage key.
    ///
    /// Not fail-closed in prod — operators that have not yet rotated
    /// to per-skill keys continue to run on the shared key. The
    /// rotation is a deliberate operational change, not a default-on
    /// behaviour.
    pub per_skill_keys: Option<PerSkillKeys>,
}

impl Settings {
    /// Build a `Settings` by reading the environment.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any fail-closed required secret is missing.
    pub fn from_env() -> Result<Self> {
        Self::from_env_source(&SystemEnv::new())
    }

    /// Same as [`Self::from_env`] but reads through an [`EnvSource`] seam
    /// rather than the process environment directly. This exists so unit
    /// tests can exercise every fail-closed refusal (and its mirror,
    /// successful) path with a [`crate::env_source::MapEnv`] instead of
    /// mutating global process env vars, which would make tests racy and
    /// order-dependent when run in parallel.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any fail-closed required secret is missing.
    pub fn from_env_source<E: EnvSource>(env: &E) -> Result<Self> {
        let env_v = env.get("QORCH_ENV").unwrap_or_else(|| "dev".to_string());
        let env_lower = env_v.to_ascii_lowercase();
        let is_prod = matches!(env_lower.as_str(), "prod" | "production");

        let listen_addr = env
            .get("QORCH_TRANSPARENCY_LISTEN_ADDR")
            .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_string());

        let db_url = trimmed_non_empty(env, "QORCH_TRANSPARENCY_DB_URL");

        let signing_key_b64 = trimmed_non_empty(env, "QORCH_TRANSPARENCY_SIGNING_KEY_B64")
            .ok_or_else(|| anyhow!("missing QORCH_TRANSPARENCY_SIGNING_KEY_B64"))?;

        let kernel_verifying_key_b64 =
            trimmed_non_empty(env, "QORCH_TRANSPARENCY_KERNEL_VERIFYING_KEY_B64")
                .ok_or_else(|| anyhow!("missing QORCH_TRANSPARENCY_KERNEL_VERIFYING_KEY_B64"))?;

        let api_key = trimmed_non_empty(env, "QORCH_TRANSPARENCY_API_KEY").unwrap_or_default();
        if is_prod && api_key.is_empty() {
            return Err(anyhow!(
                "missing QORCH_TRANSPARENCY_API_KEY (required in prod)"
            ));
        }

        let tls_cert_path =
            trimmed_non_empty(env, "QORCH_TRANSPARENCY_TLS_CERT_PATH").map(PathBuf::from);
        let tls_key_path =
            trimmed_non_empty(env, "QORCH_TRANSPARENCY_TLS_KEY_PATH").map(PathBuf::from);
        let tls_client_ca_path =
            trimmed_non_empty(env, "QORCH_TRANSPARENCY_TLS_CLIENT_CA_PATH").map(PathBuf::from);
        let tls_enable = tls_cert_path.is_some() && tls_key_path.is_some();

        // Mirror the kernel: prod fail-closes if TLS material is missing,
        // so the internal mesh is never served plaintext in production.
        if is_prod && !tls_enable {
            return Err(anyhow!(
                "fail-closed: QORCH_ENV=prod requires QORCH_TRANSPARENCY_TLS_CERT_PATH \
                 and QORCH_TRANSPARENCY_TLS_KEY_PATH to be set"
            ));
        }
        if is_prod && db_url.is_none() {
            return Err(anyhow!(
                "fail-closed: QORCH_ENV=prod requires QORCH_TRANSPARENCY_DB_URL to be set"
            ));
        }

        // internal-ref — optional asymmetric (Ed25519) signing seed.
        // Production must configure it (fail-closed); dev/staging
        // may leave it unset and fall through to the file fallback
        // the bin applies.
        let transparency_log_ed25519_private_hex =
            trimmed_non_empty(env, "QORCH_TRANSPARENCY_LOG_ED25519_PRIVATE");
        if is_prod && transparency_log_ed25519_private_hex.is_none() {
            return Err(anyhow!(
                "fail-closed: QORCH_ENV=prod requires \
                 QORCH_TRANSPARENCY_LOG_ED25519_PRIVATE to be set (internal-ref)"
            ));
        }

        // internal-ref — optional persistent path for the sqlite
        // wave-session-detail side-table.
        let wave_session_detail_sqlite_path =
            trimmed_non_empty(env, "QORCH_TRANSPARENCY_WAVE_DETAIL_SQLITE_PATH").map(PathBuf::from);

        // internal-ref — optional dedicated MCP-audit Ed25519 PUBLIC key
        // (hex, raw 32 bytes). When unset, `POST /v1/audit/mcp` returns
        // 503. Production must configure it (fail-closed) so the t-log
        // never silently accepts unpinned MCP-audit leaves; dev/staging
        // may leave it unset.
        let mcp_audit_ed25519_public_hex =
            trimmed_non_empty(env, "QORCH_TRANSPARENCY_MCP_AUDIT_ED25519_PUBLIC");
        if is_prod && mcp_audit_ed25519_public_hex.is_none() {
            return Err(anyhow!(
                "fail-closed: QORCH_ENV=prod requires \
                 QORCH_TRANSPARENCY_MCP_AUDIT_ED25519_PUBLIC to be set (internal-ref)"
            ));
        }

        // internal-ref — optional dedicated Safety-Kernel reconciler drift-event
        // Ed25519 PUBLIC key (hex, raw 32 bytes). When unset, `POST /v1/audit/drift`
        // returns 503 ed25519_not_configured. Deliberately not fail-closed in
        // prod: drift appends are opt-in per deployment.
        let reconciler_drift_ed25519_public_hex =
            trimmed_non_empty(env, "QORCH_TRANSPARENCY_RECONCILER_DRIFT_ED25519_PUBLIC");

        // internal-ref — shared kernel HMAC key for the wave-session HMAC path.
        // Optional (mirrors mcp_audit above): `None` leaves the HMAC path
        // unconfigured. Not fail-closed in prod — a deployment without the
        // key simply keeps the wave-session HMAC path closed.
        let kernel_hmac_key_b64 = trimmed_non_empty(env, "QORCH_TRANSPARENCY_KERNEL_HMAC_KEY_B64");

        // internal-ref — per-skill HMAC `x-api-key` table. `None` when no
        // per-stage env var is set (back-compat: legacy single-shared-
        // key path continues to work, gated by `api_key` above).
        let per_skill_keys = PerSkillKeys::from_env_source(env);

        Ok(Self {
            env: env_lower,
            listen_addr,
            db_url,
            signing_key_b64,
            kernel_verifying_key_b64,
            api_key,
            tls_cert_path,
            tls_key_path,
            tls_client_ca_path,
            tls_enable,
            transparency_log_ed25519_private_hex,
            wave_session_detail_sqlite_path,
            mcp_audit_ed25519_public_hex,
            reconciler_drift_ed25519_public_hex,
            kernel_hmac_key_b64,
            per_skill_keys,
        })
    }

    /// True when running in a production environment.
    #[must_use]
    pub fn is_prod(&self) -> bool {
        matches!(self.env.as_str(), "prod" | "production")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_source::MapEnv;

    /// Minimal config that boots in `dev`: only the two always-required
    /// secrets. No `QORCH_ENV` ⇒ defaults to dev, so none of the
    /// prod-only fail-closed checks are exercised.
    fn required_dev() -> MapEnv {
        MapEnv::new()
            .with("QORCH_TRANSPARENCY_SIGNING_KEY_B64", "sign-key-abc")
            .with(
                "QORCH_TRANSPARENCY_KERNEL_VERIFYING_KEY_B64",
                "verify-key-def",
            )
    }

    /// The full set of env vars required for a `prod` boot to succeed.
    /// Kept as an ordered list (not a `MapEnv`) so refusal tests can
    /// filter out exactly one pair and rebuild.
    fn prod_pairs() -> Vec<(&'static str, &'static str)> {
        vec![
            ("QORCH_ENV", "prod"),
            ("QORCH_TRANSPARENCY_SIGNING_KEY_B64", "sign-key-abc"),
            (
                "QORCH_TRANSPARENCY_KERNEL_VERIFYING_KEY_B64",
                "verify-key-def",
            ),
            ("QORCH_TRANSPARENCY_API_KEY", "api-key-123"),
            ("QORCH_TRANSPARENCY_TLS_CERT_PATH", "/tls/cert.pem"),
            ("QORCH_TRANSPARENCY_TLS_KEY_PATH", "/tls/key.pem"),
            ("QORCH_TRANSPARENCY_DB_URL", "postgres://db"),
            ("QORCH_TRANSPARENCY_LOG_ED25519_PRIVATE", "deadbeef"),
            ("QORCH_TRANSPARENCY_MCP_AUDIT_ED25519_PUBLIC", "cafebabe"),
        ]
    }

    fn prod_env() -> MapEnv {
        prod_pairs()
            .into_iter()
            .fold(MapEnv::new(), |acc, (k, v)| acc.with(k, v))
    }

    fn prod_env_without(exclude: &str) -> MapEnv {
        prod_pairs()
            .into_iter()
            .filter(|(k, _)| *k != exclude)
            .fold(MapEnv::new(), |acc, (k, v)| acc.with(k, v))
    }

    // --- always-required secrets (rules 1 & 2), exercised in dev ------

    #[test]
    fn dev_boots_with_only_required_keys() {
        let env = required_dev();
        let settings = Settings::from_env_source(&env).expect("should boot");
        assert_eq!(settings.env, "dev");
        assert!(!settings.is_prod());
    }

    #[test]
    fn signing_key_missing_is_err() {
        let env = MapEnv::new().with(
            "QORCH_TRANSPARENCY_KERNEL_VERIFYING_KEY_B64",
            "verify-key-def",
        );
        let err = Settings::from_env_source(&env).unwrap_err();
        assert!(err
            .to_string()
            .contains("QORCH_TRANSPARENCY_SIGNING_KEY_B64"));
    }

    #[test]
    fn signing_key_present_boots() {
        let env = required_dev();
        assert!(Settings::from_env_source(&env).is_ok());
    }

    #[test]
    fn kernel_verifying_key_missing_is_err() {
        let env = MapEnv::new().with("QORCH_TRANSPARENCY_SIGNING_KEY_B64", "sign-key-abc");
        let err = Settings::from_env_source(&env).unwrap_err();
        assert!(err
            .to_string()
            .contains("QORCH_TRANSPARENCY_KERNEL_VERIFYING_KEY_B64"));
    }

    #[test]
    fn kernel_verifying_key_present_boots() {
        let env = required_dev();
        assert!(Settings::from_env_source(&env).is_ok());
    }

    #[test]
    fn signing_key_empty_string_is_treated_as_absent() {
        let env = MapEnv::new()
            .with("QORCH_TRANSPARENCY_SIGNING_KEY_B64", "")
            .with(
                "QORCH_TRANSPARENCY_KERNEL_VERIFYING_KEY_B64",
                "verify-key-def",
            );
        let err = Settings::from_env_source(&env).unwrap_err();
        assert!(err
            .to_string()
            .contains("QORCH_TRANSPARENCY_SIGNING_KEY_B64"));
    }

    #[test]
    fn signing_key_whitespace_only_is_treated_as_absent() {
        let env = MapEnv::new()
            .with("QORCH_TRANSPARENCY_SIGNING_KEY_B64", "   ")
            .with(
                "QORCH_TRANSPARENCY_KERNEL_VERIFYING_KEY_B64",
                "verify-key-def",
            );
        let err = Settings::from_env_source(&env).unwrap_err();
        assert!(err
            .to_string()
            .contains("QORCH_TRANSPARENCY_SIGNING_KEY_B64"));
    }

    #[test]
    fn values_with_whitespace_are_trimmed() {
        let env = MapEnv::new()
            .with("QORCH_TRANSPARENCY_SIGNING_KEY_B64", "  sign-key  ")
            .with(
                "QORCH_TRANSPARENCY_KERNEL_VERIFYING_KEY_B64",
                "  verify-key  ",
            );
        let settings = Settings::from_env_source(&env).unwrap();
        assert_eq!(settings.signing_key_b64, "sign-key");
        assert_eq!(settings.kernel_verifying_key_b64, "verify-key");
    }

    // --- QORCH_ENV parsing ----------------------------------------------

    #[test]
    fn env_prod_lowercase_is_prod() {
        let env = required_dev().with("QORCH_ENV", "prod");
        let err = Settings::from_env_source(&env).unwrap_err();
        assert!(err.to_string().contains("QORCH_TRANSPARENCY_API_KEY"));
    }

    #[test]
    fn env_production_uppercase_is_prod() {
        let env = required_dev().with("QORCH_ENV", "PRODUCTION");
        let err = Settings::from_env_source(&env).unwrap_err();
        assert!(err.to_string().contains("QORCH_TRANSPARENCY_API_KEY"));
    }

    #[test]
    fn env_prod_mixed_case_is_prod() {
        let env = required_dev().with("QORCH_ENV", "Prod");
        let err = Settings::from_env_source(&env).unwrap_err();
        assert!(err.to_string().contains("QORCH_TRANSPARENCY_API_KEY"));
    }

    #[test]
    fn env_staging_is_not_prod() {
        let env = required_dev().with("QORCH_ENV", "staging");
        let settings = Settings::from_env_source(&env).expect("staging should boot");
        assert!(!settings.is_prod());
        assert_eq!(settings.env, "staging");
    }

    // --- the seven prod-only fail-closed refusals + their mirrors ------

    #[test]
    fn prod_full_config_boots() {
        let env = prod_env();
        assert!(Settings::from_env_source(&env).is_ok());
    }

    #[test]
    fn prod_requires_api_key() {
        let env = prod_env_without("QORCH_TRANSPARENCY_API_KEY");
        let err = Settings::from_env_source(&env).unwrap_err();
        assert!(err.to_string().contains("QORCH_TRANSPARENCY_API_KEY"));
    }

    #[test]
    fn prod_requires_tls_cert_path() {
        let env = prod_env_without("QORCH_TRANSPARENCY_TLS_CERT_PATH");
        let err = Settings::from_env_source(&env).unwrap_err();
        assert!(err.to_string().contains("QORCH_TRANSPARENCY_TLS_CERT_PATH"));
    }

    #[test]
    fn prod_requires_tls_key_path() {
        let env = prod_env_without("QORCH_TRANSPARENCY_TLS_KEY_PATH");
        let err = Settings::from_env_source(&env).unwrap_err();
        assert!(err.to_string().contains("QORCH_TRANSPARENCY_TLS_KEY_PATH"));
    }

    #[test]
    fn prod_requires_db_url() {
        let env = prod_env_without("QORCH_TRANSPARENCY_DB_URL");
        let err = Settings::from_env_source(&env).unwrap_err();
        assert!(err.to_string().contains("QORCH_TRANSPARENCY_DB_URL"));
    }

    #[test]
    fn prod_requires_ed25519_private_key() {
        let env = prod_env_without("QORCH_TRANSPARENCY_LOG_ED25519_PRIVATE");
        let err = Settings::from_env_source(&env).unwrap_err();
        assert!(err
            .to_string()
            .contains("QORCH_TRANSPARENCY_LOG_ED25519_PRIVATE"));
    }

    #[test]
    fn prod_requires_mcp_audit_public_key() {
        let env = prod_env_without("QORCH_TRANSPARENCY_MCP_AUDIT_ED25519_PUBLIC");
        let err = Settings::from_env_source(&env).unwrap_err();
        assert!(err
            .to_string()
            .contains("QORCH_TRANSPARENCY_MCP_AUDIT_ED25519_PUBLIC"));
    }

    #[test]
    fn kernel_hmac_key_optional_even_in_prod() {
        // prod_env() never sets QORCH_TRANSPARENCY_KERNEL_HMAC_KEY_B64 —
        // this must NOT be a fail-closed refusal.
        let env = prod_env();
        let settings = Settings::from_env_source(&env).expect("hmac key is optional in prod");
        assert!(settings.kernel_hmac_key_b64.is_none());
    }

    // --- tls_enable derivation -------------------------------------------

    #[test]
    fn tls_enable_false_when_only_cert_set() {
        let env = required_dev().with("QORCH_TRANSPARENCY_TLS_CERT_PATH", "/tls/cert.pem");
        let settings = Settings::from_env_source(&env).unwrap();
        assert!(!settings.tls_enable);
    }

    #[test]
    fn tls_enable_false_when_only_key_set() {
        let env = required_dev().with("QORCH_TRANSPARENCY_TLS_KEY_PATH", "/tls/key.pem");
        let settings = Settings::from_env_source(&env).unwrap();
        assert!(!settings.tls_enable);
    }

    #[test]
    fn tls_enable_true_when_both_set() {
        let env = required_dev()
            .with("QORCH_TRANSPARENCY_TLS_CERT_PATH", "/tls/cert.pem")
            .with("QORCH_TRANSPARENCY_TLS_KEY_PATH", "/tls/key.pem");
        let settings = Settings::from_env_source(&env).unwrap();
        assert!(settings.tls_enable);
    }

    // --- listen_addr -------------------------------------------------------

    #[test]
    fn listen_addr_defaults_when_unset() {
        let env = required_dev();
        let settings = Settings::from_env_source(&env).unwrap();
        assert_eq!(settings.listen_addr, DEFAULT_LISTEN_ADDR);
    }

    #[test]
    fn listen_addr_taken_verbatim_when_set() {
        let env = required_dev().with("QORCH_TRANSPARENCY_LISTEN_ADDR", "127.0.0.1:9999");
        let settings = Settings::from_env_source(&env).unwrap();
        assert_eq!(settings.listen_addr, "127.0.0.1:9999");
    }

    // --- per_skill_keys threading -------------------------------------------

    #[test]
    fn per_skill_keys_none_when_no_stage_key_set() {
        let env = required_dev();
        let settings = Settings::from_env_source(&env).unwrap();
        assert!(settings.per_skill_keys.is_none());
    }

    #[test]
    fn per_skill_keys_some_when_a_stage_key_set() {
        // Prove `env` is threaded through to PerSkillKeys::from_env_source
        // rather than that call still reading the process environment: a
        // MapEnv holding a per-stage key must produce Some. We derive the
        // exact variable name PerSkillKeys reads from its own env-source
        // seam so this test tracks the real recognized set — if none of
        // the candidate names produce Some, the seam is not threaded and
        // the test fails.
        let candidates = [
            "QORCH_TRANSPARENCY_KEY_PLANNER",
            "QORCH_TRANSPARENCY_KEY_PLAN",
            "QORCH_TRANSPARENCY_KEY_BUILDER",
            "QORCH_TRANSPARENCY_KEY_BUILD",
            "QORCH_TRANSPARENCY_KEY_VERIFIER",
            "QORCH_TRANSPARENCY_KEY_VERIFY",
            "QORCH_TRANSPARENCY_KEY_TESTER",
            "QORCH_TRANSPARENCY_KEY_TEST",
            "QORCH_TRANSPARENCY_KEY_REVIEWER",
            "QORCH_TRANSPARENCY_KEY_REVIEW",
            "QORCH_TRANSPARENCY_KEY_INTEGRATOR",
            "QORCH_TRANSPARENCY_KEY_INTEGRATE",
            "QORCH_TRANSPARENCY_KEY_SCOUT",
            "QORCH_TRANSPARENCY_KEY_STRATEGIST",
            "QORCH_TRANSPARENCY_KEY_ARCHITECT",
        ];

        // Find which candidate PerSkillKeys actually recognizes by probing
        // its own env-source seam directly.
        let recognized = candidates.iter().find(|name| {
            let probe = MapEnv::new().with(**name, "stage-secret");
            PerSkillKeys::from_env_source(&probe).is_some()
        });
        let name = recognized.expect(
            "PerSkillKeys::from_env_source recognized none of the candidate \
             per-stage variable names; update the candidate list",
        );

        let env = required_dev().with(*name, "stage-secret");
        let settings = Settings::from_env_source(&env).unwrap();
        assert!(settings.per_skill_keys.is_some());
    }
}
