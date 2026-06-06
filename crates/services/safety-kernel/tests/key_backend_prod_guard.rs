//! Step-14R / ARY-1886 — `KERNEL_KEY_BACKEND` config-gate fixtures.
//!
//! These are the Rule-8 adversarial fixtures for the key-backend change:
//! the production env-guard and the fail-closed behavior for backends
//! that are not implemented in this build. No network — pure
//! `Settings::from_env` config resolution.
//!
//! Run in one serial test (it mutates process env): each assertion sets
//! exactly the env it needs and clears the rest first.

use qorch_safety_kernel::settings::Settings;

/// Clear every env var `from_env` reads that could leak between cases.
fn clear_kernel_env() {
    for k in [
        "QORCH_ENV",
        "KERNEL_KEY_BACKEND",
        "KERNEL_KEY_GCP_PROJECT",
        "KERNEL_KEY_GCP_SECRET",
        "KERNEL_KEY_GCP_SECRET_VERSION",
        "QORCH_KERNEL_SIGNING_KEY_B64",
        "QORCH_KERNEL_AUDIT_PEPPER_B64",
        "QORCH_KERNEL_API_KEY_WORKER",
        "QORCH_KERNEL_API_KEY_API",
        "QORCH_KERNEL_API_KEY_OPERATOR",
        "QORCH_KERNEL_TRANSPARENCY_ENABLED",
    ] {
        std::env::remove_var(k);
    }
}

/// Set the fail-closed secrets that are unrelated to the key backend so
/// `from_env` can proceed to (or past) the backend block on the Ok paths.
fn set_other_required_secrets() {
    std::env::set_var("QORCH_KERNEL_AUDIT_PEPPER_B64", "AAAAAAAAAAAAAAAAAAAAAA");
    std::env::set_var("QORCH_KERNEL_API_KEY_WORKER", "w");
    std::env::set_var("QORCH_KERNEL_API_KEY_API", "a");
}

const SEED_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 zero bytes

#[test]
fn key_backend_config_gates() {
    // ── ADVERSARIAL (Rule 8): env backend in prod must be REJECTED ──
    clear_kernel_env();
    set_other_required_secrets();
    std::env::set_var("QORCH_ENV", "prod");
    std::env::set_var("KERNEL_KEY_BACKEND", "env");
    std::env::set_var("QORCH_KERNEL_SIGNING_KEY_B64", SEED_B64);
    // operator key would also be required in prod; the backend guard
    // fires first, so we don't even get there.
    let err = Settings::from_env().expect_err("env backend in prod must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("KERNEL_KEY_BACKEND=env is forbidden") && msg.contains("prod"),
        "prod env-guard error must be explicit, got: {msg}"
    );

    // PT-1 regression: whitespace-padded prod must STILL be treated as
    // prod (env var is trimmed before the prod check) — otherwise the
    // guard is trivially bypassed with QORCH_ENV=" prod".
    std::env::set_var("QORCH_ENV", " prod ");
    let ws_err =
        Settings::from_env().expect_err("whitespace-padded prod must still reject env backend");
    assert!(
        ws_err.to_string().contains("KERNEL_KEY_BACKEND=env is forbidden"),
        "whitespace prod must not bypass the guard, got: {ws_err}"
    );

    // Same config in staging is allowed (env backend is the dev/staging
    // default).
    std::env::set_var("QORCH_ENV", "staging");
    let s = Settings::from_env().expect("env backend allowed in staging");
    assert_eq!(s.key_backend.as_str(), "env");
    assert_eq!(s.signing_key_b64, SEED_B64);

    // ── gcp backend: does NOT require the seed env var, DOES require
    //    project + secret. signing_key_b64 stays empty until boot. ──
    clear_kernel_env();
    set_other_required_secrets();
    std::env::set_var("QORCH_ENV", "prod"); // gcp is allowed in prod
    std::env::set_var("KERNEL_KEY_BACKEND", "gcp");
    std::env::set_var("QORCH_KERNEL_API_KEY_OPERATOR", "op"); // required in prod
    // Transparency-log prod requirement is orthogonal to the key
    // backend; disable it so this case isolates backend behavior.
    std::env::set_var("QORCH_KERNEL_TRANSPARENCY_ENABLED", "false");
    // no QORCH_KERNEL_SIGNING_KEY_B64 set on purpose
    let missing = Settings::from_env().expect_err("gcp backend requires project+secret");
    assert!(
        missing.to_string().contains("KERNEL_KEY_GCP_PROJECT"),
        "missing gcp project must be named, got: {missing}"
    );
    std::env::set_var("KERNEL_KEY_GCP_PROJECT", "proj");
    std::env::set_var("KERNEL_KEY_GCP_SECRET", "sec");
    let g = Settings::from_env().expect("gcp backend config complete");
    assert_eq!(g.key_backend.as_str(), "gcp");
    assert!(
        g.signing_key_b64.is_empty(),
        "gcp backend must not populate signing_key_b64 from env"
    );
    assert_eq!(g.key_gcp_secret_version, "latest");

    // ── unimplemented backends fail CLOSED (no env-var fallback) ──
    for backend in ["aws", "azure", "pkcs11", "tpm"] {
        clear_kernel_env();
        set_other_required_secrets();
        std::env::set_var("QORCH_ENV", "staging");
        std::env::set_var("KERNEL_KEY_BACKEND", backend);
        std::env::set_var("QORCH_KERNEL_SIGNING_KEY_B64", SEED_B64);
        let e = Settings::from_env()
            .expect_err("unimplemented backend must fail closed, not fall back to env");
        assert!(
            e.to_string().contains("not implemented"),
            "{backend} must fail closed with 'not implemented', got: {e}"
        );
    }

    // ── unknown backend name is a hard parse error ──
    clear_kernel_env();
    set_other_required_secrets();
    std::env::set_var("KERNEL_KEY_BACKEND", "vault");
    assert!(Settings::from_env().is_err(), "unknown backend must error");

    clear_kernel_env();
}

