//! FULL-STACK generation-fence end-to-end test.
//!
//! Drives the REAL kernel handlers (`mint_revoke` -> `restore_revoke` ->
//! `pending_revoke`) and feeds their genuine, signed output into the REAL
//! control-plane Reaper. This exercises the PRODUCER (the kernel that stamps a
//! kill with the live grant generation and increments it on restore) into the
//! CONSUMER (the reaper that fences a stale kill), rather than a hand-built
//! token that would only prove the consumer.
//!
//! The scenario the reviewer flagged, driven live:
//!   1. `mint_revoke` stamps a kill with the target's current generation (0).
//!   2. `restore_revoke` establishes a NEW grant -> the live generation is 1.
//!   3. `pending_revoke` hands the reaper the still-valid kill token AND
//!      `current_grant_generation = 1`.
//!   4. The reaper fences the kill as `StaleGeneration` and issues ZERO stops.
//!
//! Plus the positive control: a kill minted AFTER the restore (stamped 1) fires.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::too_many_lines)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Extension, Json, Query, State};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};

use qorch_adapters::clock::SystemClock;
use qorch_adapters::nonce::OsRngNonceSource;
use qorch_adapters::policy_engine_client::PolicyEngineClient;
use qorch_domain::safety::{
    Clock, InstanceTarget, MintRevokeRequest, NonceSource, PendingQuery, PendingRevokeResponse,
    RestoreRequest, RevocationTier, RevokeTrigger, SignedRevokeResponse,
};
use qorch_safety_kernel::auth::CallerRole;
use qorch_safety_kernel::routes::revoke::{mint_revoke, pending_revoke, restore_revoke};
use qorch_safety_kernel::settings::Settings;
use qorch_safety_kernel::state::AppState;

use qorch_safety_kernel_client::PinnedKeyVerifier;
use qorch_safety_kernel_reaper::{
    ComputeExecutor, MemNonceStore, MockComputeExecutor, Outcome, Reaper, RejectReason,
};

/// Deterministic signing seed so the reaper can pin the kernel's public key.
const KERNEL_SEED: [u8; 32] = [7u8; 32];

/// A UNIQUE instance name so this test does not collide with any other test in
/// the same binary on the process-global pending/generation stores.
const E2E_INSTANCE: &str = "gen-fence-e2e-vm";

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn e2e_target() -> InstanceTarget {
    InstanceTarget {
        project: "example-project".to_string(),
        zone: "zone-a".to_string(),
        instance: E2E_INSTANCE.to_string(),
    }
}

fn test_settings() -> Settings {
    let zero_seed_b64 = URL_SAFE_NO_PAD.encode([0u8; 32]);
    Settings {
        env: "dev".to_string(),
        db_backend: "sqlite".to_string(),
        db_path: ".qorch/test_audit.sqlite3".to_string(),
        pg_dsn: None,
        auth_mode: "api_key".to_string(),
        api_key_worker: Some("test-worker-key".to_string()),
        api_key_api: Some("test-api-key".to_string()),
        api_key_operator: Some("test-operator-key".to_string()),
        api_key_reaper: Some("test-reaper-key".to_string()),
        signing_key_b64: URL_SAFE_NO_PAD.encode(KERNEL_SEED),
        key_backend: qorch_safety_kernel::key_backend::KeyBackendKind::Env,
        key_gcp_project: None,
        key_gcp_secret: None,
        key_gcp_secret_version: "latest".to_string(),
        audit_pepper_b64: zero_seed_b64,
        default_token_ttl_s: 60,
        max_token_ttl_s: 300,
        approval_token_ttl_s: 365 * 24 * 60 * 60,
        revoke_token_ttl_s: 120,
        build_version: "test-generation-fence".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        // A non-existent socket: the audit-append IPC fails and is fail-OPEN
        // (logged, non-fatal), which is exactly the mint/restore contract. The
        // transparency-log is disabled (below), so the fail-closed tlog gate
        // short-circuits to success and the kill/restore IS emitted.
        policy_sock_path: PathBuf::from("/tmp/qorch-test-nonexistent-genfence.sock"),
        tls_cert_path: None,
        tls_key_path: None,
        tls_client_ca_path: None,
        tls_sni: "safety-kernel-rust.internal".to_string(),
        tls_enable: false,
        transparency_enabled: false,
        transparency_log_url: None,
        transparency_log_api_key: None,
        transparency_log_timeout_seconds: 2.0,
        transparency_log_client_cert_path: None,
        transparency_log_client_key_path: None,
    }
}

fn test_state() -> (AppState, [u8; 32]) {
    let signing_key = SigningKey::from_bytes(&KERNEL_SEED);
    let verifying_key = signing_key.verifying_key();
    let pk_raw = verifying_key.to_bytes();
    let pk_b64 = URL_SAFE_NO_PAD.encode(pk_raw);
    let mut h = Sha256::new();
    h.update(pk_raw);
    let pk_fpr = hex::encode(h.finalize());

    let clock_arc: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let started_at = clock_arc.now();
    let nonce_arc: Arc<dyn NonceSource> = Arc::new(OsRngNonceSource::new());

    let state = AppState {
        settings: Arc::new(test_settings()),
        signing_key: Arc::new(signing_key),
        public_key_b64: pk_b64,
        public_key_fingerprint: pk_fpr,
        audit_pepper: Arc::new(vec![0u8; 32]),
        started_at,
        clock: clock_arc,
        nonce: nonce_arc,
        policy_client: Arc::new(PolicyEngineClient::new(PathBuf::from(
            "/tmp/qorch-test-nonexistent-genfence.sock",
        ))),
        transparency_client: None,
    };
    (state, pk_raw)
}

/// Collect a handler `Response` body into bytes.
async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec()
}

async fn mint_kill(state: &AppState) -> SignedRevokeResponse {
    let body = MintRevokeRequest {
        target: e2e_target(),
        tier: RevocationTier::VmStop,
        trigger: RevokeTrigger::OperatorEmergencyStop,
        reason: Some("e-stop".to_string()),
    };
    let resp = mint_revoke(
        State(state.clone()),
        Extension(CallerRole("operator".to_string())),
        Json(body),
    )
    .await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK, "mint must 200");
    serde_json::from_slice(&body_bytes(resp).await).expect("mint body parses")
}

async fn restore(state: &AppState) {
    let body = RestoreRequest {
        target: e2e_target(),
        reason: Some("cleared".to_string()),
    };
    let resp = restore_revoke(
        State(state.clone()),
        Extension(CallerRole("operator".to_string())),
        Json(body),
    )
    .await;
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::OK,
        "restore must 200"
    );
}

async fn pull_pending(state: &AppState) -> PendingRevokeResponse {
    let resp = pending_revoke(
        State(state.clone()),
        Extension(CallerRole("reaper".to_string())),
        Query(PendingQuery {
            instance: E2E_INSTANCE.to_string(),
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::OK,
        "pending must 200 (queue non-empty)"
    );
    serde_json::from_slice(&body_bytes(resp).await).expect("pending body parses")
}

fn build_reaper(pinned_pubkey: [u8; 32], mock: Arc<MockComputeExecutor>) -> Reaper {
    let verifier = PinnedKeyVerifier::from_pubkey_bytes(pinned_pubkey).expect("valid pubkey");
    Reaper::new(
        verifier,
        mock as Arc<dyn ComputeExecutor>,
        Arc::new(MemNonceStore::new()),
        e2e_target(),
        300.0,
        None,
        None,
    )
}

fn gen_of(resp: &SignedRevokeResponse) -> u64 {
    resp.claims
        .get("target_generation")
        .and_then(serde_json::Value::as_u64)
        .expect("kill claims carry target_generation")
}

#[tokio::test]
async fn kernel_minted_stale_kill_is_fenced_end_to_end() {
    let (state, pinned_pubkey) = test_state();

    // 1. Operator mints a kill — the kernel stamps it with the first-grant
    //    generation 0.
    let kill = mint_kill(&state).await;
    assert_eq!(
        gen_of(&kill),
        0,
        "the first-ever grant stamps the kill at generation 0"
    );

    // 2. Operator restores — the kernel establishes a NEW grant (generation 1).
    restore(&state).await;

    // 3. The reaper pulls: the still-valid kill token is pending, and the pull
    //    carries the kernel's AUTHORITATIVE live generation (1).
    let pending = pull_pending(&state).await;
    assert_eq!(
        pending.current_grant_generation, 1,
        "after a restore the kernel reports live generation 1"
    );
    assert!(
        pending.pending.contains(&kill.token),
        "the pre-restore kill token is still pending"
    );

    // 4. Drive the REAL reaper decision path with the kernel-produced token and
    //    the kernel-reported live generation. It MUST fence the stale kill.
    let mock = Arc::new(MockComputeExecutor::new());
    let reaper = build_reaper(pinned_pubkey, Arc::clone(&mock));
    let now = now_epoch();

    let outcome = reaper
        .handle_pending_candidate(&kill.token, pending.current_grant_generation, now)
        .await;

    assert_eq!(
        outcome,
        Outcome::Rejected(RejectReason::StaleGeneration),
        "a kernel-minted kill from the pre-restore grant MUST be fenced"
    );
    assert_eq!(
        mock.stop_count(),
        0,
        "ZERO stops: the restored instance keeps running"
    );
}

#[tokio::test]
async fn kernel_minted_current_generation_kill_still_fires_end_to_end() {
    // A DIFFERENT instance so this test is independent on the process-global
    // stores.
    let (state, pinned_pubkey) = test_state();
    let target = InstanceTarget {
        instance: "gen-fence-e2e-positive-vm".to_string(),
        ..e2e_target()
    };

    // Establish generation 1 via a restore, then mint a kill — it is stamped at
    // the CURRENT generation (1) and pull reports live generation 1.
    let restore_body = RestoreRequest {
        target: target.clone(),
        reason: None,
    };
    let r = restore_revoke(
        State(state.clone()),
        Extension(CallerRole("operator".to_string())),
        Json(restore_body),
    )
    .await;
    assert_eq!(r.status(), axum::http::StatusCode::OK);

    let mint_body = MintRevokeRequest {
        target: target.clone(),
        tier: RevocationTier::VmStop,
        trigger: RevokeTrigger::OperatorEmergencyStop,
        reason: None,
    };
    let mint_resp = mint_revoke(
        State(state.clone()),
        Extension(CallerRole("operator".to_string())),
        Json(mint_body),
    )
    .await;
    assert_eq!(mint_resp.status(), axum::http::StatusCode::OK);
    let kill: SignedRevokeResponse =
        serde_json::from_slice(&body_bytes(mint_resp).await).expect("mint body parses");
    assert_eq!(
        gen_of(&kill),
        1,
        "a kill minted after the restore is stamped at the live generation 1"
    );

    let pull = pending_revoke(
        State(state.clone()),
        Extension(CallerRole("reaper".to_string())),
        Query(PendingQuery {
            instance: target.instance.clone(),
        }),
    )
    .await;
    let pending: PendingRevokeResponse =
        serde_json::from_slice(&body_bytes(pull).await).expect("pending parses");
    assert_eq!(pending.current_grant_generation, 1);

    let mock = Arc::new(MockComputeExecutor::new());
    let verifier = PinnedKeyVerifier::from_pubkey_bytes(pinned_pubkey).expect("valid pubkey");
    let reaper = Reaper::new(
        verifier,
        Arc::clone(&mock) as Arc<dyn ComputeExecutor>,
        Arc::new(MemNonceStore::new()),
        target.clone(),
        300.0,
        None,
        None,
    );

    let outcome = reaper
        .handle_pending_candidate(&kill.token, pending.current_grant_generation, now_epoch())
        .await;
    assert!(
        matches!(outcome, Outcome::Executed { .. }),
        "a current-generation kill MUST fire; got {outcome:?}"
    );
    assert_eq!(
        mock.stop_count(),
        1,
        "exactly one stop for a current-generation kill (no fail-open)"
    );
}
