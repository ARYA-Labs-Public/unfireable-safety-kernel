//! Adversarial fixtures for the control-plane Reaper (Phase 1) — the reaper
//! MUST reject/behave, and every claim is re-derived IN-PROCESS with real
//! signed decisions minted from a test key (NEVER a live stop; assert
//! executor.stop was/wasn't called, don't grep logs).
//!
//! The executor is always a `MockComputeExecutor`, so a "kill" only ever
//! records a call — nothing real is stopped.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use qorch_domain::safety::{
    restore_params_fingerprint, revoke_params_fingerprint, sign_kernel_token, AuthorizeClaims,
    InstanceTarget, RestoreClaims, RevocationTier, RevokeComputeClaims, RevokeTrigger,
    KERNEL_AUTHORIZE_AUD, REVOKE_COMPUTE_AUD, REVOKE_RESTORE_AUD,
};
use qorch_safety_kernel_client::PinnedKeyVerifier;
use qorch_safety_kernel_reaper::{
    ComputeExecutor, MemNonceStore, MockComputeExecutor, Outcome, Reaper, RejectReason,
};

/// The (test) KERNEL signing key. Its verifying-key bytes are what the Reaper
/// pins. Deterministic — no system entropy.
fn kernel_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

/// A DIFFERENT key — the "attacker" / agent (which never holds the kernel
/// signing key). Tokens signed with this must NEVER verify against the pin.
fn attacker_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[99u8; 32])
}

fn pinned_pubkey() -> [u8; 32] {
    kernel_signing_key().verifying_key().to_bytes()
}

/// The agent VM the Reaper watches + fail-closed-stops (mock; never live).
fn ai_vm() -> InstanceTarget {
    InstanceTarget {
        project: "example-project".to_string(),
        zone: "zone-a".to_string(),
        instance: "ai-worker-vm".to_string(),
    }
}

const NOW: f64 = 1_000_000.0;

/// Build a Reaper wired to the given mock executor + a fresh in-memory nonce
/// store (no tlog recorder / kernel client — we assert executor behaviour in
/// isolation). Returns the Reaper plus the shared nonce store so replay tests
/// can reuse it.
fn make_reaper(mock: Arc<MockComputeExecutor>) -> Reaper {
    let verifier = PinnedKeyVerifier::from_pubkey_bytes(pinned_pubkey()).expect("valid pubkey");
    let nonce_store = Arc::new(MemNonceStore::new());
    Reaper::new(
        verifier,
        mock as Arc<dyn ComputeExecutor>,
        nonce_store,
        ai_vm(),
        300.0,
        None,
        None,
    )
}

/// Mint a signed KILL token. `fp_target` chooses the target the
/// `params_fingerprint` is computed over — pass a target DIFFERENT from
/// `claim_target` to forge a fingerprint mismatch.
fn mint_kill(
    sk: &SigningKey,
    claim_target: &InstanceTarget,
    fp_target: &InstanceTarget,
    iat: f64,
    exp: f64,
    nonce: &str,
    run_id: &str,
) -> String {
    let fp = revoke_params_fingerprint(
        run_id,
        fp_target,
        0,
        RevocationTier::VmStop,
        RevokeTrigger::OperatorEmergencyStop,
        Some("e-stop"),
    );
    let claims = RevokeComputeClaims {
        aud: REVOKE_COMPUTE_AUD.to_string(),
        run_id: run_id.to_string(),
        subject: "operator".to_string(),
        params_fingerprint: fp,
        issued_at: iat,
        expires_at: exp,
        nonce: nonce.to_string(),
        target: claim_target.clone(),
        target_generation: 0,
        tier: RevocationTier::VmStop,
        trigger: RevokeTrigger::OperatorEmergencyStop,
        reason: Some("e-stop".to_string()),
    };
    sign_kernel_token(&claims, sk)
}

/// A well-formed, correctly-bound kill token (fingerprint over the same target).
fn valid_kill(sk: &SigningKey, target: &InstanceTarget, nonce: &str, run_id: &str) -> String {
    mint_kill(sk, target, target, NOW - 10.0, NOW + 120.0, nonce, run_id)
}

fn mint_restore(sk: &SigningKey, target: &InstanceTarget, nonce: &str, run_id: &str) -> String {
    let fp = restore_params_fingerprint(run_id, target, Some("cleared"));
    let claims = RestoreClaims {
        aud: REVOKE_RESTORE_AUD.to_string(),
        run_id: run_id.to_string(),
        subject: "operator".to_string(),
        params_fingerprint: fp,
        issued_at: NOW - 10.0,
        expires_at: NOW + 120.0,
        nonce: nonce.to_string(),
        target: target.clone(),
        reason: Some("cleared".to_string()),
    };
    sign_kernel_token(&claims, sk)
}

// ============================================================================
// Fixture 1 — forged-signature kill (signed with a non-kernel key).
// ============================================================================

#[tokio::test]
async fn forged_signature_kill_is_rejected_and_executor_not_called() {
    let mock = Arc::new(MockComputeExecutor::new());
    let reaper = make_reaper(Arc::clone(&mock));

    // Signed with the ATTACKER key — the Reaper pins the KERNEL key.
    let token = valid_kill(
        &attacker_signing_key(),
        &ai_vm(),
        "nonce-forged",
        "revoke_forged",
    );
    let outcome = reaper.handle_kill_candidate(&token, 0, NOW).await;

    assert_eq!(outcome, Outcome::Rejected(RejectReason::ForgedSignature));
    assert_eq!(mock.stop_count(), 0, "forged kill MUST NOT call stop");
}

// ============================================================================
// Fixture 2 — expired kill (exp in the past).
// ============================================================================

#[tokio::test]
async fn expired_kill_is_rejected_and_executor_not_called() {
    let mock = Arc::new(MockComputeExecutor::new());
    let reaper = make_reaper(Arc::clone(&mock));

    // exp is 100s before NOW.
    let token = mint_kill(
        &kernel_signing_key(),
        &ai_vm(),
        &ai_vm(),
        NOW - 200.0,
        NOW - 100.0,
        "nonce-expired",
        "revoke_expired",
    );
    let outcome = reaper.handle_kill_candidate(&token, 0, NOW).await;

    assert_eq!(outcome, Outcome::Rejected(RejectReason::Expired));
    assert_eq!(mock.stop_count(), 0, "expired kill MUST NOT call stop");
}

// ============================================================================
// Fixture 3 — wrong-audience token (an authorize token replayed at the reaper).
// ============================================================================

#[tokio::test]
async fn wrong_audience_token_is_rejected_and_executor_not_called() {
    let mock = Arc::new(MockComputeExecutor::new());
    let reaper = make_reaper(Arc::clone(&mock));

    // A real /kernel/v1/authorize token (aud = kernel/authorize) minted with
    // the KERNEL key — signature is valid, but it is not a kill.
    let authorize = AuthorizeClaims {
        action: "sio_run_cycles".to_string(),
        aud: KERNEL_AUTHORIZE_AUD.to_string(),
        run_id: "run_replayed".to_string(),
        subject: "worker".to_string(),
        params_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_string(),
        issued_at: NOW - 10.0,
        expires_at: NOW + 120.0,
        nonce: "authorize-nonce-000000".to_string(),
    };
    let token = sign_kernel_token(&authorize, &kernel_signing_key());
    let outcome = reaper.handle_kill_candidate(&token, 0, NOW).await;

    assert_eq!(outcome, Outcome::Rejected(RejectReason::WrongAudience));
    assert_eq!(mock.stop_count(), 0, "authorize token MUST NOT call stop");
}

// ============================================================================
// Fixture 4 — replayed kill (same nonce twice): first executes, second dropped.
// ============================================================================

#[tokio::test]
async fn replayed_kill_executes_once_then_is_rejected() {
    let mock = Arc::new(MockComputeExecutor::new());
    let reaper = make_reaper(Arc::clone(&mock));

    let token = valid_kill(
        &kernel_signing_key(),
        &ai_vm(),
        "nonce-replay",
        "revoke_replay",
    );

    // First presentation: executes exactly one stop.
    let first = reaper.handle_kill_candidate(&token, 0, NOW).await;
    assert!(
        matches!(first, Outcome::Executed { .. }),
        "first got {first:?}"
    );
    assert_eq!(mock.stop_count(), 1);

    // Second presentation of the SAME signed decision: dropped by the
    // seen-nonce store — cryptographically valid, but already executed.
    let second = reaper.handle_kill_candidate(&token, 0, NOW).await;
    assert_eq!(second, Outcome::Rejected(RejectReason::AlreadyExecuted));
    assert_eq!(
        mock.stop_count(),
        1,
        "replay MUST NOT call stop a second time"
    );
}

// ============================================================================
// Fixture 5 — fingerprint-mismatch (claims target A, fingerprint binds B).
// ============================================================================

#[tokio::test]
async fn fingerprint_mismatch_kill_is_rejected_and_executor_not_called() {
    let mock = Arc::new(MockComputeExecutor::new());
    let reaper = make_reaper(Arc::clone(&mock));

    let other = InstanceTarget {
        project: "example-project".to_string(),
        zone: "zone-a".to_string(),
        instance: "some-other-vm".to_string(),
    };
    // claim_target = ai_vm, but the params_fingerprint is computed over `other`.
    // Signature is valid; the Reaper recomputes the fp from the CLAIMED target
    // and finds the mismatch.
    let token = mint_kill(
        &kernel_signing_key(),
        &ai_vm(),
        &other,
        NOW - 10.0,
        NOW + 120.0,
        "nonce-fpmm",
        "revoke_fpmm",
    );
    let outcome = reaper.handle_kill_candidate(&token, 0, NOW).await;

    assert_eq!(
        outcome,
        Outcome::Rejected(RejectReason::FingerprintMismatch)
    );
    assert_eq!(
        mock.stop_count(),
        0,
        "fingerprint-mismatch MUST NOT call stop"
    );
}

// ============================================================================
// Fixture 6 — agent-forged restore (attacker/worker-key restore).
// ============================================================================

#[tokio::test]
async fn agent_forged_restore_is_rejected_and_start_not_called() {
    let mock = Arc::new(MockComputeExecutor::new());
    let reaper = make_reaper(Arc::clone(&mock));

    // A restore signed with the ATTACKER key (the agent has no kernel signing
    // key). Verification against the pin fails — a reaped agent cannot un-kill
    // itself.
    let token = mint_restore(
        &attacker_signing_key(),
        &ai_vm(),
        "nonce-restore",
        "restore_forged",
    );
    let outcome = reaper.handle_restore_candidate(&token, NOW).await;

    assert_eq!(outcome, Outcome::Rejected(RejectReason::ForgedSignature));
    assert_eq!(mock.start_count(), 0, "forged restore MUST NOT call start");
}

/// Complement: a genuine OPERATOR-signed restore (kernel key, restore aud) DOES
/// call start exactly once — proving the reject above is about the signature,
/// not a dead path.
#[tokio::test]
async fn operator_signed_restore_calls_start_once() {
    let mock = Arc::new(MockComputeExecutor::new());
    let reaper = make_reaper(Arc::clone(&mock));

    let token = mint_restore(
        &kernel_signing_key(),
        &ai_vm(),
        "nonce-restore-ok",
        "restore_ok",
    );
    let outcome = reaper.handle_restore_candidate(&token, NOW).await;

    assert!(
        matches!(outcome, Outcome::Restored { .. }),
        "got {outcome:?}"
    );
    assert_eq!(mock.start_count(), 1);
    assert_eq!(mock.stop_count(), 0);
}

// ============================================================================
// Fixture 7 — suppressed signal / kernel unreachable past the liveness
// deadline => FAIL CLOSED (executor.stop IS called on the configured target).
// ============================================================================

#[tokio::test]
async fn liveness_timeout_fails_closed_and_stops_configured_target() {
    let mock = Arc::new(MockComputeExecutor::new());
    let reaper = make_reaper(Arc::clone(&mock));

    // last successful contact was 400s ago; deadline is 300s.
    let last_success = NOW - 400.0;
    assert!(
        reaper.liveness_expired(last_success, NOW),
        "400s > 300s deadline must be expired"
    );

    let outcome = reaper.fail_closed_stop(NOW).await;
    assert!(
        matches!(outcome, Outcome::FailClosed { .. }),
        "got {outcome:?}"
    );
    assert_eq!(mock.stop_count(), 1, "fail-closed MUST stop the target");
    assert_eq!(
        mock.stop_targets()[0].instance,
        ai_vm().instance,
        "fail-closed stops the CONFIGURED target"
    );
}

/// Complement to fixture 7 — WITHIN the deadline, no fail-closed stop fires.
#[tokio::test]
async fn kernel_blip_within_deadline_does_not_fail_closed() {
    let mock = Arc::new(MockComputeExecutor::new());
    let reaper = make_reaper(Arc::clone(&mock));

    // last success 100s ago; deadline 300s — a benign blip, not suppression.
    assert!(!reaper.liveness_expired(NOW - 100.0, NOW));
    assert_eq!(mock.stop_count(), 0);
}

// ============================================================================
// Positive control — a valid kill stops exactly the target bound in the token.
// ============================================================================

#[tokio::test]
async fn valid_kill_stops_the_bound_target_exactly_once() {
    let mock = Arc::new(MockComputeExecutor::new());
    let reaper = make_reaper(Arc::clone(&mock));

    let token = valid_kill(
        &kernel_signing_key(),
        &ai_vm(),
        "nonce-valid",
        "revoke_valid",
    );
    let outcome = reaper.handle_kill_candidate(&token, 0, NOW).await;

    match outcome {
        Outcome::Executed { run_id, outcome } => {
            assert_eq!(run_id, "revoke_valid");
            assert_eq!(outcome.instance, ai_vm().instance);
        }
        other => panic!("valid kill must execute; got {other:?}"),
    }
    assert_eq!(mock.stop_count(), 1);
    assert_eq!(mock.stop_targets()[0].instance, ai_vm().instance);
}
