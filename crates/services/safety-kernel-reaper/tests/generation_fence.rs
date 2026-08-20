//! END-TO-END generation-fence fixtures for the control-plane Reaper.
//!
//! These drive the REAL reaper decision path (`handle_kill_candidate` /
//! `handle_pending_candidate`) with a REAL signed kill token minted from the
//! kernel test key and the kernel's authoritative live grant generation — the
//! exact `u64` the pending-pull delivers. Nothing is stubbed: the reaper runs
//! its pinned-signature, audience, expiry, fingerprint, nonce, and NOW the
//! generation fence, and we assert the executor's stop count directly (a mock,
//! so nothing real is ever stopped).
//!
//! This is the scenario the reviewer flagged: the pure `honour_revocation`
//! function was proved, but the reaper never CALLED it, so a stale kill still
//! terminated a restored instance. It is now defended end-to-end.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use qorch_domain::safety::{
    revoke_params_fingerprint, sign_kernel_token, InstanceTarget, RevocationTier,
    RevokeComputeClaims, RevokeTrigger, REVOKE_COMPUTE_AUD,
};
use qorch_safety_kernel_client::PinnedKeyVerifier;
use qorch_safety_kernel_reaper::{
    ComputeExecutor, MemNonceStore, MockComputeExecutor, Outcome, Reaper, RejectReason,
};

/// The (test) KERNEL signing key — its verifying-key bytes are what the Reaper
/// pins. Deterministic; no system entropy.
fn kernel_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

fn pinned_pubkey() -> [u8; 32] {
    kernel_signing_key().verifying_key().to_bytes()
}

/// The agent VM the Reaper watches (mock; never live).
fn ai_vm() -> InstanceTarget {
    InstanceTarget {
        project: "example-project".to_string(),
        zone: "zone-a".to_string(),
        instance: "ai-worker-vm".to_string(),
    }
}

const NOW: f64 = 1_000_000.0;

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

/// Mint a REAL signed kill token STAMPED against `generation` — byte-for-byte
/// what the kernel's `mint_revoke` handler produces (same fingerprint recipe,
/// same signer). This is the producer's output; the reaper is the consumer.
fn mint_kill_at_generation(sk: &SigningKey, generation: u64, nonce: &str, run_id: &str) -> String {
    let target = ai_vm();
    let fp = revoke_params_fingerprint(
        run_id,
        &target,
        generation,
        RevocationTier::VmStop,
        RevokeTrigger::OperatorEmergencyStop,
        Some("e-stop"),
    );
    let claims = RevokeComputeClaims {
        aud: REVOKE_COMPUTE_AUD.to_string(),
        run_id: run_id.to_string(),
        subject: "operator".to_string(),
        params_fingerprint: fp,
        issued_at: NOW - 10.0,
        expires_at: NOW + 120.0,
        nonce: nonce.to_string(),
        target,
        target_generation: generation,
        tier: RevocationTier::VmStop,
        trigger: RevokeTrigger::OperatorEmergencyStop,
        reason: Some("e-stop".to_string()),
    };
    sign_kernel_token(&claims, sk)
}

// ===========================================================================
// THE FLAGGED SCENARIO — a stale kill after a restore MUST NOT fire.
//
// Interleaving: grant (gen N) -> operator mints a kill stamped gen N ->
// operator restores (the kernel bumps the live grant to N+1) -> the OLD kill
// (gen N) is redelivered on the pending pull, which now carries
// current_grant_generation = N+1. Every pre-existing gate on that kill still
// passes (valid signature, within TTL, nonce never burned, target matches);
// only the generation fence stands between it and terminating the RESTORED
// instance. The reaper MUST reject it as StaleGeneration and issue ZERO stops.
// ===========================================================================
#[tokio::test]
async fn stale_generation_kill_after_restore_is_fenced_and_never_stops() {
    let mock = Arc::new(MockComputeExecutor::new());
    let reaper = make_reaper(Arc::clone(&mock));

    // Kill minted against grant generation N = 7.
    let n: u64 = 7;
    let stale_kill =
        mint_kill_at_generation(&kernel_signing_key(), n, "nonce-stale", "revoke_stale");

    // The kernel state after a restore: the live grant generation is now N+1,
    // and that is the value the pending-pull hands the reaper.
    let current_grant_generation = n + 1;

    // Drive the REAL reaper decision path via the same entry point the poll
    // loop uses (`handle_pending_candidate`, which routes a kill to the fenced
    // kill path).
    let outcome = reaper
        .handle_pending_candidate(&stale_kill, current_grant_generation, NOW)
        .await;

    assert_eq!(
        outcome,
        Outcome::Rejected(RejectReason::StaleGeneration),
        "a kill minted against the pre-restore grant (gen {n}) MUST be fenced when the live grant \
         is gen {current_grant_generation}"
    );
    assert_eq!(
        mock.stop_count(),
        0,
        "ZERO stops: a stale kill must never terminate the restored instance"
    );

    // Re-delivering it again (the poll loop re-pulls until TTL) stays a
    // permanent skip — still zero stops, never a retry that could succeed.
    let again = reaper
        .handle_pending_candidate(&stale_kill, current_grant_generation, NOW)
        .await;
    assert_eq!(again, Outcome::Rejected(RejectReason::StaleGeneration));
    assert_eq!(
        mock.stop_count(),
        0,
        "a re-pulled stale kill still issues zero stops"
    );
}

// ===========================================================================
// POSITIVE control — a CURRENT-generation kill (stamp == live grant) with all
// gates passing MUST still fire exactly one stop. Proves the fence is not a
// fail-OPEN blanket reject: the very same code path that refuses the stale kill
// above lets the current one through.
// ===========================================================================
#[tokio::test]
async fn current_generation_kill_fires_exactly_one_stop() {
    let mock = Arc::new(MockComputeExecutor::new());
    let reaper = make_reaper(Arc::clone(&mock));

    // Kill minted against the CURRENT live grant generation (8 == 8).
    let live: u64 = 8;
    let kill = mint_kill_at_generation(&kernel_signing_key(), live, "nonce-live", "revoke_live");

    let outcome = reaper.handle_pending_candidate(&kill, live, NOW).await;

    match outcome {
        Outcome::Executed { run_id, outcome } => {
            assert_eq!(run_id, "revoke_live");
            assert_eq!(outcome.instance, ai_vm().instance);
        }
        other => panic!("a current-generation kill MUST fire; got {other:?}"),
    }
    assert_eq!(
        mock.stop_count(),
        1,
        "a current-generation kill fires exactly one stop (no fail-open, no double stop)"
    );
    assert_eq!(mock.stop_targets()[0].instance, ai_vm().instance);
}

// ===========================================================================
// The kill path uses the fence; the direct-kill entry point behaves the same.
// A newer live generation than the kill's stamp is also fenced (defence for a
// kill that somehow lags MORE than one restore behind).
// ===========================================================================
#[tokio::test]
async fn kill_two_generations_behind_is_also_fenced() {
    let mock = Arc::new(MockComputeExecutor::new());
    let reaper = make_reaper(Arc::clone(&mock));

    let kill = mint_kill_at_generation(&kernel_signing_key(), 3, "nonce-old", "revoke_old");
    // Live grant has advanced two restores ahead of the kill's stamp.
    let outcome = reaper.handle_kill_candidate(&kill, 5, NOW).await;

    assert_eq!(outcome, Outcome::Rejected(RejectReason::StaleGeneration));
    assert_eq!(mock.stop_count(), 0);
}
