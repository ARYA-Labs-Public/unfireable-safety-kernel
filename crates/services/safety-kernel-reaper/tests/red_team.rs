//! RED-TEAM PoCs for the Reaper, asserting the FIXES. Every claim is
//! re-derived IN-PROCESS with real signed decisions minted from a test key and
//! driven through the REAL `Reaper` verify->execute state machine. The executor
//! is always a mock/failing mock — NEVER a live stop.
//!
//! What each test proves:
//!   - F-6a: a transient executor error does NOT burn the replay key, so the
//!     poll loop re-pulls and the kill is RETRIED until it succeeds; the
//!     durable nonce is set ONLY after a confirmed stop.
//!   - F-6b: a fail-closed stop error is NOT swallowed — `on_kernel_pull_failure`
//!     reports `advance_liveness == false` so the deadline stays expired and the
//!     stop is retried on the next poll.
//!   - F-obs: `handle_pending_candidate` dispatches by kind, so an operator
//!     restore in the pending queue is `start()`ed exactly once (end-to-end
//!     effect), while a kill token routed there is never `start()`ed.
//!   - full audience-confusion matrix (authorize/restore -> kill, kill -> restore)
//!   - nonce key ignores `target` (nonce+run_id only)
//!   - persistence across restart (FileNonceStore) actually defeats replay

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use qorch_domain::safety::{
    restore_params_fingerprint, revoke_params_fingerprint, sign_kernel_token, AuthorizeClaims,
    InstanceTarget, RestoreClaims, RevocationTier, RevokeComputeClaims, RevokeTrigger,
    KERNEL_AUTHORIZE_AUD, REVOKE_COMPUTE_AUD, REVOKE_RESTORE_AUD,
};
use qorch_safety_kernel_client::PinnedKeyVerifier;
use qorch_safety_kernel_reaper::{
    ComputeExecutor, ExecutorError, FileNonceStore, KernelClientError, LivenessAction,
    MemNonceStore, MockComputeExecutor, NonceKey, Outcome, Reaper, RejectReason,
    ReqwestKernelClient, SeenNonceStore, StopOutcome,
};

fn kernel_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}
fn attacker_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[99u8; 32])
}
fn pinned_pubkey() -> [u8; 32] {
    kernel_signing_key().verifying_key().to_bytes()
}
fn ai_vm() -> InstanceTarget {
    InstanceTarget {
        project: "example-project".to_string(),
        zone: "zone-a".to_string(),
        instance: "ai-worker-vm".to_string(),
    }
}
const NOW: f64 = 1_000_000.0;

// ---------------------------------------------------------------------------
// A stop-executor that fails its first `fail_first` stop calls, then succeeds.
// Models a transient cloud error (503/rate-limit) at the moment of the real kill.
// ---------------------------------------------------------------------------
#[derive(Debug, Default)]
struct FlakyExecutor {
    stop_calls: AtomicUsize,
    start_calls: AtomicUsize,
    fail_first: usize,
}
impl FlakyExecutor {
    fn new(fail_first: usize) -> Self {
        Self {
            stop_calls: AtomicUsize::new(0),
            start_calls: AtomicUsize::new(0),
            fail_first,
        }
    }
    fn stop_attempts(&self) -> usize {
        self.stop_calls.load(Ordering::SeqCst)
    }
}
#[async_trait]
impl ComputeExecutor for FlakyExecutor {
    async fn stop(&self, target: &InstanceTarget) -> Result<StopOutcome, ExecutorError> {
        let n = self.stop_calls.fetch_add(1, Ordering::SeqCst);
        if n < self.fail_first {
            return Err(ExecutorError::Backend(
                "transient 503 from compute API".into(),
            ));
        }
        Ok(StopOutcome {
            instance: target.instance.clone(),
            op_id: format!("flaky-stop-{}", target.instance),
            prev_state: "RUNNING".to_string(),
        })
    }
    async fn start(&self, target: &InstanceTarget) -> Result<StopOutcome, ExecutorError> {
        self.start_calls.fetch_add(1, Ordering::SeqCst);
        Ok(StopOutcome {
            instance: target.instance.clone(),
            op_id: format!("flaky-start-{}", target.instance),
            prev_state: "TERMINATED".to_string(),
        })
    }
}

fn make_reaper_with(executor: Arc<dyn ComputeExecutor>, store: Arc<dyn SeenNonceStore>) -> Reaper {
    let verifier = PinnedKeyVerifier::from_pubkey_bytes(pinned_pubkey()).expect("valid pubkey");
    Reaper::new(verifier, executor, store, ai_vm(), 300.0, None, None)
}

fn valid_kill(sk: &SigningKey, target: &InstanceTarget, nonce: &str, run_id: &str) -> String {
    let fp = revoke_params_fingerprint(
        run_id,
        target,
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
        issued_at: NOW - 10.0,
        expires_at: NOW + 120.0,
        nonce: nonce.to_string(),
        target: target.clone(),
        target_generation: 0,
        tier: RevocationTier::VmStop,
        trigger: RevokeTrigger::OperatorEmergencyStop,
        reason: Some("e-stop".to_string()),
    };
    sign_kernel_token(&claims, sk)
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

// ===========================================================================
// FINDING 1 (F-6a) — FIXED: a transient executor error does NOT burn the
// (nonce,run_id) replay key. The token stays pending, the poll loop re-presents
// it, and the RETRY succeeds — the VM IS stopped. The durable nonce is set ONLY
// after the confirmed successful stop.
// ===========================================================================
#[tokio::test]
async fn transient_executor_error_is_retried_and_eventually_stops() {
    let exec = Arc::new(FlakyExecutor::new(1)); // fail exactly the first stop
    let store = Arc::new(MemNonceStore::new());
    let reaper = make_reaper_with(
        Arc::clone(&exec) as Arc<dyn ComputeExecutor>,
        Arc::clone(&store) as Arc<dyn SeenNonceStore>,
    );

    let token = valid_kill(
        &kernel_signing_key(),
        &ai_vm(),
        "nonce-flaky",
        "revoke_flaky",
    );

    // Poll #1: fully verifies, then the executor errors. Because the nonce is a
    // COMPLETION marker (not an intent marker), it is NOT burned on the error.
    let first = reaper.handle_kill_candidate(&token, 0, NOW).await;
    assert_eq!(
        first,
        Outcome::Rejected(RejectReason::ExecutorError(
            "compute backend error: transient 503 from compute API".to_string()
        )),
        "first attempt errors in the executor"
    );
    // The replay key must NOT be set after a FAILED stop.
    assert!(
        !store.is_seen(&NonceKey::new("nonce-flaky", "revoke_flaky")),
        "F-6a: a failed stop must NOT burn the replay key"
    );

    // The token is still pending (no ack on the error path), so the loop
    // re-presents the SAME signed decision on the next poll.
    let second = reaper.handle_kill_candidate(&token, 0, NOW).await;

    // FIX: the retry now runs a real stop and SUCCEEDS.
    assert!(
        matches!(second, Outcome::Executed { .. }),
        "retry must actually stop the VM; got {second:?}"
    );

    // Ground truth: the executor was asked to stop TWICE (failed, then ok);
    // the agent VM is now stopped.
    assert!(
        exec.stop_attempts() >= 2,
        "kill switch retried: stop was attempted across the transient error, got {}",
        exec.stop_attempts()
    );
    // And ONLY now is the durable replay key set (after the confirmed stop).
    assert!(
        store.is_seen(&NonceKey::new("nonce-flaky", "revoke_flaky")),
        "the durable nonce is set only AFTER a confirmed successful stop"
    );

    // A THIRD presentation is now a genuine replay of a COMPLETED kill -> drop
    // (F-3 preserved: a finished kill still can't be replayed).
    let third = reaper.handle_kill_candidate(&token, 0, NOW).await;
    assert_eq!(
        third,
        Outcome::Rejected(RejectReason::AlreadyExecuted),
        "a replay AFTER a completed stop is still rejected"
    );
    assert_eq!(
        exec.stop_attempts(),
        2,
        "the completed-kill replay must NOT stop a third time"
    );
}

// Control: with a healthy executor the same flow stops exactly once — proving
// the suppression above is caused by the error path, not a dead reaper.
#[tokio::test]
async fn healthy_executor_stops_once_control() {
    let exec = Arc::new(FlakyExecutor::new(0));
    let store = Arc::new(MemNonceStore::new());
    let reaper = make_reaper_with(
        Arc::clone(&exec) as Arc<dyn ComputeExecutor>,
        Arc::clone(&store) as Arc<dyn SeenNonceStore>,
    );
    let token = valid_kill(&kernel_signing_key(), &ai_vm(), "nonce-ok", "revoke_ok");
    assert!(matches!(
        reaper.handle_kill_candidate(&token, 0, NOW).await,
        Outcome::Executed { .. }
    ));
    assert_eq!(exec.stop_attempts(), 1);
}

// ===========================================================================
// FINDING 2 (F-6b) — FIXED: a fail-closed stop error is NOT swallowed.
// `on_kernel_pull_failure` (the testable core of main.rs's error branch)
// reports `advance_liveness == false` when the stop errors, so the caller keeps
// the deadline expired and RETRIES on the next poll instead of waiting a full
// deadline. A subsequent recovery then actually stops.
// ===========================================================================
#[tokio::test]
async fn fail_closed_stop_error_is_not_swallowed_and_is_retried() {
    // fail the first fail-closed stop, then recover.
    let exec = Arc::new(FlakyExecutor::new(1));
    let store = Arc::new(MemNonceStore::new());
    let reaper = make_reaper_with(
        Arc::clone(&exec) as Arc<dyn ComputeExecutor>,
        Arc::clone(&store) as Arc<dyn SeenNonceStore>,
    );

    // Kernel dark past the deadline (last success 400s ago, deadline 300s).
    let last_success = NOW - 400.0;

    // Poll #1: the fail-closed stop ERRORS. Liveness must NOT advance.
    let first = reaper.on_kernel_pull_failure(last_success, NOW).await;
    match first {
        LivenessAction::FailedClosed {
            outcome,
            advance_liveness,
        } => {
            assert_eq!(
                outcome,
                Outcome::Rejected(RejectReason::ExecutorError(
                    "compute backend error: transient 503 from compute API".to_string()
                ))
            );
            assert!(
                !advance_liveness,
                "F-6b: a FAILED fail-closed stop must NOT advance liveness"
            );
        }
        other => panic!("expected FailedClosed, got {other:?}"),
    }

    // The caller keeps last_success unchanged, so the deadline is STILL expired
    // on the next poll — the stop is retried, and now succeeds.
    let second = reaper.on_kernel_pull_failure(last_success, NOW).await;
    match second {
        LivenessAction::FailedClosed {
            outcome,
            advance_liveness,
        } => {
            assert!(
                matches!(outcome, Outcome::FailClosed { .. }),
                "retry must stop; got {outcome:?}"
            );
            assert!(
                advance_liveness,
                "a SUCCESSFUL fail-closed stop advances liveness"
            );
        }
        other => panic!("expected FailedClosed(success), got {other:?}"),
    }
    assert!(
        exec.stop_attempts() >= 2,
        "the fail-closed stop was retried across the error"
    );
}

// Control: within the deadline, on_kernel_pull_failure is a no-op blip.
#[tokio::test]
async fn pull_failure_within_deadline_does_not_fail_closed() {
    let exec = Arc::new(FlakyExecutor::new(0));
    let store = Arc::new(MemNonceStore::new());
    let reaper = make_reaper_with(
        Arc::clone(&exec) as Arc<dyn ComputeExecutor>,
        Arc::clone(&store) as Arc<dyn SeenNonceStore>,
    );
    // last success 100s ago; deadline 300s.
    let action = reaper.on_kernel_pull_failure(NOW - 100.0, NOW).await;
    assert_eq!(action, LivenessAction::WithinDeadline);
    assert_eq!(
        exec.stop_attempts(),
        0,
        "a benign blip must NOT stop anything"
    );
}

// ===========================================================================
// OBSERVATION 3 (F-obs) — FIXED: the poll loop now dispatches by kind via
// `handle_pending_candidate`. A genuine operator restore sitting in the pending
// queue is routed to the restore path and `start()`ed exactly once (end-to-end
// effect), while a kill token routed the same way is NEVER `start()`ed. Restore
// stays operator-only (still hard-verifies signature+aud).
// ===========================================================================
#[tokio::test]
async fn operator_restore_in_pending_queue_starts_exactly_once() {
    let exec = Arc::new(MockComputeExecutor::new());
    let store = Arc::new(MemNonceStore::new());
    let reaper = make_reaper_with(
        Arc::clone(&exec) as Arc<dyn ComputeExecutor>,
        Arc::clone(&store) as Arc<dyn SeenNonceStore>,
    );

    // A genuine operator-signed restore, as it would sit in the pending queue.
    let token = mint_restore(&kernel_signing_key(), &ai_vm(), "nonce-r", "restore_1");
    // The poll loop now routes by kind:
    let outcome = reaper.handle_pending_candidate(&token, 0, NOW).await;
    assert!(
        matches!(outcome, Outcome::Restored { .. }),
        "restore must start; got {outcome:?}"
    );
    assert_eq!(
        exec.start_count(),
        1,
        "restore now has end-to-end effect (start called once)"
    );
    assert_eq!(exec.stop_count(), 0, "a restore never stops anything");
}

// Complement: a KILL token through the same kind-dispatch entry point stops
// (never starts). A restore-audience token is never stop()ed and a
// kill-audience token is never start()ed — the two paths stay partitioned.
#[tokio::test]
async fn pending_dispatch_kill_stops_never_starts() {
    let exec = Arc::new(MockComputeExecutor::new());
    let store = Arc::new(MemNonceStore::new());
    let reaper = make_reaper_with(
        Arc::clone(&exec) as Arc<dyn ComputeExecutor>,
        Arc::clone(&store) as Arc<dyn SeenNonceStore>,
    );

    let kill = valid_kill(&kernel_signing_key(), &ai_vm(), "nonce-kd", "revoke_kd");
    let outcome = reaper.handle_pending_candidate(&kill, 0, NOW).await;
    assert!(
        matches!(outcome, Outcome::Executed { .. }),
        "kill must stop; got {outcome:?}"
    );
    assert_eq!(exec.stop_count(), 1);
    assert_eq!(
        exec.start_count(),
        0,
        "a kill-audience token is never start()ed"
    );
}

// ===========================================================================
// Full audience-confusion matrix, re-derived. Every cross-aud token minted with
// the REAL kernel key is rejected by the kill verifier.
// ===========================================================================
#[tokio::test]
async fn audience_confusion_matrix_all_rejected() {
    let exec = Arc::new(MockComputeExecutor::new());
    let store = Arc::new(MemNonceStore::new());
    let reaper = make_reaper_with(
        Arc::clone(&exec) as Arc<dyn ComputeExecutor>,
        Arc::clone(&store) as Arc<dyn SeenNonceStore>,
    );
    let sk = kernel_signing_key();

    // (a) authorize token -> kill verifier
    let authorize = AuthorizeClaims {
        action: "sio_run_cycles".to_string(),
        aud: KERNEL_AUTHORIZE_AUD.to_string(),
        run_id: "run_x".to_string(),
        subject: "worker".to_string(),
        params_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_string(),
        issued_at: NOW - 10.0,
        expires_at: NOW + 120.0,
        nonce: "authorize-nonce-1".to_string(),
    };
    let auth_tok = sign_kernel_token(&authorize, &sk);
    assert_eq!(
        reaper.handle_kill_candidate(&auth_tok, 0, NOW).await,
        Outcome::Rejected(RejectReason::WrongAudience),
        "a valid AUTHORIZE token must not act as a kill"
    );

    // (b) restore token -> kill verifier
    let restore = mint_restore(&sk, &ai_vm(), "nonce-r2", "restore_2");
    assert_eq!(
        reaper.handle_kill_candidate(&restore, 0, NOW).await,
        Outcome::Rejected(RejectReason::WrongAudience)
    );

    // (c) kill token -> restore verifier
    let kill = valid_kill(&sk, &ai_vm(), "nonce-k", "revoke_k");
    assert_eq!(
        reaper.handle_restore_candidate(&kill, NOW).await,
        Outcome::Rejected(RejectReason::WrongAudience),
        "a valid KILL token must not act as a restore"
    );
    assert_eq!(exec.stop_count(), 0);
    assert_eq!(exec.start_count(), 0);
}

// ===========================================================================
// The nonce key is (nonce, run_id) ONLY; `target` is NOT in the key.
// Demonstrate: after a kill for target A is recorded, a SECOND signed decision
// reusing the SAME (nonce, run_id) but a DIFFERENT target is blocked. (This is
// fail-SAFE here — it can only block, not stop-the-wrong-box, because the
// fingerprint+signature still bind the target. But it shows an operator who
// reused a nonce across targets would silently suppress the 2nd kill.)
// ===========================================================================
#[tokio::test]
async fn nonce_key_ignores_target_second_target_is_suppressed() {
    let exec = Arc::new(MockComputeExecutor::new());
    let store = Arc::new(MemNonceStore::new());
    let reaper = make_reaper_with(
        Arc::clone(&exec) as Arc<dyn ComputeExecutor>,
        Arc::clone(&store) as Arc<dyn SeenNonceStore>,
    );
    let sk = kernel_signing_key();

    let vm_b = InstanceTarget {
        project: "example-project".to_string(),
        zone: "zone-a".to_string(),
        instance: "some-other-vm".to_string(),
    };

    // Kill A: (nonce N, run_id R) -> executes, records N|R.
    let kill_a = valid_kill(&sk, &ai_vm(), "shared-nonce", "revoke_shared");
    assert!(matches!(
        reaper.handle_kill_candidate(&kill_a, 0, NOW).await,
        Outcome::Executed { .. }
    ));
    // Kill B: SAME (nonce N, run_id R), different target -> dropped by nonce key.
    let kill_b = valid_kill(&sk, &vm_b, "shared-nonce", "revoke_shared");
    assert_eq!(
        reaper.handle_kill_candidate(&kill_b, 0, NOW).await,
        Outcome::Rejected(RejectReason::AlreadyExecuted),
        "nonce key (nonce,run_id) ignores target: a nonce reused across targets suppresses the 2nd kill"
    );
    assert_eq!(exec.stop_count(), 1, "only the first target was stopped");
}

// ===========================================================================
// Persistent store defeats replay across a RESTART (hydration is synchronous in
// FileNonceStore::open, so there is no not-yet-hydrated window).
// ===========================================================================
#[tokio::test]
async fn replay_after_restart_is_defeated_by_persistent_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("seen_nonces.log");
    let sk = kernel_signing_key();
    let token = valid_kill(&sk, &ai_vm(), "nonce-restart", "revoke_restart");

    // Reaper #1: executes the kill, records the nonce durably.
    {
        let store = Arc::new(FileNonceStore::open(&path).unwrap());
        let exec = Arc::new(MockComputeExecutor::new());
        let reaper = make_reaper_with(
            Arc::clone(&exec) as Arc<dyn ComputeExecutor>,
            Arc::clone(&store) as Arc<dyn SeenNonceStore>,
        );
        assert!(matches!(
            reaper.handle_kill_candidate(&token, 0, NOW).await,
            Outcome::Executed { .. }
        ));
    }

    // Reaper #2: fresh process, re-opens the SAME store file. A captured kill
    // replayed after restart must be dropped.
    {
        let store = Arc::new(FileNonceStore::open(&path).unwrap());
        let exec = Arc::new(MockComputeExecutor::new());
        let reaper = make_reaper_with(
            Arc::clone(&exec) as Arc<dyn ComputeExecutor>,
            Arc::clone(&store) as Arc<dyn SeenNonceStore>,
        );
        let replay = reaper.handle_kill_candidate(&token, 0, NOW).await;
        assert_eq!(replay, Outcome::Rejected(RejectReason::AlreadyExecuted));
        assert_eq!(exec.stop_count(), 0, "post-restart replay MUST NOT re-stop");
    }
}

// ===========================================================================
// Forged/attacker-key kill AND an attacker-crafted fingerprint mismatch both
// fail before any stop. (Key confusion: the pin is a fixed Ed25519 VerifyingKey;
// there is no algorithm field to substitute.)
// ===========================================================================
#[tokio::test]
async fn forged_key_and_crafted_mismatch_never_stop() {
    let exec = Arc::new(MockComputeExecutor::new());
    let store = Arc::new(MemNonceStore::new());
    let reaper = make_reaper_with(
        Arc::clone(&exec) as Arc<dyn ComputeExecutor>,
        Arc::clone(&store) as Arc<dyn SeenNonceStore>,
    );

    // Attacker signs a perfectly-shaped kill with the WRONG key.
    let forged = valid_kill(&attacker_signing_key(), &ai_vm(), "nonce-f", "revoke_f");
    assert_eq!(
        reaper.handle_kill_candidate(&forged, 0, NOW).await,
        Outcome::Rejected(RejectReason::ForgedSignature)
    );

    // Attacker tampers a REAL token's payload (flip a byte) — signature breaks.
    let real = valid_kill(&kernel_signing_key(), &ai_vm(), "nonce-t", "revoke_t");
    let (payload, sig) = real.split_once('.').unwrap();
    let mut p = payload.as_bytes().to_vec();
    p[0] ^= 0x01; // corrupt one payload byte
    let tampered = format!("{}.{}", String::from_utf8_lossy(&p), sig);
    let out = reaper.handle_kill_candidate(&tampered, 0, NOW).await;
    assert!(
        matches!(
            out,
            Outcome::Rejected(RejectReason::ForgedSignature | RejectReason::MalformedClaims)
        ),
        "tampered payload must be rejected; got {out:?}"
    );

    assert_eq!(exec.stop_count(), 0);
}

// ===========================================================================
// Kernel server-cert PINNING. The Reaper previously trusted the kernel's
// pending list over plain WebPKI roots, so a MITM / lying kernel could return
// an empty list and suppress a kill without tripping liveness.
// `ReqwestKernelClient::with_pinned_ca` now builds a client that trusts ONLY the
// configured kernel CA. These tests prove the pin is REAL (a valid CA is
// accepted; a malformed one fails LOUD at construction — never silently
// degrades to an unpinned connection).
// ===========================================================================

/// A valid self-signed CA PEM (test fixture; not a real kernel CA).
const TEST_KERNEL_CA_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIUUVxFE3eCsCmIJiqmPN1bwZiLCEYwDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwOdGVzdC1rZXJuZWwtY2EwHhcNMjYwODA2MTkzMjMzWhcN
MzYwODAzMTkzMjMzWjAZMRcwFQYDVQQDDA50ZXN0LWtlcm5lbC1jYTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJqdvgsLMiI3Tr77bPCIdd9YTut/754I
0y5EuSyNYedf9gWKrnhnzrYQr0tKsWPp0fGOVZLOmtiZaFX+amrhLaMtv1UReOl8
KZWLrm4ZrwXLrt8dQyOxx6P+64rRzICbCaL7XZi+fnp3N/fHE7bm4kQgyRE9nGOT
r5O1XIpv9W8E7Hk+Bue8CoPeETRJ2F24C+wTjHR3+0Sx3pTh+QKmiQyFuG2p5OEY
UGfdroky5ruksfJyNlN6AnP/G7bxq+0zPjE0xHtcAJ//YIZDzbS+bDJqbSBHeCu2
g0ogjWqNy3FLe2CA31OcjFV2n9Y16LOQQf0lkgdaMTFDZEG/6QCWjcMCAwEAAaNT
MFEwHQYDVR0OBBYEFF02wo5CF/WAVS5PS9DxPrmO85LAMB8GA1UdIwQYMBaAFF02
wo5CF/WAVS5PS9DxPrmO85LAMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAHJ93hOqLZNw8oHVdXBOeSyf5ELFI6XNSihkfiQPEZHnUuXiG/qAqckE
6AVIQDpjCzCDD6bZ/pAAxIKCg24vErj/X1CMKg01cyk+USP0D8D0jeDSDwj6iXae
hroU6diDbtUq2tnx0Q4m+EPZcxMBwseotiyUfHWO3JMWbFBe6H/9sE8Mtxk/XO2n
LqneKlkjm8rRP3yc8QDVhlLVV7/5L2LfoBc71LyB2S3cUCvxgzPDtjsVvTHsmVWg
wZUSUbR9FTHDsoIyooJQgUsNc8h0iD9Tyo1pZB6IgX559HqTkKYLDlLwIuOVAWJy
WcQYUCgWzxnSGT8ubTy3gkF1/c9rd5I=
-----END CERTIFICATE-----";

#[test]
fn pinned_kernel_client_builds_from_a_valid_ca() {
    let client = ReqwestKernelClient::with_pinned_ca(
        "https://kernel:9000".to_string(),
        "reaper-key".to_string(),
        std::time::Duration::from_secs(10),
        TEST_KERNEL_CA_PEM,
    );
    assert!(
        client.is_ok(),
        "a valid kernel CA must build a pinned client; got {client:?}"
    );
}

#[test]
fn pinned_kernel_client_rejects_a_malformed_ca_loud() {
    // A garbage "CA" must FAIL at construction — the pin is real, not a no-op
    // that silently falls back to an unpinned connection.
    let client = ReqwestKernelClient::with_pinned_ca(
        "https://kernel:9000".to_string(),
        "reaper-key".to_string(),
        std::time::Duration::from_secs(10),
        b"-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----",
    );
    // A bad CA must fail LOUD at construction (either the PEM parse rejects it
    // -> Malformed, or the TLS builder rejects it -> Unreachable). What must
    // NEVER happen is a silent Ok that falls back to an unpinned connection.
    assert!(
        matches!(
            client,
            Err(KernelClientError::Malformed(_) | KernelClientError::Unreachable(_))
        ),
        "a malformed pinned CA must be rejected loud, never a silent unpinned fallback; got {client:?}"
    );
}
