//! The Reaper state machine (F-6a): verify -> execute -> record-COMPLETION ->
//! record-kill. The durable `(nonce, run_id)` replay key is a COMPLETION
//! marker, burned ONLY after a confirmed successful stop — never an intent
//! marker set before the executor runs. That makes the kill switch
//! at-least-once: a transient executor error leaves the token pending so the
//! poll loop re-pulls and RETRIES (a double-stop is idempotent; a skipped stop
//! is not). Every path here is injectable (executor / nonce-store / kernel
//! client / kill-recorder) so the adversarial fixtures drive it entirely with a
//! `MockComputeExecutor` and real signed decisions — never a live stop.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use qorch_domain::safety::{
    restore_params_fingerprint, revoke_params_fingerprint, InstanceTarget, RestoreClaims,
    RevokeComputeClaims, REVOKE_COMPUTE_ACTION, REVOKE_COMPUTE_AUD, REVOKE_RESTORE_ACTION,
    REVOKE_RESTORE_AUD,
};
use qorch_domain::safety::{token_sha256, KernelTokenError, VerifiedClaims};
use qorch_safety_kernel_client::PinnedKeyVerifier;
use serde_json::Value;

use crate::executor::{ComputeExecutor, StopOutcome};
use crate::kernel_client::KernelClient;
use crate::nonce_store::{NonceKey, SeenNonceStore};
use crate::tlog::{KillRecord, KillRecorder};

/// Why a candidate decision was dropped without acting. Each maps 1:1 to an
/// adversarial fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// Signature did not verify against the pinned key (forged / tampered).
    ForgedSignature,
    /// `exp` in the past — a captured kill went stale.
    Expired,
    /// `aud` claim did not match the expected audience (cross-tenant replay).
    WrongAudience,
    /// The token was malformed or missing a required claim.
    MalformedClaims,
    /// The `action` claim was not the expected discriminator.
    ActionMismatch,
    /// `params_fingerprint` recomputed from the claims did not match the
    /// signed one (claimed target A, bound target B).
    FingerprintMismatch,
    /// This `(nonce, run_id)` was already recorded as a COMPLETED kill —
    /// replay of a finished decision.
    AlreadyExecuted,
    /// The executor itself refused / errored (e.g. disarmed, transient 503).
    /// No kill happened AND the replay key was NOT burned, so the poll loop
    /// re-pulls and RETRIES (F-6a: fail toward re-attempt, never suppress).
    ExecutorError(String),
}

/// The result of processing one candidate token (or a liveness timeout).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A verified kill executed exactly one `stop`.
    Executed {
        /// The revocation id.
        run_id: String,
        /// The executor outcome.
        outcome: StopOutcome,
    },
    /// A verified restore executed exactly one `start`.
    Restored {
        /// The restore id.
        run_id: String,
        /// The executor outcome.
        outcome: StopOutcome,
    },
    /// The kernel went dark past the liveness deadline; a fail-closed `stop`
    /// ran against the configured target.
    FailClosed {
        /// The executor outcome for the fail-closed stop.
        outcome: StopOutcome,
    },
    /// The candidate was dropped without acting.
    Rejected(RejectReason),
}

/// What the poll loop should do after a kernel-pull failure (F-6b). Extracted
/// from `main.rs` so the liveness/fail-closed decision is testable in-process
/// instead of buried in the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivenessAction {
    /// The kernel was unreachable but still WITHIN the liveness deadline — a
    /// benign blip. No fail-closed stop fired; keep waiting.
    WithinDeadline,
    /// The kernel has been dark PAST the deadline, so a fail-closed stop was
    /// attempted. `advance_liveness` is true ONLY when the stop actually
    /// succeeded (`Outcome::FailClosed`); on an executor error it is FALSE so
    /// the caller must NOT reset its liveness tracker and instead retries on
    /// the next poll (F-6b: never swallow a failed fail-closed stop).
    FailedClosed {
        /// The outcome of the fail-closed stop attempt.
        outcome: Outcome,
        /// Whether the caller may advance/reset its last-success tracker.
        advance_liveness: bool,
    },
}

/// Classify a `verify_with_aud` error into a reject reason (any verify failure
/// is a hard refuse, never a kill on an unverifiable token).
fn classify_verify_error(err: &KernelTokenError) -> RejectReason {
    match err {
        KernelTokenError::Expired(_) => RejectReason::Expired,
        KernelTokenError::Signature(_) => RejectReason::ForgedSignature,
        KernelTokenError::Claims(m) if m.0 == "invalid_audience" => RejectReason::WrongAudience,
        // missing_claim:aud, invalid_aud, and every other claim/format fault.
        KernelTokenError::Claims(_) | KernelTokenError::Format(_) => RejectReason::MalformedClaims,
    }
}

/// The privileged supervisor. Generic over nothing — everything is a trait
/// object so `main` and tests wire the same struct.
pub struct Reaper {
    /// Pinned kernel public verifying key wrapper (holds ONLY the public half).
    verifier: PinnedKeyVerifier,
    /// The one privileged capability — stop / start.
    executor: Arc<dyn ComputeExecutor>,
    /// Persistent seen-nonce store (replay defeat the kernel can't do).
    nonce_store: Arc<dyn SeenNonceStore>,
    /// The instance the Reaper watches + fail-closed-stops. In mock / scratch
    /// mode this is the disposable scratch instance, NEVER the live agent VM.
    target: InstanceTarget,
    /// How long the kernel may be unreachable before the fail-closed stop.
    liveness_deadline_s: f64,
    /// Optional durable kill-record sink (tlog). `None` = skip (best-effort).
    kill_recorder: Option<Arc<dyn KillRecorder>>,
    /// Optional kernel client for ack (queue hygiene). `None` = skip.
    kernel_client: Option<Arc<dyn KernelClient>>,
}

impl Reaper {
    /// Construct a Reaper. `kill_recorder` / `kernel_client` are optional so
    /// unit tests can omit them and assert executor behaviour in isolation.
    #[must_use]
    pub fn new(
        verifier: PinnedKeyVerifier,
        executor: Arc<dyn ComputeExecutor>,
        nonce_store: Arc<dyn SeenNonceStore>,
        target: InstanceTarget,
        liveness_deadline_s: f64,
        kill_recorder: Option<Arc<dyn KillRecorder>>,
        kernel_client: Option<Arc<dyn KernelClient>>,
    ) -> Self {
        Self {
            verifier,
            executor,
            nonce_store,
            target,
            liveness_deadline_s,
            kill_recorder,
            kernel_client,
        }
    }

    /// The instance this Reaper watches.
    #[must_use]
    pub fn target(&self) -> &InstanceTarget {
        &self.target
    }

    /// Has the kernel been unreachable long enough to fail closed?
    /// `last_success_s` is the last time a pull succeeded; `now_s` is now.
    #[must_use]
    pub fn liveness_expired(&self, last_success_s: f64, now_s: f64) -> bool {
        now_s - last_success_s > self.liveness_deadline_s
    }

    /// Parse a `RevokeComputeClaims` back out of a verified claims map. The map
    /// carries an extra `action` key (not a struct field); serde ignores it.
    fn parse_revoke_claims(vc: &VerifiedClaims) -> Option<RevokeComputeClaims> {
        let obj: serde_json::Map<String, Value> = vc.claims.clone().into_iter().collect();
        serde_json::from_value(Value::Object(obj)).ok()
    }

    /// Parse a `RestoreClaims` back out of a verified claims map.
    fn parse_restore_claims(vc: &VerifiedClaims) -> Option<RestoreClaims> {
        let obj: serde_json::Map<String, Value> = vc.claims.clone().into_iter().collect();
        serde_json::from_value(Value::Object(obj)).ok()
    }

    /// Read the raw `action` claim from a verified token (defence in depth —
    /// the signed payload always carries it).
    fn action_of(vc: &VerifiedClaims) -> Option<&str> {
        vc.claims.get("action").and_then(Value::as_str)
    }

    /// Peek the UNVERIFIED `action` claim from a compact token for ROUTING
    /// ONLY (F-obs). The routed handler performs the real pinned-signature +
    /// audience + fingerprint verification, so a lying or garbage `action`
    /// just routes to a path that then rejects it. This never trusts the
    /// peeked value to authorize anything — it only picks which verifier runs.
    fn peek_action(token: &str) -> Option<String> {
        let payload_b64 = token.split('.').next()?;
        let bytes = URL_SAFE_NO_PAD.decode(payload_b64.as_bytes()).ok()?;
        let v: Value = serde_json::from_slice(&bytes).ok()?;
        v.get("action").and_then(Value::as_str).map(str::to_string)
    }

    /// Dispatch one pending token by KIND (F-obs). The pending queue carries
    /// opaque signed tokens with no kind field, and the poll loop previously
    /// forced EVERY item through `handle_kill_candidate` — so an operator
    /// restore was verified under the KILL audience, rejected as
    /// `WrongAudience`, and NEVER `start()`ed (restore was a dead endpoint).
    ///
    /// Now a restore-`action` token routes to `handle_restore_candidate`
    /// (verify under `REVOKE_RESTORE_AUD` -> `start`) and everything else to
    /// `handle_kill_candidate` (verify under `REVOKE_COMPUTE_AUD` -> `stop`).
    /// Restore stays operator-only: the restore path still hard-verifies the
    /// pinned signature + restore audience, so a kill token routed here can
    /// never `start` and a forged restore can never `start` either.
    pub async fn handle_pending_candidate(&self, token: &str, now_s: f64) -> Outcome {
        if Self::peek_action(token).as_deref() == Some(REVOKE_RESTORE_ACTION) {
            self.handle_restore_candidate(token, now_s).await
        } else {
            self.handle_kill_candidate(token, now_s).await
        }
    }

    /// Process one candidate KILL token: verify -> fingerprint-bind ->
    /// nonce-unseen -> stop -> record-kill + ack.
    ///
    /// `now_s` is the wall-clock the caller sourced from its clock.
    pub async fn handle_kill_candidate(&self, token: &str, now_s: f64) -> Outcome {
        // 1. Pinned signature + audience + expiry.
        let verified = match self
            .verifier
            .verify_with_aud(token, now_s, REVOKE_COMPUTE_AUD)
        {
            Ok(v) => v,
            Err(e) => return Outcome::Rejected(classify_verify_error(&e)),
        };

        // 1b. action discriminator must be the kill action.
        if Self::action_of(&verified) != Some(REVOKE_COMPUTE_ACTION) {
            return Outcome::Rejected(RejectReason::ActionMismatch);
        }

        // 2. Decode the typed claims.
        let Some(claims) = Self::parse_revoke_claims(&verified) else {
            return Outcome::Rejected(RejectReason::MalformedClaims);
        };

        // 3. Recompute params_fingerprint from the DECODED claims and refuse on
        //    mismatch — this is what stops "claim target A, bind target B".
        let recomputed = revoke_params_fingerprint(
            &claims.run_id,
            &claims.target,
            claims.tier,
            claims.trigger,
            claims.reason.as_deref(),
        );
        if recomputed != claims.params_fingerprint {
            return Outcome::Rejected(RejectReason::FingerprintMismatch);
        }

        // 4. Replay defeat: the durable `(nonce, run_id)` key marks a COMPLETED
        //    kill. Re-presenting it after a confirmed stop is a replay -> drop.
        //    (A never-completed kill was never recorded, so a retry after a
        //    transient executor error is NOT blocked here — that is the fix.)
        let key = NonceKey::new(claims.nonce.clone(), claims.run_id.clone());
        if self.nonce_store.is_seen(&key) {
            return Outcome::Rejected(RejectReason::AlreadyExecuted);
        }

        // 5. EXECUTE the stop against the target BOUND IN THE TOKEN. On an
        //    executor error we return WITHOUT burning the nonce, so the token
        //    stays pending and the poll loop re-pulls + retries (at-least-once).
        let outcome = match self.executor.stop(&claims.target).await {
            Ok(o) => o,
            Err(e) => return Outcome::Rejected(RejectReason::ExecutorError(e.to_string())),
        };

        // 6. BURN the replay key ONLY NOW — after a confirmed successful stop
        //    (F-6a: completion marker, not intent marker). A durable-write
        //    failure here does not un-do the kill, so we still return Executed
        //    (truthful) and log loudly; the un-burned key just means a later
        //    replay would idempotently re-stop, never a suppressed kill.
        if let Err(e) = self.nonce_store.record(&key) {
            tracing::error!(
                run_id = %claims.run_id,
                error = %e,
                "replay-marker persist FAILED after a confirmed stop — a replay would idempotently re-stop"
            );
        }

        // 7. RECORD-KILL (durable tlog) + ACK (queue hygiene). Both best-effort.
        self.record_and_ack(
            "kill_executed",
            &claims.run_id,
            &claims.nonce,
            token,
            &claims.target,
            &outcome,
            now_s,
            "stopped",
        )
        .await;

        Outcome::Executed {
            run_id: claims.run_id,
            outcome,
        }
    }

    /// Process one candidate RESTORE token: verify with the RESTORE audience,
    /// fingerprint-bind, nonce-unseen, then `start`. An agent / worker-signed
    /// or unsigned restore fails verification -> no `start`.
    pub async fn handle_restore_candidate(&self, token: &str, now_s: f64) -> Outcome {
        let verified = match self
            .verifier
            .verify_with_aud(token, now_s, REVOKE_RESTORE_AUD)
        {
            Ok(v) => v,
            Err(e) => return Outcome::Rejected(classify_verify_error(&e)),
        };
        if Self::action_of(&verified) != Some(REVOKE_RESTORE_ACTION) {
            return Outcome::Rejected(RejectReason::ActionMismatch);
        }
        let Some(claims) = Self::parse_restore_claims(&verified) else {
            return Outcome::Rejected(RejectReason::MalformedClaims);
        };
        let recomputed =
            restore_params_fingerprint(&claims.run_id, &claims.target, claims.reason.as_deref());
        if recomputed != claims.params_fingerprint {
            return Outcome::Rejected(RejectReason::FingerprintMismatch);
        }
        let key = NonceKey::new(claims.nonce.clone(), claims.run_id.clone());
        if self.nonce_store.is_seen(&key) {
            return Outcome::Rejected(RejectReason::AlreadyExecuted);
        }
        // Same completion-marker discipline as the kill path (F-6a): only burn
        // the replay key after a confirmed successful start, so a transient
        // start error is retried on the next poll rather than suppressed.
        let outcome = match self.executor.start(&claims.target).await {
            Ok(o) => o,
            Err(e) => return Outcome::Rejected(RejectReason::ExecutorError(e.to_string())),
        };
        if let Err(e) = self.nonce_store.record(&key) {
            tracing::error!(
                run_id = %claims.run_id,
                error = %e,
                "restore replay-marker persist FAILED after a confirmed start — a replay would idempotently re-start"
            );
        }
        self.record_and_ack(
            "restore_executed",
            &claims.run_id,
            &claims.nonce,
            token,
            &claims.target,
            &outcome,
            now_s,
            "started",
        )
        .await;
        Outcome::Restored {
            run_id: claims.run_id,
            outcome,
        }
    }

    /// Fail CLOSED on suppression: the kernel has been unreachable past the
    /// liveness deadline, so stop the configured target. There is no token to
    /// verify here — the posture is "never assume fine".
    pub async fn fail_closed_stop(&self, now_s: f64) -> Outcome {
        match self.executor.stop(&self.target).await {
            Ok(outcome) => {
                // Best-effort durable record of the fail-closed kill. There is
                // no signed token, so token_sha256 is over a synthetic marker.
                let synthetic = format!("liveness_failclosed:{}", self.target.instance);
                self.record_and_ack(
                    "kill_executed_failclosed",
                    &format!("failclosed_{}", self.target.instance),
                    "liveness-deadline",
                    &synthetic,
                    &self.target,
                    &outcome,
                    now_s,
                    "stopped_failclosed",
                )
                .await;
                Outcome::FailClosed { outcome }
            }
            Err(e) => Outcome::Rejected(RejectReason::ExecutorError(e.to_string())),
        }
    }

    /// Decide what the poll loop does after a kernel PULL failure (F-6b). This
    /// is the testable core of `main.rs`'s error branch: within the deadline it
    /// is a blip; past the deadline it attempts a fail-closed stop and reports
    /// whether the liveness tracker may be advanced.
    ///
    /// Crucially, `advance_liveness` is true ONLY on a real
    /// `Outcome::FailClosed` — if the fail-closed stop itself errors, it stays
    /// FALSE so the caller keeps the deadline expired and RETRIES on the next
    /// poll instead of swallowing the error and waiting a full deadline.
    pub async fn on_kernel_pull_failure(&self, last_success_s: f64, now_s: f64) -> LivenessAction {
        if !self.liveness_expired(last_success_s, now_s) {
            return LivenessAction::WithinDeadline;
        }
        let outcome = self.fail_closed_stop(now_s).await;
        let advance_liveness = matches!(outcome, Outcome::FailClosed { .. });
        LivenessAction::FailedClosed {
            outcome,
            advance_liveness,
        }
    }

    /// Append the durable kill-record to the tlog and ack the kernel. Both are
    /// best-effort: the stop already happened, so a recorder/ack failure is
    /// logged, not fatal (ack fail-open; the tlog is the evidence).
    #[allow(clippy::too_many_arguments)]
    async fn record_and_ack(
        &self,
        kind: &str,
        run_id: &str,
        nonce: &str,
        token: &str,
        target: &InstanceTarget,
        outcome: &StopOutcome,
        now_s: f64,
        ack_outcome: &str,
    ) {
        if let Some(recorder) = self.kill_recorder.as_ref() {
            let occurred = now_s.max(0.0) as u64;
            let record = KillRecord::new(
                kind,
                run_id,
                nonce,
                &token_sha256(token),
                target,
                outcome,
                occurred,
            );
            if let Err(e) = recorder.record(&record).await {
                tracing::error!(run_id, error = %e, "kill-record append failed (kill already executed)");
            }
        }
        if let Some(client) = self.kernel_client.as_ref() {
            if let Err(e) = client.ack(run_id, ack_outcome).await {
                tracing::warn!(run_id, error = %e, "revoke ack failed (queue hygiene only)");
            }
        }
    }
}
