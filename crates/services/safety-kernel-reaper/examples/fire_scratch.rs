//! `fire_scratch` — the one-shot "fire" harness (Phase 1).
//!
//! Demonstrates, END TO END, the control-plane Reaper coercively STOPPING (and
//! STARTING) a *disposable SCRATCH* cloud instance from a REAL operator-signed
//! `RevokeCompute` / `Restore` decision — driving the SAME verify -> execute
//! state machine the service runs, with the SAME live `GcpComputeExecutor`.
//!
//! Everything here is config-driven: the scratch coordinate and the protected
//! coordinate come from env vars (with generic placeholder defaults), so this
//! carries NO project-specific host names.
//!
//! What is genuine here (nothing is faked):
//!   1. A fresh Ed25519 keypair is generated in-process. In prod the Reaper pins
//!      the REAL kernel signing key; for this demo the harness plays the kernel,
//!      so we pin the demo PUBLIC key — the pinned-signature verify path is real.
//!   2. A REAL `RevokeComputeClaims` (all seven canonical claims + the revoke
//!      extras) is minted with the domain `sign_kernel_token` helper, its
//!      `params_fingerprint` binding the target, a fresh nonce, and a short exp.
//!   3. The Reaper is constructed against the ARMED live `GcpComputeExecutor`
//!      whose single scratch coordinate == the target, a durable `FileNonceStore`,
//!      and no-op (None) kill-recorder / kernel-client.
//!   4. `handle_kill_candidate` / `handle_restore_candidate` run for real: pinned
//!      signature -> audience -> expiry -> action -> fingerprint-rebind -> replay
//!      -> live `compute.instances.stop` / `.start` via the metadata token.
//!
//! SAFETY: the ONLY instance this can ever act on is the scratch target below.
//! The executor's self-protection denylist (a configured protected coordinate)
//! is never overridden, and its scratch allowlist refuses any other coordinate.
//! The live call fires ONLY when armed (default here) AND `--dry` is absent.
//!
//! # Happy-path modes
//!
//! Usage:
//!   cargo run --example fire_scratch -p qorch-safety-kernel-reaper -- stop
//!   cargo run --example fire_scratch -p qorch-safety-kernel-reaper -- start
//!   cargo run --example fire_scratch -p qorch-safety-kernel-reaper -- stop --dry
//!
//! `--dry` builds the executor DISARMED: the Reaper still fully VERIFIES the
//! signed decision and reaches the executor, which returns `LiveArmingGated`
//! WITHOUT any network call — proving the signed-decision -> verify -> execute
//! path is wired and only arming is left. No VM is touched in a `--dry` run.
//!
//! # Adversarial modes (armed-reaper adversarial confirmation)
//!
//! Each of the four modes below builds the SAME armed `GcpComputeExecutor`
//! (scratch = the configured scratch instance, plus a configured protected
//! coordinate) and drives the real verify -> execute path with a hostile input.
//! Every one of them MUST be refused before any live cloud call — that refusal,
//! not a live stop, is the expected (passing) result:
//!
//!   cargo run --example fire_scratch -p qorch-safety-kernel-reaper -- kill-protected
//!   cargo run --example fire_scratch -p qorch-safety-kernel-reaper -- forged
//!   cargo run --example fire_scratch -p qorch-safety-kernel-reaper -- expired
//!   cargo run --example fire_scratch -p qorch-safety-kernel-reaper -- wrong-target
//!
//! - `kill-protected`: a VALIDLY signed kill (correct pinned key, correct aud/
//!   exp/fingerprint) whose TARGET is a configured PROTECTED coordinate. The
//!   Reaper VERIFIES it fine — the signature is genuine — but the executor's
//!   GUARD 0 self-protection denylist refuses with `ForbiddenTarget` before any
//!   network call. THIS IS THE KEY TEST: a legitimately-signed kill for a
//!   protected host must still be refused.
//! - `forged`: a kill at the scratch target signed with a DIFFERENT (attacker)
//!   Ed25519 key the Reaper is NOT pinned to. Rejected at verification
//!   (`ForgedSignature`) — the executor is never reached.
//! - `expired`: a correct-key kill at the scratch target whose `exp` is
//!   already in the past. Rejected at verification (`Expired`) — the executor
//!   is never reached.
//! - `wrong-target`: a correct-key kill targeting an instance that is neither
//!   the protected coordinate nor the scratch target. The Reaper verifies it
//!   fine, but the executor's scratch ALLOWLIST (GUARD 3) refuses with
//!   `RefusedNonScratchTarget` before any network call.
//!
//! `--dry` is accepted by the adversarial modes too (builds the executor
//! disarmed). For `kill-protected`/`forged`/`expired` the refusal happens at
//! the SAME guard regardless of arming (the denylist check and the verify-layer
//! rejects both run before the armed check), so `--dry` reproduces the exact
//! expected `RejectReason`. For `wrong-target`, disarmed short-circuits at
//! GUARD 1 (`LiveArmingGated`) before reaching the scratch-allowlist guard, so
//! `--dry wrong-target` proves "no network call" but not the specific
//! `RefusedNonScratchTarget` reason — that requires the armed run.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use uuid::Uuid;

use qorch_domain::safety::{
    restore_params_fingerprint, revoke_params_fingerprint, sign_kernel_token, token_sha256,
    InstanceTarget, RestoreClaims, RevocationTier, RevokeComputeClaims, RevokeTrigger,
    REVOKE_COMPUTE_AUD, REVOKE_RESTORE_AUD,
};
use qorch_safety_kernel_client::PinnedKeyVerifier;
use qorch_safety_kernel_reaper::{
    FileNonceStore, GcpComputeExecutor, Outcome, ProtectedCoord, Reaper, RejectReason,
};

/// Read an env var with a generic placeholder fallback so the harness carries
/// no project-specific names by default.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Short TTL for the minted decision (seconds) — a kill goes stale fast.
const TOKEN_TTL_S: f64 = 120.0;
/// Liveness deadline for the Reaper (irrelevant to the explicit-token path here;
/// generous so nothing fail-closes during the demo).
const LIVENESS_DEADLINE_S: f64 = 3_600.0;

/// The scratch target coordinate — the ONLY instance this demo may stop/start.
/// Config-driven via `REAPER_SCRATCH_*` with generic placeholder defaults.
fn scratch_target() -> InstanceTarget {
    InstanceTarget {
        project: env_or("REAPER_SCRATCH_PROJECT", "example-project"),
        zone: env_or("REAPER_SCRATCH_ZONE", "zone-a"),
        instance: env_or("REAPER_SCRATCH_INSTANCE", "reaper-scratch-target"),
    }
}

/// A configured PROTECTED coordinate (for `kill-protected`). Config-driven via
/// `REAPER_DEMO_PROTECTED_*` with generic placeholder defaults. The executor is
/// built with this on its self-protection denylist, so a validly-signed kill
/// aimed here is refused by GUARD 0.
fn protected_target() -> InstanceTarget {
    InstanceTarget {
        project: env_or("REAPER_DEMO_PROTECTED_PROJECT", "protected-project"),
        zone: env_or("REAPER_DEMO_PROTECTED_ZONE", "zone-a"),
        instance: env_or("REAPER_DEMO_PROTECTED_INSTANCE", "protected-host"),
    }
}

/// A third, unrelated instance (for `wrong-target`) — same project/zone as
/// the scratch target so ONLY the instance name differs.
fn other_target() -> InstanceTarget {
    let s = scratch_target();
    InstanceTarget {
        project: s.project,
        zone: s.zone,
        instance: "some-other-vm".to_string(),
    }
}

/// Wall-clock now as f64 epoch seconds.
fn now_s() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs_f64()
}

/// Mint a REAL `RevokeCompute` kill token for `target`, signed by `sk`, with
/// `issued_at = iat` and `expires_at = iat + TOKEN_TTL_S`. This is the single
/// minting primitive every kill mode (happy-path and adversarial) goes
/// through — only the signing key / target / `iat` vary between modes.
fn mint_kill_for(sk: &SigningKey, target: InstanceTarget, iat: f64) -> (String, f64) {
    let run_id = format!("revoke_{}", Uuid::now_v7());
    let nonce = format!("revoke-nonce-{}", Uuid::now_v7());
    let reason = Some("fire_scratch harness".to_string());

    // params_fingerprint BINDS target/tier/trigger/reason into the signature —
    // the Reaper recomputes this and refuses on any mismatch.
    let fp = revoke_params_fingerprint(
        &run_id,
        &target,
        0,
        RevocationTier::VmStop,
        RevokeTrigger::OperatorEmergencyStop,
        reason.as_deref(),
    );
    let claims = RevokeComputeClaims {
        aud: REVOKE_COMPUTE_AUD.to_string(),
        run_id,
        subject: "operator".to_string(),
        params_fingerprint: fp,
        issued_at: iat,
        expires_at: iat + TOKEN_TTL_S,
        nonce,
        target,
        target_generation: 0,
        tier: RevocationTier::VmStop,
        trigger: RevokeTrigger::OperatorEmergencyStop,
        reason,
    };
    (sign_kernel_token(&claims, sk), iat)
}

/// Mint a REAL, valid, non-expired kill token for the scratch target, signed
/// by the operator key the Reaper is pinned to (the `stop` happy path).
fn mint_kill(sk: &SigningKey) -> (String, f64) {
    mint_kill_for(sk, scratch_target(), now_s())
}

/// Mint a REAL operator-signed restore token for the scratch target.
fn mint_restore(sk: &SigningKey) -> (String, f64) {
    let target = scratch_target();
    let run_id = format!("restore_{}", Uuid::now_v7());
    let nonce = format!("restore-nonce-{}", Uuid::now_v7());
    let reason = Some("fire_scratch demo — operator restore".to_string());
    let iat = now_s();

    let fp = restore_params_fingerprint(&run_id, &target, reason.as_deref());
    let claims = RestoreClaims {
        aud: REVOKE_RESTORE_AUD.to_string(),
        run_id,
        subject: "operator".to_string(),
        params_fingerprint: fp,
        issued_at: iat,
        expires_at: iat + TOKEN_TTL_S,
        nonce,
        target,
        reason,
    };
    (sign_kernel_token(&claims, sk), iat)
}

/// Print a human-readable verdict for one Reaper `Outcome`.
fn report(mode: &str, outcome: &Outcome) {
    println!("\n──────── REAPER OUTCOME ({mode}) ────────");
    println!("{outcome:?}");
    match outcome {
        Outcome::Executed { run_id, outcome } => {
            println!("  reaper VERIFIED signed decision : YES");
            println!("  executor CALLED live stop       : YES");
            println!("  run_id                          : {run_id}");
            println!("  cloud op_id                     : {}", outcome.op_id);
            println!("  instance                        : {}", outcome.instance);
            println!("  prev_state (P1 reports UNKNOWN) : {}", outcome.prev_state);
        }
        Outcome::Restored { run_id, outcome } => {
            println!("  reaper VERIFIED signed decision : YES");
            println!("  executor CALLED live start      : YES");
            println!("  run_id                          : {run_id}");
            println!("  cloud op_id                     : {}", outcome.op_id);
            println!("  instance                        : {}", outcome.instance);
            println!("  prev_state (P1 reports UNKNOWN) : {}", outcome.prev_state);
        }
        Outcome::Rejected(RejectReason::ExecutorError(msg)) => {
            println!("  reaper VERIFIED signed decision : YES (passed signature/aud/expiry/action/fingerprint/replay)");
            println!("  executor CALLED live {mode:<11}: NO");
            println!("  executor refusal                : {msg}");
            println!(
                "  -> the signed-decision -> verify -> execute path is WIRED; the executor's own guard refused the live call BEFORE any cloud call."
            );
        }
        Outcome::Rejected(reason) => {
            println!("  reaper VERIFIED signed decision : NO");
            println!("  reject reason                   : {reason:?}");
            println!("  executor CALLED live {mode:<11}: NO");
        }
        Outcome::FailClosed { outcome } => {
            println!(
                "  fail-closed stop fired          : op_id={}",
                outcome.op_id
            );
        }
    }
}

/// Print the compact machine-greppable `RESULT:` line every mode ends with.
fn print_result_line(mode: &str, outcome: &Outcome) {
    let (reaper_verified, executor_called_live) = match outcome {
        Outcome::Executed { .. } | Outcome::Restored { .. } => (true, true),
        Outcome::FailClosed { .. } => (true, true),
        // The envelope verified; the executor's own guard refused the call
        // before any network attempt (ForbiddenTarget, RefusedNonScratchTarget,
        // LiveArmingGated, NoScratchTarget, or a live backend error).
        Outcome::Rejected(RejectReason::ExecutorError(_)) => (true, false),
        // Verification itself failed (ForgedSignature, Expired, WrongAudience,
        // MalformedClaims, ActionMismatch, FingerprintMismatch, AlreadyExecuted)
        // — the executor is never reached at all.
        Outcome::Rejected(_) => (false, false),
    };
    println!(
        "\nRESULT: {mode} -> reaper_verified={} executor_called_live={} outcome={outcome:?}",
        if reaper_verified { "y" } else { "n" },
        if executor_called_live { "y" } else { "n" },
    );
}

#[tokio::main]
async fn main() {
    // ---- CLI: <stop|start|kill-protected|forged|expired|wrong-target> [--dry] ----
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dry = args.iter().any(|a| a == "--dry");
    let mode = args
        .iter()
        .find(|a| {
            matches!(
                a.as_str(),
                "stop" | "start" | "kill-protected" | "forged" | "expired" | "wrong-target"
            )
        })
        .cloned()
        .unwrap_or_else(|| {
            eprintln!(
                "usage: fire_scratch <stop|start|kill-protected|forged|expired|wrong-target> [--dry]"
            );
            std::process::exit(2);
        });

    // ---- 1. Fresh Ed25519 keypairs. `operator_key` is the one the Reaper is
    //         pinned to (this run plays the kernel signing key). `attacker_key`
    //         is a SECOND, unrelated key — used ONLY by `forged` to mint a
    //         token the Reaper is NOT pinned to. ----
    let operator_key = SigningKey::generate(&mut OsRng);
    let attacker_key = SigningKey::generate(&mut OsRng);
    let pubkey_bytes = operator_key.verifying_key().to_bytes();

    // ---- 3. Reaper pinned to the DEMO public key, ARMED live executor on the
    //         scratch coordinate (disarmed under --dry) with a configured
    //         protected coordinate on the self-protection denylist, durable
    //         nonce store, no-op (None) recorder/kernel-client. Every mode —
    //         happy-path AND adversarial — builds the SAME armed executor on
    //         the SAME scratch coordinate; only the minted token differs. ----
    let armed = !dry;
    let target = scratch_target();
    let protected = protected_target();
    let executor = GcpComputeExecutor::new(armed, Some(target.clone())).with_protected(vec![
        ProtectedCoord::new(protected.project.clone(), protected.instance.clone()),
    ]);
    let verifier =
        PinnedKeyVerifier::from_pubkey_bytes(pubkey_bytes).expect("demo pubkey is valid Ed25519");
    let pinned_fingerprint = verifier.fingerprint().to_string();

    let nonce_path = std::env::temp_dir().join(format!(
        "reaper_fire_scratch_nonces_{}_{mode}.log",
        std::process::id()
    ));
    let nonce_store = FileNonceStore::open(&nonce_path).expect("open temp nonce store");

    let reaper = Reaper::new(
        verifier,
        Arc::new(executor),
        Arc::new(nonce_store),
        target.clone(),
        LIVENESS_DEADLINE_S,
        None, // no-op kill-recorder (fine for the demo)
        None, // no-op kernel-client (no ack)
    );

    println!("════════ fire_scratch harness ════════");
    println!(
        "mode                 : {}",
        if dry {
            "DRY (executor DISARMED)"
        } else {
            "ARMED (LIVE)"
        }
    );
    println!("cli mode             : {mode}");
    println!(
        "scratch target       : {}/{}/{}",
        target.project, target.zone, target.instance
    );
    println!(
        "protected (denylist) : {}/{}",
        protected.project, protected.instance
    );
    println!("reaper watch target  : {}", reaper.target().instance);
    println!("pinned demo key fp   : {pinned_fingerprint}");

    // ---- 2 + 4. Mint the signed decision (real or adversarial) and drive the
    //             genuine handler — never a stub. ----
    let outcome = match mode.as_str() {
        "stop" => {
            let (token, minted_at) = mint_kill(&operator_key);
            println!("minted kill token sha256 : {}", token_sha256(&token));
            reaper.handle_kill_candidate(&token, 0, minted_at).await
        }
        "start" => {
            let (token, minted_at) = mint_restore(&operator_key);
            println!("minted restore token sha256: {}", token_sha256(&token));
            reaper.handle_restore_candidate(&token, minted_at).await
        }
        "kill-protected" => {
            // VALID key, VALID everything — the ONLY thing wrong is the target:
            // a configured PROTECTED coordinate. The Reaper's signature/aud/exp/
            // fingerprint checks all pass; only the executor's GUARD 0
            // self-protection denylist stands between this and a live stop.
            let (token, minted_at) = mint_kill_for(&operator_key, protected_target(), now_s());
            println!(
                "minted kill token sha256 (TARGET = PROTECTED, {}): {}",
                protected_target().instance,
                token_sha256(&token)
            );
            reaper.handle_kill_candidate(&token, 0, minted_at).await
        }
        "forged" => {
            // Correct target, correct claims shape — signed with a key the
            // Reaper is NOT pinned to.
            let (token, minted_at) = mint_kill_for(&attacker_key, scratch_target(), now_s());
            println!(
                "minted kill token sha256 (SIGNED BY ATTACKER KEY, NOT the pinned operator key): {}",
                token_sha256(&token)
            );
            reaper.handle_kill_candidate(&token, 0, minted_at).await
        }
        "expired" => {
            // Correct key, correct target — `exp` already elapsed. Mint with
            // `iat` far enough in the past that `iat + TOKEN_TTL_S` is well
            // before the ACTUAL wall-clock we verify against below.
            let stale_iat = now_s() - TOKEN_TTL_S - 3_600.0;
            let (token, _stale_minted_at) =
                mint_kill_for(&operator_key, scratch_target(), stale_iat);
            println!("minted kill token sha256 (EXPIRED, exp was {TOKEN_TTL_S}s past an issued_at 1h ago): {}", token_sha256(&token));
            // Verify at the REAL current wall-clock, not the stale mint time,
            // so the expiry check actually fires.
            reaper.handle_kill_candidate(&token, 0, now_s()).await
        }
        "wrong-target" => {
            // Correct key, correct claims shape — target is neither the
            // protected coordinate nor the configured scratch instance.
            let (token, minted_at) = mint_kill_for(&operator_key, other_target(), now_s());
            println!(
                "minted kill token sha256 (TARGET = NEITHER protected nor scratch, {}): {}",
                other_target().instance,
                token_sha256(&token)
            );
            reaper.handle_kill_candidate(&token, 0, minted_at).await
        }
        _ => unreachable!("CLI parsing only accepts the six known modes"),
    };

    report(&mode, &outcome);
    print_result_line(&mode, &outcome);
    println!("\n(nonce store: {})", nonce_path.display());
}
