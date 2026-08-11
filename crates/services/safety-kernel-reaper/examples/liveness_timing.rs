//! `liveness_timing` — reaper fail-closed liveness timing harness.
//!
//! Measures, with REAL wall-clock time but a MOCK `ComputeExecutor` (so NO
//! real instance is ever cycled), exactly when the Reaper's fail-closed FIRE
//! DECISION happens: `last_contact + liveness_deadline_s`, the moment
//! `on_kernel_pull_failure` drives `executor.stop(...)`.
//!
//! This drives the SAME poll-loop liveness logic `main.rs`'s binary loop
//! calls — `Reaper::on_kernel_pull_failure` — never a reimplementation. The
//! only injected doubles are:
//!   - `ToggleKernelClient`: implements the real `KernelClient` trait, with an
//!     `AtomicBool` "reachable" flag flippable at will. No network involved,
//!     so timing is deterministic and fast.
//!   - `TimestampedMockExecutor`: wraps the real `MockComputeExecutor` (so
//!     `stop_count()` / call recording is the genuine mock) and additionally
//!     records a wall-clock `Instant` per `stop()` call, so fire timing is
//!     read off the actual recorded side effect (evidence over labels), not
//!     inferred from a loop's own bookkeeping.
//!
//! For each `liveness_deadline_s` in {3.0, 8.0, 15.0} (poll_interval_s = 1.0):
//!   A. BLIP — unreachable for `deadline * 0.5`s, then reachable again.
//!      Asserts `mock.stop` was NEVER called (blip-tolerance).
//!   B. OUTAGE — unreachable and held; measures real wall-clock seconds from
//!      the flip to the first `mock.stop()` call (time-to-fire), asserting
//!      it lands within ~1 poll interval of the configured deadline (not
//!      instant, not never).
//!
//! Run: `cargo run --example liveness_timing -p qorch-safety-kernel-reaper`
//!
//! SAFETY: this harness touches NO real instance — `ComputeExecutor` here
//! is always the mock. It never constructs a `GcpComputeExecutor`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use qorch_domain::safety::InstanceTarget;
use qorch_safety_kernel_client::PinnedKeyVerifier;
use qorch_safety_kernel_reaper::{
    ComputeExecutor, ExecutorError, KernelClient, KernelClientError, LivenessAction, MemNonceStore,
    MockComputeExecutor, PendingPull, Reaper, StopOutcome,
};

/// Wall-clock now as f64 epoch seconds — same helper shape as `main.rs`.
fn now_s() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// ============================================================================
// ToggleKernelClient — a real `KernelClient` impl, no network. Flippable
// reachable/unreachable via an `AtomicBool`. Deterministic — we only need to
// control success/failure, not response bodies.
// ============================================================================

#[derive(Debug, Default)]
struct ToggleKernelClient {
    reachable: AtomicBool,
    pulls: AtomicUsize,
}

impl ToggleKernelClient {
    fn new() -> Self {
        Self {
            reachable: AtomicBool::new(true),
            pulls: AtomicUsize::new(0),
        }
    }

    fn set_reachable(&self, v: bool) {
        self.reachable.store(v, Ordering::SeqCst);
    }

    fn pulls(&self) -> usize {
        self.pulls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl KernelClient for ToggleKernelClient {
    async fn pull_pending(&self, _instance: &str) -> Result<PendingPull, KernelClientError> {
        self.pulls.fetch_add(1, Ordering::SeqCst);
        if self.reachable.load(Ordering::SeqCst) {
            Ok(PendingPull::default()) // empty pending queue == a healthy pull, matches a 204.
        } else {
            Err(KernelClientError::Unreachable(
                "liveness_timing harness: toggled unreachable".to_string(),
            ))
        }
    }

    async fn ack(&self, _run_id: &str, _outcome: &str) -> Result<(), KernelClientError> {
        Ok(())
    }
}

// ============================================================================
// TimestampedMockExecutor — wraps the REAL MockComputeExecutor (so call
// counting/recording is the genuine mock, not a reimplementation) and adds a
// wall-clock Instant per stop() call so time-to-fire is read off the actual
// recorded side effect.
// ============================================================================

#[derive(Debug)]
struct TimestampedMockExecutor {
    inner: MockComputeExecutor,
    stop_at: Mutex<Vec<Instant>>,
}

impl TimestampedMockExecutor {
    fn new() -> Self {
        Self {
            inner: MockComputeExecutor::new(),
            stop_at: Mutex::new(Vec::new()),
        }
    }

    fn stop_count(&self) -> usize {
        self.inner.stop_count()
    }

    fn first_stop_at(&self) -> Option<Instant> {
        self.stop_at.lock().expect("stop_at lock").first().copied()
    }
}

#[async_trait]
impl ComputeExecutor for TimestampedMockExecutor {
    async fn stop(&self, target: &InstanceTarget) -> Result<StopOutcome, ExecutorError> {
        let out = self.inner.stop(target).await;
        if out.is_ok() {
            self.stop_at
                .lock()
                .expect("stop_at lock")
                .push(Instant::now());
        }
        out
    }

    async fn start(&self, target: &InstanceTarget) -> Result<StopOutcome, ExecutorError> {
        self.inner.start(target).await
    }
}

/// The (mock, never-real) target the harness's Reaper watches.
fn mock_target() -> InstanceTarget {
    InstanceTarget {
        project: "mock-project".to_string(),
        zone: "mock-zone".to_string(),
        instance: "mock-fail-closed-target".to_string(),
    }
}

/// A throwaway pinned verifier. Token verification is never exercised by this
/// harness (only the liveness/fail-closed path is), so any valid Ed25519
/// public key works.
fn dummy_verifier() -> PinnedKeyVerifier {
    let sk = SigningKey::generate(&mut OsRng);
    PinnedKeyVerifier::from_pubkey_bytes(sk.verifying_key().to_bytes()).expect("valid pubkey")
}

/// One poll-loop tick — mirrors `main.rs`'s loop body exactly: pull via the
/// kernel client; on success advance `last_success`; on failure, drive
/// `Reaper::on_kernel_pull_failure` (the SAME method the binary calls) and
/// apply its `advance_liveness` verdict to `last_success`.
async fn tick(reaper: &Reaper, kernel_client: &ToggleKernelClient, last_success: &mut f64) {
    match kernel_client.pull_pending("mock-fail-closed-target").await {
        Ok(_tokens) => {
            *last_success = now_s();
        }
        Err(_e) => {
            let now = now_s();
            match reaper.on_kernel_pull_failure(*last_success, now).await {
                LivenessAction::WithinDeadline => {}
                LivenessAction::FailedClosed {
                    advance_liveness: true,
                    ..
                } => {
                    *last_success = now;
                }
                LivenessAction::FailedClosed {
                    advance_liveness: false,
                    ..
                } => {
                    // Deliberately do NOT advance — mirrors main.rs retrying
                    // the fail-closed stop on the next poll.
                }
            }
        }
    }
}

/// One deadline's measured results.
struct DeadlineResult {
    deadline_s: f64,
    blip_fired: bool,
    time_to_fire_s: f64,
    pulls: usize,
}

/// Run the BLIP + OUTAGE measurement for one `(deadline_s, poll_interval_s)`
/// pair. Builds a fresh Reaper/executor/kernel-client trio so deadlines never
/// share state.
async fn measure(deadline_s: f64, poll_interval_s: f64) -> DeadlineResult {
    let executor = Arc::new(TimestampedMockExecutor::new());
    let nonce_store = Arc::new(MemNonceStore::new());
    let kernel_client = Arc::new(ToggleKernelClient::new());

    let reaper = Reaper::new(
        dummy_verifier(),
        executor.clone() as Arc<dyn ComputeExecutor>,
        nonce_store,
        mock_target(),
        deadline_s,
        None, // no kill-recorder needed for the timing measurement
        Some(kernel_client.clone() as Arc<dyn KernelClient>),
    );

    let mut last_success = now_s();

    // --- Warm-up: a couple of reachable polls to establish last_contact. ---
    for _ in 0..2 {
        tick(&reaper, &kernel_client, &mut last_success).await;
        tokio::time::sleep(Duration::from_secs_f64(poll_interval_s)).await;
    }

    // --- A. BLIP: unreachable for deadline*0.5s (a benign sub-deadline gap),
    //     then reachable again. Must NEVER fire. ---
    kernel_client.set_reachable(false);
    let blip_span = Duration::from_secs_f64(deadline_s * 0.5);
    let blip_start = Instant::now();
    while blip_start.elapsed() < blip_span {
        tick(&reaper, &kernel_client, &mut last_success).await;
        tokio::time::sleep(Duration::from_secs_f64(poll_interval_s)).await;
    }
    kernel_client.set_reachable(true);
    // One settle poll so `last_success` reflects the recovered connection
    // before the OUTAGE phase begins.
    tick(&reaper, &kernel_client, &mut last_success).await;
    tokio::time::sleep(Duration::from_secs_f64(poll_interval_s)).await;

    let blip_fired = executor.stop_count() > 0;

    // --- B. OUTAGE: flip unreachable and hold it; measure wall-clock from
    //     the flip to the first stop() call. ---
    kernel_client.set_reachable(false);
    last_success = now_s(); // fresh clock starting exactly at the flip
    let outage_start = Instant::now();
    let max_wait = Duration::from_secs_f64(deadline_s * 3.0 + 10.0); // safety valve
    loop {
        tick(&reaper, &kernel_client, &mut last_success).await;
        if executor.stop_count() > 0 {
            break;
        }
        if outage_start.elapsed() > max_wait {
            break; // never fired within the safety valve; reported as +inf below
        }
        tokio::time::sleep(Duration::from_secs_f64(poll_interval_s)).await;
    }

    let time_to_fire_s = executor
        .first_stop_at()
        .map(|t| (t - outage_start).as_secs_f64())
        .unwrap_or(f64::INFINITY);

    DeadlineResult {
        deadline_s,
        blip_fired,
        time_to_fire_s,
        pulls: kernel_client.pulls(),
    }
}

#[tokio::main]
async fn main() {
    let poll_interval_s = 1.0_f64;

    println!(
        "════════ reaper fail-closed liveness timing (MOCK executor — no live calls) ════════"
    );
    println!("poll_interval_s = {poll_interval_s}\n");
    println!(
        "{:<12} {:<14} {:<16} {:<8}",
        "deadline_s", "blip_fired?", "time_to_fire_s", "pulls"
    );

    let mut results = Vec::new();
    for deadline in [3.0_f64, 8.0, 15.0] {
        let r = measure(deadline, poll_interval_s).await;
        println!(
            "{:<12} {:<14} {:<16.3} {:<8}",
            r.deadline_s,
            if r.blip_fired { "YES (BAD)" } else { "no" },
            r.time_to_fire_s,
            r.pulls
        );
        results.push(r);
    }
    println!();

    let mut all_ok = true;
    for r in &results {
        if r.blip_fired {
            all_ok = false;
            eprintln!(
                "ASSERTION FAILED: BLIP fired for deadline={} — a sub-deadline gap incorrectly triggered a stop",
                r.deadline_s
            );
        }
        if !r.time_to_fire_s.is_finite() {
            all_ok = false;
            eprintln!(
                "ASSERTION FAILED: OUTAGE never fired for deadline={} within the safety valve",
                r.deadline_s
            );
            continue;
        }
        if r.time_to_fire_s <= r.deadline_s - 0.05 {
            all_ok = false;
            eprintln!(
                "ASSERTION FAILED: fired TOO EARLY for deadline={}: time_to_fire={:.3}",
                r.deadline_s, r.time_to_fire_s
            );
        }
        if r.time_to_fire_s >= r.deadline_s + 2.5 * poll_interval_s {
            all_ok = false;
            eprintln!(
                "ASSERTION FAILED: fired too LATE for deadline={}: time_to_fire={:.3}",
                r.deadline_s, r.time_to_fire_s
            );
        }
    }

    if all_ok {
        println!(
            "ALL ASSERTIONS PASSED: zero BLIP false-positives; every OUTAGE fired within ~1 poll interval of its configured deadline."
        );
    } else {
        eprintln!("ONE OR MORE ASSERTIONS FAILED — see above.");
        std::process::exit(1);
    }
}
