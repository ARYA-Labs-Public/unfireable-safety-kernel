//! Circuit breaker for the Safety Kernel client.
//!
//! The state machine itself is pure (`qorch_domain::safety::CircuitState`).
//! This adapter file is the *driver* — it tracks consecutive failures
//! against a `Clock` and decides whether to forbid the next call.
//!
//! FAIL-CLOSED invariant: while `state == Open`, `before_call()` returns
//! `Err(KernelClientError::Decision(KernelDecisionError::Unavailable))` — the caller MUST refuse the
//! operation rather than treat the missing kernel response as
//! permissive.
//!
//!   Step 5 — audit hardening against ADR §6:
//! 1. HalfOpen single-probe gate (exactly ONE probe in flight; contended
//!    callers receive `Err(Unavailable)` immediately — they do NOT
//!    queue and they do NOT block).
//! 2. `tracing::info!` log emitted on every state transition for the
//!    transparency log; sensitive payloads (API keys, claim contents)
//!    are deliberately NOT included.
//! 3. There is no code path in this file that constructs
//!    `KernelDecision::Allow` — that constructor is gated by
//!    `VerifiedClaims` and lives only in `client.rs`.

use std::sync::Mutex;

use qorch_domain::safety::{CircuitConfig, CircuitState, CircuitTransition, Clock};

//   Step 2 — KernelError replaced by KernelClientError;
// the Unavailable signal is now nested under KernelDecisionError per
// Addendum 2a §4.
use super::types::{KernelClientError, KernelDecisionError};

/// Stateful breaker. `Mutex` is sufficient because the breaker is only
/// touched on the request path (low contention, no async-across-await
/// requirements for the lock held).
pub struct CircuitBreaker {
    config: CircuitConfig,
    clock: Box<dyn Clock>,
    state: Mutex<BreakerState>,
}

struct BreakerState {
    current: CircuitState,
    consecutive_failures: u32,
    opened_at_epoch_seconds: Option<f64>,
    transitions: Vec<CircuitTransition>,
    /// HalfOpen single-probe gate. Set true when a HalfOpen probe has
    /// been issued to a caller; cleared on the next `record_success` or
    /// `record_failure`. While true, concurrent callers to
    /// `before_call()` in HalfOpen receive `Err(Unavailable)` rather
    /// than racing into a second probe.
    probe_in_flight: bool,
}

/// Human-readable label for a `CircuitState`, used in transition log
/// lines. Keeping this local avoids requiring `Display` on the domain
/// enum (which would couple pure types to formatting decisions).
fn state_label(s: CircuitState) -> &'static str {
    match s {
        CircuitState::Closed => "Closed",
        CircuitState::Open => "Open",
        CircuitState::HalfOpen => "HalfOpen",
    }
}

impl CircuitBreaker {
    /// Construct a new breaker with the given config and clock.
    /// Adapter-side: a production caller passes `Box::new(SystemClock)`
    /// (`crates/adapters/src/clock.rs`); tests inject a fixed clock.
    #[must_use]
    pub fn new(config: CircuitConfig, clock: Box<dyn Clock>) -> Self {
        Self {
            config,
            clock,
            state: Mutex::new(BreakerState {
                current: CircuitState::Closed,
                consecutive_failures: 0,
                opened_at_epoch_seconds: None,
                transitions: Vec::new(),
                probe_in_flight: false,
            }),
        }
    }

    /// Returns the current state. Used by audit logging.
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned (i.e. a previous holder panicked
    /// while holding the lock). The breaker is single-purpose; this is an
    /// invariant, not a recoverable condition.
    #[must_use]
    pub fn state(&self) -> CircuitState {
        self.state.lock().expect("breaker mutex poisoned").current
    }

    /// Gate called before every outbound kernel HTTP call.
    ///
    /// Returns `Ok(())` if the call is permitted, `Err(Unavailable)`
    /// if the breaker is `Open` and cooldown has not elapsed.
    ///
    /// # Errors
    ///
    /// Returns `KernelClientError::Decision(KernelDecisionError::Unavailable)`
    /// while the breaker is `Open` and the cooldown window has not
    /// elapsed — this is the FAIL-CLOSED structural invariant.
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned (see `state` for context).
    pub fn before_call(&self) -> Result<(), KernelClientError> {
        let now = self.clock.now();
        let mut st = self.state.lock().expect("breaker mutex poisoned");
        match st.current {
            CircuitState::Closed => Ok(()),
            CircuitState::HalfOpen => {
                // ADR §6 HalfOpen single-probe gate: exactly ONE probe
                // may be in flight at a time. Concurrent callers receive
                // `Err(Unavailable)` immediately — they do NOT queue
                // and they do NOT block.
                if st.probe_in_flight {
                    Err(KernelClientError::Decision(KernelDecisionError::Unavailable {
                        reason: "circuit half-open probe in flight".to_string(),
                    }))
                } else {
                    st.probe_in_flight = true;
                    Ok(())
                }
            }
            CircuitState::Open => {
                let opened = st.opened_at_epoch_seconds.unwrap_or(now);
                if now - opened >= self.config.cooldown_seconds {
                    // Transition Open -> HalfOpen, allow probe.
                    let prev = st.current;
                    let failure_count = st.consecutive_failures;
                    st.current = CircuitState::HalfOpen;
                    st.probe_in_flight = true;
                    st.transitions.push(CircuitTransition {
                        from: prev,
                        to: CircuitState::HalfOpen,
                        at_epoch_seconds: now,
                        failure_count,
                    });
                    tracing::info!(
                        "circuit breaker {} -> {} (consecutive_failures={})",
                        state_label(prev),
                        state_label(CircuitState::HalfOpen),
                        failure_count,
                    );
                    Ok(())
                } else {
                    Err(KernelClientError::Decision(KernelDecisionError::Unavailable {
                        reason: format!(
                            "circuit breaker open ({:.1}s remaining in cooldown)",
                            self.config.cooldown_seconds - (now - opened)
                        ),
                    }))
                }
            }
        }
    }

    /// Record a successful call outcome.
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn record_success(&self) {
        let now = self.clock.now();
        let mut st = self.state.lock().expect("breaker mutex poisoned");
        let prev = st.current;
        st.consecutive_failures = 0;
        // Outcome observed — release the HalfOpen probe gate regardless
        // of whether the breaker was actually mid-probe (record_success
        // can also be called from Closed; clearing is idempotent).
        st.probe_in_flight = false;
        if prev != CircuitState::Closed {
            st.current = CircuitState::Closed;
            st.opened_at_epoch_seconds = None;
            st.transitions.push(CircuitTransition {
                from: prev,
                to: CircuitState::Closed,
                at_epoch_seconds: now,
                failure_count: 0,
            });
            tracing::info!(
                "circuit breaker {} -> {} (consecutive_failures=0)",
                state_label(prev),
                state_label(CircuitState::Closed),
            );
        }
    }

    /// Record a failed call outcome (timeout, 5xx, transport error).
    /// May trip the breaker into `Open`.
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn record_failure(&self) {
        let now = self.clock.now();
        let mut st = self.state.lock().expect("breaker mutex poisoned");
        st.consecutive_failures = st.consecutive_failures.saturating_add(1);
        let prev = st.current;
        // Outcome observed — release the HalfOpen probe gate. A failed
        // probe re-opens the breaker (see should_open below); a failed
        // call in Closed state does not own a probe slot, so clearing
        // is a no-op there.
        st.probe_in_flight = false;
        let should_open = match prev {
            CircuitState::Closed => st.consecutive_failures >= self.config.failure_threshold,
            CircuitState::HalfOpen => true,
            CircuitState::Open => false,
        };
        if should_open {
            st.current = CircuitState::Open;
            st.opened_at_epoch_seconds = Some(now);
            let failure_count = st.consecutive_failures;
            st.transitions.push(CircuitTransition {
                from: prev,
                to: CircuitState::Open,
                at_epoch_seconds: now,
                failure_count,
            });
            tracing::info!(
                "circuit breaker {} -> {} (consecutive_failures={})",
                state_label(prev),
                state_label(CircuitState::Open),
                failure_count,
            );
        }
    }

    /// Drain audit transitions (used by tests + transparency log).
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn drain_transitions(&self) -> Vec<CircuitTransition> {
        let mut st = self.state.lock().expect("breaker mutex poisoned");
        std::mem::take(&mut st.transitions)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp,
    clippy::similar_names,
    clippy::items_after_statements
)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Test clock — monotonically returns whatever the test sets.
    struct ManualClock {
        epoch_micros: AtomicU64,
    }

    impl ManualClock {
        fn new(initial_seconds: f64) -> Self {
            Self {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                epoch_micros: AtomicU64::new((initial_seconds * 1_000_000.0) as u64),
            }
        }

        fn advance_by(&self, seconds: f64) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let micros = (seconds * 1_000_000.0) as u64;
            self.epoch_micros.fetch_add(micros, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> f64 {
            #[allow(clippy::cast_precision_loss)]
            let micros = self.epoch_micros.load(Ordering::SeqCst) as f64;
            micros / 1_000_000.0
        }
    }

    fn fixture(initial: f64) -> (CircuitBreaker, std::sync::Arc<ManualClock>) {
        let clock = std::sync::Arc::new(ManualClock::new(initial));
        struct ArcClock(std::sync::Arc<ManualClock>);
        impl Clock for ArcClock {
            fn now(&self) -> f64 {
                self.0.now()
            }
        }
        let breaker = CircuitBreaker::new(
            CircuitConfig {
                failure_threshold: 3,
                cooldown_seconds: 30.0,
                call_timeout_seconds: 5.0,
            },
            Box::new(ArcClock(clock.clone())),
        );
        (breaker, clock)
    }

    #[test]
    fn closed_breaker_permits_calls() {
        let (b, _c) = fixture(1_000.0);
        assert_eq!(b.state(), CircuitState::Closed);
        b.before_call().expect("closed breaker must allow");
    }

    #[test]
    fn opens_after_failure_threshold_consecutive_failures() {
        let (b, _c) = fixture(1_000.0);
        for _ in 0..3 {
            b.record_failure();
        }
        assert_eq!(b.state(), CircuitState::Open);
    }

    #[test]
    fn open_breaker_returns_unavailable_within_cooldown_window() {
        //  AC2 (R): FAIL-CLOSED. Open breaker MUST return
        // Unavailable, never auto-approve. After Step 2 the
        // Unavailable signal is nested under KernelDecisionError,
        // wrapped by KernelClientError::Decision.
        let (b, _c) = fixture(1_000.0);
        for _ in 0..3 {
            b.record_failure();
        }
        let result = b.before_call();
        match result {
            Err(KernelClientError::Decision(KernelDecisionError::Unavailable { reason })) => {
                assert!(reason.contains("circuit breaker open"));
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn transitions_to_half_open_after_cooldown_elapses() {
        let (b, c) = fixture(1_000.0);
        for _ in 0..3 {
            b.record_failure();
        }
        // Advance past the cooldown.
        c.advance_by(31.0);
        b.before_call().expect("half-open probe must be allowed");
        assert_eq!(b.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn half_open_failure_reopens_immediately() {
        let (b, c) = fixture(1_000.0);
        for _ in 0..3 {
            b.record_failure();
        }
        c.advance_by(31.0);
        b.before_call().unwrap();
        // Probe fails -> re-open.
        b.record_failure();
        assert_eq!(b.state(), CircuitState::Open);
    }

    #[test]
    fn half_open_success_closes_breaker() {
        let (b, c) = fixture(1_000.0);
        for _ in 0..3 {
            b.record_failure();
        }
        c.advance_by(31.0);
        b.before_call().unwrap();
        b.record_success();
        assert_eq!(b.state(), CircuitState::Closed);
    }

    #[test]
    fn success_resets_consecutive_failure_count() {
        let (b, _c) = fixture(1_000.0);
        b.record_failure();
        b.record_failure();
        b.record_success();
        b.record_failure();
        b.record_failure();
        // 2 failures after the reset, threshold is 3 -> still Closed.
        assert_eq!(b.state(), CircuitState::Closed);
    }

    //   Step 5 — ADR §6 audit tests.

    /// ADR §6 failure classifier: HTTP 5xx counts as a failure. The
    /// breaker itself doesn't see HTTP codes — `client.rs` translates
    /// them to `record_failure()`. The breaker contract is: every
    /// `record_failure()` increments the counter. Three of them (the
    /// default threshold) MUST trip Open.
    ///
    /// Mirrors the 5xx → `record_failure` path in `client.rs::authorize`
    /// (`status.is_server_error()` branch).
    #[test]
    fn http_5xx_classifier_three_consecutive_open_breaker() {
        let (b, _c) = fixture(1_000.0);
        assert_eq!(b.state(), CircuitState::Closed);
        // Simulate the client's 5xx → record_failure() handoff three
        // times, matching the failure_threshold default.
        b.record_failure(); // 1st 5xx
        assert_eq!(b.state(), CircuitState::Closed);
        b.record_failure(); // 2nd 5xx
        assert_eq!(b.state(), CircuitState::Closed);
        b.record_failure(); // 3rd 5xx -> trip
        assert_eq!(b.state(), CircuitState::Open);
    }

    /// ADR §6 failure classifier: HTTP 4xx is NOT a failure. The
    /// classifier in `client.rs` only calls `record_failure()` for
    /// transport / timeout / 5xx; 4xx (including authoritative 403
    /// DENY) calls `record_success()` or returns a `Transport` error
    /// without touching the breaker counter. This test pins the
    /// breaker-side contract: if the caller does NOT call
    /// `record_failure()`, the breaker MUST remain `Closed` regardless
    /// of how many 4xx responses are observed.
    ///
    /// Mirrors `client.rs`:
    ///   - 403  -> `record_success()` (kernel reachable; DENY is decision)
    ///   - 4xx other -> returns Transport(...) error, no record_failure
    #[test]
    fn http_4xx_classifier_does_not_count_as_failure() {
        let (b, _c) = fixture(1_000.0);
        // Simulate 100 consecutive 4xx responses — none should increment
        // the breaker. We model the two 4xx sub-cases:
        //   1) 403 DENY: client calls record_success.
        //   2) other 4xx: client returns Transport error, breaker
        //      untouched. We model that as the absence of any call.
        for _ in 0..50 {
            b.record_success(); // 403 path
            // other 4xx path: no call at all
        }
        assert_eq!(b.state(), CircuitState::Closed);
    }

    /// ADR §6 cooldown semantics: a single cooldown elapsation moves
    /// Open -> HalfOpen on the next `before_call()`. The `FixedClock`
    /// (here `ManualClock`) drives the cooldown — no `SystemTime::now()`
    /// is involved.
    #[test]
    fn cooldown_elapse_open_to_half_open_via_fixed_clock() {
        let (b, c) = fixture(1_000.0);
        for _ in 0..3 {
            b.record_failure();
        }
        assert_eq!(b.state(), CircuitState::Open);
        // Pre-cooldown: still Open, requests refused.
        c.advance_by(29.9);
        assert!(matches!(
            b.before_call(),
            Err(KernelClientError::Decision(KernelDecisionError::Unavailable {.. }))
        ));
        assert_eq!(b.state(), CircuitState::Open);
        // Post-cooldown: next call transitions to HalfOpen and is allowed.
        c.advance_by(0.2); // total 30.1 s elapsed since open
        b.before_call().expect("post-cooldown probe must be allowed");
        assert_eq!(b.state(), CircuitState::HalfOpen);
    }

    /// ADR §6 HalfOpen single-probe gate: exactly ONE probe permitted.
    /// A second concurrent caller MUST receive
    /// `Err(KernelClientError::Decision(KernelDecisionError::Unavailable))`
    /// immediately — no queue, no block.
    ///
    /// The reason string is `"circuit half-open probe in flight"` (spec
    /// literal — see the Addendum 2a §6).
    #[test]
    fn contended_half_open_second_caller_receives_unavailable() {
        let (b, c) = fixture(1_000.0);
        // Drive to HalfOpen.
        for _ in 0..3 {
            b.record_failure();
        }
        c.advance_by(31.0);
        // First caller wins the probe slot.
        b.before_call().expect("first probe must be allowed");
        assert_eq!(b.state(), CircuitState::HalfOpen);

        // Second concurrent caller — must NOT block, must NOT queue,
        // must receive Unavailable with the exact spec reason.
        let second = b.before_call();
        match second {
            Err(KernelClientError::Decision(KernelDecisionError::Unavailable { reason })) => {
                assert_eq!(reason, "circuit half-open probe in flight");
            }
            other => panic!("expected Unavailable(probe in flight), got {other:?}"),
        }

        // Sanity: state remains HalfOpen — contended call did NOT cause
        // a spurious transition.
        assert_eq!(b.state(), CircuitState::HalfOpen);
    }

    /// Probe-gate release: once the probe outcome is recorded, the
    /// next probe slot is available again (otherwise a flapping
    /// HalfOpen probe could permanently lock the breaker out).
    #[test]
    fn half_open_probe_gate_releases_after_outcome() {
        let (b, c) = fixture(1_000.0);
        for _ in 0..3 {
            b.record_failure();
        }
        c.advance_by(31.0);
        b.before_call().expect("first probe must be allowed");
        // Probe fails -> re-open.
        b.record_failure();
        assert_eq!(b.state(), CircuitState::Open);
        // Cooldown again -> new probe slot must be claimable.
        c.advance_by(31.0);
        b.before_call().expect("second cooldown probe must be allowed");
        assert_eq!(b.state(), CircuitState::HalfOpen);
    }

    /// Audit / transparency log: every state transition appends a
    /// `CircuitTransition` to the drainable buffer. This is the
    /// machine-readable counterpart to the `tracing::info!` line.
    #[test]
    fn transitions_buffer_records_every_state_change() {
        let (b, c) = fixture(1_000.0);
        // Closed -> Open
        for _ in 0..3 {
            b.record_failure();
        }
        // Open -> HalfOpen
        c.advance_by(31.0);
        b.before_call().unwrap();
        // HalfOpen -> Closed
        b.record_success();

        let transitions = b.drain_transitions();
        assert_eq!(transitions.len(), 3);
        assert_eq!(transitions[0].from, CircuitState::Closed);
        assert_eq!(transitions[0].to, CircuitState::Open);
        assert_eq!(transitions[1].from, CircuitState::Open);
        assert_eq!(transitions[1].to, CircuitState::HalfOpen);
        assert_eq!(transitions[2].from, CircuitState::HalfOpen);
        assert_eq!(transitions[2].to, CircuitState::Closed);
    }
}
