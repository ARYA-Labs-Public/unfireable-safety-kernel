//! The fail-closed proof of the client circuit breaker (see the crate docs).
//!
//! Arm A properties are checked by asserting their NEGATION on a symbolic
//! trace and requiring `unsat`: no assignment of events, clock readings,
//! cooldown and threshold violates them within `PROOF_STEPS` events.
//! `unknown` is a failure, never a pass.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use qorch_domain::safety::{gate_decision, CircuitConfig, CircuitState, Clock};
use qorch_safety_kernel_client::CircuitBreaker;
use safety_kernel_fail_closed_proof::{
    decision_code, fail_open_gate, gate, real_int, state_code, trace, Trace, CLOSED, EV_CALL,
    EV_FAILURE, EV_SUCCESS, HALF_OPEN, OPEN, PERMIT, PERMIT_PROBE, PROOF_STEPS, REFUSE,
};
use z3::ast::{Ast, Bool, Int, Real};
use z3::{SatResult, Solver};

/// `sat`/`unsat` of `trace ∧ extra`; `unknown` panics.
fn check(t: &Trace, extra: &Bool) -> SatResult {
    let s = Solver::new();
    s.assert(t.valid());
    s.assert(extra);
    let r = s.check();
    assert_ne!(
        r,
        SatResult::Unknown,
        "solver returned unknown: that is not a proof"
    );
    r
}

fn any(xs: &[Bool]) -> Bool {
    let refs: Vec<&Bool> = xs.iter().collect();
    Bool::or(&refs)
}

fn int(v: i64) -> Int {
    Int::from_i64(v)
}

// ---------------------------------------------------------------------------
// Arm A — safety (negation must be unsat)
// ---------------------------------------------------------------------------

/// The negation of A1 on trace `t`: some call on an open breaker, before the
/// cooldown has elapsed, is not refused.
fn early_permit_from_open(t: &Trace) -> Bool {
    let v: Vec<Bool> = (0..t.events.len())
        .map(|i| {
            let since = Real::sub(&[&t.now[i], &t.steps[i].opened_at]);
            Bool::and(&[
                &t.events[i].eq(int(EV_CALL)),
                &t.steps[i].state.eq(int(OPEN)),
                &since.lt(&t.cooldown),
                &t.decisions[i].eq(int(REFUSE)).not(),
            ])
        })
        .collect();
    any(&v)
}

#[test]
fn a1_open_breaker_refuses_every_call_until_the_cooldown_has_elapsed() {
    let t = trace(PROOF_STEPS, gate, "");
    assert_eq!(
        check(&t, &early_permit_from_open(&t)),
        SatResult::Unsat,
        "A1 violated: an open breaker permitted a call before its cooldown"
    );
}

#[test]
fn a2_half_open_breaker_lets_only_one_probe_through() {
    let t = trace(PROOF_STEPS, gate, "");
    let v: Vec<Bool> = (0..PROOF_STEPS)
        .map(|i| {
            Bool::and(&[
                &t.events[i].eq(int(EV_CALL)),
                &t.steps[i].state.eq(int(HALF_OPEN)),
                &t.steps[i].probe,
                &t.decisions[i].eq(int(REFUSE)).not(),
            ])
        })
        .collect();
    assert_eq!(
        check(&t, &any(&v)),
        SatResult::Unsat,
        "A2 violated: a second call got through while a probe was in flight"
    );
}

#[test]
fn a3_only_a_kernel_success_closes_an_opened_breaker() {
    // Negation: the breaker is not closed at step i, is closed at a later
    // step j, and no event between them was a success.
    let t = trace(PROOF_STEPS, gate, "");
    let mut v = Vec::new();
    for i in 0..=PROOF_STEPS {
        for j in i + 1..=PROOF_STEPS {
            let mut no_success: Vec<Bool> = (i..j)
                .map(|m| t.events[m].eq(int(EV_SUCCESS)).not())
                .collect();
            no_success.push(t.steps[i].state.eq(int(CLOSED)).not());
            no_success.push(t.steps[j].state.eq(int(CLOSED)));
            let refs: Vec<&Bool> = no_success.iter().collect();
            v.push(Bool::and(&refs));
        }
    }
    assert_eq!(
        check(&t, &any(&v)),
        SatResult::Unsat,
        "A3 violated: the breaker closed without a kernel success"
    );
}

#[test]
fn a4_with_the_kernel_unreachable_every_permit_after_opening_is_a_counted_probe() {
    // Kernel unreachable: every recorded outcome is a failure. Negation:
    // once the breaker has opened, a call is let through by anything other
    // than a probe after a full cooldown or the single half-open permit.
    let t = trace(PROOF_STEPS, gate, "");
    let mut kernel_down: Vec<Bool> = (0..PROOF_STEPS)
        .map(|i| t.events[i].eq(int(EV_SUCCESS)).not())
        .collect();
    let mut v = Vec::new();
    for i in 0..PROOF_STEPS {
        let permitted = t.decisions[i].eq(int(REFUSE)).not();
        let legitimate = Bool::or(&[
            &Bool::and(&[
                &t.steps[i].state.eq(int(OPEN)),
                &t.cooldown_elapsed[i],
                &t.decisions[i].eq(int(PERMIT_PROBE)),
            ]),
            &Bool::and(&[
                &t.steps[i].state.eq(int(HALF_OPEN)),
                &t.steps[i].probe.not(),
            ]),
            &t.steps[i].state.eq(int(CLOSED)),
        ]);
        v.push(Bool::and(&[
            &t.events[i].eq(int(EV_CALL)),
            &permitted,
            &legitimate.not(),
        ]));
    }
    kernel_down.push(any(&v));
    let refs: Vec<&Bool> = kernel_down.iter().collect();
    assert_eq!(
        check(&t, &Bool::and(&refs)),
        SatResult::Unsat,
        "A4 violated: with the kernel unreachable, a call got through other than as a probe"
    );
}

#[test]
fn a5_a_half_open_breaker_refuses_every_call() {
    // Stronger than A2. The breaker only enters HalfOpen by letting the probe
    // through (which sets probe_in_flight), and leaves it on the probe's
    // outcome, so `gate_decision`'s "HalfOpen, no probe in flight -> Permit"
    // branch is unreachable in the shipped breaker: while half-open, the probe
    // is the only call that ever goes out. Negation: some half-open call is
    // permitted.
    let t = trace(PROOF_STEPS, gate, "");
    let v: Vec<Bool> = (0..PROOF_STEPS)
        .map(|i| {
            Bool::and(&[
                &t.events[i].eq(int(EV_CALL)),
                &t.steps[i].state.eq(int(HALF_OPEN)),
                &t.decisions[i].eq(int(REFUSE)).not(),
            ])
        })
        .collect();
    assert_eq!(
        check(&t, &any(&v)),
        SatResult::Unsat,
        "A5 violated: a half-open breaker permitted a call"
    );
}

// ---------------------------------------------------------------------------
// Arm B — non-vacuity (each must be sat)
// ---------------------------------------------------------------------------

#[test]
fn b1_the_model_reaches_open_and_permits_a_probe_after_the_cooldown() {
    let t = trace(PROOF_STEPS, gate, "");
    let v: Vec<Bool> = (0..PROOF_STEPS)
        .map(|i| {
            Bool::and(&[
                &t.events[i].eq(int(EV_CALL)),
                &t.steps[i].state.eq(int(OPEN)),
                &t.decisions[i].eq(int(PERMIT_PROBE)),
            ])
        })
        .collect();
    assert_eq!(check(&t, &any(&v)), SatResult::Sat);
}

#[test]
fn b2_the_model_permits_closed_calls_and_refuses_open_and_half_open_ones() {
    let t = trace(PROOF_STEPS, gate, "");
    for (state, decision) in [(CLOSED, PERMIT), (OPEN, REFUSE), (HALF_OPEN, REFUSE)] {
        let v: Vec<Bool> = (0..PROOF_STEPS)
            .map(|i| {
                Bool::and(&[
                    &t.events[i].eq(int(EV_CALL)),
                    &t.steps[i].state.eq(int(state)),
                    &t.decisions[i].eq(int(decision)),
                ])
            })
            .collect();
        assert_eq!(
            check(&t, &any(&v)),
            SatResult::Sat,
            "state {state} decision {decision} must be reachable"
        );
    }
}

#[test]
fn b3_a_fail_open_gate_violates_a1() {
    // The same trace built on a gate that permits from Open must break A1.
    // If it did not, A1 would be holding for a reason unrelated to the gate.
    let t = trace(PROOF_STEPS, fail_open_gate, "");
    assert_eq!(
        check(&t, &early_permit_from_open(&t)),
        SatResult::Sat,
        "the fail-open mutant must have a counterexample"
    );
}

// ---------------------------------------------------------------------------
// Binding — the model is the shipped code
// ---------------------------------------------------------------------------

#[test]
fn binding_symbolic_gate_equals_rust_gate_decision_on_every_input() {
    for state in [
        CircuitState::Closed,
        CircuitState::Open,
        CircuitState::HalfOpen,
    ] {
        for elapsed in [false, true] {
            for probe in [false, true] {
                let sym = gate(
                    &int(state_code(state)),
                    &Bool::from_bool(elapsed),
                    &Bool::from_bool(probe),
                )
                .simplify()
                .as_i64()
                .expect("concrete inputs give a concrete decision");
                assert_eq!(
                    sym,
                    decision_code(gate_decision(state, elapsed, probe)),
                    "model gate drifted from gate_decision at ({state:?}, {elapsed}, {probe})"
                );
            }
        }
    }
}

/// A clock the test sets by hand.
#[derive(Clone)]
struct HandClock(Arc<AtomicU64>);
impl HandClock {
    fn set(&self, t: f64) {
        self.0.store(t.to_bits(), Ordering::SeqCst);
    }
}
impl Clock for HandClock {
    fn now(&self) -> f64 {
        f64::from_bits(self.0.load(Ordering::SeqCst))
    }
}

/// Deterministic xorshift so the sequences are reproducible without a dep.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn binding_transition_system_matches_the_real_circuit_breaker() {
    const SEQUENCES: usize = 300;
    const LEN: usize = 14;
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for seq in 0..SEQUENCES {
        let threshold = 1 + rng.below(4) as u32;
        let cooldown = 1 + rng.below(20) as i32;
        let clock = HandClock(Arc::new(AtomicU64::new(0f64.to_bits())));
        let breaker = CircuitBreaker::new(
            CircuitConfig {
                failure_threshold: threshold,
                cooldown_seconds: f64::from(cooldown),
                call_timeout_seconds: 5.0,
            },
            Box::new(clock.clone()),
        );

        // Run the real breaker and pin the same inputs in a fresh trace.
        let tag = format!("q{seq}_");
        let t = trace(LEN, gate, &tag);
        let solver = Solver::new();
        solver.assert(t.valid());
        solver.assert(t.cooldown.eq(real_int(i64::from(cooldown))));
        solver.assert(t.threshold.eq(int(i64::from(threshold))));
        let mut now = 0i32;
        let mut real_states = vec![breaker.state()];
        let mut real_permits = Vec::new();
        for i in 0..LEN {
            now += rng.below(9) as i32; // includes 0: same-instant events
            clock.set(f64::from(now));
            let ev = match rng.below(3) {
                0 => EV_CALL,
                1 => EV_SUCCESS,
                _ => EV_FAILURE,
            };
            match ev {
                EV_CALL => real_permits.push(Some(breaker.before_call().is_ok())),
                EV_SUCCESS => {
                    breaker.record_success();
                    real_permits.push(None);
                }
                _ => {
                    breaker.record_failure();
                    real_permits.push(None);
                }
            }
            real_states.push(breaker.state());
            solver.assert(t.events[i].eq(int(ev)));
            solver.assert(t.now[i].eq(real_int(i64::from(now))));
        }
        assert_eq!(
            solver.check(),
            SatResult::Sat,
            "seq {seq}: the real run is not a model trace"
        );
        let m = solver.get_model().unwrap();
        assert_eq!(real_states.len(), LEN + 1, "seq {seq}: one state per step");
        for (i, real) in real_states.iter().enumerate() {
            let got = m.eval(&t.steps[i].state, true).unwrap().as_i64().unwrap();
            assert_eq!(
                got,
                state_code(*real),
                "seq {seq} step {i}: model state {got} != breaker {real:?}"
            );
        }
        for (i, permit) in real_permits.iter().enumerate() {
            if let Some(ok) = permit {
                let d = m.eval(&t.decisions[i], true).unwrap().as_i64().unwrap();
                assert_eq!(
                    d != REFUSE,
                    *ok,
                    "seq {seq} event {i}: model decision {d} vs breaker permit {ok}"
                );
            }
        }
        // The pinned trace has exactly one model: the transitions are functional.
        let pin: Vec<Bool> = t
            .steps
            .iter()
            .map(|st| st.state.eq(m.eval(&st.state, true).unwrap()))
            .collect();
        let refs: Vec<&Bool> = pin.iter().collect();
        solver.assert(Bool::and(&refs).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "seq {seq}: the model allows another state sequence"
        );
    }
}
