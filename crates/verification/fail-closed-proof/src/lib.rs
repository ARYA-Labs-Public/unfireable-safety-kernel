//! SMT (Z3) model of the Safety Kernel client's circuit breaker.
//!
//! The client refuses to call the kernel while its circuit breaker is open,
//! and an unreachable kernel is what opens it. The fail-closed contract is
//! that the breaker never turns "the kernel is unreachable" into a call that
//! goes ahead: it refuses until a full cooldown has passed, then lets exactly
//! one probe through, and only a real kernel success closes it again.
//!
//! This crate encodes the breaker as an SMT transition system: the decision
//! core [`gate`] (a symbolic copy of
//! [`qorch_domain::safety::gate_decision`]) and the state changes of
//! `CircuitBreaker::{before_call, record_success, record_failure}` in
//! `crates/adapters/safety_kernel_client/src/circuit_breaker.rs`, over
//! [`Trace`]s of any event order, with a symbolic monotonic clock, cooldown
//! and failure threshold. The proofs are in `tests/proof.rs`:
//!
//! - **Arm A (safety, by negation-unsat):** no trace permits a call from an
//!   open breaker before its cooldown, lets a second probe through while one
//!   is in flight, or closes the breaker without a kernel success; and a
//!   half-open breaker refuses every call (the probe that opened it is the
//!   only call that goes out, so `gate_decision`'s half-open permit branch is
//!   unreachable in the shipped breaker).
//! - **Arm B (non-vacuity, by witness):** each permit path is reachable, and a
//!   deliberately fail-open gate violates the contract, so Arm A is not true
//!   for a vacuous reason.
//! - **Binding:** the symbolic gate equals the Rust `gate_decision` on all 12
//!   inputs, and the transition system matches the real `CircuitBreaker` step
//!   by step on randomized event sequences. If either drifts from the code,
//!   those tests fail.
//!
//! Kani proves `gate_decision` itself over its whole input domain
//! (`crates/domain/src/safety/client_state.rs`); this proof covers the
//! breaker's behaviour over time, which a single call of the function cannot.
//! The Arm A traces are bounded at [`PROOF_STEPS`] events.

use qorch_domain::safety::{CircuitState, GateDecision};
use z3::ast::{Bool, Int, Real};

/// Events in a trace (the three breaker entry points).
pub const EV_CALL: i64 = 0;
/// `record_success`: the kernel answered.
pub const EV_SUCCESS: i64 = 1;
/// `record_failure`: the kernel call failed (unreachable, timeout, 5xx).
pub const EV_FAILURE: i64 = 2;

/// Breaker states.
pub const CLOSED: i64 = 0;
/// See [`CircuitState::Open`].
pub const OPEN: i64 = 1;
/// See [`CircuitState::HalfOpen`].
pub const HALF_OPEN: i64 = 2;

/// Gate decisions.
pub const PERMIT: i64 = 0;
/// See [`GateDecision::RefuseUnavailable`].
pub const REFUSE: i64 = 1;
/// See [`GateDecision::PermitProbeAfterCooldown`].
pub const PERMIT_PROBE: i64 = 2;

/// Number of events in the Arm A traces.
pub const PROOF_STEPS: usize = 10;

/// The model's code for a Rust breaker state.
#[must_use]
pub const fn state_code(s: CircuitState) -> i64 {
    match s {
        CircuitState::Closed => CLOSED,
        CircuitState::Open => OPEN,
        CircuitState::HalfOpen => HALF_OPEN,
    }
}

/// The model's code for a Rust gate decision.
#[must_use]
pub const fn decision_code(d: GateDecision) -> i64 {
    match d {
        GateDecision::Permit => PERMIT,
        GateDecision::RefuseUnavailable => REFUSE,
        GateDecision::PermitProbeAfterCooldown => PERMIT_PROBE,
    }
}

/// The real number `v`, exactly. Built as `to_real(v)` rather than with
/// `Real::from_real`, whose rational constructor (`Z3_mk_real_int64`) is
/// missing from the libz3 4.8 that CI and the dev box link.
#[must_use]
pub fn real_int(v: i64) -> Real {
    Real::from_int(&Int::from_i64(v))
}

/// A gate encoding: `(state, cooldown_elapsed, probe_in_flight) -> decision`.
pub type GateFn = fn(&Int, &Bool, &Bool) -> Int;

/// Symbolic `gate_decision`. Must stay line-for-line with
/// `qorch_domain::safety::gate_decision`; the binding test enforces it.
#[must_use]
pub fn gate(state: &Int, cooldown_elapsed: &Bool, probe_in_flight: &Bool) -> Int {
    let k = |v| Int::from_i64(v);
    state.eq(k(CLOSED)).ite(
        &k(PERMIT),
        &state.eq(k(HALF_OPEN)).ite(
            &probe_in_flight.ite(&k(REFUSE), &k(PERMIT)),
            // Open
            &cooldown_elapsed.ite(&k(PERMIT_PROBE), &k(REFUSE)),
        ),
    )
}

/// A deliberately FAIL-OPEN gate (an open breaker permits), used only to
/// show the Arm A properties can fail.
#[must_use]
pub fn fail_open_gate(state: &Int, cooldown_elapsed: &Bool, probe_in_flight: &Bool) -> Int {
    let k = |v| Int::from_i64(v);
    state
        .eq(k(OPEN))
        .ite(&k(PERMIT), &gate(state, cooldown_elapsed, probe_in_flight))
}

/// Breaker state before event `i`.
pub struct Step {
    /// [`CLOSED`], [`OPEN`] or [`HALF_OPEN`].
    pub state: Int,
    /// `probe_in_flight`.
    pub probe: Bool,
    /// `opened_at_epoch_seconds` (only read while not closed).
    pub opened_at: Real,
    /// `consecutive_failures`.
    pub failures: Int,
}

/// A symbolic trace: `steps[0]` is the initial state, event `i` happens at
/// `now[i]` and moves `steps[i]` to `steps[i + 1]`.
pub struct Trace {
    /// `steps.len() == events.len() + 1`.
    pub steps: Vec<Step>,
    /// One of the `EV_*` codes per event.
    pub events: Vec<Int>,
    /// Clock reading at each event; non-decreasing.
    pub now: Vec<Real>,
    /// The gate's decision at each event (meaningful when it is a call).
    pub decisions: Vec<Int>,
    /// `cooldown_elapsed` as the breaker computes it at each event.
    pub cooldown_elapsed: Vec<Bool>,
    /// `CircuitConfig::cooldown_seconds` (> 0).
    pub cooldown: Real,
    /// `CircuitConfig::failure_threshold` (>= 1).
    pub threshold: Int,
    /// Everything that makes this a run of the breaker; assert all of it.
    pub constraints: Vec<Bool>,
}

impl Trace {
    /// All constraints as one formula.
    #[must_use]
    pub fn valid(&self) -> Bool {
        let refs: Vec<&Bool> = self.constraints.iter().collect();
        Bool::and(&refs)
    }
}

/// Build a `k`-event trace of the breaker whose decision core is `gate_fn`.
/// Every name is prefixed with `tag` so several traces can share a solver.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn trace(k: usize, gate_fn: GateFn, tag: &str) -> Trace {
    let int = |v| Int::from_i64(v);
    let zero = real_int(0);
    let cooldown = Real::new_const(format!("{tag}cooldown"));
    let threshold = Int::new_const(format!("{tag}threshold"));
    let mut c = vec![cooldown.gt(&zero), threshold.ge(int(1))];

    let steps: Vec<Step> = (0..=k)
        .map(|i| Step {
            state: Int::new_const(format!("{tag}s{i}")),
            probe: Bool::new_const(format!("{tag}p{i}")),
            opened_at: Real::new_const(format!("{tag}o{i}")),
            failures: Int::new_const(format!("{tag}f{i}")),
        })
        .collect();
    let events: Vec<Int> = (0..k)
        .map(|i| Int::new_const(format!("{tag}e{i}")))
        .collect();
    let now: Vec<Real> = (0..k)
        .map(|i| Real::new_const(format!("{tag}t{i}")))
        .collect();

    // Initial state: CircuitBreaker::new.
    c.push(steps[0].state.eq(int(CLOSED)));
    c.push(steps[0].probe.not());
    c.push(steps[0].failures.eq(int(0)));

    let mut decisions = Vec::with_capacity(k);
    let mut elapsed = Vec::with_capacity(k);
    for i in 0..k {
        let (s, n) = (&steps[i], &steps[i + 1]);
        let e = &events[i];
        c.push(Bool::or(&[
            &e.eq(int(EV_CALL)),
            &e.eq(int(EV_SUCCESS)),
            &e.eq(int(EV_FAILURE)),
        ]));
        if i > 0 {
            c.push(now[i].ge(&now[i - 1]));
        }

        // before_call
        let ce = Real::sub(&[&now[i], &s.opened_at]).ge(&cooldown);
        let d = gate_fn(&s.state, &ce, &s.probe);
        let half = s.state.eq(int(HALF_OPEN));
        let after_call = Bool::and(&[
            &n.failures.eq(&s.failures),
            &n.opened_at.eq(&s.opened_at),
            &d.eq(int(PERMIT_PROBE)).ite(
                &Bool::and(&[&n.state.eq(int(HALF_OPEN)), &n.probe]),
                &d.eq(int(PERMIT)).ite(
                    &Bool::and(&[
                        &n.state.eq(&s.state),
                        &n.probe.eq(Bool::or(&[&s.probe, &half])),
                    ]),
                    // Refuse: nothing changes.
                    &Bool::and(&[&n.state.eq(&s.state), &n.probe.eq(&s.probe)]),
                ),
            ),
        ]);

        // record_success
        let after_success = Bool::and(&[
            &n.state.eq(int(CLOSED)),
            &n.probe.not(),
            &n.failures.eq(int(0)),
            &n.opened_at.eq(&s.opened_at),
        ]);

        // record_failure
        let failures = Int::add(&[&s.failures, &int(1)]);
        let should_open = Bool::or(&[
            &Bool::and(&[&s.state.eq(int(CLOSED)), &failures.ge(&threshold)]),
            &half,
        ]);
        let after_failure = Bool::and(&[
            &n.failures.eq(&failures),
            &n.probe.not(),
            &should_open.ite(
                &Bool::and(&[&n.state.eq(int(OPEN)), &n.opened_at.eq(&now[i])]),
                &Bool::and(&[&n.state.eq(&s.state), &n.opened_at.eq(&s.opened_at)]),
            ),
        ]);

        c.push(e.eq(int(EV_CALL)).ite(
            &after_call,
            &e.eq(int(EV_SUCCESS)).ite(&after_success, &after_failure),
        ));
        decisions.push(d);
        elapsed.push(ce);
    }

    Trace {
        steps,
        events,
        now,
        decisions,
        cooldown_elapsed: elapsed,
        cooldown,
        threshold,
        constraints: c,
    }
}
