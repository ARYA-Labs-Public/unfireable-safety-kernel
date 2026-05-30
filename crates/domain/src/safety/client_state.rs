//! Pure types describing the Safety Kernel client's circuit-breaker
//! state machine. Pure-type discipline (no I/O, no clock) lives here so
//! that the state machine can be deterministically tested in the
//! domain crate; the adapter at
//! `crates/adapters/src/safety_kernel_client/circuit_breaker.rs`
//! injects a `Clock` from the domain `super::Clock` trait and drives
//! the transitions.
//!
//! Per, the FAIL-CLOSED property is the
//! whole point: when the kernel is unreachable, the breaker enters
//! `Open` and every `authorize()` call returns `KernelError::Unavailable`
//! — never a silent ALLOW.  reconciliation pinned this to the
//! Rust substrate (the Python `packages/safety/client/circuit_breaker.py`
//! remains for Python callers until they migrate).

use serde::{Deserialize, Serialize};

/// Circuit-breaker state. Transitions are:
///
/// ```text
///   Closed  -- N consecutive failures -->  Open
///   Open    -- cooldown elapsed       -->  HalfOpen
///   HalfOpen -- probe succeeds        -->  Closed
///   HalfOpen -- probe fails           -->  Open
/// ```
///
/// FAIL-CLOSED invariant: while in `Open`, the breaker MUST refuse
/// requests with `KernelError::Unavailable`. Never auto-approve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CircuitState {
    /// Healthy — requests flow through to the kernel.
    Closed,
    /// Unhealthy — requests are short-circuited with `Unavailable`.
    Open,
    /// Cooldown elapsed — one probe is allowed; outcome decides next state.
    HalfOpen,
}

impl CircuitState {
    /// Returns true when the breaker is in a state that forbids new
    /// outbound calls (i.e. requires fail-closed handling at the call
    /// site).
    #[must_use]
    pub const fn forbids_call(self) -> bool {
        matches!(self, CircuitState::Open)
    }
}

/// Configuration values for the breaker. Held in the domain so callers
/// can reason about thresholds without depending on the adapter crate.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CircuitConfig {
    /// Consecutive failures required to trip from `Closed` to `Open`.
    pub failure_threshold: u32,
    /// Seconds to wait in `Open` before allowing a probe (`HalfOpen`).
    pub cooldown_seconds: f64,
    /// Timeout (seconds) for the underlying kernel call.  AC6
    /// pins this to 5.0 s by default.
    pub call_timeout_seconds: f64,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            cooldown_seconds: 30.0,
            call_timeout_seconds: 5.0,
        }
    }
}

/// Outcome of the pre-call circuit-breaker gate, expressed without any
/// I/O, clock, or lock. This is the *decision core* of the adapter's
/// `CircuitBreaker::before_call`: the adapter computes the two boolean
/// inputs (`cooldown_elapsed` from its injected `Clock`, `probe_in_flight`
/// from its locked state) and then delegates the decision to
/// [`gate_decision`]. Keeping the decision pure is what makes it
/// formally verifiable — see the `#[cfg(kani)]` proof harness below,
/// which discharges the FAIL-CLOSED theorem exhaustively over every
/// `(state, cooldown_elapsed, probe_in_flight)` input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    /// The outbound call may proceed. (`Closed`, or `HalfOpen` with no
    /// probe already in flight.)
    Permit,
    /// The call MUST be refused fail-closed; the adapter maps this to
    /// `KernelDecisionError::Unavailable`. Never an ALLOW.
    RefuseUnavailable,
    /// `Open` and the cooldown has elapsed: the adapter transitions the
    /// breaker `Open -> HalfOpen` and permits exactly one probe.
    PermitProbeAfterCooldown,
}

/// Pure FAIL-CLOSED gate decision for the circuit breaker.
///
/// This function is the decision core that
/// `crates/adapters/src/safety_kernel_client/circuit_breaker.rs`'s
/// `before_call` delegates to. Binding the production call path to this
/// exact function (rather than a re-implementation) is what makes the
/// formal proof meaningful: the verified function *is* the one the
/// shipped code calls.
///
/// The FAIL-CLOSED theorem (proved exhaustively by the `#[cfg(kani)]`
/// harness, and mirroring a model-level SMT proof of the same
/// invariant):
///
/// > A permit decision (`Permit` or `PermitProbeAfterCooldown`) is
/// > reachable *only* from `Closed`, from `HalfOpen` with no probe in
/// > flight, or from `Open` after the cooldown has elapsed. In `Open`
/// > with the cooldown not yet elapsed, the gate always refuses.
///
/// There is no `(state, cooldown_elapsed, probe_in_flight)` assignment
/// that yields a permit from an `Open` breaker whose cooldown has not
/// elapsed. The kernel being unreachable (which is what drives the
/// breaker `Open`) therefore cannot be silently converted into an
/// allow.
#[must_use]
pub const fn gate_decision(
    state: CircuitState,
    cooldown_elapsed: bool,
    probe_in_flight: bool,
) -> GateDecision {
    match state {
        CircuitState::Closed => GateDecision::Permit,
        CircuitState::HalfOpen => {
            if probe_in_flight {
                GateDecision::RefuseUnavailable
            } else {
                GateDecision::Permit
            }
        }
        CircuitState::Open => {
            if cooldown_elapsed {
                GateDecision::PermitProbeAfterCooldown
            } else {
                GateDecision::RefuseUnavailable
            }
        }
    }
}

/// A summary the adapter records each time the breaker transitions —
/// used by audit logging and by `tests/adversarial/` fixtures that
/// assert FAIL-CLOSED behaviour.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CircuitTransition {
    /// State the breaker was in.
    pub from: CircuitState,
    /// State the breaker moved to.
    pub to: CircuitState,
    /// Epoch seconds (sourced from a `Clock`) of the transition.
    pub at_epoch_seconds: f64,
    /// Number of consecutive failures observed when the transition fired.
    pub failure_count: u32,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    #[test]
    fn forbids_call_only_in_open_state() {
        assert!(!CircuitState::Closed.forbids_call());
        assert!(CircuitState::Open.forbids_call());
        assert!(!CircuitState::HalfOpen.forbids_call());
    }

    #[test]
    fn default_config_matches_ary_1883_ac6() {
        //  AC6 (R): mock kernel timeout → circuit-breaker fires
        // within configured timeout (default 5 s). Pinning that default
        // here is the structural enforcement.
        let cfg = CircuitConfig::default();
        assert_eq!(cfg.call_timeout_seconds, 5.0);
        assert_eq!(cfg.failure_threshold, 3);
        assert_eq!(cfg.cooldown_seconds, 30.0);
    }

    #[test]
    fn states_round_trip_through_serde_json() {
        for s in [
            CircuitState::Closed,
            CircuitState::Open,
            CircuitState::HalfOpen,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let back: CircuitState = serde_json::from_str(&j).unwrap();
            assert_eq!(s, back);
        }
    }

    /// Exhaustive (12-case) check of the FAIL-CLOSED gate decision —
    /// the concrete-enumeration counterpart of the `#[cfg(kani)]`
    /// symbolic proof. Runs in ordinary CI without a verifier installed.
    #[test]
    fn gate_decision_fail_closed_exhaustive() {
        for state in [
            CircuitState::Closed,
            CircuitState::Open,
            CircuitState::HalfOpen,
        ] {
            for cooldown_elapsed in [false, true] {
                for probe_in_flight in [false, true] {
                    let d = gate_decision(state, cooldown_elapsed, probe_in_flight);
                    let permits = matches!(
                        d,
                        GateDecision::Permit | GateDecision::PermitProbeAfterCooldown
                    );
                    // FAIL-CLOSED: a permit is reachable only from the
                    // three benign assignments. Anything else must refuse.
                    let permit_is_legitimate = matches!(state, CircuitState::Closed)
                        || (matches!(state, CircuitState::HalfOpen) && !probe_in_flight)
                        || (matches!(state, CircuitState::Open) && cooldown_elapsed);
                    assert_eq!(
                        permits, permit_is_legitimate,
                        "fail-closed violated at state={state:?} cooldown_elapsed={cooldown_elapsed} probe={probe_in_flight}"
                    );
                    // Open within cooldown ALWAYS refuses.
                    if matches!(state, CircuitState::Open) && !cooldown_elapsed {
                        assert_eq!(d, GateDecision::RefuseUnavailable);
                    }
                }
            }
        }
    }
}

/// Symbolic formal-verification harness for the FAIL-CLOSED gate
/// decision. Compiled only under `cargo kani`; excluded from ordinary
/// builds and tests (no `kani` dependency is pulled in normal mode).
///
/// These proofs discharge — at the level of the *actual shipped Rust
/// function* `gate_decision`, not a separate model — the same
/// fail-closed invariant the SMT harness proves over a symbolic model of
/// the gate. Together they close the model-fidelity gap: SMT proves the
/// invariant's logical structure; Kani proves the Rust implementation
/// realizes it for every input.
#[cfg(kani)]
mod kani_proofs {
    use super::{gate_decision, CircuitState, GateDecision};

    /// Build a symbolic `CircuitState` covering all three variants.
    fn any_state() -> CircuitState {
        match kani::any::<u8>() % 3 {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            _ => CircuitState::HalfOpen,
        }
    }

    /// FAIL-CLOSED, Arm A (mirrors the model-level SMT proof
    /// Arm A): in `Open` with the cooldown NOT elapsed, the gate
    /// refuses — for every `probe_in_flight` value. Never a permit.
    #[kani::proof]
    fn open_within_cooldown_always_refuses() {
        let probe_in_flight: bool = kani::any();
        let d = gate_decision(CircuitState::Open, false, probe_in_flight);
        assert!(matches!(d, GateDecision::RefuseUnavailable));
    }

    /// No permit from `Open` unless the cooldown has elapsed.
    #[kani::proof]
    fn open_permits_only_after_cooldown() {
        let cooldown_elapsed: bool = kani::any();
        let probe_in_flight: bool = kani::any();
        let d = gate_decision(CircuitState::Open, cooldown_elapsed, probe_in_flight);
        if matches!(
            d,
            GateDecision::Permit | GateDecision::PermitProbeAfterCooldown
        ) {
            assert!(cooldown_elapsed);
        }
    }

    /// HalfOpen single-probe gate: with a probe already in flight, the
    /// gate refuses regardless of cooldown.
    #[kani::proof]
    fn half_open_with_probe_in_flight_refuses() {
        let cooldown_elapsed: bool = kani::any();
        let d = gate_decision(CircuitState::HalfOpen, cooldown_elapsed, true);
        assert!(matches!(d, GateDecision::RefuseUnavailable));
    }

    /// Full characterization over the entire symbolic input domain: a
    /// permit decision is reachable ONLY from `Closed`, `HalfOpen`
    /// without a probe in flight, or `Open` after cooldown. This is the
    /// exhaustive FAIL-CLOSED theorem.
    #[kani::proof]
    fn permit_characterization_is_exhaustive() {
        let state = any_state();
        let cooldown_elapsed: bool = kani::any();
        let probe_in_flight: bool = kani::any();
        let d = gate_decision(state, cooldown_elapsed, probe_in_flight);
        let permits = matches!(
            d,
            GateDecision::Permit | GateDecision::PermitProbeAfterCooldown
        );
        if permits {
            let legitimate = matches!(state, CircuitState::Closed)
                || (matches!(state, CircuitState::HalfOpen) && !probe_in_flight)
                || (matches!(state, CircuitState::Open) && cooldown_elapsed);
            assert!(legitimate);
        }
    }
}
