//! Pure types describing the Safety Kernel client's circuit-breaker
//! state machine. Pure-type discipline (no I/O, no clock) lives here so
//! that the state machine can be deterministically tested in the
//! domain crate; the adapter at
//! `crates/adapters/src/safety_kernel_client/circuit_breaker.rs`
//! injects a `Clock` from the domain `super::Clock` trait and drives
//! the transitions.
//!
//! Per ARY-1881 Phase 2a (ARY-1883), the FAIL-CLOSED property is the
//! whole point: when the kernel is unreachable, the breaker enters
//! `Open` and every `authorize()` call returns `KernelError::Unavailable`
//! — never a silent ALLOW. ARY-2020 reconciliation pinned this to the
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
    /// Timeout (seconds) for the underlying kernel call. ARY-1883 AC6
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
        // ARY-1883 AC6 (R): mock kernel timeout → circuit-breaker fires
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
}
