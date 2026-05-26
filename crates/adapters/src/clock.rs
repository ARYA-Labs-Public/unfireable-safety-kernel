//! Production `Clock` adapter — wall-clock as f64 epoch seconds.
//!
//! Implements `qorch_domain::safety::Clock`. Per
//! Appendix B and §6.1, every `SystemTime`/`now`-style read in the
//! Rust workspace lives here so the domain crate stays pure (no
//! `std::time::SystemTime`, no system-dependent state).
//!
//! The Safety Kernel binds `now` to a single value at the top of each
//! handler (see step 6) and forwards it to the
//! Python policy sidecar — there is exactly one wall-clock read per
//! HTTP request, sourced through this trait.

use std::time::{SystemTime, UNIX_EPOCH};

use qorch_domain::safety::Clock;

/// Default production `Clock` — reads `SystemTime::now()` and returns
/// the duration since `UNIX_EPOCH` as f64 seconds.
///
/// Matches Python's `time.time()` byte-for-byte at the float level
/// modulo OS clock granularity. Equivalence harnesses inject a
/// `FixedClock(f64)` from the domain crate's test seam instead.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl SystemClock {
    /// Construct a new `SystemClock`. (Trivial — `SystemClock` is a
    /// zero-sized type, but keeping a `new()` lets call sites read
    /// like other adapter constructors.)
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn now(&self) -> f64 {
        // `duration_since` only fails if the system clock predates
        // UNIX_EPOCH (clock skew on misconfigured hosts). We map that
        // pathological case to 0.0 — the verify path will reject any
        // resulting token as `token_used_before_issued`, which is the
        // desired fail-closed behavior.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `SystemClock::now()` reading is monotonic-ish on any sane host
    /// (we permit small backwards skew). The test asserts it returns a
    /// finite, positive f64 — that's all the trait contract demands.
    #[test]
    fn now_is_finite_and_positive() {
        let t = SystemClock.now();
        assert!(t.is_finite());
        assert!(t > 0.0);
    }
}
