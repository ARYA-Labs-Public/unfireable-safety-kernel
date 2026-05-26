//! Kernel-decision pure types — promoted from the adapter under
//!   Step 2 
//!
//! The adapter still owns the *implementation* of `SafetyKernelClient`
//! (HTTP, breaker, mTLS, key verification), but the **decision shape**
//! that callers observe is a pure type and therefore lives here.
//!
//! # Fail-closed invariant
//!
//! `KernelDecision::Allow` carries `VerifiedClaims`, which can only be
//! constructed by `verify_kernel_token(...)` in `super::token` after a
//! successful Ed25519 signature check against the caller-pinned key.
//! There is no other constructor for `VerifiedClaims` in the workspace.
//! Static auditors (Addendum 2a §4 "Static fail-closed invariant") rely
//! on this: any path that yields `KernelDecision::Allow {..., claims }`
//! must therefore have flowed through verification — there is no way to
//! build an `Allow` from un-verified bytes.
//!
//! See Addendum 2a §4 "Pure-types inventory" for the rationale of why
//! exactly these two enums live here and the rest of `KernelClientError`
//! stays in the adapter crate.

use super::token::VerifiedClaims;

/// Outcome of a Safety Kernel `authorize` request from the *caller*'s
/// point of view. Returned by the adapter-side `SafetyKernelClient`
/// (see `qorch_safety_kernel_client::client::SafetyKernelClient`).
/
/// This enum is deliberately **not** `Serialize` / `Deserialize`. The
/// kernel wire format uses a compact signed-token envelope (see
/// `sign_kernel_token` / `verify_kernel_token`); the decision shape is
/// only meaningful inside the calling process and must never be
/// reconstituted from JSON without re-flowing through the verifier (the
/// fail-closed invariant above).
#[derive(Debug, Clone, PartialEq)]
pub enum KernelDecision {
    /// Kernel signed a token authorizing the action. The caller may
    /// attach `token` to downstream calls; `claims` is the verifier
    /// output — never trust the `claims_hint` echoed in the response
    /// body, always re-derive via `verify_kernel_token`.
    Allow {
        /// The kernel-issued compact token (caller may attach to
        /// downstream calls).
        token: String,
        /// Verified claims — extracted by `verify_kernel_token`, NOT
        /// taken from the response body directly.
        claims: VerifiedClaims,
    },
    /// Kernel reachable and explicitly refused (authoritative DENY).
    /// Distinct from "kernel unavailable" — see `KernelDecisionError`.
    Deny {
        /// Human-readable reason from the kernel response.
        reason: String,
    },
}

/// Failure modes a caller may observe from `authorize`. FAIL-CLOSED
/// semantics: every variant here causes the caller's operation to be
/// rejected — none of them are recoverable as ALLOW.
/
/// This enum holds only `String` payloads so it is fully serializable
/// for audit-log persistence. Transport-layer details (reqwest errors,
/// decode errors, signature errors) live in the adapter's
/// `KernelClientError` (Addendum 2a §4 — stays in the adapter so the
/// domain crate keeps zero I/O imports).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum KernelDecisionError {
    /// Kernel was unreachable (timeout, connection refused, etc.) OR
    /// the circuit breaker is in `Open` state. The caller MUST reject
    /// the operation; there is no silent fallback to ALLOW.
    Unavailable {
        /// Human-readable explanation, suitable for an audit-log line.
        reason: String,
    },
    /// Kernel explicitly refused (authoritative DENY rolled up into the
    /// error channel — distinct from `KernelDecision::Deny` which sits
    /// on the Ok arm and carries a body the caller may inspect).
    Denied {
        /// Human-readable reason from the kernel response.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_is_distinct_from_denied() {
        // Addendum 2a §4 / fail-closed invariant: the two error modes
        // must be distinguishable so the caller's audit log can
        // separate "kernel down" from "kernel refused".
        let unavail = KernelDecisionError::Unavailable {
            reason: "circuit breaker open".to_string(),
        };
        let denied = KernelDecisionError::Denied {
            reason: "subject not on allowlist".to_string(),
        };
        assert_ne!(unavail, denied);
    }

    #[test]
    fn kernel_decision_error_roundtrips_via_serde() {
        let err = KernelDecisionError::Unavailable {
            reason: "timeout".to_string(),
        };
        let j = serde_json::to_string(&err).expect("serialize");
        let back: KernelDecisionError = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(err, back);
    }
}
