//! `WaveAuditVerifier` — the audit-fields predicate that gates
//! `Wave<S>` deserialization.
//!
//! # internal-ref (purple-team finding, closes the same class of bug as
//! `wave_audit_verifier.py` FINDING-D1/D3)
//!
//! `Wave<S>`'s `_state: PhantomData<S>` field makes illegal
//! **transitions** a compile error (Rule 8 `compile_fail` doc-tests
//! on [`super::Wave`]), but `#[derive(Deserialize)]` on a plain
//! struct does not care what value `S` is instantiated at — it just
//! deserializes every non-phantom field and, if all of them parse,
//! hands back a `Wave<S>`. Because `adversarial_session`,
//! `purple_team_session`, and `uat_verdicts` are all `Option<_>`,
//! `serde`'s derive treats a *missing* JSON key as `None` rather than
//! a parse error. The result: `serde_json::from_str::<Wave<Closed>>`
//! happily synthesizes a "closed" wave out of a payload that looks
//! exactly like a freshly-`Planned` one (`ctx` + `role_assignments`,
//! nothing else) — bypassing the entire ceremony the type-state
//! exists to enforce, with no compile error and no panic.
//!
//! This module closes that gap with the [`WaveStateAuditFields`]
//! trait: each state marker declares which of the shared `Option`
//! fields MUST be populated for a wave to have honestly reached that
//! state, and [`super::Wave`]'s hand-written `Deserialize` impl (see
//! `mod.rs`) calls it **during** deserialization — a payload that
//! fails the check can never become a `Wave<S>` value in the first
//! place. That is the impossible-by-construction half of the fix.
//!
//! [`verify_wave_audit_fields`] re-exposes the same predicate as a
//! standalone, callable-again function for two reasons:
//!   1. **Parity** with the existing Python boundary check
//!      (`arya_core_py/python/arya_core/wave/wave_audit_verifier.py`,
//!      internal-ref) that already made this exact call for the PyO3 /
//!      MCP boundary — same finding codes (`FINDING-D1`, `FINDING-D3`),
//!      plus one Rust-only addition (`FINDING-D4`, UAT verdicts,
//!      which the Python module does not check).
//!   2. **Defense in depth** for the one path the custom `Deserialize`
//!      impl cannot cover: a downstream crate that builds a `Wave<S>`
//!      via `unsafe` field-by-field construction instead of `serde`
//!      (the pre-existing soundness note in `mod.rs` already flags
//!      this as the one hole `PhantomData` cannot close on its own).
//!      A consumer that receives a `Wave<S>` from such a path can
//!      still call `verify_wave_audit_fields` before trusting it.
//!
//! # What this module does NOT close
//!
//! Neither check can tell a *real* `adversarial_session` /
//! `purple_team_session` id from a *plausible-looking fabricated one*.
//! A payload such as `{"adversarial_session": "adv-fake-totally-legit"}`
//! passes both checks because the field is merely non-`None`, not
//! cryptographically bound to a real `/test` run. Closing that gap
//! requires cross-checking against the kernel-HMAC-signed
//! transparency-log chain (see [`super::session_record::WaveSessionRecord`]
//! and [`super::session_record::all_required_stages_present`]), which
//! needs network I/O the pure domain crate cannot perform per
//! `agent/boundaries.toml` (no `reqwest`, no `sqlx`, here or anywhere
//! else in this crate).
//!
//! Any service-layer consumer that accepts a `Wave<Closed>` from an
//! external source (HTTP body, PyO3 bridge, MCP tool argument) and
//! intends to treat it as the witness for `RSI_APPLY_IMPROVEMENT` or
//! `DOMAIN_DEPLOY_MODEL` MUST additionally fetch that wave's
//! `WaveSessionRecord` chain from the transparency log and call
//! `all_required_stages_present` on it before trusting the witness.
//! That mirrors the existing Python `WaveClosedWitness.from_dict`
//! chokepoint. This module narrows the attack surface down to that
//! one remaining, necessarily I/O-backed check; from inside a pure
//! domain crate it cannot eliminate that check entirely.

use super::context::{AdversarialSessionId, PurpleTeamSessionId, UatVerdict, WaveContext};
use super::{Accepted, Closed, Decomposed, Planned, PurpleTeamed, Tested, Wave};

/// A `Wave<S>`'s carried fields are inconsistent with having
/// legitimately reached state `S` via the transition methods.
///
/// Variant names and [`Self::finding_code`] mirror the Python
/// `WaveAuditFieldsError` (`wave_audit_verifier.py`, internal-ref) finding
/// codes so audit logs / Linear comments can cite one vocabulary
/// across both languages. `MissingUatVerdicts` (`FINDING-D4`) is a
/// Rust-only addition — the Python module only ported D1/D3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaveAuditFieldsError {
    /// `adversarial_session` is `None` on a state that requires the
    /// wave to have traversed `Tested` (`Tested` or later). Mirrors
    /// Python `FINDING-D3`.
    MissingAdversarialSession,
    /// `ctx.gate_surfaces` is non-empty but `purple_team_session` is
    /// `None`, on a state that requires the wave to have traversed
    /// `PurpleTeamed` (`PurpleTeamed` or later). Mirrors Python
    /// `FINDING-D1`.
    MissingPurpleTeamSession,
    /// `uat_verdicts` is `None` on a state that requires the wave to
    /// have traversed `Accepted` (`Accepted` or later). Rust-only —
    /// `FINDING-D4`.
    MissingUatVerdicts,
}

impl WaveAuditFieldsError {
    /// Finding code, for parity with the Python verifier's
    /// `WaveAuditFieldsError.finding` attribute.
    #[must_use]
    pub const fn finding_code(self) -> &'static str {
        match self {
            Self::MissingAdversarialSession => "FINDING-D3",
            Self::MissingPurpleTeamSession => "FINDING-D1",
            Self::MissingUatVerdicts => "FINDING-D4",
        }
    }

    /// Human-readable detail, matching the tone of the Python
    /// exception messages (used in `Display`/logs).
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::MissingAdversarialSession => {
                "adversarial_session is None; any wave that reached Tested or \
                 later must carry the /test session id (the type-state proves \
                 the transition ran in-process, but a JSON-deserialized \
                 witness could elide the field — this is the boundary check \
                 that catches it)"
            }
            Self::MissingPurpleTeamSession => {
                "gate_surfaces is non-empty but purple_team_session is None; \
                 a wave touching a gate surface must carry the /purple-team \
                 session id before it can be PurpleTeamed or later"
            }
            Self::MissingUatVerdicts => {
                "uat_verdicts is None; any wave that reached Accepted or \
                 later must carry /user-acceptance verdicts"
            }
        }
    }
}

impl std::fmt::Display for WaveAuditFieldsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.finding_code(), self.detail())
    }
}

impl std::error::Error for WaveAuditFieldsError {}

/// Per-state audit predicate, implemented once per state marker
/// ([`Planned`] .. [`Closed`]). Drives both `Wave<S>`'s custom
/// `Deserialize` impl (in `mod.rs`) and [`verify_wave_audit_fields`].
///
/// The trait — not a free function keyed on an enum — is deliberate:
/// it is what lets the `Deserialize` impl be generic over `S` while
/// still calling the *correct* per-state predicate at monomorphization
/// time, with no runtime state tag to get out of sync with the
/// compile-time one.
pub trait WaveStateAuditFields {
    /// Validate that the shared `Option` fields are consistent with
    /// having reached this state honestly (i.e. only via the
    /// transition methods on [`super::Wave`]).
    ///
    /// # Errors
    /// Returns the first violated finding.
    fn validate_wire_fields(
        ctx: &WaveContext,
        adversarial_session: &Option<AdversarialSessionId>,
        purple_team_session: &Option<PurpleTeamSessionId>,
        uat_verdicts: &Option<Vec<UatVerdict>>,
    ) -> Result<(), WaveAuditFieldsError>;
}

fn require_adversarial_session(
    adversarial_session: &Option<AdversarialSessionId>,
) -> Result<(), WaveAuditFieldsError> {
    if adversarial_session.is_none() {
        return Err(WaveAuditFieldsError::MissingAdversarialSession);
    }
    Ok(())
}

fn require_purple_team_if_gate_surface(
    ctx: &WaveContext,
    purple_team_session: &Option<PurpleTeamSessionId>,
) -> Result<(), WaveAuditFieldsError> {
    if ctx.requires_purple_team() && purple_team_session.is_none() {
        return Err(WaveAuditFieldsError::MissingPurpleTeamSession);
    }
    Ok(())
}

fn require_uat_verdicts(
    uat_verdicts: &Option<Vec<UatVerdict>>,
) -> Result<(), WaveAuditFieldsError> {
    if uat_verdicts.is_none() {
        return Err(WaveAuditFieldsError::MissingUatVerdicts);
    }
    Ok(())
}

impl WaveStateAuditFields for Planned {
    fn validate_wire_fields(
        _ctx: &WaveContext,
        _adversarial_session: &Option<AdversarialSessionId>,
        _purple_team_session: &Option<PurpleTeamSessionId>,
        _uat_verdicts: &Option<Vec<UatVerdict>>,
    ) -> Result<(), WaveAuditFieldsError> {
        // No transition has run yet — nothing to require.
        Ok(())
    }
}

impl WaveStateAuditFields for Decomposed {
    fn validate_wire_fields(
        _ctx: &WaveContext,
        _adversarial_session: &Option<AdversarialSessionId>,
        _purple_team_session: &Option<PurpleTeamSessionId>,
        _uat_verdicts: &Option<Vec<UatVerdict>>,
    ) -> Result<(), WaveAuditFieldsError> {
        // `decompose` only sets `role_assignments`, which is not
        // `Option` (an empty Vec is a legitimate — if unusual —
        // decomposition, so it is not checked here).
        Ok(())
    }
}

impl WaveStateAuditFields for Tested {
    fn validate_wire_fields(
        _ctx: &WaveContext,
        adversarial_session: &Option<AdversarialSessionId>,
        _purple_team_session: &Option<PurpleTeamSessionId>,
        _uat_verdicts: &Option<Vec<UatVerdict>>,
    ) -> Result<(), WaveAuditFieldsError> {
        require_adversarial_session(adversarial_session)
    }
}

impl WaveStateAuditFields for PurpleTeamed {
    fn validate_wire_fields(
        ctx: &WaveContext,
        adversarial_session: &Option<AdversarialSessionId>,
        purple_team_session: &Option<PurpleTeamSessionId>,
        _uat_verdicts: &Option<Vec<UatVerdict>>,
    ) -> Result<(), WaveAuditFieldsError> {
        require_adversarial_session(adversarial_session)?;
        require_purple_team_if_gate_surface(ctx, purple_team_session)
    }
}

impl WaveStateAuditFields for Accepted {
    fn validate_wire_fields(
        ctx: &WaveContext,
        adversarial_session: &Option<AdversarialSessionId>,
        purple_team_session: &Option<PurpleTeamSessionId>,
        uat_verdicts: &Option<Vec<UatVerdict>>,
    ) -> Result<(), WaveAuditFieldsError> {
        require_adversarial_session(adversarial_session)?;
        require_purple_team_if_gate_surface(ctx, purple_team_session)?;
        require_uat_verdicts(uat_verdicts)
    }
}

impl WaveStateAuditFields for Closed {
    fn validate_wire_fields(
        ctx: &WaveContext,
        adversarial_session: &Option<AdversarialSessionId>,
        purple_team_session: &Option<PurpleTeamSessionId>,
        uat_verdicts: &Option<Vec<UatVerdict>>,
    ) -> Result<(), WaveAuditFieldsError> {
        // `closeout` carries every field from `Accepted` forward
        // unchanged, so `Closed`'s requirement is identical.
        require_adversarial_session(adversarial_session)?;
        require_purple_team_if_gate_surface(ctx, purple_team_session)?;
        require_uat_verdicts(uat_verdicts)
    }
}

/// Re-run the audit-fields check against an already-constructed
/// `Wave<S>`.
///
/// Any value that was actually produced by `serde_json::from_str`
/// already satisfies this — the custom `Deserialize` impl on
/// `Wave<S>` calls the exact same [`WaveStateAuditFields`] impl
/// before the value can exist — so this function is redundant on
/// that path by design (cheap, and proves the invariant holds). Its
/// purpose is the *other* construction path: see the module docs for
/// why a non-serde path is a residual risk this crate cannot close
/// unilaterally.
///
/// # Errors
/// See [`WaveStateAuditFields::validate_wire_fields`].
pub fn verify_wave_audit_fields<S: WaveStateAuditFields>(
    wave: &Wave<S>,
) -> Result<(), WaveAuditFieldsError> {
    S::validate_wire_fields(
        &wave.ctx,
        &wave.adversarial_session,
        &wave.purple_team_session,
        &wave.uat_verdicts,
    )
}
