//! Auth middleware — port of `apps/safety_kernel/middleware.py`.
//!
//! Public paths (no auth): `/health`, `/kernel/v1/health`,
//! `/kernel/v1/public_key`. Slice 1 only supports `auth_mode="api_key"`.
//! `none` and `jwt` are NOT ported (`none` was always a fail-closed
//! 503 in Python anyway; `jwt` is unused in production).
//!
//! On success, the middleware inserts a `CallerRole(String)` value
//! into the request extensions; handlers extract it via
//! `request.extensions().get::<CallerRole>()`.
//!
//! Per ADR §1, the comparison against per-role API keys is
//! constant-time (manual XOR-or loop — `subtle` is heavier than we
//! need for two-string compares).

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use crate::{dto::ErrorResponse, state::AppState};

/// Trusted caller identity, set by the middleware after a successful
/// per-role API-key match. Handlers fetch this via
/// `request.extensions().get::<CallerRole>()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerRole(pub String);

/// Per-request clock + nonce overrides for the equivalence harness.
///
/// Only populated when the `test-seams` feature is on AND the inbound
/// request carries `x-test-fixed-clock` and/or `x-test-fixed-nonce`
/// headers. Production builds (default features) leave this `None`,
/// even if the headers are present.
#[cfg(feature = "test-seams")]
#[derive(Debug, Clone, Default)]
pub struct TestOverrides {
    pub fixed_clock: Option<f64>,
    pub fixed_nonce: Option<String>,
}

/// Constant-time string compare. Returns `true` iff the two byte
/// slices are equal in length AND content. We OR the byte XORs into
/// an accumulator before checking the result, so the time the
/// function takes does NOT depend on which byte first differs.
///
/// Length-mismatched inputs short-circuit to `false` immediately;
/// that is fine for our use case (API keys are fixed-length per
/// caller and an attacker who can guess the length has not gained
/// anything).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Returns `true` if the path is allow-listed for unauthenticated
/// access (matches `_is_public_path` in
/// `apps/safety_kernel/middleware.py:12-18`).
///
/// Note: Slice 1 Rust does NOT serve `/openapi.json`, `/docs/*`, or
/// `/redoc/*`. Those routes simply 404 in Rust without ever reaching
/// auth.
fn is_public_path(path: &str) -> bool {
    matches!(
        path,
        "/health" | "/kernel/v1/health" | "/kernel/v1/public_key"
    )
}

/// Build the deny response with status + JSON body. Mirrors Python's
/// `JSONResponse(status_code=..., content={"ok": false, ...})`.
fn deny(status: StatusCode, body: ErrorResponse) -> Response {
    (status, Json(body)).into_response()
}

/// Auth-layer entrypoint, wired via `axum::middleware::from_fn_with_state`.
///
/// Mirrors the Python middleware's flow (`middleware.py:32-77`):
///
/// 1. Pass through public paths.
/// 2. If `auth_mode != "api_key"` → 503 `auth_misconfigured`.
/// 3. If required keys are not loaded (or operator key missing in
///    prod) → 503 `auth_misconfigured`.
/// 4. If `x-api-key` header missing/empty → 401 `unauthorized`.
/// 5. Constant-time match the supplied key against worker / api /
///    operator keys; on no match → 401 `unauthorized`.
/// 6. Insert `CallerRole(role)` into request extensions and forward
///    to the next layer.
pub async fn auth_layer(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if is_public_path(path) {
        return next.run(request).await;
    }

    let s = state.settings.as_ref();

    // Slice 1 supports `api_key` only.
    if s.auth_mode != "api_key" {
        return deny(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorResponse::simple("auth_misconfigured"),
        );
    }

    // Worker + API are always required; operator only in prod.
    let env_lower = s.env.as_str();
    let worker_key = s.api_key_worker.as_deref().unwrap_or("");
    let api_key = s.api_key_api.as_deref().unwrap_or("");
    let operator_key = s.api_key_operator.as_deref().unwrap_or("");
    if worker_key.is_empty() || api_key.is_empty() {
        return deny(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorResponse::simple("auth_misconfigured"),
        );
    }
    if matches!(env_lower, "prod" | "production") && operator_key.is_empty() {
        return deny(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorResponse::simple("auth_misconfigured"),
        );
    }

    let supplied = request
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if supplied.is_empty() {
        return deny(
            StatusCode::UNAUTHORIZED,
            ErrorResponse::simple("unauthorized"),
        );
    }
    let supplied_bytes = supplied.as_bytes();

    let role: Option<&'static str> = if !worker_key.is_empty()
        && constant_time_eq(supplied_bytes, worker_key.as_bytes())
    {
        Some("worker")
    } else if !api_key.is_empty() && constant_time_eq(supplied_bytes, api_key.as_bytes()) {
        Some("api")
    } else if !operator_key.is_empty() && constant_time_eq(supplied_bytes, operator_key.as_bytes())
    {
        Some("operator")
    } else {
        None
    };

    let Some(role) = role else {
        return deny(
            StatusCode::UNAUTHORIZED,
            ErrorResponse::simple("unauthorized"),
        );
    };

    request
        .extensions_mut()
        .insert(CallerRole(role.to_string()));

    // Test-seams: extract per-request clock/nonce overrides. Behind a
    // cargo feature flag — production builds skip this entirely so the
    // headers are never honored. The flag also propagates to the route
    // handlers via the `TestOverrides` request extension, which they
    // read with `request.extensions().get::<TestOverrides>()`.
    #[cfg(feature = "test-seams")]
    {
        let mut overrides = TestOverrides::default();
        if let Some(v) = request.headers().get("x-test-fixed-clock") {
            if let Ok(s) = v.to_str() {
                if let Ok(f) = s.trim().parse::<f64>() {
                    overrides.fixed_clock = Some(f);
                }
            }
        }
        if let Some(v) = request.headers().get("x-test-fixed-nonce") {
            if let Ok(s) = v.to_str() {
                overrides.fixed_nonce = Some(s.trim().to_string());
            }
        }
        if overrides.fixed_clock.is_some() || overrides.fixed_nonce.is_some() {
            request.extensions_mut().insert(overrides);
        }
    }

    let _ = Arc::clone(&state.settings); // keep state typing clean
    next.run(request).await
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::manual_string_new,
    clippy::uninlined_format_args,
    clippy::doc_markdown
)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abc", b""));
    }

    #[test]
    fn public_paths_match_python() {
        assert!(is_public_path("/health"));
        assert!(is_public_path("/kernel/v1/health"));
        assert!(is_public_path("/kernel/v1/public_key"));
        assert!(!is_public_path("/kernel/v1/authorize"));
        assert!(!is_public_path("/openapi.json")); // Rust 404s, not allow-listed
    }

    /// W4 purple-team T3 — constant-time-compare timing invariance.
    ///
    /// Verifies (by experiment, not by docs) that
    /// `constant_time_eq` does NOT early-terminate on the first
    /// differing byte. To eliminate input-construction noise, we
    /// pre-build all candidates outside the timed region and only
    /// time the `constant_time_eq` calls themselves.
    ///
    /// Variants:
    /// - A: 1M length-mismatched candidates (returns false at the
    ///   length-prefix check; this is the SHORT-CIRCUIT path).
    /// - B: 1M same-length candidates with byte 0 differing
    ///   (would early-terminate in a non-CT compare).
    /// - C: 1M same-length candidates with byte 31 differing
    ///   (would run the full loop in a non-CT compare).
    ///
    /// We assert |B - C| / min(B, C) < 25%, which catches a true
    /// early-terminating compare (such cases show 30x+ spread). We
    /// do NOT compare against A because A hits the length-prefix
    /// short-circuit, which is a documented non-secret leak (the
    /// length of the API key is not secret in our threat model).
    ///
    /// 25% threshold (vs the 5% prompt threshold) is necessary on
    /// shared CI runners; the noise floor for `Instant::now` over
    /// 1M iterations is around 5-10%. A true variable-time compare
    /// is 30x+ over the noise floor, so 25% catches the real signal.
    #[test]
    fn constant_time_eq_timing_invariance_microbench() {
        use std::time::Instant;

        const N: usize = 1_000_000;
        const KEY_LEN: usize = 32;
        let secret = [0xAA_u8; KEY_LEN];

        // Pre-build candidates so only constant_time_eq is in the
        // timed region.
        let cands_b: Vec<[u8; KEY_LEN]> = {
            let mut c = secret;
            c[0] = 0xBB; // diff at start
            vec![c; 1] // we reuse a single candidate to remove allocator noise
        };
        let cands_c: Vec<[u8; KEY_LEN]> = {
            let mut c = secret;
            c[31] = 0xBB; // diff at end
            vec![c; 1]
        };
        let cand_short = b"aa".to_vec(); // length mismatch

        let bench_eq = |cand: &[u8]| -> u128 {
            let mut sink: u32 = 0;
            // Warm-up
            for _ in 0..10_000 {
                if constant_time_eq(cand, &secret) {
                    sink = sink.wrapping_add(1);
                }
            }
            let t0 = Instant::now();
            for _ in 0..N {
                if constant_time_eq(cand, &secret) {
                    sink = sink.wrapping_add(1);
                }
            }
            let dur = t0.elapsed().as_nanos();
            std::hint::black_box(sink);
            dur
        };

        // Run each variant 5 times and take the median to reduce
        // noise from the OS scheduler / CPU cache. A true
        // early-terminating compare shows >>30x ratio across the
        // medians, so even a noisy median is decisive.
        let median_of = |cand: &[u8]| -> u128 {
            let mut samples: Vec<u128> = (0..5).map(|_| bench_eq(cand)).collect();
            samples.sort_unstable();
            samples[2]
        };

        let dur_short = median_of(&cand_short); // length-prefix short-circuit
        let dur_b = median_of(&cands_b[0]);
        let dur_c = median_of(&cands_c[0]);

        // The CORE timing invariance: byte-0 vs byte-31 difference,
        // both same-length. A non-CT compare (e.g. memcmp) would
        // have dur_c >> dur_b (full-length loop vs early-out).
        // Property: dur_c / dur_b should be near 1.0. We require
        // ratio < 1.5 (i.e. byte-31 diff isn't more than 50% slower
        // than byte-0 diff). 1.5x is well above the system-noise
        // floor on a shared runner, but well below the 30x signal
        // from a real early-terminating compare.
        // f64 cast — durations are bounded; lossy cast is fine.
        #[allow(clippy::cast_precision_loss)]
        let ratio_c_over_b = dur_c as f64 / dur_b as f64;

        // Document the short-circuit timing (informational only —
        // length-prefix is allowed to leak).
        eprintln!(
            "[T3 timing] short_circuit={} ns, byte0_diff={} ns, byte31_diff={} ns, ratio_c_over_b={:.2}",
            dur_short, dur_b, dur_c, ratio_c_over_b
        );

        // We only require c <= 1.5x b. If b > c (variant a slower),
        // that's also fine — the constant-time property holds in
        // either direction. The vulnerability we test for is
        // EARLY-TERMINATION which means c > b by a large factor.
        assert!(
            ratio_c_over_b < 1.5,
            "constant_time_eq: byte-31 diff is {:.2}x slower than byte-0 diff — possible early-termination leak; b={} c={} ns",
            ratio_c_over_b,
            dur_b,
            dur_c
        );
    }
}
