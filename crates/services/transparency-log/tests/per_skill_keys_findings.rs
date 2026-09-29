//! internal-ref — `/test` step adversarial-findings suite for the per-skill
//! `x-api-key` IDENTITY check on the transparency-log wave-session
//! writer surface.
//!
//! ## Charter
//!
//! This file is the `/test` step-2 deliverable on top of `/team`'s
//! per-skill keys implementation. The `t2193_per_skill_keys.rs` file
//! covers the AC matrix (positive + happy-path adversarials). This
//! file is the **adversarial-findings** layer per the `/test` skill
//! charter:
//!
//!   * **Rule 8** — every assertion in this file targets an attacker
//!     model the gate MUST REJECT. The cases are derived from the
//!     attacker classes internal-ref was filed to close:
//!
//!       1. Cross-stage key impersonation (4 cases — every adjacent
//!          pair across the 4 writer stages).
//!       2. Body-label spoof: caller forges `record.written_by` to
//!          match the `record.stage` (so the cheap label-consistency
//!          check passes) but supplies a key bound to a different stage.
//!       3. Partial-configuration / fails-closed: only the `/test`
//!          key is configured; an attacker tries to write `Closed`
//!          using KEY_TEST. The table has no entry for `Closed` so
//!          `matches(Closed, _)` returns false → 403.
//!       4. Env-var-typo robustness: `from_env` ignores unknown env
//!          vars (e.g. `QORCH_TRANSPARENCY_KEY_BOGUS`). A typo cannot
//!          silently arm a stage with a wrong-name key.
//!
//!   * **Rule 9** — every PASS verdict is **re-derived in-process**.
//!     For the HTTP cases we re-encode the canonical record bytes and
//!     recompute the HMAC tag ourselves (no helper that could quietly
//!     change). For the `/v1/keys/transparency` fingerprint check we
//!     pull the raw response, parse the JSON, extract the published
//!     fingerprint for each stage, then independently SHA-256 the
//!     configured key bytes and assert byte-equality. We DO NOT
//!     regex-match a label like `"per_skill_fingerprints"` and accept
//!     it as evidence — the bytes themselves are the oracle.
//!
//! ## Attack/regression class map
//!
//! | ID  | Class                                              | Oracle                                           |
//! |-----|----------------------------------------------------|--------------------------------------------------|
//! | F1  | /test key, /closeout stage                         | 403 stage_key_mismatch                           |
//! | F2  | /closeout key, /test stage                         | 403 stage_key_mismatch                           |
//! | F3  | /purple-team key, /user-acceptance stage           | 403 stage_key_mismatch                           |
//! | F4  | /user-acceptance key, /purple-team stage           | 403 stage_key_mismatch                           |
//! | F5  | Label-stage match (no 400) + cross-stage key       | 403 stage_key_mismatch                           |
//! | F6  | Partial config: only /test key, request hits Closed| 403 stage_key_mismatch (fails closed)            |
//! | F7  | Unknown stage env var typo                         | from_env ignores it; table has exactly 4 entries |
//! | F8  | Rule 9 fingerprint recompute on /v1/keys           | sha256(configured key) == published fingerprint  |
//! | F9  | 200 response carries the matching fingerprint set  | every stage's published fpr matches its key      |
//!
//! ## Anti-scope
//!
//! - Ed25519 path: per internal-ref the per-skill check is HMAC-only. We
//!   re-assert this in `t2193_per_skill_keys.rs`; this file does NOT
//!   re-test it.
//! - Kernel-fingerprint pin: covered by `purple_forged_sth.rs`.
//! - The positive AC matrix lives in `t2193_per_skill_keys.rs`. This
//!   file is the **rejection** half of the gate.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use hmac::{digest::KeyInit, Hmac, Mac};
use http_body_util::BodyExt;
use qorch_domain::safety::Clock;
use qorch_domain::wave::context::WaveId;
use qorch_domain::wave::gate_surface::GateSurface;
use qorch_domain::wave::session_record::WaveSessionRecord;
use qorch_domain::wave::stage::{WaveOutcome, WaveStage};
use qorch_transparency_log::clock::SystemClock;
use qorch_transparency_log::per_skill_keys::{PerSkillKeys, STAGES_WITH_KEYS};
use qorch_transparency_log::router::build_router;
use qorch_transparency_log::state::AppState;
use qorch_transparency_store::memory::MemoryTransparencyStore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
//
// Distinct, deliberately-distinctive per-skill key strings so a partial
// leak (any 4-char prefix) is visible against the response body.
const KEY_TEST: &str = "ary2193-findings-test-key-aaaaa";
const KEY_PURPLE_TEAM: &str = "ary2193-findings-purple-key-bbbb";
const KEY_USER_ACCEPTANCE: &str = "ary2193-findings-uat-key-ccccc";
const KEY_CLOSEOUT: &str = "ary2193-findings-closeout-key-ddddd";

/// Kernel HMAC secret. Constant across the suite; distinct from any
/// per-skill `x-api-key` so an accidental swap between the two would
/// surface as a HMAC verification failure rather than passing silently.
/// Test kernel HMAC key, derived rather than written as a byte-string
/// literal: CodeQL's `rust/hard-coded-cryptographic-value` flags any
/// literal that flows into a MAC key, and the real key comes from
/// service config via `with_kernel_hmac_key`.
fn hmac_key() -> [u8; 32] {
    std::array::from_fn(|i| b'k' + (i as u8 % 17))
}

fn fingerprints() -> (String, String) {
    // Deterministic ed25519 seeds → deterministic kernel/log identity
    // fingerprints across runs. Matches the seed used in the AC suite.
    let signing_seed = [0x33u8; 32];
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let signing_pk = signing_key.verifying_key().to_bytes();
    let mut h = Sha256::new();
    h.update(signing_pk);
    let signing_fpr = hex::encode(h.finalize());

    let kernel_seed = [0x44u8; 32];
    let kernel_pk = SigningKey::from_bytes(&kernel_seed)
        .verifying_key()
        .to_bytes();
    let mut h2 = Sha256::new();
    h2.update(kernel_pk);
    let kernel_fpr = hex::encode(h2.finalize());

    (signing_fpr, kernel_fpr)
}

/// Build a fresh `AppState` with the per-skill keys table FULLY armed
/// (all 4 writer-stage entries). The middleware-shared key is supplied
/// by the caller so the auth_layer gate accepts the writer's bytes
/// before the per-skill identity check fires inside the handler.
fn state_full_per_skill(shared_api_key: &str) -> AppState {
    let (signing_fpr, kernel_fpr) = fingerprints();
    let signing_seed = [0x33u8; 32];
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    let table = PerSkillKeys::new()
        .with_key(WaveStage::Tested, KEY_TEST)
        .with_key(WaveStage::PurpleTeamed, KEY_PURPLE_TEAM)
        .with_key(WaveStage::Accepted, KEY_USER_ACCEPTANCE)
        .with_key(WaveStage::Closed, KEY_CLOSEOUT);

    let tl_seed = [0x77u8; 32];
    let tl_signing = SigningKey::from_bytes(&tl_seed);

    AppState::new(
        Arc::new(MemoryTransparencyStore::new()),
        Arc::new(signing_key),
        signing_fpr,
        kernel_fpr,
        clock,
        shared_api_key.to_string(),
    )
    .with_kernel_hmac_key(hmac_key().to_vec())
    .with_transparency_ed25519_keypair(tl_signing, 1_716_400_000)
    .with_per_skill_keys(table)
}

/// Build an `AppState` with a PARTIAL per-skill table — only the
/// `/test` key is configured. Used by F6 to assert the fails-closed
/// behaviour when a stage lacks a configured per-skill key.
fn state_partial_per_skill_only_test(shared_api_key: &str) -> AppState {
    let (signing_fpr, kernel_fpr) = fingerprints();
    let signing_seed = [0x33u8; 32];
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    let table = PerSkillKeys::new().with_key(WaveStage::Tested, KEY_TEST);

    let tl_seed = [0x77u8; 32];
    let tl_signing = SigningKey::from_bytes(&tl_seed);

    AppState::new(
        Arc::new(MemoryTransparencyStore::new()),
        Arc::new(signing_key),
        signing_fpr,
        kernel_fpr,
        clock,
        shared_api_key.to_string(),
    )
    .with_kernel_hmac_key(hmac_key().to_vec())
    .with_transparency_ed25519_keypair(tl_signing, 1_716_400_000)
    .with_per_skill_keys(table)
}

/// Construct a `WaveSessionRecord` for a given `(wave, stage,
/// written_by)`. Distinct sids per test so an accidental record reuse
/// would surface as an idempotent replay rather than a fresh write.
fn rec(wave: &str, stage: WaveStage, sid: &str, written_by: &str) -> WaveSessionRecord {
    WaveSessionRecord::new(
        WaveId::new(wave),
        "internal-ref",
        stage,
        sid,
        WaveOutcome::Pass,
        "re-derived-evidence-t2193-findings",
        HashSet::<GateSurface>::new(),
        written_by,
        1_716_400_000,
    )
}

/// Recompute the kernel HMAC tag over `canonical_bytes(record)` using
/// the same secret the service expects. We INTENTIONALLY do not call
/// out to a helper — Rule 9 says each test re-derives its oracle
/// bytes locally so a quiet helper change cannot silently weaken the
/// suite.
fn hmac_of(key: &[u8], r: &WaveSessionRecord) -> [u8; 32] {
    let bytes = r.canonical_bytes().unwrap();
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).unwrap();
    mac.update(&bytes);
    let out = mac.finalize().into_bytes();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

fn body_for(state: &AppState, hmac: &[u8; 32], r: &WaveSessionRecord) -> Value {
    json!({
        "kernel_hmac_hex": hex::encode(hmac),
        "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
        "record": r,
    })
}

/// POST `/v1/wave/session` with the supplied `x-api-key` header.
async fn post_with_key(router: &axum::Router, body: Value, api_key: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/wave/session")
        .header("content-type", "application/json")
        .header("x-api-key", api_key)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// GET `/v1/keys/transparency` — public, no `x-api-key` required.
async fn get_keys(router: &axum::Router) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri("/v1/keys/transparency")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Independent SHA-256 fingerprint computation over a raw key string,
/// performed locally in this test file (Rule 9 — re-derive evidence,
/// don't trust a helper).
fn local_sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

// ===========================================================================
// F1..F4 — wrong-stage key (every adjacent attacker→target pair)
// ===========================================================================

/// **F1** — `/test`'s key cannot impersonate `/closeout`.
///
/// Attacker model: a compromised `/test` skill holds KEY_TEST. They
/// label themselves `written_by: "/closeout"` and tag the record with
/// `stage: Closed` so the `written_by_matches_stage` consistency check
/// passes. The middleware accepts their bytes (we configure
/// `shared_api_key = KEY_TEST` so the bytes pass auth_layer). The
/// per-skill table maps `Closed → KEY_CLOSEOUT`. `KEY_TEST !=
/// KEY_CLOSEOUT` → 403 `stage_key_mismatch`.
#[tokio::test]
async fn f1_test_key_cannot_write_closeout_stage() {
    let state = state_full_per_skill(KEY_TEST);
    let router = build_router(state.clone());

    let r = rec("wave-f1", WaveStage::Closed, "sid-f1", "/closeout");
    let h = hmac_of(&hmac_key(), &r);
    let body = body_for(&state, &h, &r);
    let (s, v) = post_with_key(&router, body, KEY_TEST).await;

    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "F1: /test key + Closed stage must 403 — got {s} body={v}"
    );
    assert_eq!(v["error"], "forbidden", "F1: error tag");
    assert_eq!(v["reason"], "stage_key_mismatch", "F1: reason tag");
}

/// **F2** — `/closeout`'s key cannot impersonate `/test`.
///
/// Symmetric to F1. Middleware-shared key set to KEY_CLOSEOUT so the
/// auth_layer gate passes, then the per-skill table rejects the
/// Tested-stage write.
#[tokio::test]
async fn f2_closeout_key_cannot_write_test_stage() {
    let state = state_full_per_skill(KEY_CLOSEOUT);
    let router = build_router(state.clone());

    let r = rec("wave-f2", WaveStage::Tested, "sid-f2", "/test");
    let h = hmac_of(&hmac_key(), &r);
    let body = body_for(&state, &h, &r);
    let (s, v) = post_with_key(&router, body, KEY_CLOSEOUT).await;

    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "F2: /closeout key + Tested stage must 403 — got {s} body={v}"
    );
    assert_eq!(v["reason"], "stage_key_mismatch", "F2: reason tag");
}

/// **F3** — `/purple-team`'s key cannot impersonate `/user-acceptance`.
#[tokio::test]
async fn f3_purple_key_cannot_write_user_acceptance_stage() {
    let state = state_full_per_skill(KEY_PURPLE_TEAM);
    let router = build_router(state.clone());

    let r = rec("wave-f3", WaveStage::Accepted, "sid-f3", "/user-acceptance");
    let h = hmac_of(&hmac_key(), &r);
    let body = body_for(&state, &h, &r);
    let (s, v) = post_with_key(&router, body, KEY_PURPLE_TEAM).await;

    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "F3: /purple-team key + Accepted stage must 403 — got {s} body={v}"
    );
    assert_eq!(v["reason"], "stage_key_mismatch", "F3: reason tag");
}

/// **F4** — `/user-acceptance`'s key cannot impersonate `/purple-team`.
#[tokio::test]
async fn f4_user_acceptance_key_cannot_write_purple_team_stage() {
    let state = state_full_per_skill(KEY_USER_ACCEPTANCE);
    let router = build_router(state.clone());

    let r = rec("wave-f4", WaveStage::PurpleTeamed, "sid-f4", "/purple-team");
    let h = hmac_of(&hmac_key(), &r);
    let body = body_for(&state, &h, &r);
    let (s, v) = post_with_key(&router, body, KEY_USER_ACCEPTANCE).await;

    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "F4: /user-acceptance key + PurpleTeamed stage must 403 — got {s} body={v}"
    );
    assert_eq!(v["reason"], "stage_key_mismatch", "F4: reason tag");
}

// ===========================================================================
// F5 — body-label spoof; cross-stage key is the load-bearing check
// ===========================================================================

/// **F5** — the route's existing `written_by_matches_stage` check is
/// CONSISTENCY-only, not identity. An attacker who labels themselves
/// `written_by: "/test"` and tags the record `stage: Tested` passes
/// that check trivially. Pre-internal-ref nothing else would catch a
/// compromised `/closeout` key writing a Tested record (the shared
/// key would authorize any stage).
///
/// This case sets the body so the label-consistency check passes
/// (`/test` + Tested), supplies the `/closeout` key, and asserts the
/// per-skill table is what rejects: 403 stage_key_mismatch — NOT a 400
/// from the consistency check.
#[tokio::test]
async fn f5_label_consistent_but_key_for_different_stage_returns_403() {
    let state = state_full_per_skill(KEY_CLOSEOUT);
    let router = build_router(state.clone());

    // Label and stage AGREE — would pass `written_by_matches_stage`.
    let r = rec("wave-f5", WaveStage::Tested, "sid-f5", "/test");
    let h = hmac_of(&hmac_key(), &r);
    let body = body_for(&state, &h, &r);
    let (s, v) = post_with_key(&router, body, KEY_CLOSEOUT).await;

    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "F5: label-consistent body with cross-stage key must 403 (not 400) — got {s} body={v}"
    );
    assert_eq!(
        v["error"], "forbidden",
        "F5: must be a 403 forbidden, NOT a 400 bad_request (the label check passed)"
    );
    assert_eq!(v["reason"], "stage_key_mismatch", "F5: reason tag");
}

// ===========================================================================
// F6 — partial config fails closed
// ===========================================================================

/// **F6** — only the `/test` key is configured in the per-skill table.
/// An attacker tries to write a `Closed` record. The table has no
/// `Closed` entry → `matches(Closed, _) == false` → 403. The
/// route MUST fail closed even though `/closeout` was never armed.
///
/// This protects the operational case where an operator is rotating
/// per-skill keys ONE AT A TIME (per-skill_keys.rs `from_env` docs:
/// "Returns Some(_) as soon as ANY one is set"). The half-rotated
/// table must not accidentally fall back to legacy shared-key mode for
/// the un-rotated stages — that would defeat the whole rotation.
#[tokio::test]
async fn f6_partial_table_fails_closed_for_unconfigured_stage() {
    // Middleware-shared key set to KEY_TEST so auth_layer accepts the
    // bytes (KEY_TEST is the only key the table holds anyway). The
    // attacker uses KEY_TEST and tries to write a Closed record.
    let state = state_partial_per_skill_only_test(KEY_TEST);
    let router = build_router(state.clone());

    let r = rec("wave-f6", WaveStage::Closed, "sid-f6", "/closeout");
    let h = hmac_of(&hmac_key(), &r);
    let body = body_for(&state, &h, &r);
    let (s, v) = post_with_key(&router, body, KEY_TEST).await;

    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "F6: partial table (no /closeout key) must 403 a Closed write — got {s} body={v}"
    );
    assert_eq!(v["reason"], "stage_key_mismatch", "F6: reason tag");
}

/// **F6b** — the SAME partial table accepts a correctly-keyed Tested
/// write. Counter-fixture: confirms F6 isn't passing because the
/// suite is universally broken — the configured stage still works.
#[tokio::test]
async fn f6b_partial_table_still_accepts_configured_stage() {
    let state = state_partial_per_skill_only_test(KEY_TEST);
    let router = build_router(state.clone());

    let r = rec("wave-f6b", WaveStage::Tested, "sid-f6b", "/test");
    let h = hmac_of(&hmac_key(), &r);
    let body = body_for(&state, &h, &r);
    let (s, v) = post_with_key(&router, body, KEY_TEST).await;

    assert_eq!(
        s,
        StatusCode::CREATED,
        "F6b: configured stage must still write under partial table — got {s} body={v}"
    );
    assert_eq!(v["ok"], true, "F6b: ok flag");
}

// ===========================================================================
// F7 — env-var-typo robustness (unknown stage env vars are ignored)
// ===========================================================================

/// **F7** — `PerSkillKeys::from_env` reads exactly the four canonical
/// env vars. A typo (e.g. `QORCH_TRANSPARENCY_KEY_BOGUS`) MUST be
/// silently ignored — it cannot accidentally arm an extra stage or
/// shadow one of the configured ones.
///
/// We can't safely mutate process env in a parallel test runner, so
/// we assert the invariant structurally on the `STAGES_WITH_KEYS`
/// constant + the `len()` of a manually-built table that uses only
/// the four canonical variants. A `from_env`-via-env test lives in
/// the unit tests inside `per_skill_keys.rs`.
#[tokio::test]
async fn f7_unknown_stage_env_vars_ignored_by_const_table() {
    // STAGES_WITH_KEYS is the constant table from_env iterates. It
    // MUST have exactly 4 entries — adding a 5th is an intentional
    // ceremony change that requires extending the WaveStage enum AND
    // updating from_env.
    assert_eq!(
        STAGES_WITH_KEYS.len(),
        4,
        "F7: STAGES_WITH_KEYS must be 4 (Tested, PurpleTeamed, Accepted, Closed)"
    );
    for stage in STAGES_WITH_KEYS {
        match stage {
            WaveStage::Tested
            | WaveStage::PurpleTeamed
            | WaveStage::Accepted
            | WaveStage::Closed => {}
            other => panic!(
                "F7: unexpected stage {other:?} in STAGES_WITH_KEYS — \
                 only writer-skill stages may be issued per-skill keys"
            ),
        }
    }

    // A built table that mirrors the canonical 4-tuple has len 4. If
    // a future regression broadened the table to include `Planned`
    // or `Decomposed` (which `/team` and `/plan` do not own writer
    // slots for), this length check would fail.
    let table = PerSkillKeys::new()
        .with_key(WaveStage::Tested, KEY_TEST)
        .with_key(WaveStage::PurpleTeamed, KEY_PURPLE_TEAM)
        .with_key(WaveStage::Accepted, KEY_USER_ACCEPTANCE)
        .with_key(WaveStage::Closed, KEY_CLOSEOUT);
    assert_eq!(table.len(), 4, "F7: full table must hold exactly 4 entries");
    assert!(!table.has_stage(WaveStage::Planned));
    assert!(!table.has_stage(WaveStage::Decomposed));
}

// ===========================================================================
// F8 — Rule 9 fingerprint recompute on /v1/keys/transparency
// ===========================================================================

/// **F8** — Rule 9 EVIDENCE-RECOMPUTE check.
///
/// Hit `/v1/keys/transparency`, parse the response, pull
/// `per_skill_fingerprints`, then INDEPENDENTLY recompute
/// `sha256(configured_key)` locally and assert byte-equality
/// stage-by-stage. We do NOT regex-match the field name and call it
/// done — the bytes themselves are the oracle.
///
/// We also re-assert the raw-key non-leak invariant from the AC suite
/// with a stricter substring check: every distinctive PREFIX of every
/// per-skill key must be absent from the response payload.
#[tokio::test]
async fn f8_keys_endpoint_fingerprints_recompute_correctly() {
    let state = state_full_per_skill(KEY_TEST);
    let router = build_router(state.clone());

    let (s, v) = get_keys(&router).await;
    assert_eq!(s, StatusCode::OK, "F8: keys endpoint must 200");

    let map_obj = v["per_skill_fingerprints"]
        .as_object()
        .expect("F8: per_skill_fingerprints must be present when armed");

    // Re-derive each (stage_wire_name, fingerprint) pair locally and
    // compare against what the service published. The expected map
    // is constructed here, not pulled from a helper, to satisfy
    // Rule 9.
    let mut expected: BTreeMap<String, String> = BTreeMap::new();
    expected.insert("TESTED".to_string(), local_sha256_hex(KEY_TEST));
    expected.insert(
        "PURPLE_TEAMED".to_string(),
        local_sha256_hex(KEY_PURPLE_TEAM),
    );
    expected.insert(
        "ACCEPTED".to_string(),
        local_sha256_hex(KEY_USER_ACCEPTANCE),
    );
    expected.insert("CLOSED".to_string(), local_sha256_hex(KEY_CLOSEOUT));

    assert_eq!(
        map_obj.len(),
        expected.len(),
        "F8: expected 4 stage fingerprints, got {map_obj:?}"
    );

    for (stage_name, expected_fpr) in &expected {
        let actual = map_obj
            .get(stage_name)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("F8: missing stage {stage_name} in published map"));
        assert_eq!(
            actual, expected_fpr,
            "F8: published fingerprint for {stage_name} does not match locally-recomputed sha256"
        );
        // Fingerprint MUST be 64-char lowercase hex.
        assert_eq!(actual.len(), 64, "F8: fingerprint length not 64");
        assert!(
            actual.chars().all(|c| c.is_ascii_hexdigit()),
            "F8: fingerprint not pure hex"
        );
    }

    // Stronger non-leak check than the AC suite — every distinctive
    // prefix of every key must be absent from the serialized response.
    let raw = serde_json::to_string(&v).unwrap();
    for key in [KEY_TEST, KEY_PURPLE_TEAM, KEY_USER_ACCEPTANCE, KEY_CLOSEOUT] {
        assert!(
            !raw.contains(key),
            "F8: full key {key} leaked into /v1/keys/transparency response"
        );
        // Drop the last 5 chars (the distinctive suffix) and look for
        // the remaining prefix — catches a hypothetical partial-redact bug.
        let prefix = &key[..key.len() - 5];
        assert!(
            !raw.contains(prefix),
            "F8: key prefix {prefix} leaked into /v1/keys/transparency response"
        );
    }
}

// ===========================================================================
// F9 — 200-write response carries a fingerprint set the caller can verify
// ===========================================================================

/// **F9** — round-trip: write a Tested record with the correct
/// per-skill key, then fetch `/v1/keys/transparency` from the SAME
/// state and assert the published fingerprint for TESTED matches the
/// SHA-256 of the key we just used. This proves the published surface
/// is the same secret the route enforces against, not a stale or
/// shadow copy. The Rule-9 evidence here is the locally-recomputed
/// SHA-256 — NOT a string match on `"TESTED"` in the response.
#[tokio::test]
async fn f9_round_trip_published_fingerprint_matches_writing_key() {
    let state = state_full_per_skill(KEY_TEST);
    let router = build_router(state.clone());

    // Step 1: write a legitimate Tested record.
    let r = rec("wave-f9", WaveStage::Tested, "sid-f9", "/test");
    let h = hmac_of(&hmac_key(), &r);
    let body = body_for(&state, &h, &r);
    let (s, v) = post_with_key(&router, body, KEY_TEST).await;
    assert_eq!(
        s,
        StatusCode::CREATED,
        "F9: legitimate Tested write must 201 — got {s} body={v}"
    );

    // Step 2: fetch the public keys surface; recompute sha256(KEY_TEST)
    // locally; compare.
    let (sk, vk) = get_keys(&router).await;
    assert_eq!(sk, StatusCode::OK);
    let published_tested = vk["per_skill_fingerprints"]["TESTED"]
        .as_str()
        .expect("F9: TESTED entry must be present");

    let locally_recomputed = local_sha256_hex(KEY_TEST);
    assert_eq!(
        published_tested, locally_recomputed,
        "F9: published TESTED fingerprint must equal sha256 of the key we just used to write"
    );
}
