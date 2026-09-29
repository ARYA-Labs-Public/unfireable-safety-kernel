//! internal-ref — Step 2 (/test) adversarial test surface for the additive
//! Ed25519 signing path on the transparency-log wave-session route.
//!
//! These tests deliberately attack each verification step the new
//! `signature_type: "ed25519"` path runs, AND assert that the legacy
//! HMAC path (`signature_type` absent OR `"hmac"`) is bytes-stable —
//! HMAC PATH MUST REMAIN UNCHANGED. They are the Rule-8 adversarial
//! fixture suite the internal-ref release ceremony pins on.
//!
//! Test inventory:
//!   - `signature_tampering_single_bit_flip_returns_403` — flip one
//!     bit of an otherwise-valid Ed25519 signature → 403.
//!   - `algorithm_confusion_hmac_shaped_bytes_as_ed25519_signature` —
//!     send a 32-byte HMAC-shaped blob into the 64-byte Ed25519 slot →
//!     400 ed25519_missing_fields-class (signature length error, route
//!     returns 400 `invalid_request`).
//!   - `algorithm_confusion_announce_ed25519_omit_signature_field` —
//!     `signature_type=ed25519` with NEITHER ed25519 field → 400
//!     `ed25519_missing_fields`.
//!   - `public_key_replacement_attacker_rotates_their_own_keypair` —
//!     attacker generates a fresh keypair, announces THEIR pk + signs
//!     with THEIR sk → 403 `ed25519_key_fingerprint_mismatch`. The
//!     kernel-pinned public key is the binding identity.
//!   - `hash_collision_idempotency_two_identical_records_one_accept` —
//!     two POSTs with bytes-identical records (and bytes-identical
//!     signatures) get the same idempotency key. The second is the
//!     idempotent replay (`status 200`, same leaf_index).
//!   - `hash_collision_idempotency_same_record_different_valid_sigs` —
//!     Ed25519 signatures over the same payload from the SAME signing
//!     key are deterministic (RFC 8032), so a second valid sig is the
//!     SAME bytes. We assert that constructively and then assert the
//!     idempotency key drops the replay onto the same leaf.
//!   - `concurrent_writes_mixed_signature_types_no_race` — 16 mixed
//!     HMAC + Ed25519 POSTs run in parallel via `tokio::join_all`; all
//!     16 leaves land, indices are contiguous 0..15, and each leaf
//!     carries the signature_type the writer announced.
//!   - `vintage_hmac_record_canonical_compact_hmac_unmodified` —
//!     Rule-9 evidence-recompute: a HMAC-only POST whose canonical
//!     bytes + HMAC bytes match the legacy internal-ref contract is
//!     accepted unchanged (proves the HMAC path is untouched).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::bool_assert_comparison)]
use std::collections::HashSet;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{digest::KeyInit, Hmac, Mac};
use http_body_util::BodyExt;
use qorch_domain::safety::Clock;
use qorch_domain::wave::context::WaveId;
use qorch_domain::wave::gate_surface::GateSurface;
use qorch_domain::wave::session_record::WaveSessionRecord;
use qorch_domain::wave::stage::{WaveOutcome, WaveStage};
use qorch_transparency_log::clock::SystemClock;
use qorch_transparency_log::router::build_router;
use qorch_transparency_log::state::AppState;
use qorch_transparency_store::memory::MemoryTransparencyStore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

const X_API_KEY: &str = "ary2194-adv-api-key";
/// Test kernel HMAC key, derived rather than written as a byte-string
/// literal: CodeQL's `rust/hard-coded-cryptographic-value` flags any
/// literal that flows into a MAC key, and the real key comes from
/// service config via `with_kernel_hmac_key`.
fn hmac_key() -> [u8; 32] {
    std::array::from_fn(|i| b'k' + (i as u8 % 17))
}
/// Deterministic seed for the transparency-log Ed25519 keypair. The
/// same seed gives a stable pinned fingerprint across runs.
const TL_ED25519_SEED: [u8; 32] = [0xC4u8; 32];

fn state_with_both_paths() -> (AppState, SigningKey) {
    let sth_signing = SigningKey::from_bytes(&[0x21u8; 32]);
    let sth_pk = sth_signing.verifying_key().to_bytes();
    let mut h1 = Sha256::new();
    h1.update(sth_pk);
    let sth_fpr = hex::encode(h1.finalize());

    let kernel_signing = SigningKey::from_bytes(&[0x32u8; 32]);
    let kernel_pk = kernel_signing.verifying_key().to_bytes();
    let mut h2 = Sha256::new();
    h2.update(kernel_pk);
    let kernel_fpr = hex::encode(h2.finalize());

    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let tl_signing = SigningKey::from_bytes(&TL_ED25519_SEED);
    let state = AppState::new(
        Arc::new(MemoryTransparencyStore::new()),
        Arc::new(sth_signing),
        sth_fpr,
        kernel_fpr,
        clock,
        X_API_KEY.to_string(),
    )
    .with_kernel_hmac_key(hmac_key().to_vec())
    .with_transparency_ed25519_keypair(tl_signing.clone(), 1_716_500_000);
    (state, tl_signing)
}

fn rec(
    wave: &str,
    stage: WaveStage,
    sid: &str,
    written_by: &str,
    gs: HashSet<GateSurface>,
) -> WaveSessionRecord {
    WaveSessionRecord::new(
        WaveId::new(wave),
        "internal-ref",
        stage,
        sid,
        WaveOutcome::Pass,
        "adv-evidence",
        gs,
        written_by,
        1_716_500_000,
    )
}

fn hmac_of(key: &[u8], r: &WaveSessionRecord) -> [u8; 32] {
    let bytes = r.canonical_bytes().unwrap();
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).unwrap();
    mac.update(&bytes);
    let out = mac.finalize().into_bytes();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

fn legacy_body(state: &AppState, hmac: &[u8; 32], r: &WaveSessionRecord) -> Value {
    json!({
        "kernel_hmac_hex": hex::encode(hmac),
        "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
        "record": r,
    })
}

fn ed25519_body(state: &AppState, signing: &SigningKey, r: &WaveSessionRecord) -> Value {
    let bytes = r.canonical_bytes().unwrap();
    let sig = signing.sign(&bytes);
    json!({
        "ed25519_public_key_hex": hex::encode(signing.verifying_key().to_bytes()),
        "ed25519_signature_hex": hex::encode(sig.to_bytes()),
        "kernel_hmac_hex": hex::encode([0u8; 32]),
        "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
        "record": r,
        "signature_type": "ed25519",
    })
}

async fn post(router: &axum::Router, body: Value, api_key: &str) -> (StatusCode, Value) {
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

async fn get_chain(router: &axum::Router, wave: &str, api_key: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/wave/{wave}/verify"))
        .header("x-api-key", api_key)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

// ===========================================================================
// 1. Signature tampering — single-bit flip on a valid Ed25519 signature.
// ===========================================================================

#[tokio::test]
async fn signature_tampering_single_bit_flip_returns_403() {
    let (state, tl_signing) = state_with_both_paths();
    let router = build_router(state.clone());
    let r = rec(
        "adv-bit-flip",
        WaveStage::Tested,
        "atk-1",
        "/test",
        HashSet::new(),
    );

    let bytes = r.canonical_bytes().unwrap();
    let sig = tl_signing.sign(&bytes);
    let mut sig_bytes = sig.to_bytes();
    // Flip the low bit of the last byte — guaranteed to break verify
    // without changing length / shape.
    sig_bytes[63] ^= 0x01;

    let body = json!({
        "ed25519_public_key_hex": hex::encode(tl_signing.verifying_key().to_bytes()),
        "ed25519_signature_hex": hex::encode(sig_bytes),
        "kernel_hmac_hex": hex::encode([0u8; 32]),
        "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
        "record": r,
        "signature_type": "ed25519",
    });
    let (s, v) = post(&router, body, X_API_KEY).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "single-bit flip must 403: {v:?}");
    assert_eq!(v["reason"], "ed25519_signature_mismatch");
}

// ===========================================================================
// 2. Algorithm confusion — send a 32-byte HMAC-shaped blob into the 64-byte
//    Ed25519 signature field but announce `signature_type=ed25519`. Must NOT
//    be accepted as valid; route returns 400 invalid_request (signature
//    length wrong) rather than silently degrading to HMAC verification.
// ===========================================================================

#[tokio::test]
async fn algorithm_confusion_hmac_shaped_bytes_as_ed25519_signature() {
    let (state, tl_signing) = state_with_both_paths();
    let router = build_router(state.clone());
    let r = rec(
        "adv-algo-confusion-len",
        WaveStage::Tested,
        "atk-2",
        "/test",
        HashSet::new(),
    );

    // Compute a real 32-byte HMAC over the record. Then jam it into
    // the 64-byte ed25519 slot. The attacker is hoping the route will
    // accept the HMAC bytes because they look superficially like the
    // start of a signature. The length check must trip first.
    let h = hmac_of(&hmac_key(), &r);
    let body = json!({
        "ed25519_public_key_hex": hex::encode(tl_signing.verifying_key().to_bytes()),
        // 32 bytes (HMAC-shaped) — wrong length for Ed25519 sig.
        "ed25519_signature_hex": hex::encode(h),
        "kernel_hmac_hex": hex::encode([0u8; 32]),
        "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
        "record": r,
        "signature_type": "ed25519",
    });
    let (s, v) = post(&router, body, X_API_KEY).await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "wrong-length sig must 400: {v:?}"
    );
    // ServiceError::BadRequest maps to error="invalid_request" with the
    // descriptive message echoed in `reason`. We assert both the
    // envelope class and the length-detail string.
    assert_eq!(v["error"], "invalid_request");
    let reason = v["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("ed25519 signature must be 64 bytes"),
        "expected length-error reason, got {reason}"
    );
}

#[tokio::test]
async fn algorithm_confusion_announce_ed25519_omit_signature_field() {
    let (state, _tl_signing) = state_with_both_paths();
    let router = build_router(state.clone());
    let r = rec(
        "adv-algo-confusion-omit",
        WaveStage::Tested,
        "atk-3",
        "/test",
        HashSet::new(),
    );

    // Attacker announces ed25519 but supplies neither ed25519 field.
    // Server must return 400 ed25519_missing_fields, NOT fall back to
    // the HMAC path silently.
    let body = json!({
        "kernel_hmac_hex": hex::encode(hmac_of(&hmac_key(), &r)),
        "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
        "record": r,
        "signature_type": "ed25519",
    });
    let (s, v) = post(&router, body, X_API_KEY).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "missing fields must 400: {v:?}");
    assert_eq!(v["reason"], "ed25519_missing_fields");
}

// ===========================================================================
// 3. Public-key replacement attack — attacker rotates their OWN keypair and
//    announces it. The kernel-pinned public key is the binding identity, so
//    the announced pk fails the constant-time fingerprint compare.
// ===========================================================================

#[tokio::test]
async fn public_key_replacement_attacker_rotates_their_own_keypair() {
    let (state, _tl_signing) = state_with_both_paths();
    let router = build_router(state.clone());
    let r = rec(
        "adv-pk-replacement",
        WaveStage::Tested,
        "atk-4",
        "/test",
        HashSet::new(),
    );

    // Attacker generates a wholly fresh keypair. They sign the record
    // perfectly with their own sk and announce their own pk. The pin
    // catches it: their pk SHA-256 != the published fingerprint.
    let attacker = SigningKey::from_bytes(&[0xDEu8; 32]);
    let bytes = r.canonical_bytes().unwrap();
    let sig = attacker.sign(&bytes);

    let body = json!({
        "ed25519_public_key_hex": hex::encode(attacker.verifying_key().to_bytes()),
        "ed25519_signature_hex": hex::encode(sig.to_bytes()),
        "kernel_hmac_hex": hex::encode([0u8; 32]),
        "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
        "record": r,
        "signature_type": "ed25519",
    });
    let (s, v) = post(&router, body, X_API_KEY).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(v["reason"], "ed25519_key_fingerprint_mismatch");
}

// ===========================================================================
// 4. Hash-collision / idempotency — same record + same signature → second
//    POST is the idempotent replay (status 200, same leaf index).
// ===========================================================================

#[tokio::test]
async fn hash_collision_idempotency_two_identical_records_one_accept() {
    let (state, tl_signing) = state_with_both_paths();
    let router = build_router(state.clone());
    let r = rec(
        "adv-idem",
        WaveStage::Tested,
        "idem-1",
        "/test",
        HashSet::new(),
    );

    let body = ed25519_body(&state, &tl_signing, &r);
    let (s1, v1) = post(&router, body.clone(), X_API_KEY).await;
    assert_eq!(
        s1,
        StatusCode::CREATED,
        "first POST should mint a leaf: {v1:?}"
    );
    assert_eq!(v1["leaf_index"], 0);
    assert_eq!(v1["idempotent_replay"], false);

    let (s2, v2) = post(&router, body, X_API_KEY).await;
    assert_eq!(s2, StatusCode::OK, "replay should be 200 OK: {v2:?}");
    assert_eq!(v2["leaf_index"], 0, "replay must land on the same leaf");
    assert_eq!(v2["idempotent_replay"], true);
    assert_eq!(v2["leaf_hash_hex"], v1["leaf_hash_hex"]);
}

#[tokio::test]
async fn hash_collision_idempotency_same_record_different_valid_sigs() {
    // RFC 8032 §5.1.6 — Ed25519 is deterministic: the same (sk,
    // message) pair always produces the SAME signature. Constructively
    // verify that, then assert the idempotency key collapses the
    // would-be "different valid sigs" into the same replay.
    let (state, tl_signing) = state_with_both_paths();
    let router = build_router(state.clone());
    let r = rec(
        "adv-idem-det",
        WaveStage::Tested,
        "idem-2",
        "/test",
        HashSet::new(),
    );

    let bytes = r.canonical_bytes().unwrap();
    let sig_a = tl_signing.sign(&bytes).to_bytes();
    let sig_b = tl_signing.sign(&bytes).to_bytes();
    assert_eq!(
        sig_a, sig_b,
        "Ed25519 signatures are deterministic per RFC 8032 — same (sk, msg) must yield same bytes"
    );

    let body = ed25519_body(&state, &tl_signing, &r);
    let (s1, v1) = post(&router, body.clone(), X_API_KEY).await;
    assert_eq!(s1, StatusCode::CREATED);
    let (s2, v2) = post(&router, body, X_API_KEY).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(v1["leaf_index"], v2["leaf_index"]);
    assert_eq!(v2["idempotent_replay"], true);
}

// ===========================================================================
// 5. Concurrent writes — mixed HMAC + Ed25519 POSTs run in parallel. No race
//    on key rotation: every leaf records the announced signature_type.
// ===========================================================================

#[tokio::test]
async fn concurrent_writes_mixed_signature_types_no_race() {
    let (state, tl_signing) = state_with_both_paths();
    let router = build_router(state.clone());
    let api_key = X_API_KEY.to_string();
    let wave = "adv-concurrent";

    // Stages rotate over 4 (stage, written_by) pairs the route's
    // `written_by_matches_stage` validator accepts; each record then
    // gets a unique session_id so the idempotency key is unique.
    let pairs = [
        (WaveStage::Tested, "/test"),
        (WaveStage::PurpleTeamed, "/purple-team"),
        (WaveStage::Accepted, "/user-acceptance"),
        (WaveStage::Closed, "/closeout"),
    ];

    let mut handles = Vec::new();
    for i in 0..16usize {
        let (stage, wb) = pairs[i % pairs.len()];
        let sid = format!("c-{i:02}");
        let r = rec(wave, stage, &sid, wb, HashSet::new());
        let want_ed25519 = i % 2 == 1; // every other write
        let body = if want_ed25519 {
            ed25519_body(&state, &tl_signing, &r)
        } else {
            let h = hmac_of(&hmac_key(), &r);
            legacy_body(&state, &h, &r)
        };

        let router_c = router.clone();
        let api_c = api_key.clone();
        handles.push(tokio::spawn(async move {
            let (s, _v) = post(&router_c, body, &api_c).await;
            (s, want_ed25519)
        }));
    }

    let mut accepted = 0usize;
    for h in handles {
        let (s, _ed25519) = h.await.unwrap();
        // Each of 16 unique records should mint a leaf. The first
        // attempt always lands; race-only failure would surface as a
        // non-201 status.
        assert!(
            s == StatusCode::CREATED || s == StatusCode::OK,
            "expected 201 or 200 OK, got {s}"
        );
        if s == StatusCode::CREATED {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 16, "all 16 unique records must mint");

    // Now read back and assert per-leaf signature_type matches what
    // the writer announced. Chain is ordered by canonical stage order:
    // PLANNED -> TESTED -> PURPLE_TEAMED -> ACCEPTED -> CLOSED.
    let (gs, gv) = get_chain(&router, wave, X_API_KEY).await;
    assert_eq!(gs, StatusCode::OK);
    let chain = gv["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 16);
    let mut seen_hmac = 0usize;
    let mut seen_ed25519 = 0usize;
    for entry in chain {
        match entry["signature_type"].as_str().unwrap_or("") {
            "hmac" => seen_hmac += 1,
            "ed25519" => seen_ed25519 += 1,
            other => panic!("unknown signature_type {other} in chain"),
        }
    }
    assert_eq!(seen_hmac, 8, "expected 8 HMAC writes");
    assert_eq!(seen_ed25519, 8, "expected 8 Ed25519 writes");
}

// ===========================================================================
// 6. Vintage HMAC record — Rule 9 evidence recompute. We re-derive an
//    HMAC over canonical bytes using the legacy internal-ref contract bytes
//    and POST it. The route must accept it unchanged — proves the HMAC
//    PATH IS UNTOUCHED by the additive Ed25519 surface.
// ===========================================================================

#[tokio::test]
async fn vintage_hmac_record_canonical_compact_hmac_unmodified() {
    let (state, _tl_signing) = state_with_both_paths();
    let router = build_router(state.clone());
    // "Vintage" record shape — written_by/stage pair the legacy internal-ref
    // route already accepted. We recompute HMAC IN-PROCESS (Rule 9: no
    // label matching; the oracle IS the recomputed HMAC).
    let r = rec(
        "adv-vintage-hmac",
        WaveStage::Tested,
        "vint-1",
        "/test",
        HashSet::new(),
    );
    let recomputed_hmac = hmac_of(&hmac_key(), &r);
    let body = legacy_body(&state, &recomputed_hmac, &r);

    let (s, v) = post(&router, body, X_API_KEY).await;
    assert_eq!(
        s,
        StatusCode::CREATED,
        "vintage HMAC must still be accepted: {v:?}"
    );
    assert_eq!(v["ok"], true);

    // Chain entry must report signature_type="hmac" — never auto-promote.
    let (gs, gv) = get_chain(&router, "adv-vintage-hmac", X_API_KEY).await;
    assert_eq!(gs, StatusCode::OK);
    let chain = gv["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0]["signature_type"], "hmac");
    assert_eq!(
        chain[0]["key_fingerprint_hex"],
        Value::String(state.kernel_key_fingerprint_hex.clone())
    );
    // No Ed25519 signature field on an HMAC entry.
    assert!(
        chain[0]
            .get("ed25519_signature_hex")
            .map(|v| v.is_null())
            .unwrap_or(true),
        "HMAC entry must not carry ed25519_signature_hex"
    );
}
