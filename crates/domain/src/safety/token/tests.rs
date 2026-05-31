//! Unit + adversarial tests for the kernel-token sign/verify surface.
//!
//! Moved verbatim from the original single-file `token.rs` test module
//! during the ARY token/ split. `super::*` pulls the re-exported public
//! surface (`stable_json`, `sign_kernel_token`, `verify_kernel_token`,
//! `params_fingerprint`, `token_sha256`, `VerifiedClaims`); the
//! remaining imports (the dalek traits/types, the base64 engine, the
//! claims types, and `KernelTokenError`) are pulled in explicitly below
//! since they are no longer in the parent module's value scope.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp,
    clippy::similar_names
)]

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};

use super::*;
use crate::safety::claims::{ApprovalClaims, AuthorizeClaims, ToClaimsMap, APPROVAL_AUD};
use crate::safety::error::KernelTokenError;

/// Helper — deterministic 32-byte signing seed. Tests must NOT
/// depend on system entropy; we feed a fixed array straight into
/// `SigningKey::from_bytes`.
fn fixed_signing_key() -> SigningKey {
    let seed = [7u8; 32];
    SigningKey::from_bytes(&seed)
}

/// Slice-5 binding vector — `AuthorizeClaims` with the `aud` field
/// produces a stable JSON string with `aud` in lex
/// position. The Appendix A original vector (no `aud`) is
/// preserved in `stable_json_matches_legacy_pre_slice5_vector`
/// because old tokens without `aud` MUST still verify when
/// `expected_aud=None`.
#[test]
fn stable_json_matches_slice5_authorize_vector_with_aud() {
    let claims = AuthorizeClaims {
        action: "sio_run_cycles".to_string(),
        aud: crate::safety::claims::KERNEL_AUTHORIZE_AUD.to_string(),
        run_id: "run_abc".to_string(),
        subject: "worker".to_string(),
        params_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_string(),
        issued_at: 1_715_212_345.0,
        expires_at: 1_715_212_405.0,
        nonce: "abcdEFgh-12_AB".to_string(),
    };
    let map = claims.to_btreemap();
    let s = stable_json(&map);
    // Note: serde_json renders `1715212345.0` as `1715212345.0`
    // (Ryu) — identical to Python's `repr(float)` here.
    // "aud" sorts after "action" and before "expires_at".
    assert_eq!(
        s,
        r#"{"action":"sio_run_cycles","aud":"kernel/authorize","expires_at":1715212405.0,"issued_at":1715212345.0,"nonce":"abcdEFgh-12_AB","params_fingerprint":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","run_id":"run_abc","subject":"worker"}"#
    );
}

///  Appendix A — the legacy binding test vector
/// (no `aud` claim). Pre-slice-5 tokens MUST still serialize the
/// same way when emitted via a hand-built `BTreeMap`. The
/// `AuthorizeClaims` struct itself now always carries `aud`, so
/// this test builds the map directly to mirror what a pre-slice-5
/// signer would have produced.
#[test]
fn stable_json_matches_legacy_pre_slice5_vector() {
    use serde_json::json;
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    map.insert(
        "action".to_string(),
        Value::String("sio_run_cycles".to_string()),
    );
    map.insert("run_id".to_string(), Value::String("run_abc".to_string()));
    map.insert("subject".to_string(), Value::String("worker".to_string()));
    map.insert(
        "params_fingerprint".to_string(),
        Value::String(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ),
    );
    map.insert("issued_at".to_string(), json!(1_715_212_345.0_f64));
    map.insert("expires_at".to_string(), json!(1_715_212_405.0_f64));
    map.insert(
        "nonce".to_string(),
        Value::String("abcdEFgh-12_AB".to_string()),
    );
    let s = stable_json(&map);
    assert_eq!(
        s,
        r#"{"action":"sio_run_cycles","expires_at":1715212405.0,"issued_at":1715212345.0,"nonce":"abcdEFgh-12_AB","params_fingerprint":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","run_id":"run_abc","subject":"worker"}"#
    );
}

/// Stable JSON sorts every nesting level lexicographically, not
/// just the top-level claims map. Critical for `params_fingerprint`
/// equivalence when params is itself a nested dict.
#[test]
fn stable_json_sorts_nested_objects() {
    let mut top = BTreeMap::new();
    top.insert("outer".to_string(), json!({"z": 1, "a": {"y": 2, "b": 3}}));
    let s = stable_json(&top);
    assert_eq!(s, r#"{"outer":{"a":{"b":3,"y":2},"z":1}}"#);
}

/// Sign + verify round-trip with a fixed key. Confirms the
/// signature input contract (b64-encoded ASCII bytes, NOT raw
/// JSON) is consistent across both halves of the implementation.
/// Passes `expected_aud=None` (legacy permissive verifier mode).
#[test]
#[allow(clippy::panic)]
fn sign_verify_roundtrip() {
    let sk = fixed_signing_key();
    let vk: VerifyingKey = sk.verifying_key();

    let claims = AuthorizeClaims {
        action: "sio_run_cycles".to_string(),
        aud: crate::safety::claims::KERNEL_AUTHORIZE_AUD.to_string(),
        run_id: "run_abc".to_string(),
        subject: "worker".to_string(),
        params_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_string(),
        issued_at: 1_715_212_345.0,
        expires_at: 1_715_212_405.0,
        nonce: "abcdEFgh-12_AB".to_string(),
    };
    let token = sign_kernel_token(&claims, &sk);

    // Verify with `now_s` inside the validity window. None=>legacy.
    let verified = match verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, None) {
        Ok(v) => v,
        Err(e) => panic!("token should verify, got {e:?}"),
    };
    assert_eq!(
        verified.claims.get("action").and_then(Value::as_str),
        Some("sio_run_cycles")
    );
    assert_eq!(
        verified.claims.get("nonce").and_then(Value::as_str),
        Some("abcdEFgh-12_AB")
    );
}

/// Tampered-signature case — flipping one byte must fail the
/// signature check, NOT silently pass.
#[test]
fn verify_rejects_tampered_signature() {
    let sk = fixed_signing_key();
    let vk: VerifyingKey = sk.verifying_key();
    let claims = AuthorizeClaims {
        action: "sio_run_cycles".to_string(),
        aud: crate::safety::claims::KERNEL_AUTHORIZE_AUD.to_string(),
        run_id: "run_abc".to_string(),
        subject: "worker".to_string(),
        params_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_string(),
        issued_at: 1_715_212_345.0,
        expires_at: 1_715_212_405.0,
        nonce: "abcdEFgh-12_AB".to_string(),
    };
    let token = sign_kernel_token(&claims, &sk);
    // Flip last char of signature half.
    let mut tampered = token.clone();
    let _ = tampered.pop();
    tampered.push(if token.ends_with('A') { 'B' } else { 'A' });
    let result = verify_kernel_token(&tampered, &vk, 1_715_212_350.0, 0.0, None);
    assert!(matches!(
        result,
        Err(KernelTokenError::Signature(_) | KernelTokenError::Format(_))
    ));
}

/// Expired token must return Expired (not Claims, not Format).
#[test]
fn verify_detects_expiry() {
    let sk = fixed_signing_key();
    let vk: VerifyingKey = sk.verifying_key();
    let claims = AuthorizeClaims {
        action: "sio_run_cycles".to_string(),
        aud: crate::safety::claims::KERNEL_AUTHORIZE_AUD.to_string(),
        run_id: "run_abc".to_string(),
        subject: "worker".to_string(),
        params_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_string(),
        issued_at: 1_715_212_345.0,
        expires_at: 1_715_212_405.0,
        nonce: "abcdEFgh-12_AB".to_string(),
    };
    let token = sign_kernel_token(&claims, &sk);
    // `now_s` past expiry by 100s.
    let result = verify_kernel_token(&token, &vk, 1_715_212_505.0, 0.0, None);
    assert!(matches!(result, Err(KernelTokenError::Expired(_))));
}

/// Format error — token has wrong number of dots.
#[test]
fn verify_rejects_malformed_token() {
    let sk = fixed_signing_key();
    let vk: VerifyingKey = sk.verifying_key();
    let result = verify_kernel_token("not-a-token", &vk, 1_715_212_345.0, 0.0, None);
    assert!(matches!(result, Err(KernelTokenError::Format(_))));
}

/// `params_fingerprint` is `sha256_hex(stable_json(params))` —
/// nested dicts must produce a stable digest regardless of key
/// insertion order on the caller side.
#[test]
fn params_fingerprint_is_stable_across_key_order() {
    let a = json!({"z": 1, "a": {"y": 2, "b": 3}});
    let b = json!({"a": {"b": 3, "y": 2}, "z": 1});
    assert_eq!(params_fingerprint(&a), params_fingerprint(&b));
}

/// `token_sha256` is `sha256_hex` of the compact UTF-8 token bytes.
#[test]
fn token_sha256_matches_known_vector() {
    // Expected: sha256_hex(b"abc")
    let h = token_sha256("abc");
    assert_eq!(
        h,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// W3 adversarial fixture 14 — b64-padding-attack equivalent.
/// Mutating the payload b64 (different bytes after stripping
/// pad) MUST fail signature verification, since the signature
/// was over the ORIGINAL b64 ASCII bytes.
#[test]
fn verify_rejects_payload_b64_mutation() {
    let sk = fixed_signing_key();
    let vk: VerifyingKey = sk.verifying_key();
    let claims = AuthorizeClaims {
        action: "sio_run_cycles".to_string(),
        aud: crate::safety::claims::KERNEL_AUTHORIZE_AUD.to_string(),
        run_id: "run_abc".to_string(),
        subject: "worker".to_string(),
        params_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_string(),
        issued_at: 1_715_212_345.0,
        expires_at: 1_715_212_405.0,
        nonce: "abcdEFgh-12_AB".to_string(),
    };
    let token = sign_kernel_token(&claims, &sk);
    // Find the dot, mutate the LAST char of the payload half.
    let dot = token.find('.').expect("token has dot");
    let mut bytes = token.into_bytes();
    // Choose a different ASCII char from whatever's there.
    let target = if bytes[dot - 1] == b'A' { b'B' } else { b'A' };
    bytes[dot - 1] = target;
    let mutated = String::from_utf8(bytes).expect("ascii");
    let result = verify_kernel_token(&mutated, &vk, 1_715_212_350.0, 0.0, None);
    assert!(
        matches!(
            result,
            Err(KernelTokenError::Signature(_)
                | KernelTokenError::Format(_)
                | KernelTokenError::Claims(_))
        ),
        "expected error variant; got {result:?}"
    );
}

/// W3 adversarial fixture 15 — extra claim is permissive.
/// `verify_kernel_token` MUST accept tokens with claims beyond
/// the §1.2 required set (forward-compat guarantee). The extra
/// claim is part of the signed payload, so the signature passes.
#[test]
fn verify_accepts_extra_claim_for_forward_compat() {
    use serde_json::Map as SerdeMap;

    let sk = fixed_signing_key();
    let vk: VerifyingKey = sk.verifying_key();
    let claims = AuthorizeClaims {
        action: "sio_run_cycles".to_string(),
        aud: crate::safety::claims::KERNEL_AUTHORIZE_AUD.to_string(),
        run_id: "run_abc".to_string(),
        subject: "worker".to_string(),
        params_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_string(),
        issued_at: 1_715_212_345.0,
        expires_at: 1_715_212_405.0,
        nonce: "abcdEFgh-12_AB".to_string(),
    };
    let mut map = claims.to_btreemap();
    map.insert(
        "future_field".to_string(),
        Value::String("not_in_required".to_string()),
    );
    let payload_json = stable_json(&map);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let sig = sk.sign(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let token = format!("{payload_b64}.{sig_b64}");

    let verified =
        verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, None).expect("must verify");
    assert_eq!(
        verified.claims.get("future_field").and_then(Value::as_str),
        Some("not_in_required")
    );
    // Silence the unused import warning when no other code in this
    // mod uses SerdeMap; the binding above is for documentation.
    let _ = SerdeMap::<String, Value>::new();
}

/// W4 purple-team T1 — Ed25519 signature malleability check.
///
/// An Ed25519 signature is (R, S) where S MUST be in [0, L) for
/// the curve order L. A signature with S >= L (or with the high
/// bit set in the encoded S) is non-canonical and creates a
/// signature-malleability surface (RFC 8032 §5.1.7, RFC 8032
/// errata).
///
/// ed25519-dalek v2's default `Verifier::verify` enforces
/// canonical S — but verify by experiment, not by docs.
///
/// We construct a non-canonical signature by computing a real
/// signature, then mutating S to be > L (by setting high bits
/// in the encoded S half), and assert that
/// `verify_kernel_token` rejects via `KernelTokenError::Signature`.
#[test]
fn verify_rejects_non_canonical_s() {
    let sk = fixed_signing_key();
    let vk: VerifyingKey = sk.verifying_key();
    let claims = AuthorizeClaims {
        action: "sio_run_cycles".to_string(),
        aud: crate::safety::claims::KERNEL_AUTHORIZE_AUD.to_string(),
        run_id: "run_abc".to_string(),
        subject: "worker".to_string(),
        params_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_string(),
        issued_at: 1_715_212_345.0,
        expires_at: 1_715_212_405.0,
        nonce: "abcdEFgh-12_AB".to_string(),
    };
    let token = sign_kernel_token(&claims, &sk);
    let dot = token.find('.').expect("dot");
    let (payload_b64, _) = token.split_at(dot);
    // Real signature bytes.
    let real_sig = sk.sign(payload_b64.as_bytes());
    let mut sig_bytes = real_sig.to_bytes();
    // Set the top bit of the LAST byte. This sets the high bit
    // of the S half (the upper 32 bytes of the 64-byte signature).
    // S must be < L = 2^252 + 27742...; setting bit 255 makes S
    // ~ 2^255 which is far above L. ed25519-dalek's strict
    // canonical check rejects this.
    sig_bytes[63] |= 0x80;
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);
    let bad_token = format!("{payload_b64}.{sig_b64}");

    let result = verify_kernel_token(&bad_token, &vk, 1_715_212_350.0, 0.0, None);
    assert!(
        matches!(result, Err(KernelTokenError::Signature(_))),
        "non-canonical S MUST be rejected; got {result:?}"
    );
}

/// W3 adversarial fixture 16 — missing required claim.
/// A token whose payload omits any §1.2 required field MUST fail
/// verification (`KernelTokenError::Claims`), even if the
/// signature itself is valid over the truncated payload.
#[test]
fn verify_rejects_missing_required_claim() {
    let sk = fixed_signing_key();
    let vk: VerifyingKey = sk.verifying_key();
    // Hand-craft a payload missing `action`.
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    map.insert("run_id".to_string(), Value::String("no_action".into()));
    map.insert("subject".to_string(), Value::String("worker".into()));
    map.insert(
        "params_fingerprint".to_string(),
        Value::String("abc".into()),
    );
    map.insert("issued_at".to_string(), json!(1_715_212_345.0_f64));
    map.insert("expires_at".to_string(), json!(1_715_212_405.0_f64));
    map.insert("nonce".to_string(), Value::String("abc".into()));
    let payload_json = stable_json(&map);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let sig = sk.sign(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let token = format!("{payload_b64}.{sig_b64}");

    let result = verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, None);
    assert!(
        matches!(result, Err(KernelTokenError::Claims(_))),
        "expected KernelTokenError::Claims; got {result:?}"
    );
}

// ========================================================================
//  ( slice 5) — `aud` claim + verifier allowlist tests.

// The kernel signing key is shared between `/kernel/v1/authorize` and
// `/policy/*`. Without an audience tag, a token minted for one endpoint
// could in principle be presented to the verifier of another. The `aud`
// claim + `expected_aud` verifier parameter close that cross-tenant
// replay surface. The tests below pin the wire contract.
// ========================================================================

/// Helper — sign a slice-5-shape `AuthorizeClaims` with the given
/// `aud` value. Used by the tests.
fn sign_authorize_with_aud(sk: &SigningKey, aud: &str) -> String {
    let claims = AuthorizeClaims {
        action: "sio_run_cycles".to_string(),
        aud: aud.to_string(),
        run_id: "run_abc".to_string(),
        subject: "worker".to_string(),
        params_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_string(),
        issued_at: 1_715_212_345.0,
        expires_at: 1_715_212_405.0,
        nonce: "abcdEFgh-12_AB".to_string(),
    };
    sign_kernel_token(&claims, sk)
}

///  case (a) — token signed with `aud=A` verifies under
/// `expected_aud=A`. Happy-path.
#[test]
#[allow(clippy::panic)]
fn aud_claim_matches_expected_aud_verifies() {
    let sk = fixed_signing_key();
    let vk = sk.verifying_key();
    let token = sign_authorize_with_aud(&sk, "kernel/authorize");
    let result = verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some("kernel/authorize"));
    match result {
        Ok(v) => assert_eq!(
            v.claims.get("aud").and_then(Value::as_str),
            Some("kernel/authorize"),
        ),
        Err(e) => panic!("token with matching aud must verify; got {e:?}"),
    }
}

///  case (b) — token signed with `aud=A` rejected under
/// `expected_aud=B`. The negative-direction of the aud check.
#[test]
fn aud_claim_mismatch_is_rejected() {
    let sk = fixed_signing_key();
    let vk = sk.verifying_key();
    let token = sign_authorize_with_aud(&sk, "kernel/authorize");
    let result = verify_kernel_token(
        &token,
        &vk,
        1_715_212_350.0,
        0.0,
        Some("policy/module/authorize"),
    );
    match result {
        Err(KernelTokenError::Claims(msg)) => assert_eq!(msg.0.as_str(), "invalid_audience"),
        other => panic!("expected Claims(invalid_audience); got {other:?}"),
    }
}

///  case (c) — token signed with `aud=A` and verified with
/// `expected_aud=None` STAYS PERMISSIVE. This is the documented
/// backwards-compat behaviour — pre-slice-5 callers (and verifiers
/// that don't opt in) keep working. New callers MUST pass
/// `Some(...)` to actually close the cross-tenant replay surface.
#[test]
#[allow(clippy::panic)]
fn aud_claim_with_expected_aud_none_stays_permissive() {
    let sk = fixed_signing_key();
    let vk = sk.verifying_key();
    let token = sign_authorize_with_aud(&sk, "kernel/authorize");
    let result = verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, None);
    match result {
        Ok(v) => assert_eq!(
            v.claims.get("aud").and_then(Value::as_str),
            Some("kernel/authorize"),
        ),
        Err(e) => panic!("None=>permissive: token must verify; got {e:?}"),
    }
}

///  case (d) — old-shape tokens with NO `aud` claim are
/// rejected when the verifier opts in via `Some(...)`. The check
/// produces `KernelTokenError::Claims("missing_claim:aud")`.
#[test]
fn missing_aud_claim_rejected_when_expected_aud_set() {
    use serde_json::json;
    let sk = fixed_signing_key();
    let vk = sk.verifying_key();
    // Hand-craft a pre-slice-5-shape claims map (no `aud`).
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    map.insert(
        "action".to_string(),
        Value::String("sio_run_cycles".to_string()),
    );
    map.insert("run_id".to_string(), Value::String("run_abc".into()));
    map.insert("subject".to_string(), Value::String("worker".into()));
    map.insert(
        "params_fingerprint".to_string(),
        Value::String(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ),
    );
    map.insert("issued_at".to_string(), json!(1_715_212_345.0_f64));
    map.insert("expires_at".to_string(), json!(1_715_212_405.0_f64));
    map.insert("nonce".to_string(), Value::String("abcdEFgh-12_AB".into()));
    let payload_json = stable_json(&map);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let sig = sk.sign(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let token = format!("{payload_b64}.{sig_b64}");

    let result = verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some("kernel/authorize"));
    match result {
        Err(KernelTokenError::Claims(msg)) => assert_eq!(msg.0.as_str(), "missing_claim:aud"),
        other => panic!("expected Claims(missing_claim:aud); got {other:?}"),
    }
}

///  case (e) — cross-tenant replay scenario. A token minted
/// for `/kernel/v1/authorize` (aud=`kernel/authorize`) presented to
/// a `/policy/module/authorize` verifier (expected
/// `policy/module/authorize`) MUST be rejected. This is the
/// load-bearing test for the slice-2 purple-team finding.
#[test]
fn cross_tenant_replay_kernel_authorize_to_policy_rejected() {
    let sk = fixed_signing_key();
    let vk = sk.verifying_key();
    // Sign a token with the kernel/authorize aud.
    let token = sign_authorize_with_aud(&sk, "kernel/authorize");
    // The policy/module/authorize verifier expects a different aud.
    let result = verify_kernel_token(
        &token,
        &vk,
        1_715_212_350.0,
        0.0,
        Some("policy/module/authorize"),
    );
    assert!(
        matches!(result, Err(KernelTokenError::Claims(ref msg)) if msg.0 == "invalid_audience"),
        "cross-tenant replay MUST be rejected; got {result:?}"
    );
}

///  case (f) — allowlist with multiple tokens: token signed
/// with `aud=A` verifies under `expected_aud=A`, but the
/// *complementary* token (aud=B) is rejected under
/// `expected_aud=A`. Demonstrates a single-element allowlist via
/// `Option<&str>`. Multi-element allowlists are deferred to a
/// future helper; for slice 5 every verifier site knows exactly one
/// expected `aud` value, so `Option<&str>` is sufficient.
#[test]
fn aud_allowlist_two_tokens_only_matching_accepted() {
    let sk = fixed_signing_key();
    let vk = sk.verifying_key();
    let kernel_token = sign_authorize_with_aud(&sk, "kernel/authorize");
    let policy_token = sign_authorize_with_aud(&sk, "policy/module/authorize");

    // Verifier expecting "kernel/authorize":
    assert!(verify_kernel_token(
        &kernel_token,
        &vk,
        1_715_212_350.0,
        0.0,
        Some("kernel/authorize")
    )
    .is_ok());
    assert!(matches!(
        verify_kernel_token(
            &policy_token,
            &vk,
            1_715_212_350.0,
            0.0,
            Some("kernel/authorize")
        ),
        Err(KernelTokenError::Claims(_))
    ));

    // Verifier expecting "policy/module/authorize":
    assert!(verify_kernel_token(
        &policy_token,
        &vk,
        1_715_212_350.0,
        0.0,
        Some("policy/module/authorize")
    )
    .is_ok());
    assert!(matches!(
        verify_kernel_token(
            &kernel_token,
            &vk,
            1_715_212_350.0,
            0.0,
            Some("policy/module/authorize")
        ),
        Err(KernelTokenError::Claims(_))
    ));
}

///  — wrong-typed `aud` (number, not string) is rejected
/// with `Claims("invalid_aud")`. Hardens against attackers who
/// might try to bypass the audience check by emitting `aud: 0`
/// (which is falsy in Python `if aud:` but not in our explicit
/// string check).
#[test]
fn aud_claim_wrong_type_is_rejected() {
    use serde_json::json;
    let sk = fixed_signing_key();
    let vk = sk.verifying_key();
    // Hand-craft a payload with `aud` as a number.
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    map.insert(
        "action".to_string(),
        Value::String("sio_run_cycles".to_string()),
    );
    map.insert("aud".to_string(), json!(42_i64));
    map.insert("run_id".to_string(), Value::String("run_abc".into()));
    map.insert("subject".to_string(), Value::String("worker".into()));
    map.insert(
        "params_fingerprint".to_string(),
        Value::String(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ),
    );
    map.insert("issued_at".to_string(), json!(1_715_212_345.0_f64));
    map.insert("expires_at".to_string(), json!(1_715_212_405.0_f64));
    map.insert("nonce".to_string(), Value::String("abcdEFgh-12_AB".into()));
    let payload_json = stable_json(&map);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let sig = sk.sign(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let token = format!("{payload_b64}.{sig_b64}");
    let result = verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some("kernel/authorize"));
    match result {
        Err(KernelTokenError::Claims(msg)) => assert_eq!(msg.0.as_str(), "invalid_aud"),
        other => panic!("expected Claims(invalid_aud); got {other:?}"),
    }
}

// ========================================================================
//  (-followup item 1) — `aud` on the APPROVALS path.

//  closed the `aud` cross-tenant replay surface on the
// authorize + policy claim types only. `ApprovalClaims` was left without
// an audience tag, so an approval-decision token signed by the shared
// kernel key could in principle be replayed against the
// `/kernel/v1/authorize` or `/policy/*` verifiers (or vice versa). The
// tests below mirror the slice-5 authorize cases (token.rs:771-985) but
// exercise `ApprovalClaims` minted with `APPROVAL_AUD`.
// ========================================================================

/// Helper — sign a -shape `ApprovalClaims` with the given
/// `aud` value. Mirrors `sign_authorize_with_aud`.
fn sign_approval_with_aud(sk: &SigningKey, aud: &str) -> String {
    let claims = ApprovalClaims {
        action: "approval_decision".to_string(),
        aud: aud.to_string(),
        run_id: "item_42".to_string(),
        subject: "operator".to_string(),
        params_fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_string(),
        issued_at: 1_715_212_345.0,
        expires_at: 1_715_212_405.0,
        nonce: "abcdEFgh-12_AB".to_string(),
        decision: "approved".to_string(),
        reason: None,
        approver: "seth@aryalabs.io".to_string(),
        proposal_fingerprint: "f".repeat(64),
    };
    sign_kernel_token(&claims, sk)
}

///  case (a) — approval token signed with `aud=APPROVAL_AUD`
/// verifies under `expected_aud=APPROVAL_AUD`. Happy-path.
#[test]
#[allow(clippy::panic)]
fn approval_aud_matches_expected_aud_verifies() {
    let sk = fixed_signing_key();
    let vk = sk.verifying_key();
    let token = sign_approval_with_aud(&sk, APPROVAL_AUD);
    let result = verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some(APPROVAL_AUD));
    match result {
        Ok(v) => assert_eq!(
            v.claims.get("aud").and_then(Value::as_str),
            Some(APPROVAL_AUD),
        ),
        Err(e) => panic!("approval token with matching aud must verify; got {e:?}"),
    }
}

///  case (b) — approval token signed with `aud=APPROVAL_AUD`
/// rejected under a different `expected_aud`. Negative direction.
#[test]
fn approval_aud_mismatch_is_rejected() {
    let sk = fixed_signing_key();
    let vk = sk.verifying_key();
    let token = sign_approval_with_aud(&sk, APPROVAL_AUD);
    let result = verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some("kernel/authorize"));
    match result {
        Err(KernelTokenError::Claims(msg)) => assert_eq!(msg.0.as_str(), "invalid_audience"),
        other => panic!("expected Claims(invalid_audience); got {other:?}"),
    }
}

///  case (c) — approval token verified with `expected_aud=None`
/// STAYS PERMISSIVE (documented backwards-compat: legacy verifiers that
/// have not opted in keep working). Do not regress authorize/policy.
#[test]
#[allow(clippy::panic)]
fn approval_aud_with_expected_aud_none_stays_permissive() {
    let sk = fixed_signing_key();
    let vk = sk.verifying_key();
    let token = sign_approval_with_aud(&sk, APPROVAL_AUD);
    let result = verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, None);
    match result {
        Ok(v) => assert_eq!(
            v.claims.get("aud").and_then(Value::as_str),
            Some(APPROVAL_AUD),
        ),
        Err(e) => panic!("None=>permissive: approval token must verify; got {e:?}"),
    }
}

///  case (d) — pre-followup-shape approval tokens with NO
/// `aud` claim are rejected when the verifier opts in via `Some(...)`.
#[test]
fn approval_missing_aud_rejected_when_expected_aud_set() {
    let sk = fixed_signing_key();
    let vk = sk.verifying_key();
    // Hand-craft a pre--shape approval claims map (no `aud`).
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    map.insert(
        "action".to_string(),
        Value::String("approval_decision".to_string()),
    );
    map.insert(
        "approver".to_string(),
        Value::String("seth@aryalabs.io".into()),
    );
    map.insert("decision".to_string(), Value::String("approved".into()));
    map.insert("expires_at".to_string(), json!(1_715_212_405.0_f64));
    map.insert("issued_at".to_string(), json!(1_715_212_345.0_f64));
    map.insert("nonce".to_string(), Value::String("abcdEFgh-12_AB".into()));
    map.insert(
        "params_fingerprint".to_string(),
        Value::String(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ),
    );
    map.insert(
        "proposal_fingerprint".to_string(),
        Value::String("f".repeat(64)),
    );
    map.insert("reason".to_string(), Value::Null);
    map.insert("run_id".to_string(), Value::String("item_42".into()));
    map.insert("subject".to_string(), Value::String("operator".into()));
    let payload_json = stable_json(&map);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let sig = sk.sign(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let token = format!("{payload_b64}.{sig_b64}");

    let result = verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some(APPROVAL_AUD));
    match result {
        Err(KernelTokenError::Claims(msg)) => assert_eq!(msg.0.as_str(), "missing_claim:aud"),
        other => panic!("expected Claims(missing_claim:aud); got {other:?}"),
    }
}

///  case (e) — cross-tenant replay scenario. An approval
/// token (aud=`kernel/approvals/decision`) presented to a
/// `/kernel/v1/authorize` verifier (expected `kernel/authorize`) MUST
/// be rejected. Load-bearing test for the finding.
#[test]
fn cross_tenant_replay_approval_to_authorize_rejected() {
    let sk = fixed_signing_key();
    let vk = sk.verifying_key();
    let token = sign_approval_with_aud(&sk, APPROVAL_AUD);
    let result = verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some("kernel/authorize"));
    assert!(
        matches!(result, Err(KernelTokenError::Claims(ref msg)) if msg.0 == "invalid_audience"),
        "cross-tenant approval->authorize replay MUST be rejected; got {result:?}"
    );
}

///  case (f) — allowlist: an approval token verifies under
/// `expected_aud=APPROVAL_AUD`, but the complementary authorize token
/// (aud=`kernel/authorize`) is rejected under `expected_aud=APPROVAL_AUD`
/// — and symmetrically. Confirms the approvals tag does not regress
/// the authorize/policy verifier sites.
#[test]
fn approval_aud_allowlist_two_tokens_only_matching_accepted() {
    let sk = fixed_signing_key();
    let vk = sk.verifying_key();
    let approval_token = sign_approval_with_aud(&sk, APPROVAL_AUD);
    let authorize_token = sign_authorize_with_aud(&sk, "kernel/authorize");

    // Verifier expecting the approvals aud:
    assert!(verify_kernel_token(
        &approval_token,
        &vk,
        1_715_212_350.0,
        0.0,
        Some(APPROVAL_AUD)
    )
    .is_ok());
    assert!(matches!(
        verify_kernel_token(
            &authorize_token,
            &vk,
            1_715_212_350.0,
            0.0,
            Some(APPROVAL_AUD)
        ),
        Err(KernelTokenError::Claims(_))
    ));

    // Verifier expecting the authorize aud (must NOT accept approval):
    assert!(verify_kernel_token(
        &authorize_token,
        &vk,
        1_715_212_350.0,
        0.0,
        Some("kernel/authorize")
    )
    .is_ok());
    assert!(matches!(
        verify_kernel_token(
            &approval_token,
            &vk,
            1_715_212_350.0,
            0.0,
            Some("kernel/authorize")
        ),
        Err(KernelTokenError::Claims(_))
    ));
}
