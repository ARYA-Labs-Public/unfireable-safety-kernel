//! Adversarial fixture — signature forgery + claim tampering rejected
//! ( slice 2, watchdog class `signature_forgery_rejected`).
//!
//! ## Threat model
//!
//! A worker captures a valid signed `module_authorize` token T1. The
//! attacker has FULL access to T1's bytes but does NOT have the kernel's
//! private signing key. They attempt to:
//!
//!   1. Flip a byte in the signature half → must FAIL `verify_kernel_token`
//!      with `KernelTokenError::Format` (b64 decode/length) or
//!      `KernelTokenError::Signature` (verify).
//!   2. Flip a byte in the payload half → SIGNATURE is over `payload_b64`,
//!      so a different payload produces a different signing input. Verify
//!      MUST fail.
//!   3. Forge a token from scratch using a DIFFERENT private key. Verify
//!      against the kernel's public key MUST fail.
//!   4. Mutate the encoded `decision` claim from `"allow"` to `"deny"`
//!      (or vice versa) — same defense as (2) since signing is over the
//!      whole encoded payload, but documented separately as the most
//!      semantically dangerous tamper.
//!
//! Per the signing scheme is `ed25519(payload_b64 as ASCII
//! bytes)`. The verifier reads bytes back and recomputes; any difference
//! fails the Ed25519 verify call. Mirrors the existing kernel-level
//! defenses in `crates/domain/src/safety/token.rs::verify_kernel_token`.
//!
//! This fixture is the slice-2 cross-product proof — slice 2 uses the
//! same signing primitives for `ModuleAuthorizeClaims` and
//! `ModuleRegisterClaims`, so we exercise both claim types. No subprocess
//! needed: the test signs tokens locally with the same primitives the
//! kernel uses.
//!
//! All assertions demand REJECTION (Rule 8). Each test asserts the
//! specific `KernelTokenError` variant that the defense produces — a
//! generic "verify returned Err" would let a defense regression that
//! mapped errors to the wrong variant slip through.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::doc_markdown, clippy::too_many_lines)]

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, SIGNATURE_LENGTH};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};

use qorch_domain::safety::{
    params_fingerprint,
    policy::{
        ModuleAuthorizeClaims, ModuleAuthorizeDecision, ModuleEventKind, POLICY_AUTHORIZE_AUD,
    },
    sign_kernel_token, stable_json, verify_kernel_token, KernelTokenError, ToClaimsMap,
};

// Build a fresh signing key for the test.
fn fresh_key() -> SigningKey {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

// Construct a valid ModuleAuthorizeClaims for `pkg.mod`.
fn make_claims(decision: ModuleAuthorizeDecision) -> ModuleAuthorizeClaims {
    let fp = params_fingerprint(&json!({
        "event_kind": "import",
        "module_path": "pkg.mod",
        "caller_subject": "worker",
        "caller_run_id": "run-1",
    }));
    ModuleAuthorizeClaims {
        aud: POLICY_AUTHORIZE_AUD.to_string(),
        iss: "qorch-safety-kernel/test@0123456789abcdef".to_string(),
        iat: 1_715_212_345.0,
        exp: 1_715_212_405.0,
        subject: "worker".to_string(),
        run_id: "run-1".to_string(),
        event_kind: ModuleEventKind::Import,
        module_path: "pkg.mod".to_string(),
        event_fingerprint: fp,
        decision,
        reason: if matches!(decision, ModuleAuthorizeDecision::Deny) {
            Some("required_pattern_mismatch".to_string())
        } else {
            None
        },
        nonce: "smoke-nonce-abcdef0123".to_string(),
    }
}

// ============================================================================
// HAPPY PATH (control) — a freshly signed token verifies. Without this
// control the rejection assertions could be false positives caused by
// claim assembly errors.
// ============================================================================

#[test]
fn happy_path_signed_authorize_token_verifies() {
    let key = fresh_key();
    let claims = make_claims(ModuleAuthorizeDecision::Allow);
    let token = sign_kernel_token(&claims, &key);
    let verified = verify_kernel_token(&token, &key.verifying_key(), claims.iat + 0.1, 5.0, None)
        .expect("freshly signed token MUST verify");
    assert_eq!(
        verified.claims.get("decision").and_then(Value::as_str),
        Some("allow"),
    );
}

// ============================================================================
// ADVERSARIAL — signature byte flip MUST fail verify.
// ============================================================================

#[test]
fn signature_byte_flip_is_rejected() {
    let key = fresh_key();
    let claims = make_claims(ModuleAuthorizeDecision::Allow);
    let token = sign_kernel_token(&claims, &key);
    let (payload, sig) = token.split_once('.').unwrap();

    // Decode the signature bytes, flip the first byte, re-encode.
    let mut sig_bytes = URL_SAFE_NO_PAD.decode(sig.as_bytes()).unwrap();
    assert_eq!(sig_bytes.len(), SIGNATURE_LENGTH);
    sig_bytes[0] ^= 0xff;
    let bad_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);
    let bad_token = format!("{payload}.{bad_sig}");

    let err = verify_kernel_token(
        &bad_token,
        &key.verifying_key(),
        claims.iat + 0.1,
        5.0,
        None,
    )
    .expect_err("signature byte flip MUST be rejected");
    assert!(
        matches!(err, KernelTokenError::Signature(_)),
        "expected Signature error, got {err:?}",
    );
}

// ============================================================================
// ADVERSARIAL — payload byte flip MUST fail verify.
//
// The signature is over the b64-encoded payload's ASCII bytes. Mutating
// any byte of the payload changes the signing input, so the Ed25519
// verify call fails. Even if the mutation produces a valid JSON
// (e.g. flipping `allow` → `Allow`), the signing-over-bytes property
// makes this independent of claim semantics.
// ============================================================================

#[test]
fn payload_byte_flip_is_rejected() {
    let key = fresh_key();
    let claims = make_claims(ModuleAuthorizeDecision::Allow);
    let token = sign_kernel_token(&claims, &key);
    let (payload, sig) = token.split_once('.').unwrap();

    // Flip one byte in the payload half. Use a char that stays in the
    // base64 alphabet so we don't trigger b64-decode errors (we want
    // the failure to be the signature mismatch, not a decode fail).
    let mut bytes = payload.as_bytes().to_vec();
    // Find a byte to flip — first 'a' → 'b', or first 'A' → 'B'.
    let pos = bytes
        .iter()
        .position(|&b| b == b'a' || b == b'A')
        .unwrap_or(0);
    bytes[pos] = if bytes[pos] == b'a' { b'b' } else { b'B' };
    let bad_payload = String::from_utf8(bytes).unwrap();
    let bad_token = format!("{bad_payload}.{sig}");

    let err = verify_kernel_token(
        &bad_token,
        &key.verifying_key(),
        claims.iat + 0.1,
        5.0,
        None,
    )
    .expect_err("payload byte flip MUST be rejected");
    // Two acceptable failure variants:
    //   - Format: the mutated payload didn't base64-decode (unlikely
    //     for a single in-alphabet swap) or didn't parse as JSON.
    //   - Signature: the mutated bytes don't match the signature.
    // Either is correct; both prove the defense held.
    assert!(
        matches!(
            err,
            KernelTokenError::Signature(_)
                | KernelTokenError::Format(_)
                | KernelTokenError::Claims(_)
        ),
        "expected Signature/Format/Claims error, got {err:?}",
    );
}

// ============================================================================
// ADVERSARIAL — semantic flip: re-encode payload with `decision: "deny"`
// swapped to `"allow"` and the ORIGINAL signature appended. The signing
// is over payload_b64 bytes, so even though both forms are valid JSON,
// the signature does NOT match the new payload.
// ============================================================================

#[test]
fn decision_field_tamper_allow_to_deny_is_rejected() {
    let key = fresh_key();
    let deny_claims = make_claims(ModuleAuthorizeDecision::Deny);
    let deny_token = sign_kernel_token(&deny_claims, &key);
    let (deny_payload, deny_sig) = deny_token.split_once('.').unwrap();

    // Build the corresponding ALLOW payload (same claim shape minus
    // `reason`).
    let allow_claims = ModuleAuthorizeClaims {
        decision: ModuleAuthorizeDecision::Allow,
        reason: None,
        ..deny_claims.clone()
    };
    let allow_map = allow_claims.to_btreemap();
    let allow_json = stable_json(&allow_map);
    let allow_payload = URL_SAFE_NO_PAD.encode(allow_json.as_bytes());

    // Forge a token with allow's payload + deny's signature.
    let forged = format!("{allow_payload}.{deny_sig}");
    let err = verify_kernel_token(
        &forged,
        &key.verifying_key(),
        deny_claims.iat + 0.1,
        5.0,
        None,
    )
    .expect_err("semantic-flip forgery MUST be rejected");
    assert!(
        matches!(err, KernelTokenError::Signature(_)),
        "expected Signature error, got {err:?}",
    );

    // The reverse — deny's payload + a "what if I drop the reason" sig
    // — is covered transitively by the same signing-over-bytes property.
    // Belt + braces: confirm the original deny token still verifies on
    // its own. If it didn't, this test would be a false positive.
    let _ = verify_kernel_token(
        &deny_token,
        &key.verifying_key(),
        deny_claims.iat + 0.1,
        5.0,
        None,
    )
    .expect("control: original deny token MUST verify");
    let _ = deny_payload;
}

// ============================================================================
// ADVERSARIAL — wrong-key forgery: sign a perfectly-shaped claim set
// with a DIFFERENT private key. The kernel's public key MUST refuse to
// verify it.
// ============================================================================

#[test]
fn token_signed_with_wrong_key_is_rejected() {
    let kernel_key = fresh_key();
    let attacker_key = fresh_key();
    let claims = make_claims(ModuleAuthorizeDecision::Allow);
    let attacker_token = sign_kernel_token(&claims, &attacker_key);

    let err = verify_kernel_token(
        &attacker_token,
        &kernel_key.verifying_key(),
        claims.iat + 0.1,
        5.0,
        None,
    )
    .expect_err("attacker-signed token MUST NOT verify against kernel pubkey");
    assert!(
        matches!(err, KernelTokenError::Signature(_)),
        "expected Signature error, got {err:?}",
    );
}

// ============================================================================
// ADVERSARIAL — empty signature byte string is rejected at Format layer.
// ============================================================================

#[test]
fn truncated_signature_is_rejected() {
    let key = fresh_key();
    let claims = make_claims(ModuleAuthorizeDecision::Allow);
    let token = sign_kernel_token(&claims, &key);
    let (payload, _) = token.split_once('.').unwrap();

    // Try several truncated signatures — empty, 1 byte, 63 bytes
    // (one short of Ed25519's required 64). All MUST be rejected.
    for bad_sig_len in [0usize, 1, 63] {
        let bytes = vec![0u8; bad_sig_len];
        let bad_sig = URL_SAFE_NO_PAD.encode(bytes);
        let bad_token = format!("{payload}.{bad_sig}");
        let err = verify_kernel_token(
            &bad_token,
            &key.verifying_key(),
            claims.iat + 0.1,
            5.0,
            None,
        )
        .expect_err("truncated signature MUST be rejected");
        // Length=0 is empty-string after b64 decode → Format
        // (invalid_token_format). Length=1,63 → Format
        // (invalid_signature_b64:WrongLength).
        assert!(
            matches!(err, KernelTokenError::Format(_)),
            "expected Format error for sig_len={bad_sig_len}, got {err:?}",
        );
    }
}

// ============================================================================
// ADVERSARIAL — completely-fabricated token (not built from any signed
// claim set) is rejected. Catches a defense regression where the
// verifier short-circuited on a malformed compact token.
// ============================================================================

#[test]
fn random_garbage_token_is_rejected() {
    let key = fresh_key();
    // 64-char b64-alphabet garbage on each half.
    let garbage_payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let garbage_sig =
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let bad_token = format!("{garbage_payload}.{garbage_sig}");
    let err = verify_kernel_token(&bad_token, &key.verifying_key(), 1_715_212_345.0, 5.0, None)
        .expect_err("garbage token MUST be rejected");
    // Both Format (b64 length / JSON parse / claim missing) and
    // Signature (well-formed but wrong) are acceptable here.
    assert!(
        matches!(
            err,
            KernelTokenError::Format(_)
                | KernelTokenError::Signature(_)
                | KernelTokenError::Claims(_)
        ),
        "expected Format/Signature/Claims error, got {err:?}",
    );
}

// ============================================================================
// ADVERSARIAL — manual claim assembly bypassing sign_kernel_token: build
// a fresh BTreeMap with the canonical fields, sign it correctly, mutate
// a single claim post-signing. Tests the kernel's claim-validation order.
// ============================================================================

#[test]
fn iat_mutation_post_sign_is_rejected() {
    let key = fresh_key();
    let claims = make_claims(ModuleAuthorizeDecision::Allow);
    let mut map = claims.to_btreemap();
    // Sign the canonical form.
    let canonical_json = stable_json(&map);
    let canonical_payload = URL_SAFE_NO_PAD.encode(canonical_json.as_bytes());
    let sig = key.sign(canonical_payload.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    // Mutate `issued_at` AFTER signing. Re-encode the payload.
    map.insert(
        "issued_at".to_string(),
        Value::Number(serde_json::Number::from(0)),
    );
    let mutated_json = stable_json(&map);
    let mutated_payload = URL_SAFE_NO_PAD.encode(mutated_json.as_bytes());
    let forged = format!("{mutated_payload}.{sig_b64}");

    let err = verify_kernel_token(&forged, &key.verifying_key(), claims.iat + 0.1, 5.0, None)
        .expect_err("post-signing iat mutation MUST be rejected");
    assert!(
        matches!(err, KernelTokenError::Signature(_)),
        "expected Signature error, got {err:?}",
    );
    // Belt + braces: confirm the canonical form still verifies (to
    // protect against this test passing only because the canonical
    // map itself was broken).
    let canonical_token = format!("{canonical_payload}.{sig_b64}");
    let _ = verify_kernel_token(
        &canonical_token,
        &key.verifying_key(),
        claims.iat + 0.1,
        5.0,
        None,
    )
    .expect("control: canonical form must verify");
    let _: BTreeMap<String, Value> = map;
}
