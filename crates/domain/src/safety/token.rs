//! Ed25519 sign/verify + stable-JSON serialization — Slice 1 binding.
//!
//! Load-bearing for the equivalence gate: the byte-stable JSON
//! serialization here MUST match Python's
//! `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
//! for every input the Safety Kernel feeds it, and Ed25519 signatures
//! are computed over the **base64url-no-pad ASCII bytes of the
//! serialized payload** (NOT the raw JSON) per ADR-014 Slice 1 §1.3.
//!
//! Source of truth: `packages/core/safety_tokens.py` (`_stable_json`,
//! `_b64url_encode`, `sign_kernel_token`, `verify_kernel_token`,
//! `params_fingerprint`, `token_sha256`).

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use serde_json::{Map as SerdeMap, Value};
use sha2::{Digest, Sha256};

use super::claims::ToClaimsMap;
use super::error::KernelTokenError;

// ============================================================================
// Stable JSON serialization (the byte-equality footgun — §1.2 binding)
// ============================================================================

/// Recursively rewrite a `serde_json::Value` so every nested object is
/// represented as a sorted-key `serde_json::Map`. `serde_json::Map`
/// preserves insertion order (and DOES NOT enable `preserve_order` per
/// ADR §6.2 anti-pin), so by re-inserting keys in lexicographic order
/// we get the same byte output as Python's `sort_keys=True`.
fn sort_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            // Collect into a BTreeMap to get lexicographic ordering, then
            // pour back into a `serde_json::Map` so the resulting Value
            // round-trips through `serde_json::to_string` with sorted
            // keys.
            let mut sorted: BTreeMap<&String, Value> = BTreeMap::new();
            for (k, child) in map {
                sorted.insert(k, sort_value(child));
            }
            let mut out = SerdeMap::with_capacity(sorted.len());
            for (k, child) in sorted {
                out.insert(k.clone(), child);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_value).collect()),
        // Strings, numbers, bools, null — already byte-stable.
        other => other.clone(),
    }
}

/// Serialize a `BTreeMap<String, Value>` (top-level claims map) as
/// canonical stable JSON: lexicographic key order at every nesting
/// level, no whitespace, UTF-8 passthrough.
///
/// Mirrors Python `_stable_json` exactly. Required for byte equality
/// of the signed payload — see ADR-014 Slice 1 §1.5 mandatory test.
#[must_use]
pub fn stable_json(map: &BTreeMap<String, Value>) -> String {
    // The top-level BTreeMap iterates in sorted order, but its child
    // values may contain nested objects whose keys aren't yet sorted.
    // Walk the entire tree via `sort_value` and serialize once.
    let top = {
        let mut out = SerdeMap::with_capacity(map.len());
        for (k, v) in map {
            out.insert(k.clone(), sort_value(v));
        }
        Value::Object(out)
    };
    // `serde_json::to_string` uses CompactFormatter (no whitespace) by
    // default, which matches Python's `separators=(",", ":")`. Floats
    // round-trip via Ryu, identical bit pattern → identical output.
    // Serialization of a `Value` tree never fails (no I/O, no custom
    // serializer that returns Err), but we still bubble any error up
    // as an empty string rather than panicking — the equivalence test
    // would catch this on the byte-equality assertion anyway.
    serde_json::to_string(&top).unwrap_or_default()
}

// ============================================================================
// SHA-256 helpers
// ============================================================================

/// Compute hex-lowercase SHA-256 of a string (UTF-8) or byte slice.
fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// SHA-256 of the compact token string (UTF-8). Mirrors Python
/// `safety_tokens.py:283-284`.
#[must_use]
pub fn token_sha256(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

/// Stable fingerprint of an arbitrary params object.
///
/// The input is a `serde_json::Value` representing the params dict.
/// Non-object inputs are coerced through the same JSON-string surface
/// Python uses (`dict(params)` then `_stable_json`).
///
/// Per ADR-014 Slice 1 §1.6 binding: `sha256_hex(stable_json(params))`.
/// Equivalent to Python `params_fingerprint` (`safety_tokens.py:53-56`).
#[must_use]
pub fn params_fingerprint(params: &Value) -> String {
    // Convert to BTreeMap for top-level signature; non-object inputs
    // serialize via the recursive `sort_value` walk.
    let canonical = sort_value(params);
    let json = serde_json::to_string(&canonical).unwrap_or_default();
    sha256_hex(json.as_bytes())
}

// ============================================================================
// Sign / verify
// ============================================================================

/// Verified-token output — what `verify_kernel_token` returns on
/// success. Mirrors Python `VerifiedKernelToken`
/// (`safety_tokens.py:147-152`).
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedClaims {
    /// The compact token string the caller verified (echoed back).
    pub token: String,
    /// Decoded claims, preserving every key Python would have decoded.
    pub claims: BTreeMap<String, Value>,
    /// Base64url-no-pad signature half of the token.
    pub signature_b64: String,
}

/// Sign a typed claim set and return the compact token
/// `<payload_b64>.<signature_b64>` per ADR-014 Slice 1 §1.1.
///
/// The signature is computed over the ASCII bytes of `payload_b64`
/// (NOT the raw JSON) per §1.3 / Python `safety_tokens.py:163-165`.
#[must_use]
pub fn sign_kernel_token(claims: &impl ToClaimsMap, signing_key: &SigningKey) -> String {
    let map = claims.to_btreemap();
    let payload_json = stable_json(&map);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    // Per §1.3: signature is over the b64-encoded payload's ASCII bytes.
    let sig: Signature = signing_key.sign(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    format!("{payload_b64}.{sig_b64}")
}

/// Required claim keys per `safety_tokens.py:116-124`. Verified
/// against in `verify_kernel_token`.
const REQUIRED_FIELDS: &[&str] = &[
    "action",
    "run_id",
    "subject",
    "params_fingerprint",
    "issued_at",
    "expires_at",
    "nonce",
];

/// Verify a compact token against a public key and time bounds.
///
/// Returns `Ok(VerifiedClaims)` on success or a typed
/// `KernelTokenError` on any failure. Mirrors Python
/// `verify_kernel_token` (`safety_tokens.py:170-267`) exactly.
///
/// # `expected_aud` parameter (ARY-2028 slice 5, PT-S2-M1 fold-in)
///
/// When `Some(aud)`, the verifier requires the token's `aud` claim to
/// be present AND equal to the supplied string. Failure modes:
///
/// - Token has no `aud` claim ⇒ `KernelTokenError::Claims("missing_claim:aud")`
/// - Token's `aud` is the wrong type ⇒ `KernelTokenError::Claims("invalid_aud")`
/// - Token's `aud` doesn't match ⇒ `KernelTokenError::Claims("invalid_audience")`
///
/// When `None`, the `aud` claim (if present) is NOT inspected. This is
/// the **backwards-compatible** mode — pre-slice-5 callers and legacy
/// tokens that don't have an `aud` claim keep working. New callers
/// (Bundle A handlers, future verifiers) MUST pass `Some(&...)` to opt
/// in to enforcement. PT-S2-M1 closes the cross-tenant replay surface
/// between `/kernel/v1/authorize` and `/policy/*` tokens; the surface
/// only closes for callers that opt in.
///
/// # Errors
///
/// Returns `Err` for: malformed token (Format), failed signature
/// (Signature), missing or wrong-typed claim (Claims), expired token
/// (Expired), audience mismatch (Claims). Specific error code strings
/// match Python message strings for cross-implementation equivalence.
// Long but linear: each block ports one Python step from
// `safety_tokens.py:170-267`. Splitting it would make the equivalence
// review harder.
#[allow(clippy::too_many_lines)]
pub fn verify_kernel_token(
    token: &str,
    public_key: &VerifyingKey,
    now_s: f64,
    leeway_s: f64,
    expected_aud: Option<&str>,
) -> Result<VerifiedClaims, KernelTokenError> {
    let t = token.trim();
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() != 2 {
        return Err(KernelTokenError::format("invalid_token_format"));
    }
    let payload_b64 = parts[0].trim();
    let sig_b64 = parts[1].trim();
    if payload_b64.is_empty() || sig_b64.is_empty() {
        return Err(KernelTokenError::format("invalid_token_format"));
    }

    let payload_json = URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .map_err(|e| KernelTokenError::format(format!("invalid_payload_b64:{e}")))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64.as_bytes())
        .map_err(|e| KernelTokenError::format(format!("invalid_signature_b64:{e}")))?;

    // ed25519-dalek requires exactly SIGNATURE_LENGTH (64) bytes; map
    // any size mismatch to the same Format error class Python emits
    // (`invalid_signature_b64:...`).
    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err(KernelTokenError::format(
            "invalid_signature_b64:WrongLength",
        ));
    }
    let sig_array: [u8; SIGNATURE_LENGTH] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            return Err(KernelTokenError::format(
                "invalid_signature_b64:WrongLength",
            ));
        }
    };
    let signature = Signature::from_bytes(&sig_array);

    // Per §1.3: the signature input is the ASCII bytes of `payload_b64`.
    public_key
        .verify(payload_b64.as_bytes(), &signature)
        .map_err(|e| KernelTokenError::signature(format!("invalid_signature:{e}")))?;

    // Decode the JSON payload.
    let parsed: Value = serde_json::from_slice(&payload_json)
        .map_err(|e| KernelTokenError::format(format!("invalid_payload_json:{e}")))?;
    let Value::Object(obj) = parsed else {
        return Err(KernelTokenError::claims("claims_not_object"));
    };

    // Required-key + type validation, matching Python order.
    for k in REQUIRED_FIELDS {
        if !obj.contains_key(*k) {
            return Err(KernelTokenError::claims(format!("missing_claim:{k}")));
        }
    }
    let action = obj
        .get("action")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| KernelTokenError::claims("invalid_action"))?;
    let _ = action;
    let run_id = obj
        .get("run_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| KernelTokenError::claims("invalid_run_id"))?;
    let _ = run_id;
    let subject = obj
        .get("subject")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| KernelTokenError::claims("invalid_subject"))?;
    let _ = subject;
    let pf = obj
        .get("params_fingerprint")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| KernelTokenError::claims("invalid_params_fingerprint"))?;
    let _ = pf;
    let nonce = obj
        .get("nonce")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| KernelTokenError::claims("invalid_nonce"))?;
    let _ = nonce;

    let iat = obj
        .get("issued_at")
        .and_then(Value::as_f64)
        .ok_or_else(|| KernelTokenError::claims("invalid_time_claims:ValueError"))?;
    let exp = obj
        .get("expires_at")
        .and_then(Value::as_f64)
        .ok_or_else(|| KernelTokenError::claims("invalid_time_claims:ValueError"))?;

    let leeway = leeway_s.max(0.0);

    if now_s + leeway < iat {
        return Err(KernelTokenError::claims("token_used_before_issued"));
    }
    if now_s - leeway > exp {
        return Err(KernelTokenError::expired("token_expired"));
    }
    if exp <= iat {
        return Err(KernelTokenError::claims("invalid_expiry_window"));
    }

    // Audience check (PT-S2-M1, ARY-2028 slice 5).
    //
    // The audience claim partitions the signing-key space between
    // `/kernel/v1/authorize` and `/policy/*` so a token minted for
    // one endpoint cannot be presented to the verifier of another.
    // When `expected_aud == None`, the check is skipped entirely to
    // preserve backwards-compatibility with pre-slice-5 callers (and
    // tokens that pre-date the claim). When `Some(...)`, the `aud`
    // claim MUST be a string and MUST equal the expected value.
    if let Some(want_aud) = expected_aud {
        let aud_val = obj
            .get("aud")
            .ok_or_else(|| KernelTokenError::claims("missing_claim:aud"))?;
        let got_aud = aud_val
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| KernelTokenError::claims("invalid_aud"))?;
        if got_aud != want_aud {
            return Err(KernelTokenError::claims("invalid_audience"));
        }
    }

    // Store the claims as BTreeMap for caller convenience (sorted
    // ordering matches the signed form).
    let mut claims = BTreeMap::new();
    for (k, v) in obj {
        claims.insert(k, v);
    }

    Ok(VerifiedClaims {
        token: t.to_string(),
        claims,
        signature_b64: sig_b64.to_string(),
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp,
    clippy::similar_names
)]
mod tests {
    use super::*;
    use crate::safety::claims::{ApprovalClaims, AuthorizeClaims, APPROVAL_AUD};
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    /// Helper — deterministic 32-byte signing seed. Tests must NOT
    /// depend on system entropy; we feed a fixed array straight into
    /// `SigningKey::from_bytes`.
    fn fixed_signing_key() -> SigningKey {
        let seed = [7u8; 32];
        SigningKey::from_bytes(&seed)
    }

    /// Slice-5 binding vector — `AuthorizeClaims` with the `aud` field
    /// (PT-S2-M1) produces a stable JSON string with `aud` in lex
    /// position. The ADR-014 Appendix A original vector (no `aud`) is
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

    /// ADR-014 Slice 1 Appendix A — the legacy binding test vector
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
    // PT-S2-M1 (ARY-2028 slice 5) — `aud` claim + verifier allowlist tests.
    //
    // The kernel signing key is shared between `/kernel/v1/authorize` and
    // `/policy/*`. Without an audience tag, a token minted for one endpoint
    // could in principle be presented to the verifier of another. The `aud`
    // claim + `expected_aud` verifier parameter close that cross-tenant
    // replay surface. The tests below pin the wire contract.
    // ========================================================================

    /// Helper — sign a slice-5-shape `AuthorizeClaims` with the given
    /// `aud` value. Used by the PT-S2-M1 tests.
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

    /// PT-S2-M1 case (a) — token signed with `aud=A` verifies under
    /// `expected_aud=A`. Happy-path.
    #[test]
    #[allow(clippy::panic)]
    fn aud_claim_matches_expected_aud_verifies() {
        let sk = fixed_signing_key();
        let vk = sk.verifying_key();
        let token = sign_authorize_with_aud(&sk, "kernel/authorize");
        let result =
            verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some("kernel/authorize"));
        match result {
            Ok(v) => assert_eq!(
                v.claims.get("aud").and_then(Value::as_str),
                Some("kernel/authorize"),
            ),
            Err(e) => panic!("token with matching aud must verify; got {e:?}"),
        }
    }

    /// PT-S2-M1 case (b) — token signed with `aud=A` rejected under
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

    /// PT-S2-M1 case (c) — token signed with `aud=A` and verified with
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

    /// PT-S2-M1 case (d) — old-shape tokens with NO `aud` claim are
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

        let result =
            verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some("kernel/authorize"));
        match result {
            Err(KernelTokenError::Claims(msg)) => assert_eq!(msg.0.as_str(), "missing_claim:aud"),
            other => panic!("expected Claims(missing_claim:aud); got {other:?}"),
        }
    }

    /// PT-S2-M1 case (e) — cross-tenant replay scenario. A token minted
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

    /// PT-S2-M1 case (f) — allowlist with multiple tokens: token signed
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

    /// PT-S2-M1 — wrong-typed `aud` (number, not string) is rejected
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
        let result =
            verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some("kernel/authorize"));
        match result {
            Err(KernelTokenError::Claims(msg)) => assert_eq!(msg.0.as_str(), "invalid_aud"),
            other => panic!("expected Claims(invalid_aud); got {other:?}"),
        }
    }

    // ========================================================================
    // PT-S5-M1 (ARY-2028-followup item 1) — `aud` on the APPROVALS path.
    //
    // Slice 5 (PT-S2-M1) closed the `aud` cross-tenant replay surface on the
    // authorize + policy claim types only. `ApprovalClaims` was left without
    // an audience tag, so an approval-decision token signed by the shared
    // kernel key could in principle be replayed against the
    // `/kernel/v1/authorize` or `/policy/*` verifiers (or vice versa). The
    // tests below mirror the slice-5 authorize cases (token.rs:771-985) but
    // exercise `ApprovalClaims` minted with `APPROVAL_AUD`.
    // ========================================================================

    /// Helper — sign a PT-S5-M1-shape `ApprovalClaims` with the given
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

    /// PT-S5-M1 case (a) — approval token signed with `aud=APPROVAL_AUD`
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

    /// PT-S5-M1 case (b) — approval token signed with `aud=APPROVAL_AUD`
    /// rejected under a different `expected_aud`. Negative direction.
    #[test]
    fn approval_aud_mismatch_is_rejected() {
        let sk = fixed_signing_key();
        let vk = sk.verifying_key();
        let token = sign_approval_with_aud(&sk, APPROVAL_AUD);
        let result =
            verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some("kernel/authorize"));
        match result {
            Err(KernelTokenError::Claims(msg)) => assert_eq!(msg.0.as_str(), "invalid_audience"),
            other => panic!("expected Claims(invalid_audience); got {other:?}"),
        }
    }

    /// PT-S5-M1 case (c) — approval token verified with `expected_aud=None`
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

    /// PT-S5-M1 case (d) — pre-followup-shape approval tokens with NO
    /// `aud` claim are rejected when the verifier opts in via `Some(...)`.
    #[test]
    fn approval_missing_aud_rejected_when_expected_aud_set() {
        let sk = fixed_signing_key();
        let vk = sk.verifying_key();
        // Hand-craft a pre-PT-S5-M1-shape approval claims map (no `aud`).
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

    /// PT-S5-M1 case (e) — cross-tenant replay scenario. An approval
    /// token (aud=`kernel/approvals/decision`) presented to a
    /// `/kernel/v1/authorize` verifier (expected `kernel/authorize`) MUST
    /// be rejected. Load-bearing test for the PT-S5-M1 finding.
    #[test]
    fn cross_tenant_replay_approval_to_authorize_rejected() {
        let sk = fixed_signing_key();
        let vk = sk.verifying_key();
        let token = sign_approval_with_aud(&sk, APPROVAL_AUD);
        let result =
            verify_kernel_token(&token, &vk, 1_715_212_350.0, 0.0, Some("kernel/authorize"));
        assert!(
            matches!(result, Err(KernelTokenError::Claims(ref msg)) if msg.0 == "invalid_audience"),
            "cross-tenant approval->authorize replay MUST be rejected; got {result:?}"
        );
    }

    /// PT-S5-M1 case (f) — allowlist: an approval token verifies under
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
}
