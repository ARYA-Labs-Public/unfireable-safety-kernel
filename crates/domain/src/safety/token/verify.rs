//! Ed25519 token verification — `VerifiedClaims` + `verify_kernel_token`.
//!
//! Mirrors Python `verify_kernel_token` (`safety_tokens.py:170-267`)
//! exactly, including the required-claim set and the error-code strings
//! used for cross-implementation equivalence.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use serde_json::Value;

use crate::safety::error::KernelTokenError;

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
/// # `expected_aud` parameter ( slice 5,  fold-in)
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
/// in to enforcement.  closes the cross-tenant replay surface
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

    // Audience check.

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
