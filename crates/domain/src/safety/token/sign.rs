//! Ed25519 token signing — `sign_kernel_token`.
//!
//! Mirrors Python `safety_tokens.py:163-165`: the signature is computed
//! over the ASCII bytes of the base64url-no-pad payload (NOT the raw
//! JSON).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey};

use super::canonical::stable_json;
use crate::safety::claims::ToClaimsMap;

/// Sign a typed claim set and return the compact token
/// `<payload_b64>.<signature_b64>` 1.
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
