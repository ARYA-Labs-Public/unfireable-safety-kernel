//! Ed25519 sign/verify + stable-JSON serialization —  binding.
//!
//! Load-bearing for the equivalence gate: the byte-stable JSON
//! serialization here MUST match Python's
//! `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
//! for every input the Safety Kernel feeds it, and Ed25519 signatures
//! are computed over the **base64url-no-pad ASCII bytes of the
//! serialized payload** (NOT the raw JSON) 3.
//!
//! Source of truth: `packages/core/safety_tokens.py` (`_stable_json`,
//! `_b64url_encode`, `sign_kernel_token`, `verify_kernel_token`,
//! `params_fingerprint`, `token_sha256`).

mod canonical;
mod sign;
mod verify;

pub use canonical::{params_fingerprint, stable_json, token_sha256};
pub use sign::sign_kernel_token;
pub use verify::{verify_kernel_token, VerifiedClaims};

#[cfg(test)]
mod tests;
