//! Canonicalization + hashing helpers for the kernel-token surface.
//!
//! These are the byte-stable JSON serialization (`stable_json`) and the
//! SHA-256 derivations (`token_sha256`, `params_fingerprint`) that the
//! sign/verify paths and the equivalence gate depend on. Mirrors the
//! Python helpers in `packages/core/safety_tokens.py` (`_stable_json`,
//! `token_sha256`, `params_fingerprint`).

use std::collections::BTreeMap;

use serde_json::{Map as SerdeMap, Value};
use sha2::{Digest, Sha256};

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
/// of the signed payload — see mandatory test.
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
/// 6 binding: `sha256_hex(stable_json(params))`.
/// Equivalent to Python `params_fingerprint` (`safety_tokens.py:53-56`).
#[must_use]
pub fn params_fingerprint(params: &Value) -> String {
    // Convert to BTreeMap for top-level signature; non-object inputs
    // serialize via the recursive `sort_value` walk.
    let canonical = sort_value(params);
    let json = serde_json::to_string(&canonical).unwrap_or_default();
    sha256_hex(json.as_bytes())
}
