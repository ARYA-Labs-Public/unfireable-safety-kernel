#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

//! PyO3 binding — `safety_kernel_client` Python extension module.
//!
//! Exposes the **real** public Rust safety-kernel primitives to Python so the
//! Python surface is the same code the kernel + Rust SDK ship, not a
//! reimplementation:
//!
//! - [`params_fingerprint`] → `qorch_domain::safety::token::params_fingerprint`.
//!   The canonical `sha256_hex(stable_json(params))` contract the kernel
//!   recomputes server-side; byte-identical to the Python `_wire.py`
//!   fingerprint, which this replaces at the source.
//! - [`PinnedKeyVerifier`] → `qorch_safety_kernel_client::token::PinnedKeyVerifier`.
//!   The offline Ed25519 receipt verifier: verify a kernel authorization token
//!   against a pinned public key with NO network call. Any verification failure
//!   (bad signature, expiry, missing claim, wrong audience) raises — callers
//!   MUST treat a raise as a hard refusal (fail-closed).
//!
//! The marshalling pattern (`pythonize` / `depythonize`) mirrors the internal
//! `arya-core-py` binding. `extension-module` is a build-time-only feature so
//! `cargo test`/`cargo check` link libpython while the wheel does not.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::Value;

use qorch_safety_kernel_client::token::PinnedKeyVerifier as RustPinnedKeyVerifier;

/// Map any `Display` Rust error into a Python `ValueError`. Fail-closed: every
/// error path becomes a raised exception, never a silent falsy return.
fn to_pyerr<E: std::fmt::Display>(e: E) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// Canonical params fingerprint: `sha256_hex(stable_json(params))`.
///
/// Accepts any JSON-compatible Python value (typically a `dict`) and returns
/// the 64-char lowercase hex digest the kernel uses to bind a token to its
/// exact params. Byte-identical to the Rust kernel's `params_fingerprint`.
#[pyfunction]
fn params_fingerprint(params: &Bound<'_, PyAny>) -> PyResult<String> {
    let value: Value = pythonize::depythonize(params).map_err(to_pyerr)?;
    Ok(qorch_domain::safety::token::params_fingerprint(&value))
}

/// Offline Ed25519 receipt verifier pinned to one public key.
///
/// Construct with the 32-byte pinned public key (and optional clock leeway in
/// seconds, default 5.0). `verify` returns the decoded claims on success and
/// raises on ANY failure.
#[pyclass(name = "PinnedKeyVerifier", frozen)]
struct PyPinnedKeyVerifier {
    inner: RustPinnedKeyVerifier,
}

#[pymethods]
impl PyPinnedKeyVerifier {
    /// `PinnedKeyVerifier(pubkey: bytes, leeway_seconds: float | None = None)`.
    #[new]
    #[pyo3(signature = (pubkey, leeway_seconds=None))]
    fn new(pubkey: Vec<u8>, leeway_seconds: Option<f64>) -> PyResult<Self> {
        let arr: [u8; 32] = pubkey.as_slice().try_into().map_err(|_| {
            PyValueError::new_err(format!(
                "pinned pubkey must be exactly 32 bytes, got {}",
                pubkey.len()
            ))
        })?;
        let inner = match leeway_seconds {
            Some(l) => RustPinnedKeyVerifier::with_leeway(arr, l),
            None => RustPinnedKeyVerifier::from_pubkey_bytes(arr),
        }
        .map_err(to_pyerr)?;
        Ok(Self { inner })
    }

    /// The 16-hex-char audit fingerprint of the pinned key.
    #[getter]
    fn fingerprint(&self) -> String {
        self.inner.fingerprint().to_string()
    }

    /// Verify `token` against the pinned key at wall-clock `now_epoch_seconds`.
    ///
    /// When `expected_aud` is given, the token's `aud` claim must match it
    /// (cross-tenant replay protection). Returns a dict
    /// `{token, claims, signature_b64}` on success; raises `ValueError` on any
    /// verification failure — treat a raise as a hard refusal.
    #[pyo3(signature = (token, now_epoch_seconds, expected_aud=None))]
    fn verify(
        &self,
        py: Python<'_>,
        token: &str,
        now_epoch_seconds: f64,
        expected_aud: Option<&str>,
    ) -> PyResult<PyObject> {
        let claims = match expected_aud {
            Some(aud) => self
                .inner
                .verify_with_aud(token, now_epoch_seconds, aud),
            None => self.inner.verify(token, now_epoch_seconds),
        }
        .map_err(to_pyerr)?;

        // Build a JSON-shaped view of VerifiedClaims (which is intentionally
        // not Serialize) and marshal it to a Python dict.
        let mut obj = serde_json::Map::new();
        obj.insert("token".to_string(), Value::String(claims.token));
        obj.insert(
            "claims".to_string(),
            serde_json::to_value(claims.claims).map_err(to_pyerr)?,
        );
        obj.insert(
            "signature_b64".to_string(),
            Value::String(claims.signature_b64),
        );
        let out = pythonize::pythonize(py, &Value::Object(obj)).map_err(to_pyerr)?;
        Ok(out.into())
    }
}

/// The `safety_kernel_client` Python module.
#[pymodule]
fn safety_kernel_client(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(params_fingerprint, m)?)?;
    m.add_class::<PyPinnedKeyVerifier>()?;
    Ok(())
}
