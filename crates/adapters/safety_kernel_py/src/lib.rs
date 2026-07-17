#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

//! PyO3 binding — `safety_kernel_client` Python extension module.
//!
//! Exposes the real public Rust safety-kernel primitives to Python so the
//! Python surface is the same code the kernel + Rust SDK ship, not a
//! reimplementation:
//!
//! - [`params_fingerprint`] — `qorch_domain::safety::token::params_fingerprint`.
//!   Canonical `sha256_hex(stable_json(params))`; byte-identical to the Rust
//!   kernel's fingerprint.
//! - `PinnedKeyVerifier` — `qorch_safety_kernel_client::token::PinnedKeyVerifier`.
//!   Offline Ed25519 receipt verifier (no network); `verify` is fail-closed.
//! - `SafetyKernelClient` — `qorch_safety_kernel_client::client::SafetyKernelClient`.
//!   The signature-verifying, circuit-broken, fail-closed HTTP client. Its
//!   `authorize` drives the async Rust client on a small owned tokio runtime.
//!   ALLOW returns a dict; DENY raises `PermissionError`; unreachable / breaker
//!   open / bad signature raise `ConnectionError`. A raise is a hard refusal.
//!
//! Marshalling (`pythonize`/`depythonize`) mirrors the internal `arya-core-py`
//! binding. `extension-module` is a build-time-only feature so `cargo test`
//! links libpython while the wheel does not.
//!
//! PyO3 0.29: methods returning a Python object return `Py<PyAny>` (`PyObject`
//! left the prelude), and `pythonize(...)` yields a `Bound` that `.unbind()`
//! turns into the owned `Py<PyAny>`.

use pyo3::exceptions::{PyConnectionError, PyPermissionError, PyValueError};
use pyo3::prelude::*;
use serde_json::Value;

use qorch_domain::safety::token::VerifiedClaims;
use qorch_domain::safety::{CircuitConfig, Clock, KernelDecision, KernelDecisionError};
use qorch_safety_kernel_client::circuit_breaker::CircuitBreaker;
use qorch_safety_kernel_client::client::SafetyKernelClient as RustSafetyKernelClient;
use qorch_safety_kernel_client::token::PinnedKeyVerifier as RustPinnedKeyVerifier;
use qorch_safety_kernel_client::types::{AuthorizeRequest, KernelClientError};

/// Default per-request HTTP timeout when the caller does not specify one.
const DEFAULT_TIMEOUT_MS: u64 = 2000;

/// Map any `Display` Rust error into a Python `ValueError`. Fail-closed: every
/// error path becomes a raised exception, never a silent falsy return.
fn to_pyerr<E: std::fmt::Display>(e: E) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// Wall-clock source (`time.time()`-equivalent) for the breaker + verifier.
/// A clock error (system time before the epoch) maps to `0.0`, which the verify
/// path rejects as `token_used_before_issued` — the desired fail-closed result.
struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64())
    }
}

/// Build a JSON view of `VerifiedClaims` (which is intentionally not `Serialize`).
fn verified_claims_to_value(vc: VerifiedClaims) -> PyResult<Value> {
    let mut obj = serde_json::Map::new();
    obj.insert("token".to_string(), Value::String(vc.token));
    obj.insert(
        "claims".to_string(),
        serde_json::to_value(vc.claims).map_err(to_pyerr)?,
    );
    obj.insert("signature_b64".to_string(), Value::String(vc.signature_b64));
    Ok(Value::Object(obj))
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

    /// Verify `token` against the pinned key at `now_epoch_seconds`; raises on
    /// any failure (fail-closed). Returns `{token, claims, signature_b64}`.
    #[pyo3(signature = (token, now_epoch_seconds, expected_aud=None))]
    fn verify(
        &self,
        py: Python<'_>,
        token: &str,
        now_epoch_seconds: f64,
        expected_aud: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let claims = match expected_aud {
            Some(aud) => self.inner.verify_with_aud(token, now_epoch_seconds, aud),
            None => self.inner.verify(token, now_epoch_seconds),
        }
        .map_err(to_pyerr)?;
        let out = pythonize::pythonize(py, &verified_claims_to_value(claims)?).map_err(to_pyerr)?;
        Ok(out.unbind())
    }
}

/// Signature-verifying, fail-closed HTTP client for the Safety Kernel.
///
/// Construct with the kernel base URL, an API key, and the 32-byte pinned
/// Ed25519 public key. `authorize` performs `POST /kernel/v1/authorize`,
/// verifies the returned token against the pinned key, and:
///
/// - ALLOW → returns `{"decision": "allow", "token", "claims", "signature_b64"}`
/// - DENY  → raises `PermissionError` (authoritative refusal)
/// - unreachable / circuit-breaker-open / bad signature → raises
///   `ConnectionError`
///
/// Any raise is a hard refusal — never treat it as ALLOW.
#[pyclass(name = "SafetyKernelClient")]
struct PySafetyKernelClient {
    inner: RustSafetyKernelClient,
    rt: tokio::runtime::Runtime,
}

#[pymethods]
impl PySafetyKernelClient {
    /// `SafetyKernelClient(base_url, api_key, pinned_pubkey: bytes,
    /// timeout_ms=2000, leeway_seconds=None)`.
    #[new]
    #[pyo3(signature = (base_url, api_key, pinned_pubkey, timeout_ms=DEFAULT_TIMEOUT_MS, leeway_seconds=None))]
    fn new(
        base_url: String,
        api_key: String,
        pinned_pubkey: Vec<u8>,
        timeout_ms: u64,
        leeway_seconds: Option<f64>,
    ) -> PyResult<Self> {
        let arr: [u8; 32] = pinned_pubkey.as_slice().try_into().map_err(|_| {
            PyValueError::new_err(format!(
                "pinned pubkey must be exactly 32 bytes, got {}",
                pinned_pubkey.len()
            ))
        })?;
        let verifier = match leeway_seconds {
            Some(l) => RustPinnedKeyVerifier::with_leeway(arr, l),
            None => RustPinnedKeyVerifier::from_pubkey_bytes(arr),
        }
        .map_err(to_pyerr)?;

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build()
            .map_err(to_pyerr)?;
        let breaker = CircuitBreaker::new(CircuitConfig::default(), Box::new(SystemClock));
        let inner = RustSafetyKernelClient::new(
            http,
            base_url,
            api_key,
            breaker,
            verifier,
            Box::new(SystemClock),
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(to_pyerr)?;
        Ok(Self { inner, rt })
    }

    /// The 16-hex-char audit fingerprint of the pinned key.
    #[getter]
    fn pinned_key_fingerprint(&self) -> String {
        self.inner.pinned_key_fingerprint().to_string()
    }

    /// `POST /kernel/v1/authorize` for `action` bound to `params_fingerprint`.
    ///
    /// Returns the ALLOW dict on success; raises on DENY (`PermissionError`) or
    /// any unavailable / verification failure (`ConnectionError`). Fail-closed.
    #[pyo3(signature = (action, params_fingerprint, run_id, subject, traceparent=None))]
    fn authorize(
        &self,
        py: Python<'_>,
        action: String,
        params_fingerprint: String,
        run_id: String,
        subject: String,
        traceparent: Option<String>,
    ) -> PyResult<Py<PyAny>> {
        let request = AuthorizeRequest {
            action,
            params_fingerprint,
            run_id,
            subject,
            traceparent,
        };
        // Release the GIL while the blocking HTTP round-trip runs (pyo3 0.29
        // renamed `allow_threads` to `detach`).
        let outcome = py.detach(|| self.rt.block_on(self.inner.authorize(&request)));

        match outcome {
            Ok(KernelDecision::Allow { token, claims }) => {
                let mut obj = serde_json::Map::new();
                obj.insert("decision".to_string(), Value::String("allow".to_string()));
                obj.insert("token".to_string(), Value::String(token));
                if let Value::Object(vc_map) = verified_claims_to_value(claims)? {
                    for (k, v) in vc_map {
                        obj.insert(k, v);
                    }
                }
                let out = pythonize::pythonize(py, &Value::Object(obj)).map_err(to_pyerr)?;
                Ok(out.unbind())
            }
            Ok(KernelDecision::Deny { reason }) => Err(PyPermissionError::new_err(format!(
                "kernel_denied: {reason}"
            ))),
            Err(KernelClientError::Decision(KernelDecisionError::Denied { reason })) => Err(
                PyPermissionError::new_err(format!("kernel_denied: {reason}")),
            ),
            Err(e) => Err(PyConnectionError::new_err(format!(
                "kernel_unavailable: {e}"
            ))),
        }
    }
}

/// The `safety_kernel_client` Python module.
#[pymodule]
fn safety_kernel_client(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(params_fingerprint, m)?)?;
    m.add_class::<PyPinnedKeyVerifier>()?;
    m.add_class::<PySafetyKernelClient>()?;
    Ok(())
}
