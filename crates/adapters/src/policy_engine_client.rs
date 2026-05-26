//! Unix-socket JSON-line client for the Python policy sidecar.
//!
//! Implements the IPC contract described in:
//! line-delimited JSON over `tokio::net::UnixStream`, one connection
//! per HTTP request. No retries. Connect/request timeouts wired in.
//!
//! Failure semantics are split between the two ops (§3.5):
//!
//! - `op=authorize` → fail-CLOSED. The kernel handler converts any
//!   `IpcError` into `PolicyDecision { allowed: false, reason: "policy_error:<kind>" }`.
//! - `op=audit_append` → fail-OPEN. The kernel handler logs and continues;
//!   token issuance still proceeds.
//!
//! This module does NOT implement either policy itself — it merely
//! returns `Result<_, IpcError>` and lets the handler decide. That
//! separation matches Python `routes/authorize.py`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::timeout;
use tracing::warn;
use uuid::Uuid;

// ============================================================================
// Error type — stable kinds for the `policy_error:<kind>` reason string
// ============================================================================

/// IPC-layer error returned by `PolicyEngineClient`. The `kind()`
/// helper returns a stable `&'static str` used to build the
/// `policy_error:<kind>` reason on the deny path (ADR §3.5).
#[derive(Debug, Error)]
pub enum IpcError {
    /// Failed to connect to the Unix-domain socket (path missing,
    /// permissions denied, sidecar not running).
    #[error("ipc_connect:{0}")]
    IpcConnect(String),

    /// Connect or read exceeded the configured timeout.
    #[error("ipc_timeout:{0}")]
    IpcTimeout(String),

    /// Unexpected EOF reading the response line — sidecar closed
    /// the connection before sending a full JSON line.
    #[error("ipc_eof")]
    IpcEof,

    /// Response was received but failed shape validation: not valid
    /// UTF-8 / not single-line JSON / missing `ok` / `ok=true` without
    /// expected success fields.
    #[error("malformed_response:{0}")]
    MalformedResponse(String),

    /// Sidecar returned `ok: false` with an error string. The string
    /// is forwarded as part of the deny `metadata` but the reason kind
    /// is stable.
    #[error("sidecar_error:{0}")]
    SidecarReportedError(String),

    /// The sidecar's response carried a `request_id` that did NOT
    /// echo the request's `request_id`. A hostile sidecar could
    /// otherwise mis-correlate two parallel requests and serve
    /// request A's response to request B (ADR §3.2 binding).
    /// Reported as `policy_error:RequestIdMismatch` on the deny path.
    #[error("request_id_mismatch:{expected} vs {got}")]
    RequestIdMismatch {
        /// The `request_id` we sent.
        expected: String,
        /// The `request_id` the sidecar echoed.
        got: String,
    },
}

impl IpcError {
    /// Stable, version-independent kind string. Used by the handler to
    /// build `policy_error:<kind>` 5 — the
    /// equivalence harness asserts these strings byte-equal across
    /// implementations.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::IpcConnect(_) => "IpcConnect",
            Self::IpcTimeout(_) => "IpcTimeout",
            Self::IpcEof => "IpcEof",
            Self::MalformedResponse(_) => "MalformedResponse",
            Self::SidecarReportedError(_) => "SidecarReportedError",
            Self::RequestIdMismatch { .. } => "RequestIdMismatch",
        }
    }

    /// Human-readable detail string, suitable for the deny
    /// `metadata.error` field.
    #[must_use]
    pub fn detail(&self) -> String {
        self.to_string()
    }
}

// ============================================================================
// IPC payload shapes (NOT byte-stable wire — internal only)
// ============================================================================
//
// These are NOT part of the kernel's HTTP wire format. They serialize
// to JSON for the Unix-socket hop, which the Python sidecar parses
// with its own (Python) deserializer. The byte-stable surface is the
// kernel's HTTP response, NOT the IPC payload.

/// Authorize-policy request payload (§3.3 of ).
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizePolicyRequest {
    /// Sensitive action name (e.g. ).
    pub action: String,
    /// Subject — the trusted `caller_role` (NOT body.subject).
    pub subject: String,
    /// Wall-clock seconds at handler entry.
    pub now: f64,
    /// Free-form metadata; mirrors Python `routes/authorize.py:107-111`.
    /// Per inconsistency note 8, the `params` key
    /// is OMITTED entirely when the body's `params` is `None`. The
    /// caller is responsible for not inserting that key — this struct
    /// just carries whatever the caller built.
    pub metadata: Value,
}

/// Authorize-policy response (§3.3 success body).
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// `true` → token issuance proceeds; `false` → handler returns 403.
    pub allowed: bool,
    /// Stable machine-readable reason code (e.g. `allowed`,
    /// `subject_denylist`).
    pub reason: String,
    /// Free-form metadata echoed back to the caller's audit record.
    pub metadata: Value,
}

/// Audit-append request (§3.4).
#[derive(Debug, Clone, Serialize)]
pub struct AuditAppendRequest {
    /// Stable unit identifier — always `"safety_kernel"` for
    /// kernel writes.
    pub unit_id: String,
    /// `kernel_authorize` | `kernel_signed_approval`.
    pub action_name: String,
    /// `payload_base` (NOT including the `audit_chain` echo).
    pub payload: Value,
    /// Whether the underlying decision succeeded.
    pub success: bool,
    /// Optional error string when `success == false`.
    pub error: Option<String>,
    /// Wall-clock at handler entry.
    pub started_at: f64,
    /// Wall-clock at audit time (post-sign).
    pub ended_at: f64,
}

/// Audit-append response (§3.4 success body).
#[derive(Debug, Clone)]
pub struct AuditChainEntry {
    /// `outcome_<uuid>` — generated by the sidecar.
    pub outcome_id: String,
    /// HMAC-SHA256(pepper, _`stable_json(record)`) hex.
    pub record_hash: String,
    /// Free-form chain entry from the `OutcomeStore` — includes
    /// `chain_id`, `seq`, `prev_hash`, `entry_hash`, `recorded_at`.
    pub chain_entry: Value,
}

// ============================================================================
// Policy-engine ( slice 2) — IPC payload shapes
// ============================================================================
//
// All four shapes carry an  §" design" `op` discriminator
// in the outer envelope:
//
//   `op=policy_authorize`     — `PolicyModuleAuthorizeRequest`
//   `op=policy_register`      — `PolicyModuleRegisterRequest`
//   `op=policy_audit_event`   — `PolicyAuditEventRequest`
//   `op=policy_status`        — `PolicyModuleStatusRequest`
//
// The Rust kernel is stateless — the sidecar owns the `module_registry`
// SQLite table and the audit-chain backing store. The kernel forwards
// every registry mutation and lookup over Unix-socket IPC; the
// `op=policy_*` verbs are the new IPC surface added in slice 2.

/// `op=policy_authorize` request envelope. The kernel sends this to the
/// sidecar on every `POST /policy/module/authorize` after validating
/// the inbound HTTP request shape + recomputing the event fingerprint.
///
/// The sidecar looks up `module_path` in its `module_registry` table,
/// compiles the registered regex set into a `RegexSet`, evaluates
/// against `module_path`, and replies with `PolicyModuleAuthorizeResponseInner`.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyModuleAuthorizeRequest {
    /// `"import"` | `"exec"` | `"compile"`.
    pub event_kind: String,
    /// Dotted module name or source-hash hex (per `event_kind`).
    pub module_path: String,
    /// Caller subject from the request body.
    pub caller_subject: String,
    /// Caller run id from the request body.
    pub caller_run_id: String,
    /// Server-recomputed event fingerprint (NOT the value the caller
    /// supplied — the kernel recomputes before issuing IPC).
    pub event_fingerprint: String,
    /// Optional caller-side regex-set expectation for drift detection.
    /// `None` ⇒ caller has no expectation; the sidecar enforces the
    /// recorded set without drift check.
    pub expected_required_patterns: Option<Vec<String>>,
    /// Free-form audit metadata echoed into the audit chain.
    pub metadata: Option<Value>,
}

/// Sidecar response payload for `op=policy_authorize` (the inner
/// `decision` envelope; the outer IPC envelope wraps with `ok` /
/// `request_id`).
///
/// `decision` is the discriminator: `"allow"`, `"deny"`, or
/// `"kernel_unavailable"`. The kernel branches on this string to
/// choose the HTTP status code + signed envelope (200 / 403 / 503).
/// `KernelUnavailable` is returned by the sidecar when its policy
/// backend is unreachable; the kernel returns 503 without signing.
#[derive(Debug, Clone)]
pub struct PolicyModuleAuthorizeResponseInner {
    /// `"allow"` | `"deny"` | `"kernel_unavailable"`.
    pub decision: String,
    /// Machine-readable refusal reason on `deny`; `None` on `allow`.
    /// Stable enum strings 2 table.
    pub reason: Option<String>,
    /// Registration timestamp of the matched row (allow/deny only;
    /// `None` on `kernel_unavailable` / `module_not_registered`).
    pub registered_at_unix_ms: Option<i64>,
}

/// `op=policy_register` request envelope. Validated server-side by the
/// kernel BEFORE the IPC call: each pattern is compiled via
/// `regex::Regex::new` (kernel-side pre-validation per ),
/// and the bounds in §5 are enforced (`max_pattern_length=512`,
/// `max_patterns_per_module=32`, `max_dfa_size=10 MiB`). The sidecar
/// trusts patterns that reach it but re-compiles to its own `RegexSet`
/// for evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyModuleRegisterRequest {
    /// Module path being registered.
    pub module_path: String,
    /// Regex set the path must match on every subsequent authorize call.
    pub required_patterns_regex_set: Vec<String>,
    /// Caller subject — recorded in the registry's `registered_by`
    /// column.
    pub caller_subject: String,
}

/// Sidecar response payload for `op=policy_register`.
///
/// On conflict (path already registered + not revoked), the sidecar
/// returns `conflict=true` and the existing `registered_at_unix_ms`;
/// the kernel converts to a 409 with the existing-row metadata.
#[derive(Debug, Clone)]
pub struct PolicyModuleRegisterResponseInner {
    /// New or existing registration timestamp.
    pub registered_at_unix_ms: i64,
    /// Echoed back; `None` on a fresh registration.
    pub revoked_at_unix_ms: Option<i64>,
    /// `true` ⇒ path already registered and not revoked. Kernel
    /// responds 409.
    pub conflict: bool,
}

/// `op=policy_audit_event` request envelope. Surfaces a non-decision
/// audit entry from the audit-hook reference; the sidecar appends one
/// row with `audit_kind="policy_audit_event"` and returns an ack.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyAuditEventRequest {
    /// Closed-enum string (`hook_install_violation`, etc.).
    pub event_kind: String,
    /// Caller subject from the request body.
    pub subject: String,
    /// Free-form audit metadata bound into the chain entry.
    pub metadata: Option<BTreeMap<String, Value>>,
}

/// `op=policy_status` request envelope. Read-only lookup; the sidecar
/// joins `module_registry` with the last 20 `policy_authorize_*`
/// audit entries for the path.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyModuleStatusRequest {
    /// Module path to look up.
    pub module_path: String,
}

/// One row of `recent_decisions` returned by `op=policy_status`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyModuleStatusDecisionRow {
    /// Decision timestamp (unix milliseconds).
    pub ts_unix_ms: i64,
    /// `"allow"` or `"deny"`.
    pub decision: String,
    /// Echo of `caller_run_id` at decision time.
    pub caller_run_id: String,
    /// SHA-256 hex of the signed decision token.
    pub token_sha256: String,
}

/// Sidecar response payload for `op=policy_status`. The IPC layer
/// returns `None` when no registry row exists for the path (the
/// kernel maps that to 404).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyModuleStatusResponseInner {
    /// Echo of the requested path.
    pub module_path: String,
    /// Regex set associated with the current registration row.
    pub required_patterns_regex_set: Vec<String>,
    /// Registration timestamp (unix milliseconds).
    pub registered_at_unix_ms: i64,
    /// Caller subject that performed the registration.
    pub registered_by: String,
    /// Revocation timestamp, `None` while active.
    pub revoked_at_unix_ms: Option<i64>,
    /// Newest-first decision rows (≤20).
    pub recent_decisions: Vec<PolicyModuleStatusDecisionRow>,
}

// ============================================================================
// Client
// ============================================================================

/// Configuration + stateless client for the Python policy sidecar.
///
/// One connection per HTTP request — see The
/// path is canonicalized once at startup by `main.rs`; we don't
/// re-resolve here.
#[derive(Debug, Clone)]
pub struct PolicyEngineClient {
    /// Path to the sidecar's Unix-domain socket.
    pub sock_path: PathBuf,
    /// Connect timeout (default 1s per ADR §3.6).
    pub connect_timeout: Duration,
    /// Per-request read timeout (default 5s per ADR §3.6).
    pub request_timeout: Duration,
}

impl PolicyEngineClient {
    /// Build a client. Defaults match ADR §3.6 — 1s connect, 5s request.
    #[must_use]
    pub fn new(sock_path: PathBuf) -> Self {
        Self {
            sock_path,
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(5),
        }
    }

    /// Override timeouts (used by tests + env-var-driven main).
    #[must_use]
    pub fn with_timeouts(mut self, connect: Duration, request: Duration) -> Self {
        self.connect_timeout = connect;
        self.request_timeout = request;
        self
    }

    /// Send `op=authorize` and return the decision.
    ///
    /// **Fail-CLOSED**: the kernel handler converts any `Err(IpcError)`
    /// from this method into `PolicyDecision { allowed: false }` per
    /// ADR §3.5. We do NOT do that conversion here — keeping the error
    /// type explicit lets the caller log and audit the failure mode
    /// before producing the deny response.
    ///
    /// # Errors
    ///
    /// Returns `IpcError` for any connect/timeout/eof/malformed/sidecar
    /// failure mode. The handler converts these to a denial with
    /// `reason = "policy_error:<kind>"`.
    pub async fn authorize(&self, req: AuthorizePolicyRequest) -> Result<PolicyDecision, IpcError> {
        let request_id = Uuid::now_v7().to_string();
        let payload = serde_json::json!({
            "action": req.action,
            "subject": req.subject,
            "now": req.now,
            "metadata": req.metadata,
        });
        let envelope = serde_json::json!({
            "op": "authorize",
            "request_id": request_id,
            "payload": payload,
        });
        let resp = self.round_trip(&envelope).await?;
        Self::parse_authorize_response(&resp, &request_id)
    }

    /// Send `op=audit_append` and return the chain entry.
    ///
    /// **Fail-OPEN**: the kernel handler logs and discards any
    /// `Err(IpcError)` returned here so token issuance still
    /// proceeds. Audit append is the ONLY fail-open path in the
    /// kernel, per ADR §3.5 / §4.4.
    ///
    /// # Errors
    ///
    /// Returns `IpcError` for any connect/timeout/eof/malformed/sidecar
    /// failure mode. Caller MUST log + swallow.
    pub async fn audit_append(&self, req: AuditAppendRequest) -> Result<AuditChainEntry, IpcError> {
        let request_id = Uuid::now_v7().to_string();
        let payload = serde_json::json!({
            "unit_id": req.unit_id,
            "action_name": req.action_name,
            "payload": req.payload,
            "success": req.success,
            "error": req.error,
            "started_at": req.started_at,
            "ended_at": req.ended_at,
        });
        let envelope = serde_json::json!({
            "op": "audit_append",
            "request_id": request_id,
            "payload": payload,
        });
        let resp = self.round_trip(&envelope).await?;
        Self::parse_audit_append_response(&resp, &request_id)
    }

    // ------------------------------------------------------------------
    //  slice 2 — policy-engine IPC verbs
    // ------------------------------------------------------------------

    /// Send `op=policy_authorize` and return the sidecar's decision.
    ///
    /// **Fail-CLOSED at the handler layer**: the kernel handler converts
    /// any `Err(IpcError)` here into HTTP 503 with no signed token. The
    /// `decision="kernel_unavailable"` sidecar response is a separate
    /// signal (the sidecar reached its policy backend but that backend
    /// is unavailable); both result in 503 to the caller.
    ///
    /// # Errors
    ///
    /// Returns `IpcError` for any connect/timeout/eof/malformed/sidecar
    /// failure mode. The handler maps these to 503.
    pub async fn policy_authorize(
        &self,
        req: PolicyModuleAuthorizeRequest,
    ) -> Result<PolicyModuleAuthorizeResponseInner, IpcError> {
        let request_id = Uuid::now_v7().to_string();
        let payload = serde_json::json!({
            "event_kind": req.event_kind,
            "module_path": req.module_path,
            "caller_subject": req.caller_subject,
            "caller_run_id": req.caller_run_id,
            "event_fingerprint": req.event_fingerprint,
            "expected_required_patterns": req.expected_required_patterns,
            "metadata": req.metadata,
        });
        let envelope = serde_json::json!({
            "op": "policy_authorize",
            "request_id": request_id,
            "payload": payload,
        });
        let resp = self.round_trip(&envelope).await?;
        Self::parse_policy_authorize_response(&resp, &request_id)
    }

    /// Send `op=policy_register` and return the registry row metadata.
    ///
    /// Pattern compilation has already happened kernel-side per
    ///  — the sidecar trusts that patterns sent here parse
    /// cleanly. The sidecar will additionally compile them into its
    /// own `RegexSet` for evaluation; an internal compile error would
    /// surface here as `IpcError::SidecarReportedError`.
    ///
    /// # Errors
    ///
    /// Returns `IpcError` for any IPC-layer failure.
    pub async fn policy_register(
        &self,
        req: PolicyModuleRegisterRequest,
    ) -> Result<PolicyModuleRegisterResponseInner, IpcError> {
        let request_id = Uuid::now_v7().to_string();
        let payload = serde_json::json!({
            "module_path": req.module_path,
            "required_patterns_regex_set": req.required_patterns_regex_set,
            "caller_subject": req.caller_subject,
        });
        let envelope = serde_json::json!({
            "op": "policy_register",
            "request_id": request_id,
            "payload": payload,
        });
        let resp = self.round_trip(&envelope).await?;
        Self::parse_policy_register_response(&resp, &request_id)
    }

    /// Send `op=policy_audit_event` and return ack-only.
    ///
    /// Fail-CLOSED at the handler layer 3 (the caller
    /// has no signed artifact yet so they can retry).
    ///
    /// # Errors
    ///
    /// Returns `IpcError` for any IPC-layer failure.
    pub async fn policy_audit_event(&self, req: PolicyAuditEventRequest) -> Result<i64, IpcError> {
        let request_id = Uuid::now_v7().to_string();
        let payload = serde_json::json!({
            "event_kind": req.event_kind,
            "subject": req.subject,
            "metadata": req.metadata,
        });
        let envelope = serde_json::json!({
            "op": "policy_audit_event",
            "request_id": request_id,
            "payload": payload,
        });
        let resp = self.round_trip(&envelope).await?;
        Self::parse_policy_audit_event_response(&resp, &request_id)
    }

    /// Send `op=policy_status` and return the registration record +
    /// recent-decision rows. `None` ⇒ no registry row for the path
    /// (kernel maps to 404).
    ///
    /// # Errors
    ///
    /// Returns `IpcError` for any IPC-layer failure (NOT for
    /// "not registered" — that's `Ok(None)`).
    pub async fn policy_module_status(
        &self,
        req: PolicyModuleStatusRequest,
    ) -> Result<Option<PolicyModuleStatusResponseInner>, IpcError> {
        let request_id = Uuid::now_v7().to_string();
        let payload = serde_json::json!({
            "module_path": req.module_path,
        });
        let envelope = serde_json::json!({
            "op": "policy_status",
            "request_id": request_id,
            "payload": payload,
        });
        let resp = self.round_trip(&envelope).await?;
        Self::parse_policy_status_response(&resp, &request_id)
    }

    // ------------------------------------------------------------------
    // private helpers
    // ------------------------------------------------------------------

    /// Open a fresh `UnixStream`, write one JSON line + `\n`, read one
    /// line back, parse JSON. All steps subject to the configured
    /// timeouts.
    async fn round_trip(&self, envelope: &Value) -> Result<Value, IpcError> {
        let stream = match timeout(self.connect_timeout, UnixStream::connect(&self.sock_path)).await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(IpcError::IpcConnect(e.to_string())),
            Err(_) => {
                return Err(IpcError::IpcTimeout(format!(
                    "connect:{:?}",
                    self.connect_timeout
                )))
            }
        };

        // Split into reader + writer so we can issue the write and read
        // back the response without re-borrowing.
        let (read_half, mut write_half) = tokio::io::split(stream);

        // Write the request line.
        let mut line = match serde_json::to_string(envelope) {
            Ok(s) => s,
            // Serializing a `Value` we built ourselves can never fail
            // outside of OOM, but map to a defensive error anyway.
            Err(e) => {
                return Err(IpcError::MalformedResponse(format!(
                    "serialize_request:{e}"
                )))
            }
        };
        line.push('\n');

        let write_result = timeout(self.request_timeout, async {
            write_half.write_all(line.as_bytes()).await?;
            write_half.flush().await?;
            Ok::<(), std::io::Error>(())
        })
        .await;
        match write_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(IpcError::MalformedResponse(format!("write:{e}"))),
            Err(_) => {
                return Err(IpcError::IpcTimeout(format!(
                    "write:{:?}",
                    self.request_timeout
                )))
            }
        }

        // Read one line back.
        let mut reader = BufReader::new(read_half);
        let mut buf = String::new();
        let read_result = timeout(self.request_timeout, reader.read_line(&mut buf)).await;

        let n = match read_result {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(IpcError::MalformedResponse(format!("read:{e}"))),
            Err(_) => {
                return Err(IpcError::IpcTimeout(format!(
                    "read:{:?}",
                    self.request_timeout
                )))
            }
        };
        if n == 0 {
            return Err(IpcError::IpcEof);
        }

        // Parse JSON. Reject non-UTF-8 implicitly via `read_line` (which
        // requires UTF-8) and non-JSON via the parser.
        let parsed: Value = serde_json::from_str(buf.trim_end_matches(['\n', '\r']))
            .map_err(|e| IpcError::MalformedResponse(format!("parse:{e}")))?;

        if !parsed.is_object() {
            return Err(IpcError::MalformedResponse("not_object".to_string()));
        }
        Ok(parsed)
    }

    fn parse_authorize_response(
        resp: &Value,
        expected_request_id: &str,
    ) -> Result<PolicyDecision, IpcError> {
        let ok = resp
            .get("ok")
            .and_then(Value::as_bool)
            .ok_or_else(|| IpcError::MalformedResponse("missing_ok".to_string()))?;
        // request_id echo is a HARD check (ADR §3.2 / W4 purple-team
        // T2 finding). A hostile sidecar must not be able to swap
        // decisions between parallel requests by misechoing the
        // request_id. We require an exact-byte match. If the sidecar
        // legitimately drops the field, the kernel fails-CLOSED with
        // `policy_error:RequestIdMismatch` (mismatch against the
        // empty string) — which is correct: no echo means the
        // sidecar is non-conformant.
        let echoed_rid = resp.get("request_id").and_then(Value::as_str).unwrap_or("");
        if echoed_rid != expected_request_id {
            warn!(
                expected = expected_request_id,
                got = echoed_rid,
                "policy sidecar request_id echo mismatch — failing closed"
            );
            return Err(IpcError::RequestIdMismatch {
                expected: expected_request_id.to_string(),
                got: echoed_rid.to_string(),
            });
        }

        if !ok {
            let err_msg = resp
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unspecified")
                .to_string();
            return Err(IpcError::SidecarReportedError(err_msg));
        }

        let decision = resp
            .get("decision")
            .ok_or_else(|| IpcError::MalformedResponse("missing_decision".to_string()))?;
        let allowed = decision
            .get("allowed")
            .and_then(Value::as_bool)
            .ok_or_else(|| IpcError::MalformedResponse("missing_decision.allowed".to_string()))?;
        let reason = decision
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let metadata = decision
            .get("metadata")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        Ok(PolicyDecision {
            allowed,
            reason,
            metadata,
        })
    }

    fn parse_audit_append_response(
        resp: &Value,
        expected_request_id: &str,
    ) -> Result<AuditChainEntry, IpcError> {
        let ok = resp
            .get("ok")
            .and_then(Value::as_bool)
            .ok_or_else(|| IpcError::MalformedResponse("missing_ok".to_string()))?;
        // request_id echo is a HARD check (ADR §3.2 / W4 purple-team
        // T2 finding). The audit-append path is fail-OPEN at the
        // handler level (ADR §3.5), but we still surface the
        // mismatch as an `IpcError::RequestIdMismatch` so the
        // handler logs the right reason kind.
        let echoed_rid = resp.get("request_id").and_then(Value::as_str).unwrap_or("");
        if echoed_rid != expected_request_id {
            warn!(
                expected = expected_request_id,
                got = echoed_rid,
                "audit sidecar request_id echo mismatch — failing closed"
            );
            return Err(IpcError::RequestIdMismatch {
                expected: expected_request_id.to_string(),
                got: echoed_rid.to_string(),
            });
        }
        if !ok {
            let err_msg = resp
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unspecified")
                .to_string();
            return Err(IpcError::SidecarReportedError(err_msg));
        }
        let outcome_id = resp
            .get("outcome_id")
            .and_then(Value::as_str)
            .ok_or_else(|| IpcError::MalformedResponse("missing_outcome_id".to_string()))?
            .to_string();
        let record_hash = resp
            .get("record_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| IpcError::MalformedResponse("missing_record_hash".to_string()))?
            .to_string();
        let chain_entry = resp
            .get("chain_entry")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        Ok(AuditChainEntry {
            outcome_id,
            record_hash,
            chain_entry,
        })
    }

    // ------------------------------------------------------------------
    //  slice 2 — IPC response parsers
    // ------------------------------------------------------------------

    /// Common envelope validation — `ok` boolean + `request_id` echo.
    /// Returns the inner `decision` / `result` Value on success.
    fn validate_envelope<'a>(
        resp: &'a Value,
        expected_request_id: &str,
        result_key: &str,
    ) -> Result<&'a Value, IpcError> {
        let ok = resp
            .get("ok")
            .and_then(Value::as_bool)
            .ok_or_else(|| IpcError::MalformedResponse("missing_ok".to_string()))?;
        let echoed_rid = resp.get("request_id").and_then(Value::as_str).unwrap_or("");
        if echoed_rid != expected_request_id {
            warn!(
                expected = expected_request_id,
                got = echoed_rid,
                "policy sidecar request_id echo mismatch — failing closed"
            );
            return Err(IpcError::RequestIdMismatch {
                expected: expected_request_id.to_string(),
                got: echoed_rid.to_string(),
            });
        }
        if !ok {
            let err_msg = resp
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unspecified")
                .to_string();
            return Err(IpcError::SidecarReportedError(err_msg));
        }
        resp.get(result_key)
            .ok_or_else(|| IpcError::MalformedResponse(format!("missing_{result_key}")))
    }

    fn parse_policy_authorize_response(
        resp: &Value,
        expected_request_id: &str,
    ) -> Result<PolicyModuleAuthorizeResponseInner, IpcError> {
        let decision_obj = Self::validate_envelope(resp, expected_request_id, "decision")?;
        let decision = decision_obj
            .get("decision")
            .and_then(Value::as_str)
            .ok_or_else(|| IpcError::MalformedResponse("missing_decision.decision".to_string()))?
            .to_string();
        let reason = decision_obj
            .get("reason")
            .and_then(Value::as_str)
            .map(str::to_string);
        let registered_at_unix_ms = decision_obj
            .get("registered_at_unix_ms")
            .and_then(Value::as_i64);
        Ok(PolicyModuleAuthorizeResponseInner {
            decision,
            reason,
            registered_at_unix_ms,
        })
    }

    fn parse_policy_register_response(
        resp: &Value,
        expected_request_id: &str,
    ) -> Result<PolicyModuleRegisterResponseInner, IpcError> {
        let result = Self::validate_envelope(resp, expected_request_id, "result")?;
        let registered_at_unix_ms = result
            .get("registered_at_unix_ms")
            .and_then(Value::as_i64)
            .ok_or_else(|| {
                IpcError::MalformedResponse("missing_result.registered_at_unix_ms".to_string())
            })?;
        let revoked_at_unix_ms = result.get("revoked_at_unix_ms").and_then(Value::as_i64);
        let conflict = result
            .get("conflict")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(PolicyModuleRegisterResponseInner {
            registered_at_unix_ms,
            revoked_at_unix_ms,
            conflict,
        })
    }

    fn parse_policy_audit_event_response(
        resp: &Value,
        expected_request_id: &str,
    ) -> Result<i64, IpcError> {
        let result = Self::validate_envelope(resp, expected_request_id, "result")?;
        result
            .get("ts_unix_ms")
            .and_then(Value::as_i64)
            .ok_or_else(|| IpcError::MalformedResponse("missing_result.ts_unix_ms".to_string()))
    }

    fn parse_policy_status_response(
        resp: &Value,
        expected_request_id: &str,
    ) -> Result<Option<PolicyModuleStatusResponseInner>, IpcError> {
        // `ok=true` + `result=null` ⇒ module not registered (kernel
        // maps to 404). `ok=true` + `result=<object>` ⇒ status payload.
        let ok = resp
            .get("ok")
            .and_then(Value::as_bool)
            .ok_or_else(|| IpcError::MalformedResponse("missing_ok".to_string()))?;
        let echoed_rid = resp.get("request_id").and_then(Value::as_str).unwrap_or("");
        if echoed_rid != expected_request_id {
            warn!(
                expected = expected_request_id,
                got = echoed_rid,
                "policy sidecar request_id echo mismatch — failing closed"
            );
            return Err(IpcError::RequestIdMismatch {
                expected: expected_request_id.to_string(),
                got: echoed_rid.to_string(),
            });
        }
        if !ok {
            let err_msg = resp
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unspecified")
                .to_string();
            return Err(IpcError::SidecarReportedError(err_msg));
        }
        let Some(result) = resp.get("result") else {
            return Err(IpcError::MalformedResponse("missing_result".to_string()));
        };
        if result.is_null() {
            return Ok(None);
        }
        // Defer to serde for the field-by-field deserialization — the
        // response shape is stable 4 and serde gives us
        // descriptive errors on shape mismatch.
        let inner: PolicyModuleStatusResponseInner = serde_json::from_value(result.clone())
            .map_err(|e| IpcError::MalformedResponse(format!("status_payload:{e}")))?;
        Ok(Some(inner))
    }
}

// Silence unused — `BTreeMap` reaches the file only through the
// `PolicyAuditEventRequest::metadata` field, which means it's used.
// Belt-and-braces: re-export marker so the `use` line isn't seen as
// dead by `unused_imports`.
const _: fn() = || {
    let _: Option<BTreeMap<String, Value>> = None;
};

// ============================================================================
// Deserialize helpers — used by tests + sidecar mock
// ============================================================================

/// Generic IPC envelope `{op, request_id, payload}` — exposed for the
/// sidecar reference implementation and the smoke test harness.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IpcEnvelope {
    /// `authorize` or `audit_append`.
    pub op: String,
    /// UUID v7 string for correlation.
    pub request_id: String,
    /// Op-specific payload.
    pub payload: Value,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::doc_markdown
)]
mod tests {
    use super::*;

    #[test]
    fn ipc_error_kinds_are_stable() {
        assert_eq!(IpcError::IpcEof.kind(), "IpcEof");
        assert_eq!(IpcError::IpcConnect("foo".into()).kind(), "IpcConnect");
        assert_eq!(IpcError::IpcTimeout("foo".into()).kind(), "IpcTimeout");
        assert_eq!(
            IpcError::MalformedResponse("foo".into()).kind(),
            "MalformedResponse"
        );
        assert_eq!(
            IpcError::SidecarReportedError("foo".into()).kind(),
            "SidecarReportedError"
        );
    }

    #[test]
    fn parse_authorize_success() {
        let r = serde_json::json!({
            "ok": true,
            "request_id": "rid",
            "decision": {"allowed": true, "reason": "allowed", "metadata": {}}
        });
        let d = PolicyEngineClient::parse_authorize_response(&r, "rid").unwrap();
        assert!(d.allowed);
        assert_eq!(d.reason, "allowed");
    }

    #[test]
    fn parse_authorize_sidecar_error() {
        let r = serde_json::json!({
            "ok": false,
            "request_id": "rid",
            "error": "ValueError:bad input"
        });
        let e = PolicyEngineClient::parse_authorize_response(&r, "rid").unwrap_err();
        assert_eq!(e.kind(), "SidecarReportedError");
    }

    #[test]
    fn parse_authorize_missing_ok() {
        let r = serde_json::json!({"request_id": "rid"});
        let e = PolicyEngineClient::parse_authorize_response(&r, "rid").unwrap_err();
        assert_eq!(e.kind(), "MalformedResponse");
    }

    #[test]
    fn parse_authorize_missing_decision_when_ok() {
        let r = serde_json::json!({"ok": true, "request_id": "rid"});
        let e = PolicyEngineClient::parse_authorize_response(&r, "rid").unwrap_err();
        assert_eq!(e.kind(), "MalformedResponse");
    }

    /// W4 purple-team T2 — `request_id` correlation hard check.
    /// A response whose `request_id` does NOT echo the expected one
    /// MUST be rejected with `IpcError::RequestIdMismatch`.
    #[test]
    fn parse_authorize_rejects_request_id_mismatch() {
        let r = serde_json::json!({
            "ok": true,
            "request_id": "wrong-rid",
            "decision": {"allowed": true, "reason": "allowed", "metadata": {}}
        });
        let e = PolicyEngineClient::parse_authorize_response(&r, "expected-rid").unwrap_err();
        assert_eq!(e.kind(), "RequestIdMismatch");
    }

    /// W4 purple-team T2 — `request_id` correlation hard check on
    /// audit-append. The handler treats `audit_append` errors as
    /// fail-OPEN at the kernel layer, but the IPC layer MUST still
    /// flag the mismatch so the handler can log the right reason.
    #[test]
    fn parse_audit_append_rejects_request_id_mismatch() {
        let r = serde_json::json!({
            "ok": true,
            "request_id": "wrong-rid",
            "outcome_id": "outcome_x",
            "record_hash": "deadbeef",
            "chain_entry": {}
        });
        let e = PolicyEngineClient::parse_audit_append_response(&r, "expected-rid").unwrap_err();
        assert_eq!(e.kind(), "RequestIdMismatch");
    }

    /// Echo-match success path — kernel accepts the response when
    /// `request_id` matches exactly.
    #[test]
    fn parse_authorize_accepts_echoed_request_id() {
        let r = serde_json::json!({
            "ok": true,
            "request_id": "rid-match",
            "decision": {"allowed": true, "reason": "allowed", "metadata": {}}
        });
        let d = PolicyEngineClient::parse_authorize_response(&r, "rid-match").unwrap();
        assert!(d.allowed);
    }

    // -----------------------------------------------------------------
    //  slice 2 — policy-engine parser tests
    // -----------------------------------------------------------------

    #[test]
    fn parse_policy_authorize_allow() {
        let r = serde_json::json!({
            "ok": true,
            "request_id": "rid",
            "decision": {
                "decision": "allow",
                "registered_at_unix_ms": 1_700_000_000_000_i64
            }
        });
        let inner = PolicyEngineClient::parse_policy_authorize_response(&r, "rid").unwrap();
        assert_eq!(inner.decision, "allow");
        assert!(inner.reason.is_none());
        assert_eq!(inner.registered_at_unix_ms, Some(1_700_000_000_000_i64));
    }

    #[test]
    fn parse_policy_authorize_deny_with_reason() {
        let r = serde_json::json!({
            "ok": true,
            "request_id": "rid",
            "decision": {
                "decision": "deny",
                "reason": "module_not_registered"
            }
        });
        let inner = PolicyEngineClient::parse_policy_authorize_response(&r, "rid").unwrap();
        assert_eq!(inner.decision, "deny");
        assert_eq!(inner.reason.as_deref(), Some("module_not_registered"));
    }

    #[test]
    fn parse_policy_authorize_kernel_unavailable() {
        let r = serde_json::json!({
            "ok": true,
            "request_id": "rid",
            "decision": { "decision": "kernel_unavailable" }
        });
        let inner = PolicyEngineClient::parse_policy_authorize_response(&r, "rid").unwrap();
        assert_eq!(inner.decision, "kernel_unavailable");
    }

    #[test]
    fn parse_policy_authorize_rejects_request_id_mismatch() {
        let r = serde_json::json!({
            "ok": true,
            "request_id": "wrong-rid",
            "decision": { "decision": "allow" }
        });
        let e = PolicyEngineClient::parse_policy_authorize_response(&r, "rid").unwrap_err();
        assert_eq!(e.kind(), "RequestIdMismatch");
    }

    #[test]
    fn parse_policy_register_success() {
        let r = serde_json::json!({
            "ok": true,
            "request_id": "rid",
            "result": {
                "registered_at_unix_ms": 1_700_000_000_000_i64,
                "conflict": false
            }
        });
        let inner = PolicyEngineClient::parse_policy_register_response(&r, "rid").unwrap();
        assert_eq!(inner.registered_at_unix_ms, 1_700_000_000_000);
        assert!(!inner.conflict);
        assert!(inner.revoked_at_unix_ms.is_none());
    }

    #[test]
    fn parse_policy_register_conflict() {
        let r = serde_json::json!({
            "ok": true,
            "request_id": "rid",
            "result": {
                "registered_at_unix_ms": 1_700_000_000_000_i64,
                "conflict": true
            }
        });
        let inner = PolicyEngineClient::parse_policy_register_response(&r, "rid").unwrap();
        assert!(inner.conflict);
    }

    #[test]
    fn parse_policy_audit_event_success() {
        let r = serde_json::json!({
            "ok": true,
            "request_id": "rid",
            "result": { "ts_unix_ms": 1_700_000_000_000_i64 }
        });
        let ts = PolicyEngineClient::parse_policy_audit_event_response(&r, "rid").unwrap();
        assert_eq!(ts, 1_700_000_000_000_i64);
    }

    #[test]
    fn parse_policy_status_not_registered_returns_none() {
        let r = serde_json::json!({
            "ok": true,
            "request_id": "rid",
            "result": null
        });
        let opt = PolicyEngineClient::parse_policy_status_response(&r, "rid").unwrap();
        assert!(opt.is_none());
    }

    #[test]
    fn parse_policy_status_returns_payload() {
        let r = serde_json::json!({
            "ok": true,
            "request_id": "rid",
            "result": {
                "module_path": "pkg.mod",
                "required_patterns_regex_set": ["^pkg\\."],
                "registered_at_unix_ms": 1_700_000_000_000_i64,
                "registered_by": "worker",
                "revoked_at_unix_ms": null,
                "recent_decisions": []
            }
        });
        let opt = PolicyEngineClient::parse_policy_status_response(&r, "rid")
            .unwrap()
            .unwrap();
        assert_eq!(opt.module_path, "pkg.mod");
        assert_eq!(opt.recent_decisions.len(), 0);
        assert!(opt.revoked_at_unix_ms.is_none());
    }

    #[test]
    fn parse_policy_status_sidecar_error() {
        let r = serde_json::json!({
            "ok": false,
            "request_id": "rid",
            "error": "sqlite_locked"
        });
        let e = PolicyEngineClient::parse_policy_status_response(&r, "rid").unwrap_err();
        assert_eq!(e.kind(), "SidecarReportedError");
    }
}
