//! `McpAuditRecord` — pure wire/record shape for the PII-free,
//! tamper-evident MCP `call_tool` audit ledger (ADR-016, internal-ref).
//!
//! This module is the DOMAIN half of the audit sink: the record type
//! and its canonical-bytes projection. It is pure — no I/O, no clock,
//! no network, no env, no sqlx, no logging — per `agent/boundaries.toml`.
//! The scrub / fingerprint / keyed-HMAC-pseudonym / Postgres-write /
//! transparency-log-append logic all lives in the adapter
//! (`crates/adapters/aara_audit/`), which is the only place those
//! forbidden imports are allowed.
//!
//! ## What feeds the hash chain
//!
//! Per ADR-016 §"Record shape", the `record_hash` is
//! `SHA-256(canonical_bytes(record))` over the **[chain]** fields plus
//! the hex-encoded `prev_hash`. The following fields are DELIBERATELY
//! EXCLUDED from the chain so an operator may redact a preview / pointer
//! / error string / extension without breaking tamper-evidence of the
//! load-bearing fields:
//!
//!   - `args_preview`
//!   - `result_pointer`
//!   - `error_detail`
//!   - `extension`
//!
//! Two purely-storage columns are also outside the chain because they
//! are assigned AFTER the record hash is computed and sealed:
//!
//!   - `latency_ms` (derived; redundant with `received_at`/`completed_at`)
//!   - `tlog_leaf_index` / `tlog_leaf_hash` / `tlog_pending` (assigned by
//!     the transparency-log on append, written back onto the row later)
//!   - `id` (Postgres `BIGSERIAL` storage identity — not a chain field)
//!
//! ## Canonical-bytes rule (mirrors `WaveSessionRecord::canonical_bytes`)
//!
//! The chain fields are serialized as COMPACT, LEX-SORTED JSON
//! (`serde_json` over a [`BTreeMap`], whose key order is sorted and
//! whose `to_vec` output uses the compact `","` / `":"` separators).
//! `prev_hash` is hex-encoded (or the JSON string `""` when absent so
//! the genesis record of a stream is still well-defined). This matches
//! the ADR-014 lex-sorted-JSON convention and the kernel's
//! `WaveSessionRecord` precedent byte-for-byte in SHAPE (sorted keys,
//! compact separators), so an external auditor can re-derive the hash
//! with any sorted-JSON serializer.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Which of the two correlated events this record captures. Every
/// `call_tool` invocation writes BOTH a `Dispatch` (received) and a
/// `Completion` (success / failure / rejected / timeout) event,
/// correlated by `job_id` + `trace_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// The dispatch (received) event. Carries the request fingerprint;
    /// `status` / result fields are absent.
    Dispatch,
    /// The completion event. Carries `status` + result fingerprint +
    /// timing.
    Completion,
}

impl EventKind {
    /// Stable wire string (`"dispatch"` / `"completion"`). Matches the
    /// `mcp_audit.mcp_audit_log.event_kind` CHECK constraint values.
    #[must_use]
    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::Dispatch => "dispatch",
            Self::Completion => "completion",
        }
    }
}

/// Caller-type taxonomy (matches the DDL CHECK constraint). The MCP
/// single point of entry can be driven by a human via claude.ai, an
/// autonomous agent loop, a cron job, or a sub-agent dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerType {
    /// A human operating through the claude.ai MCP surface.
    HumanViaClaudeAi,
    /// An autonomous agent / `/loop` invocation.
    AutonomousLoop,
    /// A scheduled / cron-driven invocation.
    Cron,
    /// A child / sub-agent dispatch (carries `parent_trace_id`).
    SubAgent,
}

impl CallerType {
    /// Stable wire string. Matches the DDL CHECK constraint values.
    #[must_use]
    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::HumanViaClaudeAi => "human_via_claude_ai",
            Self::AutonomousLoop => "autonomous_loop",
            Self::Cron => "cron",
            Self::SubAgent => "sub_agent",
        }
    }
}

/// Tool execution class (Slice 5.B classification). Drives the
/// asymmetric audit-sink-unavailable failure policy: a mutating tool
/// fails closed when the durable Postgres write fails; a read-only
/// tool never hard-blocks on audit loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolClass {
    /// Produces no unsafe state on its own; never hard-blocks on audit
    /// loss (proceed + durably queue).
    ReadOnly,
    /// Changes state; fails closed when the durable audit row cannot be
    /// written (un-attributable state change is exactly what the ledger
    /// exists to prevent).
    Mutating,
    /// Generic passthrough dispatch — treated like `read_only` for the
    /// availability policy (no attested mutation on this path).
    Passthrough,
}

impl ToolClass {
    /// Stable wire string. Matches the DDL CHECK constraint values.
    #[must_use]
    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Mutating => "mutating",
            Self::Passthrough => "passthrough",
        }
    }

    /// True iff a failed DURABLE Postgres write must fail the tool call
    /// closed (do NOT execute). Only `Mutating` fails closed; read-only
    /// + passthrough proceed and spill to the durable WAL.
    #[must_use]
    pub fn fails_closed_on_pg_write_failure(&self) -> bool {
        matches!(self, Self::Mutating)
    }
}

/// Completion-event status (matches the DDL CHECK constraint). `None`
/// on a dispatch event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionStatus {
    /// The tool body returned a result.
    Success,
    /// The tool body raised / returned an error.
    Failure,
    /// The dispatch was rejected before execution (authorizer reject,
    /// or audit-sink fail-closed on a mutating tool).
    Rejected,
    /// The tool exceeded its time budget.
    Timeout,
}

impl CompletionStatus {
    /// Stable wire string. Matches the DDL CHECK constraint values.
    #[must_use]
    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Rejected => "rejected",
            Self::Timeout => "timeout",
        }
    }
}

/// The canonical MCP audit record (ADR-016 §"Record shape").
///
/// One record == one event (a `call_tool` invocation produces two:
/// dispatch + completion). The struct carries EVERY ADR field. Fields
/// marked `[chain]` in the ADR feed [`Self::canonical_bytes`]; the four
/// excluded preview/pointer/error/extension fields plus the
/// storage-assigned tamper-evidence columns do NOT.
///
/// NO field marked "raw" in the ADR ever holds PII or a secret — that
/// is the adapter's scrub/fingerprint/pseudonymise responsibility,
/// enforced before this type is constructed. The domain type is
/// agnostic of HOW the fingerprints were produced; it only defines the
/// shape and the canonical projection.
///
/// Field declaration order is alphabetic so the derived `Serialize`
/// (used for transport / debugging, NOT for the hash) is byte-stable;
/// the hash itself goes through the explicit [`BTreeMap`] projection in
/// [`Self::canonical_bytes`] so it does not depend on struct field
/// order at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuditRecord {
    // ── Request: fingerprint (chain) + bounded preview (NOT chain) ──
    /// **[chain]** `SHA-256` over the scrubbed canonical args. Never raw.
    pub args_fingerprint: String,
    /// NOT chained — bounded + scrubbed + truncated copy. Redactable
    /// without breaking tamper-evidence.
    pub args_preview: Option<Value>,

    /// **[chain]** Rust dispatch verdict: `allow` | `allow_attest` |
    /// `reject` | `degraded`. `None` when the authorizer was not
    /// consulted (e.g. generic passthrough).
    pub authorizer_verdict: Option<String>,

    /// **[chain]** Caller-type taxonomy.
    pub caller_type: CallerType,

    /// **[chain]** Completion instant (epoch seconds). `None` on a
    /// dispatch event.
    pub completed_at_epoch_seconds: Option<u64>,

    /// NOT chained — scrubbed + truncated error string (completion
    /// failure only). Redactable.
    pub error_detail: Option<String>,

    /// **[chain]** `dispatch` | `completion`.
    pub event_kind: EventKind,

    /// **[chain]** UUID (string form) unique per event.
    pub event_id: String,

    /// NOT chained — versioned extension blob (HIPAA/ITAR/GDPR attach
    /// here). Redactable.
    pub extension: Option<Value>,

    /// **[chain]** UUID (string form) correlating dispatch↔completion.
    pub job_id: String,

    /// **[chain]** `parent_trace_id` (string UUID) on sub-agent /
    /// child dispatches. `None` otherwise.
    pub parent_trace_id: Option<String>,

    /// **[chain]** Authenticated OAuth subject / client_id (an
    /// identifier, not free PII). `None` when unauthenticated.
    pub principal: Option<String>,

    /// **[chain]** schema/record format version. Gates `extension`
    /// interpretation.
    pub schema_version: i32,

    /// **[chain]** dispatch instant (epoch seconds).
    pub received_at_epoch_seconds: u64,

    /// NOT chained — GCS URI / Postgres large-object ref to the full
    /// result payload (never inline). Redactable.
    pub result_pointer: Option<String>,

    /// **[chain]** `SHA-256` of the full result (completion only).
    pub result_fingerprint: Option<String>,

    /// **[chain]** resolved sub-tool / handler / backend. Raw (not PII).
    pub resolved_route: Option<String>,

    /// **[chain]** MCP session id.
    pub session_id: Option<String>,

    /// **[chain]** Safety Kernel attestation token id (when attested).
    pub sk_token_id: Option<String>,

    /// **[chain]** SK verdict (`allow` | `deny` + embedded reason).
    pub sk_verdict: Option<String>,

    /// **[chain]** `SHA-256(ip)` fingerprint (raw IP never stored).
    pub source_ip_hash: Option<String>,

    /// **[chain]** `SHA-256(ua)` fingerprint (raw UA never stored).
    pub source_ua_hash: Option<String>,

    /// **[chain]** completion status (`None` on a dispatch event).
    pub status: Option<CompletionStatus>,

    /// **[chain]** keyed-HMAC pseudonym of a subject id. Non-reversible
    /// correlation token; `None` when no subject / scrubbed.
    pub subject_pseudonym: Option<String>,

    /// **[chain]** read_only | mutating | passthrough (Slice 5.B).
    pub tool_class: ToolClass,

    /// **[chain]** raw tool name (tool names are not PII).
    pub tool_name: String,

    /// **[chain]** tool risk tier (from registry).
    pub tool_risk_tier: Option<String>,

    /// **[chain]** UUID (string form); parent/child correlation for
    /// multi-step orchestrate pipelines.
    pub trace_id: String,
}

impl McpAuditRecord {
    /// Project the **[chain]** fields into the deterministic
    /// lex-sorted-JSON byte string that `record_hash` is computed over.
    ///
    /// Implementation: build a [`BTreeMap`] of `field_name ->
    /// serde_json::Value` containing EXACTLY the chain fields plus the
    /// hex-encoded `prev_hash`, then `serde_json::to_vec`. `BTreeMap`
    /// gives sorted keys; `to_vec` gives compact `","`/`":"` separators
    /// — together that is `sort_keys=true, separators=(",",":")`.
    ///
    /// `prev_hash` is included as a hex string (empty string when
    /// `None`, i.e. the genesis record of a `(tool_name, trace_id)`
    /// stream). Enum fields use their stable wire strings so a future
    /// serde rename cannot silently re-key historical records.
    ///
    /// Excluded (per ADR-016): `args_preview`, `result_pointer`,
    /// `error_detail`, `extension`, plus the storage-only `latency_ms`
    /// and `tlog_*` columns.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if serialization fails (not reachable
    /// for the current shape — all values are plain scalars / strings).
    pub fn canonical_bytes(&self, prev_hash: Option<&[u8]>) -> Result<Vec<u8>, serde_json::Error> {
        let mut m: BTreeMap<&str, Value> = BTreeMap::new();

        m.insert(
            "args_fingerprint",
            Value::String(self.args_fingerprint.clone()),
        );
        m.insert(
            "authorizer_verdict",
            opt_str(self.authorizer_verdict.as_deref()),
        );
        m.insert(
            "caller_type",
            Value::String(self.caller_type.as_wire().to_string()),
        );
        m.insert(
            "completed_at_epoch_seconds",
            opt_u64(self.completed_at_epoch_seconds),
        );
        m.insert("event_id", Value::String(self.event_id.clone()));
        m.insert(
            "event_kind",
            Value::String(self.event_kind.as_wire().to_string()),
        );
        m.insert("job_id", Value::String(self.job_id.clone()));
        m.insert("parent_trace_id", opt_str(self.parent_trace_id.as_deref()));
        // prev_hash: hex of the previous row's record_hash, or "" for a
        // stream-genesis record. Hex-encoded so the chain bytes are
        // pure-ASCII and re-derivable by any sorted-JSON serializer.
        m.insert(
            "prev_hash",
            Value::String(prev_hash.map(hex::encode).unwrap_or_default()),
        );
        m.insert("principal", opt_str(self.principal.as_deref()));
        m.insert(
            "received_at_epoch_seconds",
            Value::from(self.received_at_epoch_seconds),
        );
        m.insert("resolved_route", opt_str(self.resolved_route.as_deref()));
        m.insert(
            "result_fingerprint",
            opt_str(self.result_fingerprint.as_deref()),
        );
        m.insert("schema_version", Value::from(self.schema_version));
        m.insert("session_id", opt_str(self.session_id.as_deref()));
        m.insert("sk_token_id", opt_str(self.sk_token_id.as_deref()));
        m.insert("sk_verdict", opt_str(self.sk_verdict.as_deref()));
        m.insert("source_ip_hash", opt_str(self.source_ip_hash.as_deref()));
        m.insert("source_ua_hash", opt_str(self.source_ua_hash.as_deref()));
        m.insert(
            "status",
            self.status
                .map(|s| Value::String(s.as_wire().to_string()))
                .unwrap_or(Value::Null),
        );
        m.insert(
            "subject_pseudonym",
            opt_str(self.subject_pseudonym.as_deref()),
        );
        m.insert(
            "tool_class",
            Value::String(self.tool_class.as_wire().to_string()),
        );
        m.insert("tool_name", Value::String(self.tool_name.clone()));
        m.insert("tool_risk_tier", opt_str(self.tool_risk_tier.as_deref()));
        m.insert("trace_id", Value::String(self.trace_id.clone()));

        serde_json::to_vec(&m)
    }

    /// `record_hash = SHA-256(canonical_bytes(record, prev_hash))`.
    /// 32 raw bytes (the `mcp_audit_log.record_hash BYTEA` value).
    ///
    /// # Errors
    ///
    /// Propagates [`Self::canonical_bytes`] serialization failure.
    pub fn record_hash(&self, prev_hash: Option<&[u8]>) -> Result<[u8; 32], serde_json::Error> {
        let bytes = self.canonical_bytes(prev_hash)?;
        let mut h = Sha256::new();
        h.update(&bytes);
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }
}

/// `Option<&str>` → JSON string or `null`. Keeps every absent optional
/// chain field as JSON `null` (a stable, distinguishable token) rather
/// than dropping the key — so the presence/absence of a value is itself
/// committed to the chain and an attacker cannot promote `null` to a
/// value (or vice-versa) without changing the hash.
fn opt_str(v: Option<&str>) -> Value {
    v.map_or(Value::Null, |s| Value::String(s.to_string()))
}

/// `Option<u64>` → JSON number or `null`.
fn opt_u64(v: Option<u64>) -> Value {
    v.map_or(Value::Null, Value::from)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A minimal dispatch record for chain tests.
    fn dispatch_record(event_id: &str, trace_id: &str) -> McpAuditRecord {
        McpAuditRecord {
            args_fingerprint: "a".repeat(64),
            args_preview: Some(serde_json::json!({"k": "[redacted]"})),
            authorizer_verdict: Some("allow".to_string()),
            caller_type: CallerType::HumanViaClaudeAi,
            completed_at_epoch_seconds: None,
            error_detail: None,
            event_kind: EventKind::Dispatch,
            event_id: event_id.to_string(),
            extension: None,
            job_id: "job-1".to_string(),
            parent_trace_id: None,
            principal: Some("client-xyz".to_string()),
            schema_version: 1,
            received_at_epoch_seconds: 1_716_400_000,
            result_pointer: None,
            result_fingerprint: None,
            resolved_route: Some("orchestrate_tool".to_string()),
            session_id: Some("sess-1".to_string()),
            sk_token_id: None,
            sk_verdict: None,
            source_ip_hash: Some("b".repeat(64)),
            source_ua_hash: Some("c".repeat(64)),
            status: None,
            subject_pseudonym: Some("d".repeat(64)),
            tool_class: ToolClass::Mutating,
            tool_name: "biotech_protein_fold".to_string(),
            tool_risk_tier: Some("A2".to_string()),
            trace_id: trace_id.to_string(),
        }
    }

    #[test]
    fn canonical_bytes_are_compact_lex_sorted_json() {
        let r = dispatch_record("ev-1", "tr-1");
        let bytes = r.canonical_bytes(None).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        // Compact separators — no ", " or ": ".
        assert!(!s.contains(", "));
        assert!(!s.contains(": "));
        // Lex-sorted keys: args_fingerprint must precede authorizer_verdict
        // must precede caller_type.
        let i_args = s.find("\"args_fingerprint\"").unwrap();
        let i_auth = s.find("\"authorizer_verdict\"").unwrap();
        let i_caller = s.find("\"caller_type\"").unwrap();
        assert!(i_args < i_auth && i_auth < i_caller);
        // Excluded fields must NOT appear in the chain bytes.
        assert!(!s.contains("args_preview"));
        assert!(!s.contains("result_pointer"));
        assert!(!s.contains("error_detail"));
        assert!(!s.contains("extension"));
    }

    #[test]
    fn excluded_fields_do_not_change_record_hash() {
        // Two records identical on chain fields but different on the
        // redactable preview/pointer/error/extension must hash the same.
        let mut a = dispatch_record("ev-x", "tr-x");
        let mut b = a.clone();
        a.args_preview = Some(serde_json::json!({"preview": "one"}));
        a.error_detail = Some("boom".to_string());
        a.result_pointer = Some("gs://bucket/one".to_string());
        a.extension = Some(serde_json::json!({"hipaa": {"phi_category": "x"}}));
        b.args_preview = None;
        b.error_detail = None;
        b.result_pointer = None;
        b.extension = None;
        assert_eq!(
            a.record_hash(None).unwrap(),
            b.record_hash(None).unwrap(),
            "redactable fields must not affect the chain hash"
        );
    }

    #[test]
    fn chain_field_change_changes_record_hash() {
        let a = dispatch_record("ev-1", "tr-1");
        let mut b = a.clone();
        b.tool_name = "biotech_molecule_design".to_string();
        assert_ne!(a.record_hash(None).unwrap(), b.record_hash(None).unwrap());
    }

    #[test]
    fn prev_hash_links_the_chain() {
        // record N's prev_hash == record N-1's record_hash. Recomputing
        // record N with the WRONG prev (tamper / reorder) yields a
        // different hash — that's the local intra-stream tamper signal.
        let r0 = dispatch_record("ev-0", "tr-1");
        let h0 = r0.record_hash(None).unwrap();
        let r1 = dispatch_record("ev-1", "tr-1");
        let h1_linked = r1.record_hash(Some(&h0)).unwrap();
        // Re-derive r1 against a DIFFERENT prev (as if r0 were deleted /
        // reordered): the hash must differ → reorder is detectable.
        let bogus_prev = [0xFFu8; 32];
        let h1_bogus = r1.record_hash(Some(&bogus_prev)).unwrap();
        assert_ne!(h1_linked, h1_bogus);
        // And the genesis (no prev) differs from a linked one too.
        let h1_genesis = r1.record_hash(None).unwrap();
        assert_ne!(h1_linked, h1_genesis);
    }

    #[test]
    fn null_vs_value_changes_hash() {
        // An attacker cannot promote a null optional to a value (or
        // vice-versa) without changing the chain hash.
        let mut a = dispatch_record("ev-1", "tr-1");
        a.sk_token_id = None;
        let mut b = a.clone();
        b.sk_token_id = Some("tok-1".to_string());
        assert_ne!(a.record_hash(None).unwrap(), b.record_hash(None).unwrap());
    }

    #[test]
    fn record_round_trips_through_json() {
        let r = dispatch_record("ev-1", "tr-1");
        let j = serde_json::to_string(&r).unwrap();
        let back: McpAuditRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn tool_class_failure_policy() {
        assert!(ToolClass::Mutating.fails_closed_on_pg_write_failure());
        assert!(!ToolClass::ReadOnly.fails_closed_on_pg_write_failure());
        assert!(!ToolClass::Passthrough.fails_closed_on_pg_write_failure());
    }

    #[test]
    fn wire_strings_match_ddl_check_constraints() {
        assert_eq!(EventKind::Dispatch.as_wire(), "dispatch");
        assert_eq!(EventKind::Completion.as_wire(), "completion");
        assert_eq!(
            CallerType::HumanViaClaudeAi.as_wire(),
            "human_via_claude_ai"
        );
        assert_eq!(CallerType::SubAgent.as_wire(), "sub_agent");
        assert_eq!(ToolClass::ReadOnly.as_wire(), "read_only");
        assert_eq!(CompletionStatus::Timeout.as_wire(), "timeout");
    }
}
