//! HTTP client for the Safety Kernel.
//!
//! Wires the breaker (`circuit_breaker.rs`), the pinned-key verifier
//! (`token.rs`), and the reqwest HTTP client into a single
//! `SafetyKernelClient` surface. Matches the `OpenAPI` contract at
//! `contracts/openapi/safety_kernel.yaml`.

use std::sync::Mutex;
use std::time::Duration;

use qorch_domain::safety::Clock;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use super::circuit_breaker::CircuitBreaker;
use super::token::PinnedKeyVerifier;
//   Step 2 — KernelClientError replaces the pre-split
// KernelError; the unavailable / denied signal now lives inside
// KernelDecisionError, wrapped by KernelClientError::Decision.
use super::types::{
    AuditEntry, AuthorizeRequest, AuthorizeResponse, HealthResponse, KernelClientError,
    KernelDecision, KernelDecisionError, PublicKeyResponse,
};

const API_KEY_HEADER: &str = "x-api-key";
const TRACEPARENT_HEADER: &str = "traceparent";

/// Public Safety Kernel client.
///
/// Construction is two-step (`SafetyKernelClient::builder()`) because
/// the live reqwest client needs an API key and base URL that come
/// from the binding layer (env, secret backend), not from the adapter
/// crate directly — preserving the forbidden-import discipline.
pub struct SafetyKernelClient {
    inner: reqwest::Client,
    base_url: String,
    api_key: String,
    breaker: CircuitBreaker,
    verifier: PinnedKeyVerifier,
    clock: Box<dyn Clock>,
    /// Local audit ring — every `authorize()` call appends one entry.
    /// `audit_trail()` returns a snapshot. Bounded only by caller
    /// reset cadence; callers that want a hard cap should drain the
    /// trail periodically.
    audit: Mutex<Vec<AuditEntry>>,
}

impl SafetyKernelClient {
    /// Construct a client from already-loaded materials. Production
    /// callers go through `builder()` so the breaker config and clock
    /// are explicit; this entry point exists for tests.
    #[must_use]
    pub fn new(
        inner: reqwest::Client,
        base_url: String,
        api_key: String,
        breaker: CircuitBreaker,
        verifier: PinnedKeyVerifier,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            inner,
            base_url,
            api_key,
            breaker,
            verifier,
            clock,
            audit: Mutex::new(Vec::new()),
        }
    }

    /// Audit fingerprint of the pinned key — useful for boot logs and
    /// the `wiring-checklist.md` sanity check.
    #[must_use]
    pub fn pinned_key_fingerprint(&self) -> &str {
        self.verifier.fingerprint()
    }

    /// Snapshot of the local audit trail.
    ///
    /// **Local accessor — does NOT issue an HTTP request.** Mirrors the
    /// Python client's `audit_trail()` surface per ADR §7 drift finding
    /// (C). Each entry is appended by `authorize()` regardless of
    /// outcome (ALLOW, DENY, UNAVAILABLE, VERIFICATION_FAILED) so the
    /// caller can produce a complete post-hoc transparency log.
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned (a previous holder
    /// panicked while holding it). The audit log is single-purpose;
    /// this is treated as an invariant, not a recoverable condition.
    #[must_use]
    pub fn audit_trail(&self) -> Vec<AuditEntry> {
        self.audit
            .lock()
            .expect("audit mutex poisoned")
            .clone()
    }

    /// Append an entry to the local audit trail. Internal helper used
    /// from `authorize()`; not exposed publicly so the audit shape
    /// remains the adapter's invariant.
    fn record_audit(&self, entry: AuditEntry) {
        if let Ok(mut g) = self.audit.lock() {
            g.push(entry);
        }
    }

    /// Call `POST /kernel/v1/authorize`.
    ///
    /// FAIL-CLOSED contract: any of {circuit breaker `Open`, transport
    /// error, response not signed by the pinned key, expired claim,
    /// malformed body} returns `Err(KernelClientError)`. Callers MUST NOT
    /// treat `Err` as ALLOW.
    ///
    /// **traceparent (AC8)**: when `request.traceparent` is `Some`, the
    /// value is emitted as the W3C `traceparent` HTTP header — never
    /// embedded in the JSON body. `boundary_check.rs` (Step 6) asserts
    /// this structurally by grepping the serialized body.
    pub async fn authorize(
        &self,
        request: &AuthorizeRequest,
    ) -> Result<KernelDecision, KernelClientError> {
        // Circuit-breaker gate first — short-circuit Open state.
        if let Err(e) = self.breaker.before_call() {
            self.record_audit(AuditEntry {
                outcome: "UNAVAILABLE".to_string(),
                recorded_at_epoch_seconds: self.clock.now(),
                run_id: request.run_id.clone(),
                subject: request.subject.clone(),
                traceparent: request.traceparent.clone(),
            });
            return Err(e);
        }

        let url = format!(
            "{}/kernel/v1/authorize",
            self.base_url.trim_end_matches('/')
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(API_KEY_HEADER),
            HeaderValue::from_str(&self.api_key)
                .map_err(|e| KernelClientError::Transport(format!("bad api key header: {e}")))?,
        );
        if let Some(tp) = &request.traceparent {
            if let Ok(v) = HeaderValue::from_str(tp) {
                headers.insert(HeaderName::from_static(TRACEPARENT_HEADER), v);
            }
        }

        let resp_result = self
            .inner
            .post(&url)
            .headers(headers)
            .timeout(Duration::from_secs_f64(5.0))
            .json(request)
            .send()
            .await;

        let resp = match resp_result {
            Ok(r) => r,
            Err(e) => {
                self.breaker.record_failure();
                self.record_audit(AuditEntry {
                    outcome: "UNAVAILABLE".to_string(),
                    recorded_at_epoch_seconds: self.clock.now(),
                    run_id: request.run_id.clone(),
                    subject: request.subject.clone(),
                    traceparent: request.traceparent.clone(),
                });
                return Err(KernelClientError::Decision(KernelDecisionError::Unavailable {
                    reason: format!("kernel call failed: {e}"),
                }));
            }
        };

        let status = resp.status();
        if status.is_server_error() {
            self.breaker.record_failure();
            self.record_audit(AuditEntry {
                outcome: "UNAVAILABLE".to_string(),
                recorded_at_epoch_seconds: self.clock.now(),
                run_id: request.run_id.clone(),
                subject: request.subject.clone(),
                traceparent: request.traceparent.clone(),
            });
            return Err(KernelClientError::Decision(KernelDecisionError::Unavailable {
                reason: format!("kernel returned {status}"),
            }));
        }
        if status == reqwest::StatusCode::FORBIDDEN {
            // Authoritative DENY from the kernel — distinct from
            // "kernel unavailable". Bytes carry the reason in JSON.
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "(no body)".to_string());
            self.breaker.record_success(); // Kernel reachable — not a breaker event.
            self.record_audit(AuditEntry {
                outcome: "DENY".to_string(),
                recorded_at_epoch_seconds: self.clock.now(),
                run_id: request.run_id.clone(),
                subject: request.subject.clone(),
                traceparent: request.traceparent.clone(),
            });
            return Ok(KernelDecision::Deny { reason: body });
        }
        if !status.is_success() {
            // 4xx other than 403 — contract drift, not unavailability.
            let body = resp.text().await.unwrap_or_default();
            return Err(KernelClientError::Transport(format!(
                "unexpected status {status}: {body}"
            )));
        }

        let body: AuthorizeResponse = resp.json().await.map_err(|e| {
            self.breaker.record_failure();
            KernelClientError::Decode(format!("response decode failed: {e}"))
        })?;

        // Re-verify the token locally against the pinned key. Never
        // trust the `claims` field returned by the kernel; always
        // re-derive from the signed token.
        let now = self.clock.now();
        let verified = match self.verifier.verify(&body.token, now) {
            Ok(v) => v,
            Err(e) => {
                self.record_audit(AuditEntry {
                    outcome: "VERIFICATION_FAILED".to_string(),
                    recorded_at_epoch_seconds: self.clock.now(),
                    run_id: request.run_id.clone(),
                    subject: request.subject.clone(),
                    traceparent: request.traceparent.clone(),
                });
                return Err(KernelClientError::Verification(e));
            }
        };

        self.breaker.record_success();
        self.record_audit(AuditEntry {
            outcome: "ALLOW".to_string(),
            recorded_at_epoch_seconds: self.clock.now(),
            run_id: request.run_id.clone(),
            subject: request.subject.clone(),
            traceparent: request.traceparent.clone(),
        });
        Ok(KernelDecision::Allow {
            token: body.token,
            claims: verified,
        })
    }

    /// Call `GET /kernel/v1/health`. Public endpoint (no auth required
    /// per `auth.rs::is_public_path`), but the SDK still forwards the
    /// configured api key + optional traceparent for trace continuity.
    ///
    /// `health()` is a thin liveness probe — it does NOT participate
    /// in the circuit-breaker state and never enters the audit trail.
    pub async fn health(
        &self,
        traceparent: Option<&str>,
    ) -> Result<HealthResponse, KernelClientError> {
        let url = format!("{}/kernel/v1/health", self.base_url.trim_end_matches('/'));
        let headers = self.build_get_headers(traceparent)?;
        let resp = self
            .inner
            .get(&url)
            .headers(headers)
            .timeout(Duration::from_secs_f64(5.0))
            .send()
            .await
            .map_err(|e| {
                KernelClientError::Decision(KernelDecisionError::Unavailable {
                    reason: format!("kernel health call failed: {e}"),
                })
            })?;
        let status = resp.status();
        if !status.is_success() {
            return Err(KernelClientError::Decision(KernelDecisionError::Unavailable {
                reason: format!("kernel health returned {status}"),
            }));
        }
        resp.json::<HealthResponse>()
            .await
            .map_err(|e| KernelClientError::Decode(format!("health response decode failed: {e}")))
    }

    /// Call `GET /kernel/v1/public_key`. Public endpoint. The returned
    /// `public_key_b64` is the kernel's CURRENT signing key — the SDK
    /// caller compares it against the **pinned** verifier's fingerprint
    /// (via `pinned_key_fingerprint()`) and aborts the boot sequence if
    /// they diverge ( AC9). This adapter intentionally does NOT
    /// perform that comparison; the boot/wiring layer owns the abort
    /// policy.
    pub async fn public_key(
        &self,
        traceparent: Option<&str>,
    ) -> Result<PublicKeyResponse, KernelClientError> {
        let url = format!(
            "{}/kernel/v1/public_key",
            self.base_url.trim_end_matches('/')
        );
        let headers = self.build_get_headers(traceparent)?;
        let resp = self
            .inner
            .get(&url)
            .headers(headers)
            .timeout(Duration::from_secs_f64(5.0))
            .send()
            .await
            .map_err(|e| {
                KernelClientError::Decision(KernelDecisionError::Unavailable {
                    reason: format!("kernel public_key call failed: {e}"),
                })
            })?;
        let status = resp.status();
        if !status.is_success() {
            return Err(KernelClientError::Decision(KernelDecisionError::Unavailable {
                reason: format!("kernel public_key returned {status}"),
            }));
        }
        resp.json::<PublicKeyResponse>().await.map_err(|e| {
            KernelClientError::Decode(format!("public_key response decode failed: {e}"))
        })
    }

    /// Shared header builder for the GET endpoints. Always emits
    /// `x-api-key` (per ADR §5 rule 6 — never Authorization Bearer)
    /// and `traceparent` when supplied.
    fn build_get_headers(
        &self,
        traceparent: Option<&str>,
    ) -> Result<HeaderMap, KernelClientError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(API_KEY_HEADER),
            HeaderValue::from_str(&self.api_key)
                .map_err(|e| KernelClientError::Transport(format!("bad api key header: {e}")))?,
        );
        if let Some(tp) = traceparent {
            if let Ok(v) = HeaderValue::from_str(tp) {
                headers.insert(HeaderName::from_static(TRACEPARENT_HEADER), v);
            }
        }
        Ok(headers)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use qorch_domain::safety::CircuitConfig;

    struct FixedClock(f64);
    impl Clock for FixedClock {
        fn now(&self) -> f64 {
            self.0
        }
    }

    fn build_test_client() -> SafetyKernelClient {
        let inner = reqwest::Client::new();
        let breaker = CircuitBreaker::new(CircuitConfig::default(), Box::new(FixedClock(0.0)));
        let signing = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        let verifier = PinnedKeyVerifier::from_pubkey_bytes(pubkey).expect("valid pubkey");
        SafetyKernelClient::new(
            inner,
            "http://127.0.0.1:9000".to_string(),
            "dev-key".to_string(),
            breaker,
            verifier,
            Box::new(FixedClock(0.0)),
        )
    }

    #[test]
    fn client_exposes_pinned_key_fingerprint() {
        // Sanity check that the fingerprint surface is present at
        // construction time — used by the boot-log smoke test in the
        // wiring checklist ( docs/integration/wiring-checklist.md).
        let signing = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        let expected_fp =
            PinnedKeyVerifier::from_pubkey_bytes(pubkey).unwrap().fingerprint().to_string();
        let client = build_test_client();
        assert_eq!(client.pinned_key_fingerprint(), expected_fp);
    }

    #[test]
    fn audit_trail_is_empty_on_fresh_client() {
        // ADR §7(C) — audit_trail() is a local accessor; on a freshly
        // constructed client it MUST start empty. Population happens
        // inside authorize() per the ALLOW/DENY/UNAVAILABLE/
        // VERIFICATION_FAILED branches.
        let client = build_test_client();
        assert!(client.audit_trail().is_empty());
    }
}
