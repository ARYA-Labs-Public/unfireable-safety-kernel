//! The ONE privileged capability the Reaper holds: stop / start a compute
//! instance. Injected behind a trait so tests use a mock and real runs target
//! a SCRATCH instance — never the live agent VM.
//!
//! Live arming (this file): the real [`GcpComputeExecutor`] wires the live
//! cloud `compute.instances.stop` / `.start` calls, but ONLY behind a stack of
//! hard safety guards evaluated in a fixed order:
//!
//! 1. **SELF-PROTECTION DENYLIST (unconditional, FIRST)** — the executor
//!    refuses, no matter the config or armed state, to touch (a) the box the
//!    Reaper process itself runs on (self-identified from the cloud metadata
//!    server at startup, cached), and (b) any operator-configured protected
//!    instance ([`ProtectedCoord`]). This guard runs BEFORE the armed /
//!    allowlist checks and NO env/config/armed combination can override it, so
//!    a misconfiguration can never stop the host the Reaper depends on.
//! 2. **ARMED** — disarmed (`REAPER_ARMED != true`) is the default posture and
//!    makes NO network call.
//! 3. **SCRATCH ALLOWLIST** — even armed, the executor acts ONLY on the exact
//!    configured scratch coordinate (project + zone + instance).
//!
//! Only after all three pass is a live OAuth token minted from the cloud
//! metadata server and a POST issued to the compute API. The whole live path
//! sits behind the [`GceInstanceOps`] seam so the guard logic is unit-testable
//! WITHOUT a live call (re-derive behaviour in-process).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use qorch_domain::safety::InstanceTarget;
use serde::Deserialize;
use thiserror::Error;

// ============================================================================
// Self-protection denylist — coordinates the Reaper must NEVER stop/start.
// ============================================================================

/// A protected `(project, instance)` coordinate the executor refuses to act
/// on. Matching is on project + instance only (zone is ignored) so an attacker
/// cannot evade the guard by supplying a different zone for the same instance.
///
/// The denylist is populated from two sources, both config-driven (nothing is
/// hardcoded to a specific host): the Reaper's OWN host, self-identified from
/// the cloud metadata server at startup (see [`fetch_self_identity`]), and any
/// operator-configured protected instances (`REAPER_PROTECTED_INSTANCES`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedCoord {
    /// Cloud project id.
    pub project: String,
    /// Instance name.
    pub instance: String,
}

impl ProtectedCoord {
    /// Build a protected coordinate from a project + instance name.
    #[must_use]
    pub fn new(project: impl Into<String>, instance: impl Into<String>) -> Self {
        Self {
            project: project.into(),
            instance: instance.into(),
        }
    }

    /// True if `target` names this protected instance (project + instance
    /// match; zone ignored).
    #[must_use]
    pub fn matches(&self, target: &InstanceTarget) -> bool {
        self.project == target.project && self.instance == target.instance
    }
}

// ============================================================================
// Live cloud endpoints — how the token + URL are built.
// ============================================================================

/// Cloud metadata-server token endpoint. A `GET` with `Metadata-Flavor:
/// Google` returns `{access_token, expires_in, token_type}` for the instance's
/// default service account — the OAuth bearer used for the compute call.
const METADATA_TOKEN_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

/// Cloud metadata-server instance-name endpoint (plain text). Used at startup
/// to self-identify the host the Reaper runs on for the self-protection guard.
const METADATA_INSTANCE_NAME_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/name";

/// Cloud metadata-server project-id endpoint (plain text). Paired with the
/// instance name to form the self-protection coordinate.
const METADATA_PROJECT_ID_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/project/project-id";

/// Root of the Compute Engine v1 REST API.
const COMPUTE_API_ROOT: &str = "https://compute.googleapis.com/compute/v1";

/// Build the compute `stop` / `start` endpoint for `target`. Pure — unit-tested
/// directly so the URL shape is verifiable without a live call.
///
/// e.g. `.../projects/{project}/zones/{zone}/instances/{instance}/stop`.
#[must_use]
fn instance_op_url(target: &InstanceTarget, op: &str) -> String {
    format!(
        "{COMPUTE_API_ROOT}/projects/{}/zones/{}/instances/{}/{op}",
        target.project, target.zone, target.instance
    )
}

/// Self-identify the host the Reaper runs on by querying the cloud metadata
/// server for the instance name + project id. Returns `None` (never an error)
/// when the metadata server is unreachable — e.g. the Reaper is running off a
/// cloud instance — so self-protection is simply absent there and the
/// operator-configured denylist still applies. Callers should log a loud
/// warning on `None` because the self-protection guard is a live-arming
/// prerequisite.
#[must_use]
pub async fn fetch_self_identity() -> Option<ProtectedCoord> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;
    let fetch = |url: &'static str| {
        let http = http.clone();
        async move {
            let resp = http
                .get(url)
                .header("Metadata-Flavor", "Google")
                .send()
                .await
                .ok()?;
            if !resp.status().is_success() {
                return None;
            }
            let body = resp.text().await.ok()?;
            let trimmed = body.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }
    };
    let instance = fetch(METADATA_INSTANCE_NAME_URL).await?;
    let project = fetch(METADATA_PROJECT_ID_URL).await?;
    Some(ProtectedCoord::new(project, instance))
}

/// Outcome of a stop / start call — mirrors the compute API op shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopOutcome {
    /// The instance the op acted on.
    pub instance: String,
    /// The compute operation id (mock returns a synthetic one).
    pub op_id: String,
    /// The instance state observed BEFORE the op (e.g. `"RUNNING"`). The live
    /// path does not read prior state (a coarse P1 accept-the-op flow), so it
    /// reports `"UNKNOWN"`.
    pub prev_state: String,
}

/// Errors an executor can surface. All are hard failures — the Reaper never
/// treats an executor error as "assume the kill happened".
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExecutorError {
    /// The asked target is on the self-protection denylist (the Reaper's own
    /// host or a configured protected instance). Returned BEFORE any
    /// armed/allowlist/network step and no config can override it. This is the
    /// primary kill-switch safety guard.
    #[error("refused: {instance} in {project} is a protected host (never stop/start the box we run on or a configured protected instance)")]
    ForbiddenTarget {
        /// The protected project.
        project: String,
        /// The protected instance name.
        instance: String,
    },
    /// The executor is not armed (`REAPER_ARMED != true`) — the DEFAULT posture.
    /// No network call is made; live arming is operator-gated.
    #[error("executor disarmed: REAPER_ARMED is not true, live arming is operator-gated; op={op}")]
    LiveArmingGated {
        /// `"stop"` or `"start"`.
        op: &'static str,
    },
    /// Armed, but no scratch target configured — refuse rather than guess.
    #[error("executor armed but no scratch target configured; refusing to act")]
    NoScratchTarget,
    /// Armed, but asked to act on an instance other than the configured
    /// scratch target. The Reaper NEVER touches an instance outside its
    /// single configured scratch coordinate in this phase.
    #[error("refused: target {asked} is not the configured scratch instance {scratch}")]
    RefusedNonScratchTarget {
        /// The instance the caller asked to act on.
        asked: String,
        /// The single scratch instance this executor is allowed to touch.
        scratch: String,
    },
    /// Live compute/metadata backend failure (token fetch, POST, non-2xx).
    #[error("compute backend error: {0}")]
    Backend(String),
}

/// The injectable privileged capability. `stop` executes a revoke; `start`
/// executes an operator-signed restore.
#[async_trait]
pub trait ComputeExecutor: Send + Sync {
    /// Stop `target`. Called ONLY after a kill token fully verifies (or on a
    /// fail-closed liveness timeout against the configured target).
    async fn stop(&self, target: &InstanceTarget) -> Result<StopOutcome, ExecutorError>;
    /// Start `target`. Called ONLY after an operator-signed restore verifies.
    async fn start(&self, target: &InstanceTarget) -> Result<StopOutcome, ExecutorError>;
}

// ============================================================================
// MockComputeExecutor — records calls, for tests. Never touches the cloud.
// ============================================================================

/// Records every `stop`/`start` call so adversarial fixtures can assert
/// exactly which calls happened (re-derive behaviour, don't grep logs).
#[derive(Debug, Default)]
pub struct MockComputeExecutor {
    /// Targets passed to `stop`, in call order.
    stop_calls: Mutex<Vec<InstanceTarget>>,
    /// Targets passed to `start`, in call order.
    start_calls: Mutex<Vec<InstanceTarget>>,
}

impl MockComputeExecutor {
    /// A fresh mock with no recorded calls.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of `stop` calls recorded.
    #[must_use]
    pub fn stop_count(&self) -> usize {
        self.stop_calls.lock().expect("stop_calls lock").len()
    }

    /// Number of `start` calls recorded.
    #[must_use]
    pub fn start_count(&self) -> usize {
        self.start_calls.lock().expect("start_calls lock").len()
    }

    /// Snapshot of the targets passed to `stop`.
    #[must_use]
    pub fn stop_targets(&self) -> Vec<InstanceTarget> {
        self.stop_calls.lock().expect("stop_calls lock").clone()
    }

    /// Snapshot of the targets passed to `start`.
    #[must_use]
    pub fn start_targets(&self) -> Vec<InstanceTarget> {
        self.start_calls.lock().expect("start_calls lock").clone()
    }
}

#[async_trait]
impl ComputeExecutor for MockComputeExecutor {
    async fn stop(&self, target: &InstanceTarget) -> Result<StopOutcome, ExecutorError> {
        self.stop_calls
            .lock()
            .expect("stop_calls lock")
            .push(target.clone());
        Ok(StopOutcome {
            instance: target.instance.clone(),
            op_id: format!("mock-stop-{}", target.instance),
            prev_state: "RUNNING".to_string(),
        })
    }

    async fn start(&self, target: &InstanceTarget) -> Result<StopOutcome, ExecutorError> {
        self.start_calls
            .lock()
            .expect("start_calls lock")
            .push(target.clone());
        Ok(StopOutcome {
            instance: target.instance.clone(),
            op_id: format!("mock-start-{}", target.instance),
            prev_state: "TERMINATED".to_string(),
        })
    }
}

// ============================================================================
// GceInstanceOps — the live-network seam (token fetch + POST). Injectable so
// the guard logic above it is testable without ever calling the cloud.
// ============================================================================

/// The live compute-op backend: mint a token, POST the op. Split out behind a
/// trait so the [`GcpComputeExecutor`] guards can be exercised in-process with a
/// recording double, and the real path only runs against a live metadata server
/// + compute API.
#[async_trait]
pub trait GceInstanceOps: Send + Sync + std::fmt::Debug {
    /// Issue `op` (`"stop"` / `"start"`) against `target`. Implementations may
    /// assume the caller already cleared every safety guard.
    async fn instance_op(
        &self,
        target: &InstanceTarget,
        op: &'static str,
    ) -> Result<StopOutcome, ExecutorError>;
}

/// Metadata-token response subset — only the bearer is needed.
#[derive(Debug, Deserialize)]
struct MetadataToken {
    /// The OAuth access token for the instance default service account.
    access_token: String,
}

/// Compute zonal-operation response subset — the op `name` becomes the op id.
#[derive(Debug, Deserialize)]
struct ComputeOpResponse {
    /// The zonal operation name, e.g. `operation-1699-...`.
    name: Option<String>,
}

/// The real live backend: OAuth via the cloud metadata server, POST to the
/// compute API. Any 2xx is treated as "op accepted" (P1 — the zonal operation
/// is returned but not polled to completion here).
#[derive(Debug, Clone)]
pub struct MetadataGceOps {
    /// Shared reqwest client (crate style — timeout-bounded).
    http: reqwest::Client,
}

impl MetadataGceOps {
    /// Build the live backend with a timeout-bounded client.
    #[must_use]
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { http }
    }

    /// Mint a bearer token from the cloud metadata server:
    /// `GET {METADATA_TOKEN_URL}` with `Metadata-Flavor: Google`.
    async fn fetch_token(&self) -> Result<String, ExecutorError> {
        let resp = self
            .http
            .get(METADATA_TOKEN_URL)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|e| ExecutorError::Backend(format!("metadata token fetch: {e}")))?;
        if !resp.status().is_success() {
            return Err(ExecutorError::Backend(format!(
                "metadata token status {}",
                resp.status().as_u16()
            )));
        }
        let tok: MetadataToken = resp
            .json()
            .await
            .map_err(|e| ExecutorError::Backend(format!("metadata token decode: {e}")))?;
        Ok(tok.access_token)
    }
}

impl Default for MetadataGceOps {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GceInstanceOps for MetadataGceOps {
    async fn instance_op(
        &self,
        target: &InstanceTarget,
        op: &'static str,
    ) -> Result<StopOutcome, ExecutorError> {
        let token = self.fetch_token().await?;
        let url = instance_op_url(target, op);
        let resp = self
            .http
            .post(&url)
            .header("authorization", format!("Bearer {token}"))
            // The stop/start ops carry no request body.
            .header("content-length", "0")
            .send()
            .await
            .map_err(|e| ExecutorError::Backend(format!("compute {op} POST: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ExecutorError::Backend(format!(
                "compute {op} returned {}: {}",
                status.as_u16(),
                body.chars().take(200).collect::<String>()
            )));
        }
        // Accept the 2xx zonal operation. The op `name` is the durable id.
        let op_id = resp
            .json::<ComputeOpResponse>()
            .await
            .ok()
            .and_then(|o| o.name)
            .unwrap_or_else(|| format!("{op}-accepted"));
        Ok(StopOutcome {
            instance: target.instance.clone(),
            op_id,
            prev_state: "UNKNOWN".to_string(),
        })
    }
}

// ============================================================================
// GcpComputeExecutor — real path, guarded:
//   self/protected denylist -> armed -> scratch -> act.
// ============================================================================

/// The real executor. It is INERT by default (`disarmed()`), and even when
/// armed it acts ONLY on its single configured scratch coordinate — never the
/// live agent VM, and NEVER a self-protected host (guard order:
/// self/protected denylist -> armed -> scratch-allowlist -> act).
#[derive(Debug, Clone)]
pub struct GcpComputeExecutor {
    /// Whether the executor is armed. Default false. Only the operator flips it.
    armed: bool,
    /// The single disposable instance this executor may touch when armed.
    /// `None` = refuse everything even when armed.
    scratch: Option<InstanceTarget>,
    /// The Reaper's OWN host, self-identified from the metadata server at
    /// startup. `None` when self-identification was unavailable (off-cloud).
    self_identity: Option<ProtectedCoord>,
    /// Operator-configured protected instances (`REAPER_PROTECTED_INSTANCES`).
    protected: Vec<ProtectedCoord>,
    /// The live-network backend (token + POST). Injectable for tests so the
    /// guards can be verified without a live cloud call.
    ops: Arc<dyn GceInstanceOps>,
}

impl GcpComputeExecutor {
    /// A disarmed executor — the default, safe construction. Every call errors
    /// with [`ExecutorError::LiveArmingGated`] and makes no network call.
    #[must_use]
    pub fn disarmed() -> Self {
        Self {
            armed: false,
            scratch: None,
            self_identity: None,
            protected: Vec::new(),
            ops: Arc::new(MetadataGceOps::new()),
        }
    }

    /// Construct with an explicit arm flag + scratch target, wired to the live
    /// metadata/compute backend. Even armed, this only ever touches `scratch`,
    /// and never a self-protected host.
    ///
    /// Callers wiring this from config MUST pass the SCRATCH instance, never
    /// the live agent VM, and should attach the self-protection denylist via
    /// [`GcpComputeExecutor::with_self_identity`] +
    /// [`GcpComputeExecutor::with_protected`].
    #[must_use]
    pub fn new(armed: bool, scratch: Option<InstanceTarget>) -> Self {
        Self {
            armed,
            scratch,
            self_identity: None,
            protected: Vec::new(),
            ops: Arc::new(MetadataGceOps::new()),
        }
    }

    /// Construct with an injected [`GceInstanceOps`] backend. Used by tests to
    /// assert the guarded code path reaches (or refuses to reach) the live op
    /// without issuing a real cloud call.
    #[must_use]
    pub fn with_ops(
        armed: bool,
        scratch: Option<InstanceTarget>,
        ops: Arc<dyn GceInstanceOps>,
    ) -> Self {
        Self {
            armed,
            scratch,
            self_identity: None,
            protected: Vec::new(),
            ops,
        }
    }

    /// Attach the Reaper's self-identified host to the self-protection denylist.
    /// GUARD 0 refuses this coordinate unconditionally.
    #[must_use]
    pub fn with_self_identity(mut self, self_identity: Option<ProtectedCoord>) -> Self {
        self.self_identity = self_identity;
        self
    }

    /// Attach the operator-configured protected instances to the denylist.
    /// GUARD 0 refuses every one of these unconditionally.
    #[must_use]
    pub fn with_protected(mut self, protected: Vec<ProtectedCoord>) -> Self {
        self.protected = protected;
        self
    }

    /// True if `asked` is on the self-protection denylist — the Reaper's own
    /// host or any configured protected instance.
    fn is_protected(&self, asked: &InstanceTarget) -> bool {
        if let Some(me) = self.self_identity.as_ref() {
            if me.matches(asked) {
                return true;
            }
        }
        self.protected.iter().any(|p| p.matches(asked))
    }

    /// Shared guard for both stop + start. Guard ORDER is load-bearing:
    /// `self/protected denylist -> armed -> scratch-allowlist`. Returns the
    /// exact scratch coordinate to act on, or the reason to refuse. Makes NO
    /// network call.
    fn guard<'a>(
        &'a self,
        asked: &InstanceTarget,
        op: &'static str,
    ) -> Result<&'a InstanceTarget, ExecutorError> {
        // GUARD 0 — SELF-PROTECTION DENYLIST, unconditional and FIRST. No
        // config, env, or armed state can direct a stop/start at the box we run
        // on or at a configured protected instance.
        if self.is_protected(asked) {
            return Err(ExecutorError::ForbiddenTarget {
                project: asked.project.clone(),
                instance: asked.instance.clone(),
            });
        }
        // GUARD 1 — disarmed by default: no network call until the operator arms it.
        if !self.armed {
            return Err(ExecutorError::LiveArmingGated { op });
        }
        // GUARD 2 — armed but no scratch target: refuse rather than guess.
        let Some(scratch) = self.scratch.as_ref() else {
            return Err(ExecutorError::NoScratchTarget);
        };
        // GUARD 3 — allowlist: only the EXACT configured scratch coordinate
        // (project + zone + instance; InstanceTarget's Eq compares all three).
        if asked != scratch {
            return Err(ExecutorError::RefusedNonScratchTarget {
                asked: asked.instance.clone(),
                scratch: scratch.instance.clone(),
            });
        }
        Ok(scratch)
    }
}

#[async_trait]
impl ComputeExecutor for GcpComputeExecutor {
    async fn stop(&self, target: &InstanceTarget) -> Result<StopOutcome, ExecutorError> {
        // Act on the CONFIGURED scratch coordinate (== target, guard-enforced),
        // never on caller-supplied bytes that bypassed the allowlist.
        let scratch = self.guard(target, "stop")?;
        self.ops.instance_op(scratch, "stop").await
    }

    async fn start(&self, target: &InstanceTarget) -> Result<StopOutcome, ExecutorError> {
        let scratch = self.guard(target, "start")?;
        self.ops.instance_op(scratch, "start").await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn target(instance: &str) -> InstanceTarget {
        InstanceTarget {
            project: "p".to_string(),
            zone: "z".to_string(),
            instance: instance.to_string(),
        }
    }

    /// A recording [`GceInstanceOps`] double — proves whether the guarded code
    /// path REACHED the live op, without ever issuing a real cloud call.
    #[derive(Debug, Default)]
    struct RecordingOps {
        calls: Mutex<Vec<(InstanceTarget, String)>>,
    }
    impl RecordingOps {
        fn count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }
    #[async_trait]
    impl GceInstanceOps for RecordingOps {
        async fn instance_op(
            &self,
            target: &InstanceTarget,
            op: &'static str,
        ) -> Result<StopOutcome, ExecutorError> {
            self.calls
                .lock()
                .unwrap()
                .push((target.clone(), op.to_string()));
            Ok(StopOutcome {
                instance: target.instance.clone(),
                op_id: format!("recorded-{op}"),
                prev_state: "UNKNOWN".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn mock_records_stop_and_start_calls() {
        let m = MockComputeExecutor::new();
        assert_eq!(m.stop_count(), 0);
        m.stop(&target("scratch-vm")).await.unwrap();
        m.start(&target("scratch-vm")).await.unwrap();
        assert_eq!(m.stop_count(), 1);
        assert_eq!(m.start_count(), 1);
        assert_eq!(m.stop_targets()[0].instance, "scratch-vm");
    }

    #[test]
    fn instance_op_url_is_the_compute_stop_endpoint() {
        let url = instance_op_url(&target("scratch-vm"), "stop");
        assert_eq!(
            url,
            "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances/scratch-vm/stop"
        );
        let start = instance_op_url(&target("scratch-vm"), "start");
        assert!(start.ends_with("/instances/scratch-vm/start"));
    }

    #[tokio::test]
    async fn gcp_disarmed_is_inert_and_makes_no_call() {
        let ops = Arc::new(RecordingOps::default());
        let e = GcpComputeExecutor::with_ops(false, None, ops.clone());
        assert_eq!(
            e.stop(&target("anything")).await.unwrap_err(),
            ExecutorError::LiveArmingGated { op: "stop" }
        );
        assert_eq!(
            e.start(&target("anything")).await.unwrap_err(),
            ExecutorError::LiveArmingGated { op: "start" }
        );
        // Disarmed makes NO live call.
        assert_eq!(ops.count(), 0);
        // The default constructor is disarmed too.
        assert_eq!(
            GcpComputeExecutor::disarmed()
                .stop(&target("anything"))
                .await
                .unwrap_err(),
            ExecutorError::LiveArmingGated { op: "stop" }
        );
    }

    #[tokio::test]
    async fn gcp_armed_without_scratch_refuses() {
        let ops = Arc::new(RecordingOps::default());
        let e = GcpComputeExecutor::with_ops(true, None, ops.clone());
        assert_eq!(
            e.stop(&target("anything")).await.unwrap_err(),
            ExecutorError::NoScratchTarget
        );
        assert_eq!(ops.count(), 0);
    }

    // ------------------------------------------------------------------------
    // Self-protection (GUARD 0) — the config-driven replacement for the old
    // hardcoded box denylist. Two independent sources: the Reaper's OWN host
    // (self-identified, here MOCKED by injecting a self_identity), and an
    // operator-configured protected instance.
    // ------------------------------------------------------------------------

    /// (i) The Reaper's own host is refused BEFORE any network call, even when
    /// fully armed AND even when misconfigured as the scratch target — and even
    /// when disarmed (GUARD 0 runs first, unconditionally). The self-identity
    /// is mocked by injecting it directly (as `fetch_self_identity` would at
    /// startup on a real host).
    #[tokio::test]
    async fn gcp_self_host_is_refused_before_network_unconditionally() {
        let self_id = ProtectedCoord::new("self-proj", "reaper-host");
        let self_target = InstanceTarget {
            project: "self-proj".to_string(),
            zone: "any-zone".to_string(),
            instance: "reaper-host".to_string(),
        };
        let ops = Arc::new(RecordingOps::default());
        // Worst case: someone MISCONFIGURES scratch to be the Reaper's own host
        // AND arms the reaper. GUARD 0 must still refuse, before any network.
        let e = GcpComputeExecutor::with_ops(true, Some(self_target.clone()), ops.clone())
            .with_self_identity(Some(self_id.clone()));
        assert!(
            matches!(
                e.stop(&self_target).await.unwrap_err(),
                ExecutorError::ForbiddenTarget { .. }
            ),
            "the reaper's own host must be refused"
        );
        assert!(matches!(
            e.start(&self_target).await.unwrap_err(),
            ExecutorError::ForbiddenTarget { .. }
        ));
        // Even DISARMED — the self-protection guard runs first, unconditionally.
        let disarmed = GcpComputeExecutor::with_ops(false, None, ops.clone())
            .with_self_identity(Some(self_id));
        assert!(matches!(
            disarmed.stop(&self_target).await.unwrap_err(),
            ExecutorError::ForbiddenTarget { .. }
        ));
        // A different zone for the SAME instance is still refused (zone ignored).
        let other_zone = InstanceTarget {
            zone: "other-zone".to_string(),
            ..self_target
        };
        assert!(matches!(
            e.stop(&other_zone).await.unwrap_err(),
            ExecutorError::ForbiddenTarget { .. }
        ));
        // NOT ONE live call was attempted at the protected target.
        assert_eq!(
            ops.count(),
            0,
            "protected target must never reach the network"
        );
    }

    /// (ii) A configured-protected instance (operator denylist, distinct from
    /// the Reaper's own host) is refused before any network call.
    #[tokio::test]
    async fn gcp_configured_protected_instance_is_refused() {
        let protected = ProtectedCoord::new("prod-proj", "prod-database");
        let protected_target = InstanceTarget {
            project: "prod-proj".to_string(),
            zone: "prod-zone".to_string(),
            instance: "prod-database".to_string(),
        };
        let ops = Arc::new(RecordingOps::default());
        let e = GcpComputeExecutor::with_ops(true, Some(target("scratch-vm")), ops.clone())
            .with_protected(vec![protected.clone()]);
        assert!(
            matches!(
                e.stop(&protected_target).await.unwrap_err(),
                ExecutorError::ForbiddenTarget { .. }
            ),
            "a configured protected instance must be refused"
        );
        assert!(matches!(
            e.start(&protected_target).await.unwrap_err(),
            ExecutorError::ForbiddenTarget { .. }
        ));
        assert_eq!(
            ops.count(),
            0,
            "protected target must never reach the network"
        );
    }

    /// (iii) Target confusion still cannot reach the executor: armed with a
    /// scratch target, a kill aimed at any OTHER instance (neither protected
    /// nor the scratch coordinate) is refused by the scratch allowlist (GUARD
    /// 3) before any network call.
    #[tokio::test]
    async fn gcp_armed_refuses_non_scratch_target() {
        let ops = Arc::new(RecordingOps::default());
        let e = GcpComputeExecutor::with_ops(true, Some(target("scratch-vm")), ops.clone());
        let err = e.stop(&target("some-other-vm")).await.unwrap_err();
        assert!(matches!(err, ExecutorError::RefusedNonScratchTarget { .. }));
        // Refused BEFORE the live op.
        assert_eq!(ops.count(), 0);
    }

    #[tokio::test]
    async fn gcp_armed_scratch_match_reaches_the_live_op() {
        // Armed + asked == the exact configured scratch coordinate: the guarded
        // path reaches the live op. Asserted via the injected seam — NO real
        // cloud call is made in the test.
        let ops = Arc::new(RecordingOps::default());
        let scratch = target("scratch-vm");
        let e = GcpComputeExecutor::with_ops(true, Some(scratch.clone()), ops.clone());

        let out = e.stop(&scratch).await.unwrap();
        assert_eq!(out.op_id, "recorded-stop");
        let out = e.start(&scratch).await.unwrap();
        assert_eq!(out.op_id, "recorded-start");

        // Exactly the two ops reached the backend, both against the scratch VM.
        let calls = ops.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], (scratch.clone(), "stop".to_string()));
        assert_eq!(calls[1], (scratch, "start".to_string()));
    }
}
