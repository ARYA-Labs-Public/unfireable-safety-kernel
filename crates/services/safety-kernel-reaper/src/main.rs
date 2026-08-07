//! Reaper binary — wire config into the poll loop with a liveness deadline.
//! Defaults to the MOCK executor; the real cloud path is INERT until the
//! operator arms it. Live arming (IAM binding, real `compute.instances.stop`)
//! is a deliberate operator step.

use std::sync::Arc;
use std::time::Duration;

use qorch_safety_kernel_client::PinnedKeyVerifier;

use qorch_safety_kernel_reaper::{
    fetch_self_identity, ComputeExecutor, FileNonceStore, GcpComputeExecutor, KernelClient,
    KillRecorder, LivenessAction, MockComputeExecutor, Reaper, ReaperConfig, ReqwestKernelClient,
    ReqwestKillRecorder,
};

/// Wall-clock now as f64 epoch seconds.
fn now_s() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = ReaperConfig::from_env()?;

    let verifier = PinnedKeyVerifier::from_pubkey_bytes(cfg.pinned_pubkey)
        .map_err(|e| anyhow::anyhow!("invalid pinned verifying key: {e:?}"))?;
    tracing::info!(
        fingerprint = verifier.fingerprint(),
        "pinned kernel verifying key loaded"
    );

    // SAFETY: default to the MOCK executor. Even when armed, the cloud executor
    // is scratch-scoped + live-arming-gated and never defaults to the agent VM.
    let executor: Arc<dyn ComputeExecutor> = if cfg.armed {
        // Self-identify the host we run on so GUARD 0 refuses stopping ourselves
        // (config-driven self-protection — nothing is hardcoded to a specific
        // host). Best-effort: off-cloud this returns None and only the
        // operator-configured protected list applies; warn loudly because
        // self-protection is a live-arming prerequisite.
        let self_identity = fetch_self_identity().await;
        match self_identity.as_ref() {
            Some(id) => tracing::info!(
                self_project = %id.project,
                self_instance = %id.instance,
                "self-identified host for the self-protection denylist"
            ),
            None => tracing::warn!(
                "could not self-identify the host from the metadata server — the reaper's OWN host \
                 is NOT on the self-protection denylist; only REAPER_PROTECTED_INSTANCES applies. \
                 Self-identification is a LIVE-ARMING PREREQUISITE."
            ),
        }
        tracing::warn!(
            scratch = ?cfg.scratch.as_ref().map(|s| &s.instance),
            protected = cfg.protected_instances.len(),
            "REAPER_ARMED=true: constructing scratch-scoped GcpComputeExecutor (LIVE \
             compute.instances.stop/start enabled for the scratch target ONLY; the \
             self-protection denylist still refuses the host box + configured protected instances)"
        );
        Arc::new(
            GcpComputeExecutor::new(true, cfg.scratch.clone())
                .with_self_identity(self_identity)
                .with_protected(cfg.protected_instances.clone()),
        )
    } else {
        tracing::info!("disarmed: using MockComputeExecutor (no instance will be stopped)");
        Arc::new(MockComputeExecutor::new())
    };

    let nonce_path = std::env::var("REAPER_NONCE_STORE_PATH")
        .unwrap_or_else(|_| "/var/lib/qorch-reaper/seen_nonces.log".to_string());
    let nonce_store = Arc::new(FileNonceStore::open(&nonce_path)?);

    // Pin the kernel's server cert when a CA is configured, so a MITM / lying
    // kernel cannot suppress a kill under an untrusted TLS identity. Absent a
    // pin, fall back to WebPKI roots and warn LOUD — pinning is a live-arming
    // prerequisite, never silently skipped.
    let kernel_client: Arc<dyn KernelClient> = match &cfg.kernel_ca_path {
        Some(ca_path) => {
            let ca_pem = std::fs::read(ca_path)
                .map_err(|e| anyhow::anyhow!("read REAPER_KERNEL_CA_PATH {ca_path}: {e}"))?;
            let client = ReqwestKernelClient::with_pinned_ca(
                cfg.kernel_url.clone(),
                cfg.reaper_api_key.clone(),
                Duration::from_secs(10),
                &ca_pem,
            )
            .map_err(|e| anyhow::anyhow!("build cert-pinned kernel client: {e}"))?;
            tracing::info!(ca_path, "kernel connection is CERT-PINNED");
            Arc::new(client)
        }
        None => {
            tracing::error!(
                "REAPER_KERNEL_CA_PATH not set — kernel connection is NOT cert-pinned; a MITM / \
                 lying kernel could suppress a kill by returning an empty pending list. Pinning \
                 the kernel server CA is a LIVE-ARMING PREREQUISITE."
            );
            Arc::new(ReqwestKernelClient::new(
                cfg.kernel_url.clone(),
                cfg.reaper_api_key.clone(),
                Duration::from_secs(10),
            ))
        }
    };

    let kill_recorder: Option<Arc<dyn KillRecorder>> = match (&cfg.tlog_url, &cfg.tlog_api_key) {
        (Some(url), Some(key)) => Some(Arc::new(ReqwestKillRecorder::new(
            url.clone(),
            key.clone(),
            verifier.fingerprint().to_string(),
            Duration::from_secs(10),
        ))),
        _ => {
            tracing::warn!("no transparency-log configured — kill-records will not be durable");
            None
        }
    };

    let reaper = Reaper::new(
        verifier,
        executor,
        nonce_store,
        cfg.target.clone(),
        cfg.liveness_deadline_s,
        kill_recorder,
        Some(Arc::clone(&kernel_client)),
    );

    tracing::info!(
        instance = cfg.target.instance,
        poll_interval_s = cfg.poll_interval_s,
        liveness_deadline_s = cfg.liveness_deadline_s,
        "reaper poll loop starting"
    );

    // The pull loop with a liveness deadline.
    let mut last_success = now_s();
    loop {
        match kernel_client.pull_pending(&cfg.target.instance).await {
            Ok(tokens) => {
                last_success = now_s();
                for token in tokens {
                    // F-obs: dispatch by KIND — kill tokens stop(), operator
                    // restore tokens start(). The old loop forced everything
                    // through the kill path, so restores were dead.
                    let outcome = reaper.handle_pending_candidate(&token, now_s()).await;
                    tracing::info!(?outcome, "processed pending revoke candidate");
                }
            }
            Err(e) => {
                let now = now_s();
                // F-6b: the liveness/fail-closed decision now lives in a
                // testable helper. Only advance the tracker on a SUCCESSFUL
                // fail-closed stop; a failed stop is alarmed and RETRIED on the
                // next poll instead of being swallowed for a full deadline.
                match reaper.on_kernel_pull_failure(last_success, now).await {
                    LivenessAction::WithinDeadline => {
                        tracing::warn!(error = %e, "kernel pull failed (within liveness deadline)");
                    }
                    LivenessAction::FailedClosed {
                        outcome,
                        advance_liveness: true,
                    } => {
                        tracing::error!(
                            ?outcome,
                            unreachable_for_s = now - last_success,
                            "kernel dark past liveness deadline — fail-closed stop SUCCEEDED"
                        );
                        // Reset so we don't hammer the executor every poll while
                        // the kernel stays dark (the box is already stopped).
                        last_success = now;
                    }
                    LivenessAction::FailedClosed {
                        outcome,
                        advance_liveness: false,
                    } => {
                        tracing::error!(
                            ?outcome,
                            unreachable_for_s = now - last_success,
                            "ALARM: fail-closed stop FAILED — liveness NOT advanced, retrying next poll"
                        );
                        // Deliberately do NOT reset last_success: the deadline
                        // stays expired so the next poll re-attempts the stop.
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs_f64(cfg.poll_interval_s.max(1.0))).await;
    }
}
