//! Shared test helpers — workspace discovery, sidecar spawn, free-port
//! allocation. Used by every integration test that needs a live Python
//! policy sidecar + Rust kernel binary running side-by-side.
//!
//! The helpers are intentionally minimal — every test that uses them
//! still owns its own scenario, body construction, and assertions. The
//! common code only handles the process-lifecycle dance.
//!
//! `#![allow(dead_code)]` because Cargo compiles every integration test
//! binary independently — a test file that uses only a subset of these
//! helpers leaves the rest unused, but the alternative (per-test
//! duplication of 100 lines of process plumbing) is worse.

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::doc_markdown)]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

/// Walk up from `CARGO_MANIFEST_DIR` until we find a `Cargo.toml` that
/// declares a `[workspace]`. Mirrors the `smoke_e2e.rs` helper.
pub fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while p.pop() {
        let candidate = p.join("Cargo.toml");
        if candidate.exists() {
            if let Ok(contents) = std::fs::read_to_string(&candidate) {
                if contents.contains("[workspace]") {
                    return p;
                }
            }
        }
    }
    panic!("workspace root not found");
}

/// Probe whether `python3` is on PATH.
pub fn have_python3() -> bool {
    std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Bind a fresh TCP listener to a free port, return the port, drop the
/// listener so the Rust binary can bind it.
pub fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// Generate a fresh 32-byte signing seed (or pepper) base64url-no-pad.
pub fn fresh_seed_b64() -> String {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Spawn the **test registry sidecar** at
/// `apps/safety_kernel/tests/_test_registry_sidecar.py`. Runs the real
/// `policy_module_registry` module against SQLite (in-memory by default)
/// and stubs the audit-chain verbs.
///
/// Why a test-only sidecar: the production `policy_sidecar.py` imports
/// `packages.core.outcome_store_factory`, which transitively pulls in
/// `torch` (via `packages.core.crystal_form`). The test environment may
/// not have torch installed; even when it does, paying that import cost
/// per test spawn is wasteful. The test sidecar is byte-equivalent on
/// the registry IPC surface (same `register_module` / `authorize_module`
/// / `lookup_module_status` calls) — only the audit chain is stubbed.
///
/// For the audit-chain integrity test, use a different harness that
/// drives the production sidecar.
pub fn spawn_sidecar(root: &PathBuf, sock_path: &PathBuf) -> Option<Child> {
    let sidecar_script = root.join("apps/safety_kernel/tests/_test_registry_sidecar.py");
    let child = std::process::Command::new("python3")
        .current_dir(root)
        .env("PYTHONPATH", root)
        .args([sidecar_script.to_str().unwrap(), "--sock-path"])
        .arg(sock_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if !sock_path.exists() {
        return None;
    }
    Some(child)
}

/// Spawn the policy sidecar in **mock** mode — used for tests where the
/// IPC layer matters but the registry semantics don't.
pub fn spawn_sidecar_mock(root: &PathBuf, sock_path: &PathBuf) -> Option<Child> {
    let sidecar_script = root.join("apps/safety_kernel/policy_sidecar.py");
    let child = std::process::Command::new("python3")
        .current_dir(root)
        .env("PYTHONPATH", root)
        .args([sidecar_script.to_str().unwrap(), "--mock", "--sock-path"])
        .arg(sock_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if !sock_path.exists() {
        return None;
    }
    Some(child)
}

/// Build the cargo workspace binary (once per test run; cached by
/// cargo). Returns the path to the binary or an error.
pub fn build_kernel_binary(root: &PathBuf) -> Result<PathBuf, String> {
    let out = std::process::Command::new("cargo")
        .current_dir(root)
        .args(["build", "-p", "qorch-safety-kernel"])
        .output()
        .map_err(|e| format!("cargo build spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo build failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(root.join("target/debug/qorch-safety-kernel"))
}

/// Spawn the kernel binary against the supplied sidecar socket + listen
/// addr + signing key + pepper. Waits up to 10s for `/health` to
/// return 2xx. Returns the `Child` handle.
pub async fn spawn_kernel(
    bin_path: &PathBuf,
    listen_addr: &str,
    sock_path: &PathBuf,
    signing_key_b64: &str,
    audit_pepper_b64: &str,
) -> Option<Child> {
    let mut child = std::process::Command::new(bin_path)
        .env("QORCH_ENV", "dev")
        .env("QORCH_KERNEL_LISTEN_ADDR", listen_addr)
        .env("QORCH_KERNEL_POLICY_SOCK", sock_path)
        .env("QORCH_KERNEL_SIGNING_KEY_B64", signing_key_b64)
        .env("QORCH_KERNEL_AUDIT_PEPPER_B64", audit_pepper_b64)
        .env("QORCH_KERNEL_API_KEY_WORKER", "test-worker-key")
        .env("QORCH_KERNEL_API_KEY_API", "test-api-key")
        .env("QORCH_KERNEL_API_KEY_OPERATOR", "test-operator-key")
        .env("QORCH_KERNEL_BUILD_VERSION", "test-build-0.0.0")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let url = format!("http://{listen_addr}");
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(r) = client.get(format!("{url}/health")).send().await {
            if r.status().is_success() {
                return Some(child);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = child.kill();
    None
}
