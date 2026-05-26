//! Criterion microbenchmark for `POST /policy/module/authorize`.
//!
//! INFORMATIONAL bench —  slice 5 §3.2. Captures kernel-side
//! regressions early; the gating number is the end-to-end
//! `pytest-benchmark` harness at
//! `crates/services/safety-kernel/tests/perf/policy_authorize_e2e.py`.
//!
//! Methodology (per `slice5_design.md` §3.1):
//!  * One Rust kernel binary + one Python sidecar (mock mode) — both
//!    spawned once in `setup_stack()` and shared by every iteration.
//!  * Body is a pre-built `ModuleAuthorizeRequest` with an
//!    `event_fingerprint` server-recomputable from the canonical
//!    fields (so step 3 of the handler does not reject the request).
//!  * Pre-warm with 100 calls before timing.
//!  * Bench function uses `iter_batched` with a cloned per-iteration
//!    JSON value to keep allocation noise out of the timed region.
//!
//! Spawn-or-skip rules (mirror `tests/smoke_e2e.rs`):
//!  * Skip cleanly if `python3` is not on PATH.
//!  * Skip cleanly if `cargo build` fails.
//!  * Skip cleanly if the kernel does not become ready within 30s.
//!
//! Run locally:
//!
//! ```bash
//! cargo bench -p qorch-safety-kernel --bench policy_authorize_p99 -- --quick
//! ```
//!
//! Criterion auto-saves a baseline (target/criterion/) so the CI lane
//! can diff successive runs and surface regressions in the bench
//! comment. The HARD/SOFT gates are NOT enforced here — see
//! `policy_authorize_e2e.py` for the gated p99 numbers.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines,
    clippy::uninlined_format_args
)]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use qorch_domain::safety::params_fingerprint;

// ---------------------------------------------------------------------------
// Workspace helpers (lifted from `tests/smoke_e2e.rs`)
// ---------------------------------------------------------------------------

/// Discover the workspace root by walking up from the current crate
/// directory until we find a `Cargo.toml` containing `[workspace]`.
fn workspace_root() -> PathBuf {
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
fn have_python3() -> bool {
    std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Bind a fresh TCP listener to port 0, return the OS-assigned port,
/// then drop the listener so the Rust binary can bind it.
fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// Generate a fresh 32-byte signing seed as a base64url-no-pad string.
fn fresh_seed_b64() -> String {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

// ---------------------------------------------------------------------------
// Stack: sidecar + kernel + canonical request body
// ---------------------------------------------------------------------------

/// Holds the spawned processes + the URL/key so iter functions can
/// reuse them without re-spawning. Dropping this struct kills both
/// children.
struct PerfStack {
    base_url: String,
    api_key_worker: String,
    request_body: Value,
    kernel: Child,
    sidecar: Child,
    // Held to keep the tempdir alive for the duration of the stack.
    _tmp: tempfile::TempDir,
}

impl Drop for PerfStack {
    fn drop(&mut self) {
        let _ = self.kernel.kill();
        let _ = self.sidecar.kill();
        let _ = self.kernel.wait();
        let _ = self.sidecar.wait();
    }
}

/// Build a canonical `ModuleAuthorizeRequest` body whose
/// `event_fingerprint` matches the server-side recompute so the
/// handler progresses past step 3.
///
/// The shape mirrors `recompute_event_fingerprint` in
/// `routes/policy/authorize.rs`:
///
/// ```json
/// {
///   "event_kind": "import",
///   "module_path": "pkg.mod",
///   "caller_subject": "perf-bench-worker",
///   "caller_run_id": "perf-bench-run"
/// }
/// ```
fn build_canonical_request() -> Value {
    let module_path = "pkg.mod";
    let caller_subject = "perf-bench-worker";
    let caller_run_id = "perf-bench-run";
    let canonical = json!({
        "event_kind": "import",
        "module_path": module_path,
        "caller_subject": caller_subject,
        "caller_run_id": caller_run_id,
    });
    let fp = params_fingerprint(&canonical);
    json!({
        "event_kind": "import",
        "module_path": module_path,
        "caller_subject": caller_subject,
        "caller_run_id": caller_run_id,
        "event_fingerprint": fp,
    })
}

/// Spawn the sidecar (mock mode) + the kernel binary on a fresh port,
/// poll `/health` until the kernel is ready, then issue a warm-up
/// burst against `/policy/module/authorize`.
///
/// Returns `None` if the toolchain or build is unavailable — the
/// caller treats this as a clean skip.
#[allow(clippy::too_many_lines)]
fn setup_stack() -> Option<PerfStack> {
    if !have_python3() {
        eprintln!("[perf-bench] python3 not on PATH — skipping setup");
        return None;
    }

    let root = workspace_root();
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("sk.sock");

    // 1. Spawn sidecar (mock).
    let sidecar_script = root.join("apps/safety_kernel/policy_sidecar.py");
    let mut sidecar = match std::process::Command::new("python3")
        .current_dir(&root)
        .env("PYTHONPATH", &root)
        .args([sidecar_script.to_str().unwrap(), "--mock", "--sock-path"])
        .arg(&sock_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[perf-bench] failed to spawn sidecar: {e}");
            return None;
        }
    };

    // Wait up to 5s for the socket to appear.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if !sock_path.exists() {
        let _ = sidecar.kill();
        eprintln!("[perf-bench] sidecar socket did not appear in 5s");
        return None;
    }

    // 2. Build the kernel (idempotent — cargo skips if cached).
    let build = std::process::Command::new("cargo")
        .current_dir(&root)
        .args(["build", "-p", "qorch-safety-kernel", "--release"])
        .output();
    let build = match build {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            let _ = sidecar.kill();
            eprintln!(
                "[perf-bench] cargo build failed:\n{}",
                String::from_utf8_lossy(&o.stderr)
            );
            return None;
        }
        Err(e) => {
            let _ = sidecar.kill();
            eprintln!("[perf-bench] cargo build spawn failed: {e}");
            return None;
        }
    };
    drop(build);
    let bin_path = root.join("target/release/qorch-safety-kernel");
    if !bin_path.exists() {
        let _ = sidecar.kill();
        eprintln!(
            "[perf-bench] release binary missing at {}",
            bin_path.display()
        );
        return None;
    }

    // 3. Spawn the binary on a free port.
    let port = pick_free_port();
    let listen_addr = format!("127.0.0.1:{port}");
    let signing_key_b64 = fresh_seed_b64();
    let audit_pepper_b64 = fresh_seed_b64();
    let api_key_worker = "perf-bench-worker-key".to_string();

    let mut kernel = match std::process::Command::new(&bin_path)
        .env("QORCH_ENV", "dev")
        .env("QORCH_KERNEL_LISTEN_ADDR", &listen_addr)
        .env("QORCH_KERNEL_POLICY_SOCK", &sock_path)
        .env("QORCH_KERNEL_SIGNING_KEY_B64", &signing_key_b64)
        .env("QORCH_KERNEL_AUDIT_PEPPER_B64", &audit_pepper_b64)
        .env("QORCH_KERNEL_API_KEY_WORKER", &api_key_worker)
        .env("QORCH_KERNEL_API_KEY_API", "perf-bench-api-key")
        .env("QORCH_KERNEL_API_KEY_OPERATOR", "perf-bench-operator-key")
        .env("QORCH_KERNEL_BUILD_VERSION", "perf-bench-0.0.0")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = sidecar.kill();
            eprintln!("[perf-bench] failed to spawn kernel: {e}");
            return None;
        }
    };

    // 4. Wait for /health.
    let base_url = format!("http://{listen_addr}");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut up = false;
    while Instant::now() < deadline {
        if let Ok(r) = client.get(format!("{base_url}/health")).send() {
            if r.status().is_success() {
                up = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !up {
        let _ = kernel.kill();
        let _ = sidecar.kill();
        eprintln!("[perf-bench] kernel did not become ready in 30s");
        return None;
    }

    // 5. Build canonical request body.
    let request_body = build_canonical_request();

    // 6. Pre-warm with 100 authorize calls to amortize cold-path
    //    allocations (regex DFA build, sidecar worker spin-up, etc.).
    for _ in 0..100 {
        let _ = client
            .post(format!("{base_url}/policy/module/authorize"))
            .header("x-api-key", &api_key_worker)
            .json(&request_body)
            .send()
            .ok()
            .and_then(|r| {
                if r.status().is_success() {
                    Some(())
                } else {
                    None
                }
            });
    }

    // Cross-check the body hashes by mixing in a sha256 over the
    // canonical params (used by the audit chain mock). The handler
    // ignores this; the call here is only to keep the import of
    // `Sha256` non-dead so the file compiles cleanly even if the
    // canonical-fingerprint helper changes shape.
    let mut h = Sha256::new();
    h.update(request_body.to_string());
    let _digest = h.finalize();

    Some(PerfStack {
        base_url,
        api_key_worker,
        request_body,
        kernel,
        sidecar,
        _tmp: tmp,
    })
}

// ---------------------------------------------------------------------------
// Criterion entrypoint
// ---------------------------------------------------------------------------

fn bench_policy_authorize_hot_path(c: &mut Criterion) {
    let Some(stack) = setup_stack() else {
        // Skip the bench entirely. Criterion has no
        // first-class skip; the next-best is to register a bench
        // that exits immediately so the binary itself stays green.
        eprintln!("[perf-bench] stack setup unavailable — skipping bench");
        return;
    };

    // Reuse one blocking client across all iterations to amortize
    // connection setup. The kernel is HTTP/1.1; reqwest's blocking
    // client keeps a connection pool by default.
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .pool_idle_timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client");

    let url = format!("{}/policy/module/authorize", stack.base_url);
    let api_key = stack.api_key_worker.clone();
    let body = stack.request_body.clone();

    c.bench_function("policy_authorize_hot_path", |b| {
        b.iter_batched(
            // Clone the request body per iteration — keep allocation
            // noise outside the timed region by handing the iter
            // function an owned value it can move.
            || body.clone(),
            |req| {
                let resp = client
                    .post(&url)
                    .header("x-api-key", &api_key)
                    .json(&req)
                    .send()
                    .expect("http send");
                // Touch the body so any I/O cost shows up in the
                // measurement (axum streams the response).
                let _ = resp.bytes().expect("http body");
            },
            BatchSize::SmallInput,
        );
    });

    // The drop impl on stack terminates kernel + sidecar.
    drop(stack);
}

criterion_group! {
    name = benches;
    // Default sample size is 100 which is fine for HTTP RTT.
    // Warm-up is criterion's own; we already pre-warmed in setup.
    config = Criterion::default()
        .sample_size(100)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(10));
    targets = bench_policy_authorize_hot_path
}
criterion_main!(benches);
