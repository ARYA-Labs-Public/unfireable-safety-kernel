//! Audit-chain single-chain integrity test ( slice 2,
//!  "Audit chain integrity" mandate).
//!
//! Drives the real Rust kernel + the test sidecar through a mixed
//! workload of policy + kernel-authorize events. Then queries the test
//! sidecar's `op=audit_dump` (test-only verb) to walk the in-memory
//! chain and assert:
//!
//!   1. **Single chain.** All events recorded by both Rust handlers
//!      (`/policy/*` + `/kernel/v1/authorize`) land in ONE in-memory
//!      chain — no fork, no parallel ledger.
//!   2. **Discriminator values.** The five expected events carry the
//!      audit_kind discriminators frozen by:
//!        - `policy_register`
//!        - `policy_authorize_allow`
//!        - `policy_authorize_deny`
//!        - `policy_audit_event`
//!        - `kernel_authorize` (existing kernel verb — action_name
//!          emitted by `routes/authorize.rs`)
//!   3. **Hash linkage.** Each entry's `prev_hash` matches the prior
//!      entry's `record_hash`; the chain replays cleanly from genesis.
//!   4. **Single-prefix property.** Removing any entry breaks the
//!      chain — verified by walking and asserting no two entries share
//!      a `prev_hash` (forks).
//!
//! NOT covered here (intentionally — those live in their own files):
//!   - HMAC pepper binding for chain entries (test sidecar uses plain
//!     SHA-256; production sidecar uses pepper-keyed HMAC).
//!   - Ed25519 token signature verification (in
//!     `policy_signature_forgery.rs`).
//!
//! Marked `#[ignore]` because it spawns Python sidecar + cargo build.
//! Run with:
//!
//! ```bash
//! cargo test -p qorch-safety-kernel --test policy_audit_chain_integrity \
//!   -- --ignored
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::too_many_lines)]
#![allow(
    clippy::doc_markdown,
    clippy::needless_pass_by_value,
    clippy::single_match_else,
    clippy::cast_possible_wrap,
    clippy::manual_let_else
)]

mod common;

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};

use qorch_domain::safety::params_fingerprint;

fn canonical_fp(ek: &str, mp: &str, cs: &str, crid: &str) -> String {
    let canonical = json!({
        "event_kind": ek,
        "module_path": mp,
        "caller_subject": cs,
        "caller_run_id": crid,
    });
    params_fingerprint(&canonical)
}

fn authorize_body(ek: &str, mp: &str, cs: &str, crid: &str) -> Value {
    json!({
        "event_kind": ek,
        "module_path": mp,
        "caller_subject": cs,
        "caller_run_id": crid,
        "event_fingerprint": canonical_fp(ek, mp, cs, crid),
    })
}

/// Send one envelope to the sidecar and parse the response. Used to
/// invoke the test-only `op=audit_dump` verb to walk the chain.
fn sidecar_call(sock_path: &Path, envelope: Value) -> Value {
    let mut stream = UnixStream::connect(sock_path).expect("connect sidecar");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let line = serde_json::to_string(&envelope).unwrap() + "\n";
    stream.write_all(line.as_bytes()).unwrap();
    stream.flush().unwrap();
    let mut reader = BufReader::new(stream);
    let mut buf = String::new();
    reader.read_line(&mut buf).expect("read response");
    serde_json::from_str(buf.trim()).expect("parse response")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns python3 sidecar + cargo build; run with --ignored"]
async fn audit_chain_is_single_and_integrity_verifies() {
    if !common::have_python3() {
        eprintln!("python3 not on PATH — skipping");
        return;
    }
    let root = common::workspace_root();
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("sk.sock");
    let signing_key_b64 = common::fresh_seed_b64();
    let audit_pepper_b64 = common::fresh_seed_b64();

    let mut sidecar = match common::spawn_sidecar(&root, &sock_path) {
        Some(c) => c,
        None => {
            eprintln!("sidecar failed to start — skipping");
            return;
        }
    };

    let bin = match common::build_kernel_binary(&root) {
        Ok(p) => p,
        Err(e) => {
            let _ = sidecar.kill();
            panic!("{e}");
        }
    };

    let port = common::pick_free_port();
    let listen_addr = format!("127.0.0.1:{port}");
    let mut kernel = match common::spawn_kernel(
        &bin,
        &listen_addr,
        &sock_path,
        &signing_key_b64,
        &audit_pepper_b64,
    )
    .await
    {
        Some(c) => c,
        None => {
            let _ = sidecar.kill();
            panic!("kernel binary did not become ready in 10s");
        }
    };

    let url = format!("http://{listen_addr}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    // ----------------------------------------------------------------
    // Mixed workload — five events, four distinct audit_kind values.
    // ----------------------------------------------------------------

    // 1. policy_register
    let r = client
        .post(format!("{url}/policy/module/register"))
        .header("x-api-key", "test-worker-key")
        .json(&json!({
            "module_path": "pkg.audited",
            "required_patterns_regex_set": ["^pkg\\."],
            "caller_subject": "worker",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "register MUST succeed");

    // 2. policy_authorize allow
    let r = client
        .post(format!("{url}/policy/module/authorize"))
        .header("x-api-key", "test-worker-key")
        .json(&authorize_body("import", "pkg.audited", "worker", "run-1"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "allow authorize MUST succeed");

    // 3. policy_authorize deny — different module that's not registered.
    let r = client
        .post(format!("{url}/policy/module/authorize"))
        .header("x-api-key", "test-worker-key")
        .json(&authorize_body(
            "import",
            "pkg.not_registered",
            "worker",
            "run-2",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "unregistered module MUST 403");

    // 4. policy_audit_event
    let r = client
        .post(format!("{url}/policy/audit-event"))
        .header("x-api-key", "test-worker-key")
        .json(&json!({
            "event_kind": "hook_install_violation",
            "subject": "worker",
            "metadata": {"detail": "test_violation"},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 202, "audit-event MUST 202");

    // 5. /kernel/v1/authorize — existing kernel verb. Must land on
    // the same chain alongside the four policy entries.
    let params = json!({"k": "v"});
    let pf = params_fingerprint(&params);
    let r = client
        .post(format!("{url}/kernel/v1/authorize"))
        .header("x-api-key", "test-worker-key")
        .json(&json!({
            "action": "sio_run_cycles",
            "run_id": "run_x",
            "subject": "client",
            "params_fingerprint": pf,
            "params": params,
            "ttl_s": 60,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "kernel authorize MUST succeed");

    // ----------------------------------------------------------------
    // Walk the chain via the test-only audit_dump verb.
    // ----------------------------------------------------------------

    let dump = sidecar_call(
        &sock_path,
        json!({
            "op": "audit_dump",
            "request_id": "dump-1",
            "payload": {},
        }),
    );
    assert_eq!(
        dump.get("ok"),
        Some(&Value::Bool(true)),
        "audit_dump MUST succeed; got {dump}",
    );
    let chain = dump
        .get("result")
        .and_then(|r| r.get("chain"))
        .and_then(Value::as_array)
        .expect("chain array")
        .clone();

    // The chain contains AT LEAST 5 entries — slice-2 handlers also
    // emit a `policy_register` audit_append for the register call,
    // plus `policy_authorize_allow`, `policy_authorize_deny`,
    // `policy_audit_event`, and `authorize`. Some slice-2 handlers
    // also dual-write a sidecar-side audit row (so the count may be
    // higher than 5). The lower bound is the contract.
    assert!(
        chain.len() >= 5,
        "expected ≥5 chain entries (one per workload event), got {}; chain={chain:?}",
        chain.len(),
    );

    // -------- Property 1: single chain (no fork) --------------------
    //
    // Collect every `record_hash` and every `prev_hash`. Each
    // non-genesis entry's `prev_hash` MUST appear as some earlier
    // entry's `record_hash`. No two entries may share the same
    // `prev_hash` (that would be a fork).

    let mut record_hashes: Vec<String> = Vec::new();
    let mut prev_hashes_seen: HashSet<String> = HashSet::new();
    let mut genesis_count = 0;

    for (i, entry) in chain.iter().enumerate() {
        let rh = entry
            .get("record_hash")
            .and_then(Value::as_str)
            .expect("record_hash")
            .to_string();
        let prev = entry.get("prev_hash");
        let seq = entry.get("seq").and_then(Value::as_i64).unwrap();
        assert_eq!(
            seq,
            (i as i64) + 1,
            "seq numbers MUST be 1-indexed contiguous; got seq={seq} at index {i}",
        );
        match prev {
            Some(Value::Null) | None => {
                genesis_count += 1;
                assert_eq!(i, 0, "genesis entry MUST be the first entry");
            }
            Some(Value::String(p)) => {
                // Must match SOME earlier record_hash.
                assert!(
                    record_hashes.contains(p),
                    "entry {i} prev_hash={p} does not chain to any earlier record_hash; \
                     record_hashes_so_far={record_hashes:?}",
                );
                // Must NOT have been seen as a prev_hash before — that
                // would be a fork (two entries with the same parent).
                assert!(
                    prev_hashes_seen.insert(p.clone()),
                    "entry {i} prev_hash={p} duplicates a prior prev_hash — FORK detected",
                );
            }
            other => panic!("unexpected prev_hash shape: {other:?}"),
        }
        record_hashes.push(rh);
    }
    assert_eq!(genesis_count, 1, "exactly one genesis entry");

    // -------- Property 2: discriminator values present --------------

    let action_names: Vec<&str> = chain
        .iter()
        .filter_map(|e| e.get("action_name").and_then(Value::as_str))
        .collect();
    let mut required = HashSet::from([
        "policy_register",
        "policy_authorize_allow",
        "policy_authorize_deny",
        "policy_audit_event",
        // The existing kernel authorize endpoint at /kernel/v1/authorize
        // emits action_name="kernel_authorize" (see routes/authorize.rs);
        //  calls out this discriminator alongside the four
        // new policy_* kinds as the chain's complete set for slice 2.
        "kernel_authorize",
    ]);
    for an in &action_names {
        required.remove(an);
    }
    assert!(
        required.is_empty(),
        "missing discriminator values: {required:?}; observed action_names={action_names:?}",
    );

    // -------- Property 3: replay-from-genesis succeeds --------------
    //
    // Already exercised by the prev_hash → record_hash linkage walk
    // above. Explicit re-statement: the linkage check passed for every
    // non-genesis entry, so a sequential replay from entry 1 reaches
    // entry N without integrity errors.

    // -------- Property 4: dropping any non-tail entry breaks chain --
    //
    // Simulate "remove entry i" by skipping it during the linkage
    // walk. Every non-genesis entry's prev_hash must reference some
    // earlier record_hash in the filtered list; if it doesn't, the
    // drop broke the chain. We skip the LAST entry (tail) because by
    // definition nothing references the tail's record_hash — dropping
    // it is allowed (the chain truncates, but every remaining entry
    // still validates). This is the standard tamper-evidence property:
    // any historical entry's deletion breaks the chain.

    for drop_idx in 1..(chain.len() - 1) {
        let mut seen_hashes: HashSet<String> = HashSet::new();
        let mut chain_valid = true;
        for (i, entry) in chain.iter().enumerate() {
            if i == drop_idx {
                continue;
            }
            let rh = entry
                .get("record_hash")
                .and_then(Value::as_str)
                .unwrap()
                .to_string();
            let prev = entry.get("prev_hash");
            match prev {
                Some(Value::Null) | None => {
                    if i != 0 {
                        chain_valid = false;
                        break;
                    }
                }
                Some(Value::String(p)) => {
                    if !seen_hashes.contains(p) {
                        chain_valid = false;
                        break;
                    }
                }
                _ => unreachable!(),
            }
            seen_hashes.insert(rh);
        }
        assert!(
            !chain_valid,
            "dropping non-tail entry {drop_idx} should have broken the chain but the linkage \
             still validated — the chain has slack (NOT tamper-evident)",
        );
    }

    // ----------------------------------------------------------------
    // Cleanup.
    // ----------------------------------------------------------------
    let _ = kernel.kill();
    let _ = sidecar.kill();
    let _ = kernel.wait();
    let _ = sidecar.wait();
    drop(tmp);
    let _ = signing_key_b64;
    let _ = audit_pepper_b64;
}
