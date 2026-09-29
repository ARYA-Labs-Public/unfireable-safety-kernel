//! internal-ref Slice-2 Leg-2 evidence harness — ephemeral transparency-log.
//!
//! Boots the REAL `qorch_transparency_log::router::build_router` (so the
//! genuine `/v1/audit/mcp`, `/v1/verify/{id}`, and `/v1/sth` handlers are
//! exercised) on an EPHEMERAL port, with the dedicated MCP-audit Ed25519
//! fingerprint installed via the crate's public
//! `AppState::with_mcp_audit_ed25519_fingerprint`.
//!
//! WHY THIS HARNESS EXISTS (finding): the production binary `src/main.rs`
//! never calls `with_mcp_audit_ed25519_fingerprint` and reads no env var
//! for it, so a stock `qorch-transparency-log` boot returns 503
//! `ed25519_not_configured` on `POST /v1/audit/mcp`. This harness wires
//! the fingerprint exactly as the route's own unit-test fixture does,
//! using a deterministic MCP-audit signing seed so the matching PUBLIC
//! key (announced + verified by the route) is reproducible. The TlogSweeper
//! (driven from Python) signs leaves under the SAME seed.
//!
//! Config (env):
//!   LEG2_LISTEN          — listen addr (default 127.0.0.1:3199)
//!   LEG2_MCP_AUDIT_SEED  — 32-byte hex Ed25519 seed for the MCP-audit
//!                          signing key (default = 0x99 * 32, matching the
//!                          route unit-test fixture). The sweeper MUST use
//!                          this same seed.
//!   LEG2_STH_SEED        — 32-byte hex STH signer seed (default 0x11*32)
//!   LEG2_API_KEY         — x-api-key the service expects (default test-key)
//!
//! In-memory store: the seal evidence (leaf_index/leaf_hash, inclusion
//! proof, STH) is what Leg 2 verifies; durability of the t-log itself is
//! out of scope (the Postgres audit row is the durable record-of-truth).

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use qorch_domain::safety::Clock;
use qorch_transparency_log::clock::SystemClock;
use qorch_transparency_log::router::build_router;
use qorch_transparency_log::state::AppState;
use qorch_transparency_store::memory::MemoryTransparencyStore;

fn seed_from_hex_or(default: [u8; 32], var: &str) -> [u8; 32] {
    match std::env::var(var) {
        Ok(s) if !s.trim().is_empty() => {
            let raw = hex::decode(s.trim()).expect("seed hex");
            let mut out = [0u8; 32];
            assert_eq!(raw.len(), 32, "{var} must be 32 bytes hex");
            out.copy_from_slice(&raw);
            out
        }
        _ => default,
    }
}

fn fingerprint(pk: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(pk);
    hex::encode(h.finalize())
}

#[tokio::main]
async fn main() {
    let listen = std::env::var("LEG2_LISTEN").unwrap_or_else(|_| "127.0.0.1:3199".to_string());
    let api_key = std::env::var("LEG2_API_KEY").unwrap_or_else(|_| "test-key".to_string());

    // STH signing key (signs the Merkle tree head served at /v1/sth).
    let sth_seed = seed_from_hex_or([0x11u8; 32], "LEG2_STH_SEED");
    let sth_key = SigningKey::from_bytes(&sth_seed);
    let sth_fpr = fingerprint(&sth_key.verifying_key().to_bytes());

    // Kernel fingerprint — unused by the MCP-audit route; a placeholder
    // distinct from the audit + STH keys.
    let kernel_key = SigningKey::from_bytes(&[0x22u8; 32]);
    let kernel_fpr = fingerprint(&kernel_key.verifying_key().to_bytes());

    // Dedicated MCP-audit signing key: the route PINS this public key's
    // fingerprint; the sweeper signs leaves with the matching private key.
    let mcp_audit_seed = seed_from_hex_or([0x99u8; 32], "LEG2_MCP_AUDIT_SEED");
    let mcp_audit_key = SigningKey::from_bytes(&mcp_audit_seed);
    let mcp_audit_pk_hex = hex::encode(mcp_audit_key.verifying_key().to_bytes());
    let mcp_audit_fpr = fingerprint(&mcp_audit_key.verifying_key().to_bytes());

    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let state = AppState::new(
        Arc::new(MemoryTransparencyStore::new()),
        Arc::new(sth_key),
        sth_fpr,
        kernel_fpr,
        clock,
        api_key.clone(),
    )
    .with_mcp_audit_ed25519_fingerprint(mcp_audit_fpr.clone());

    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .expect("bind ephemeral tlog");
    let bound = listener.local_addr().expect("local_addr");

    eprintln!("[leg2-tlog] listening on http://{bound}");
    // Secrets are not echoed. The operator already holds them: the seed
    // is whatever LEG2_MCP_AUDIT_SEED was set to (or the documented
    // default), and the API key is LEG2_API_KEY (or the default). Only
    // the public half and its fingerprint are printed.
    eprintln!(
        "[leg2-tlog] mcp_audit_seed: {} (not echoed)",
        if std::env::var_os("LEG2_MCP_AUDIT_SEED").is_some() {
            "from LEG2_MCP_AUDIT_SEED"
        } else {
            "default"
        }
    );
    eprintln!("[leg2-tlog] mcp_audit_public_key_hex={mcp_audit_pk_hex}");
    eprintln!("[leg2-tlog] mcp_audit_fingerprint_hex={mcp_audit_fpr}");
    eprintln!(
        "[leg2-tlog] api_key: {} (not echoed)",
        if std::env::var_os("LEG2_API_KEY").is_some() {
            "from LEG2_API_KEY"
        } else {
            "default"
        }
    );

    axum::serve(listener, router.into_make_service())
        .await
        .expect("serve");
}
