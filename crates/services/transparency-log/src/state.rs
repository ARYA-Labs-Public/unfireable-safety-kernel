//! `AppState` for the transparency-log service (ADR-014 Phase 3 §3,
//! internal-ref Step 5).
//!
//! Holds the (Send + Sync) handles every route handler needs:
//!
//! - `store` — `Arc<dyn TransparencyStore>` (Step 4 trait). The
//!   Postgres impl in production; the memory impl in tests + dev.
//! - `signing_key` — the Ed25519 private key used to mint STHs. STH
//!   signs with a separate, independently-rotated key per ADR-014
//!   Phase 3 §4b — distinct from the kernel's token-signing key. Read
//!   from env var `QORCH_TRANSPARENCY_SIGNING_KEY_B64` at service
//!   startup.
//! - `signing_key_fingerprint_hex` — SHA-256 of the raw 32-byte public
//!   key, hex-encoded. Echoed in `GET /v1/sth` so external verifiers
//!   know which key to use.
//! - `kernel_key_fingerprint_hex` — SHA-256 of the kernel's signing
//!   public key. `POST /v1/append` rejects any submission that does not
//!   carry this fingerprint (binds the ledger to a specific kernel).
//! - `clock` — `Arc<dyn Clock>` for the STH timestamp + inserted_at
//!   columns. The pure-domain `mint_sth` takes a caller-supplied
//!   `timestamp_epoch_seconds`; we drive that from this clock so tests
//!   can pin it.
//! - `api_key` — the kernel-supplied `x-api-key` value the middleware
//!   compares against. Held as a single string (only one caller is
//!   authorized to append); empty string means the service was started
//!   with no auth (dev only).

use std::sync::Arc;

use ed25519_dalek::SigningKey;

use qorch_domain::safety::Clock;
use qorch_transparency_store::TransparencyStore;

/// Process-level state shared by every handler.
///
/// `Clone` is `Arc`-cheap; axum's `State<AppState>` extractor requires
/// `Clone` and we hold every heavy field behind `Arc`.
#[derive(Clone)]
pub struct AppState {
    /// Append-only Merkle store (Postgres in prod, memory in tests).
    pub store: Arc<dyn TransparencyStore>,
    /// Ed25519 private key used to mint STHs. Wrapped in `Arc` so route
    /// handlers can hand it to `mint_sth` without cloning the seed.
    pub signing_key: Arc<SigningKey>,
    /// Hex SHA-256 of the raw 32-byte STH-signer public key (this
    /// service's signing key). Echoed in `GET /v1/sth` responses so
    /// external verifiers know which key to use.
    pub signing_key_fingerprint_hex: String,
    /// Hex SHA-256 of the kernel's signing public key. Pinned at
    /// startup; `POST /v1/append` rejects any payload that does not
    /// carry this fingerprint — binds the ledger to a specific kernel.
    pub kernel_key_fingerprint_hex: String,
    /// Production `Clock` adapter — `SystemClock`. Tests inject a
    /// `FixedClock` so STH timestamps are deterministic.
    pub clock: Arc<dyn Clock>,
    /// `x-api-key` value the middleware compares against. Empty string
    /// disables the gate (dev only).
    pub api_key: String,
}

impl AppState {
    /// Construct an `AppState`. Held by `Arc` inside axum but we
    /// expose a non-`Arc` constructor here so tests can build one
    /// without ceremony.
    #[must_use]
    pub fn new(
        store: Arc<dyn TransparencyStore>,
        signing_key: Arc<SigningKey>,
        signing_key_fingerprint_hex: String,
        kernel_key_fingerprint_hex: String,
        clock: Arc<dyn Clock>,
        api_key: String,
    ) -> Self {
        Self {
            store,
            signing_key,
            signing_key_fingerprint_hex,
            kernel_key_fingerprint_hex,
            clock,
            api_key,
        }
    }
}
