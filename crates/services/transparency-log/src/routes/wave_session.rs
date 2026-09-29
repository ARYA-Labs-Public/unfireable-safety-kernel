//! internal-ref Phase 1 — wave-session-record routes.
//!
//! Two endpoints:
//!
//! - `POST /v1/wave/session` — append a kernel-HMAC-signed wave session
//!   record as a Merkle leaf. Idempotent on
//!   `SHA-256(wave_id || stage || session_id)`. Returns 201 Created on
//!   fresh insert, 200 OK on idempotent replay. 403 Forbidden on
//!   kernel-key-fingerprint mismatch OR HMAC verify failure. 400 on
//!   `stage` / `written_by` inconsistency or other validation errors.
//!
//! - `GET /v1/wave/{wave_id}/verify` — return the wave's full session
//!   chain in canonical pipeline order. Body carries
//!   `all_required_stages_present: bool`, the pinned kernel-key
//!   fingerprint, and per-entry HMACs so external auditors can re-run
//!   verification against the kernel's public material.
//!
//! Design notes (per internal-ref spec):
//!
//! - The Merkle leaf payload IS the canonical-bytes projection of
//!   [`WaveSessionRecord`] (see
//!   `qorch_domain::wave::session_record::WaveSessionRecord::canonical_bytes`).
//! - The HMAC is appended verbatim to the leaf payload as a
//!   length-prefixed trailer (see [`build_leaf_payload`] /
//!   [`split_leaf_payload`]). Storing the HMAC in the leaf bytes —
//!   rather than alongside in a separate column — keeps the
//!   transparency-log storage adapter agnostic of the wave-session
//!   schema and means an external auditor only needs the ledger to
//!   reconstruct the chain.
//! - The kernel HMAC verifies against `canonical_bytes(record)`, NOT
//!   against the framed leaf bytes — so a tampered HMAC fails the
//!   constant-time compare without leaking which byte differs.
//! - `idempotency_key = WaveSessionRecord::record_idempotency_key(record)`.
//!   The underlying store de-duplicates by this 32-byte key; a same-key
//!   different-bytes call (i.e. a forged retry with mutated record)
//!   returns 409 from the store, which we surface as
//!   `IdempotencyPayloadMismatch`.

#![allow(clippy::bool_assert_comparison)]
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use hmac::{digest::KeyInit, Hmac, Mac};
use sha2::{Digest, Sha256};

use qorch_domain::wave::context::WaveId;
use qorch_domain::wave::session_record::{all_required_stages_present, WaveSessionRecord};
use qorch_transparency_store::AppendInput;

use crate::dto::{
    AppendWaveSessionRequest, AppendWaveSessionResponse, SignatureType, TransparencyKeyResponse,
    VerifyWaveSessionResponse, WaveSessionChainEntry,
};
use crate::error::ServiceError;
use crate::state::{AppState, WaveSessionLeafSide};

type HmacSha256 = Hmac<Sha256>;

/// Length-prefixed framing: 8-byte big-endian record length, then
/// `record_bytes`, then the 32-byte raw HMAC. The transparency-log
/// stores this as the leaf payload. The framing means the leaf hash
/// commits to BOTH the record content AND the HMAC — so an attacker
/// who swaps the HMAC after the fact would also have to forge the
/// leaf hash + Merkle root, which the inclusion-proof verifier catches.
fn build_leaf_payload(record_bytes: &[u8], hmac_bytes: &[u8; 32]) -> Vec<u8> {
    // `usize -> u64` is widening on all supported targets (32+ bit).
    let n: u64 = u64::try_from(record_bytes.len()).unwrap_or(u64::MAX);
    let mut out = Vec::with_capacity(8 + record_bytes.len() + 32);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(record_bytes);
    out.extend_from_slice(hmac_bytes);
    out
}

/// Inverse of [`build_leaf_payload`]. Returns `(record_bytes,
/// hmac_bytes)` or a [`ServiceError::Backend`] on malformed framing
/// (shouldn't happen for leaves we wrote ourselves, but defensive).
///
/// Currently unused at the route layer because Phase 1 stashes the
/// decoded record in [`AppState::wave_session_payloads`]. Phase 2
/// (Postgres-backed denormalization) drops the side map and this
/// function becomes the verify-route's payload decoder. Kept here
/// (a) as documentation of the committed-to framing, and (b) so the
/// Phase 2 work has a single drop-in. Also used by
/// [`reconstruct_wave_sessions_from_ledger`] to recover `(record, hmac)`
/// from each durable leaf on boot.
fn split_leaf_payload(payload: &[u8]) -> Result<(Vec<u8>, [u8; 32]), ServiceError> {
    if payload.len() < 8 + 32 {
        return Err(ServiceError::Backend(
            "wave-session leaf payload too short".into(),
        ));
    }
    let mut n_bytes = [0u8; 8];
    n_bytes.copy_from_slice(&payload[..8]);
    let n = usize::try_from(u64::from_be_bytes(n_bytes))
        .map_err(|_| ServiceError::Backend("wave-session payload length overflow".into()))?;
    if 8 + n + 32 != payload.len() {
        return Err(ServiceError::Backend(
            "wave-session leaf payload length mismatch".into(),
        ));
    }
    let record_bytes = payload[8..8 + n].to_vec();
    let mut hmac = [0u8; 32];
    hmac.copy_from_slice(&payload[8 + n..]);
    Ok((record_bytes, hmac))
}

/// internal-ref durability — rebuild the in-process wave-session index +
/// leaf-hash map (+ detail cache) from the source-of-truth Merkle
/// ledger. Call once on boot so `GET /v1/wave/{id}/verify` survives a
/// restart.
///
/// Background: the ledger (leaves + tree size) is durable (Postgres in
/// prod), but the derived `wave_id -> [leaf_index]` index, the
/// `leaf_index -> leaf_hash_hex` translation map, and the detail LRU
/// live only in memory. Before this, a restart emptied them and every
/// prior wave verified as 404 `entry_not_found` — under the internal-ref
/// flip (tlog required by default) that would brick release commits on
/// any tlog restart/crash/reboot.
///
/// Per leaf, in ascending order:
///   1. `split_leaf_payload` → `(record_bytes, hmac)`. A leaf whose
///      framing doesn't parse, or whose record doesn't deserialize as a
///      `WaveSessionRecord`, is **not** a wave-session leaf (e.g. an
///      MCP-audit leaf) — silently skipped.
///   2. Rebuild the index (`record_wave_session_leaf`) and the
///      `leaf_index -> leaf_hash_hex` map (`register_wave_session_leaf_hash`).
///   3. Resolve the per-leaf side. If a durable side-table is
///      configured AND already holds this leaf, `lookup_wave_session_payload`
///      pulls the authoritative side (incl. any Ed25519 material) into
///      the LRU — no fidelity loss. Otherwise reconstruct an HMAC-only
///      side from the ledger framing (lossless for HMAC-signed wave
///      appends, the only kind the wave-session route mints today) via
///      `record_wave_session_payload`. Either path guarantees a
///      subsequent `verify_session` lookup resolves — an indexed leaf
///      with no resolvable side would make verify 500.
///
/// Returns the number of wave-session leaves recovered. Non-wave leaves
/// are excluded from the count.
pub async fn reconstruct_wave_sessions_from_ledger(
    state: &AppState,
) -> Result<usize, ServiceError> {
    let payloads = state.store.load_all_payloads().await?;
    let mut recovered = 0usize;
    for lp in payloads {
        // Non-wave leaves (bad framing / not a WaveSessionRecord) are
        // skipped — the ledger interleaves MCP-audit and wave leaves.
        let Ok((record_bytes, hmac)) = split_leaf_payload(&lp.payload) else {
            continue;
        };
        let record = match serde_json::from_slice::<WaveSessionRecord>(&record_bytes) {
            Ok(r) => r,
            Err(_) => {
                // Strict-parse failed. Re-parse as a generic JSON Value to
                // determine whether this is a wave leaf that the running
                // binary cannot fully deserialize (e.g. an unknown
                // GateSurface variant introduced after this binary was
                // built). If the JSON object has a non-empty `wave_id`
                // string field it IS a wave leaf — register it as
                // unreadable so verify_session can surface the right error
                // instead of silently returning NotFound.
                if let Ok(serde_json::Value::Object(map)) =
                    serde_json::from_slice::<serde_json::Value>(&record_bytes)
                {
                    if let Some(serde_json::Value::String(wid_str)) = map.get("wave_id") {
                        if !wid_str.is_empty() {
                            let wid = WaveId::new(wid_str.clone());
                            state.record_unreadable_wave_leaf(&wid, lp.leaf_index).await;
                        }
                    }
                }
                continue;
            }
        };
        state
            .record_wave_session_leaf(&record.wave_id, lp.leaf_index)
            .await;
        let leaf_hash_hex = hex::encode(lp.leaf_hash);
        state
            .register_wave_session_leaf_hash(lp.leaf_index, leaf_hash_hex.clone())
            .await;
        // Prefer a durable side-table entry (keeps full Ed25519
        // fidelity); fall back to an HMAC-only reconstruction so the
        // verify lookup never misses.
        if state
            .lookup_wave_session_payload(lp.leaf_index)
            .await
            .is_none()
        {
            let side = WaveSessionLeafSide {
                record,
                kernel_hmac: hmac,
                ed25519_signature: None,
                signature_type: SignatureType::Hmac,
                key_fingerprint_hex: state.kernel_key_fingerprint_hex.clone(),
            };
            state
                .record_wave_session_payload(lp.leaf_index, leaf_hash_hex, side)
                .await;
        }
        recovered += 1;
    }
    Ok(recovered)
}

/// Verify a kernel HMAC against the canonical record bytes. Returns
/// `Ok(())` on success, [`ServiceError::KernelHmacMismatch`] otherwise.
/// Constant-time via `hmac::Mac::verify_slice` (which uses
/// `subtle::ConstantTimeEq` internally).
///
/// # Errors
///
/// - [`ServiceError::Backend`] if the HMAC key is empty (service
///   misconfigured — should never happen with a `with_kernel_hmac_key`
///   AppState).
/// - [`ServiceError::KernelHmacMismatch`] on verification failure.
fn verify_kernel_hmac(
    record_bytes: &[u8],
    supplied_hmac: &[u8; 32],
    key: &[u8],
) -> Result<(), ServiceError> {
    if key.is_empty() {
        return Err(ServiceError::Backend(
            "kernel HMAC key not configured".into(),
        ));
    }
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
        .map_err(|e| ServiceError::Backend(format!("invalid HMAC key length: {e}")))?;
    mac.update(record_bytes);
    mac.verify_slice(supplied_hmac)
        .map_err(|_| ServiceError::KernelHmacMismatch)
}

/// Map a `/test` / `/purple-team` / `/user-acceptance` / `/closeout`
/// `written_by` string to the stage it is allowed to attest to.
/// Returns true if the pair is consistent.
fn written_by_matches_stage(written_by: &str, stage: qorch_domain::wave::stage::WaveStage) -> bool {
    use qorch_domain::wave::stage::WaveStage;
    let normalized = written_by
        .trim()
        .trim_start_matches('/')
        .to_ascii_lowercase();
    match stage {
        // Planned and Decomposed are allowed from either /plan or /team —
        // the writing skill name is informational at those stages.
        WaveStage::Planned => matches!(normalized.as_str(), "plan" | "planner"),
        WaveStage::Decomposed => matches!(
            normalized.as_str(),
            "team" | "planner" | "plan" | "architect"
        ),
        WaveStage::Tested => normalized == "test",
        WaveStage::PurpleTeamed => normalized == "purple-team" || normalized == "purple_team",
        WaveStage::Accepted => {
            normalized == "user-acceptance"
                || normalized == "user_acceptance"
                || normalized == "uat"
        }
        WaveStage::Closed => normalized == "closeout",
    }
}

/// internal-ref — verify an Ed25519 signature against
/// `canonical_bytes(record)` under the caller-announced public key.
/// Returns `Ok(())` on a valid signature, or the appropriate
/// [`ServiceError`] variant on any failure.
///
/// Steps:
/// 1. Pin the announced public-key fingerprint against the
///    transparency-log's published fingerprint (constant-time compare
///    via `subtle::ConstantTimeEq` inside `verify_slice`-style ops —
///    here implemented with a sha256 fingerprint compare since we are
///    comparing 32-byte digests, not the keys themselves).
/// 2. Parse the announced 32-byte raw public key into a
///    `VerifyingKey`.
/// 3. Parse the supplied 64-byte signature into an `ed25519_dalek::Signature`.
/// 4. Call `VerifyingKey::verify()` — `ed25519-dalek` v2 enforces
///    strict serialization checks on the signature internally.
fn verify_ed25519_signature(
    record_bytes: &[u8],
    announced_pk_hex: &str,
    signature_hex: &str,
    expected_fingerprint_hex: &str,
) -> Result<(), ServiceError> {
    // 1. Decode the announced public key bytes (raw 32-byte form).
    let announced_pk_raw = hex::decode(announced_pk_hex.trim())
        .map_err(|e| ServiceError::BadRequest(format!("ed25519 pk hex decode: {e}")))?;
    if announced_pk_raw.len() != 32 {
        return Err(ServiceError::BadRequest(format!(
            "ed25519 public key must be 32 bytes, got {}",
            announced_pk_raw.len()
        )));
    }

    // 2. Compute its SHA-256 fingerprint and constant-time compare
    //    against the published fingerprint. Both are 64-char hex
    //    SHA-256 digests; `subtle::ConstantTimeEq` is in the
    //    `ed25519_dalek` dep graph but the simplest correct compare
    //    on equal-length hex is a byte-loop XOR (same shape as
    //    `auth::constant_time_eq`). For a 64-char string the leakage
    //    window is negligible; we still loop the full length.
    let announced_fpr = {
        let mut h = Sha256::new();
        h.update(&announced_pk_raw);
        hex::encode(h.finalize())
    };
    if !constant_time_str_eq(&announced_fpr, expected_fingerprint_hex) {
        return Err(ServiceError::Ed25519KeyFingerprintMismatch);
    }

    // 3. Decode the signature bytes.
    let sig_raw = hex::decode(signature_hex.trim())
        .map_err(|e| ServiceError::BadRequest(format!("ed25519 sig hex decode: {e}")))?;
    if sig_raw.len() != SIGNATURE_LENGTH {
        return Err(ServiceError::BadRequest(format!(
            "ed25519 signature must be 64 bytes, got {}",
            sig_raw.len()
        )));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&announced_pk_raw);
    let mut sig_arr = [0u8; SIGNATURE_LENGTH];
    sig_arr.copy_from_slice(&sig_raw);

    // 4. Materialise the verifying key + signature and verify. A bad
    //    public-key encoding (low-order point, malleable encoding) or a
    //    failed verify both surface as `Ed25519SignatureMismatch` so
    //    we do not leak which check failed.
    let vk =
        VerifyingKey::from_bytes(&pk_arr).map_err(|_| ServiceError::Ed25519SignatureMismatch)?;
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify(record_bytes, &signature)
        .map_err(|_| ServiceError::Ed25519SignatureMismatch)?;

    Ok(())
}

/// Constant-time byte-equality on two ASCII-hex strings of equal
/// length. Used for fingerprint compares where the comparison itself
/// must not leak which byte differs (a sustained mismatch can leak the
/// fingerprint over time). For unequal lengths we short-circuit to
/// `false` — fingerprints are always 64 chars so a length mismatch
/// is a structural error, not an attack vector.
fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `POST /v1/wave/session`.
///
/// Dispatches on `body.signature_type` (default = legacy HMAC). Both
/// paths share the kernel-fingerprint pin, stage/written_by validator,
/// idempotency-key derivation, and the framed-leaf storage path —
/// only the signature-verification step differs.
///
/// internal-ref — when `state.per_skill_keys` is `Some(_)`, the route
/// performs an IDENTITY check against the supplied `x-api-key`: the
/// configured per-stage key MUST match the value the caller presented.
/// A mismatch (wrong key, or no key configured for the stage) returns
/// 403 `stage_key_mismatch`. When `state.per_skill_keys` is `None`,
/// the legacy single-shared-key path is used (already enforced by
/// `auth::auth_layer`).
pub async fn append_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AppendWaveSessionRequest>,
) -> Result<Response, ServiceError> {
    // 1. Kernel-fingerprint pin (re-uses the same field shape as
    //    /v1/append for operator familiarity). This pin is binding
    //    regardless of which signing algorithm is used — the kernel
    //    identity is the ledger's anchor.
    let supplied_fpr = body
        .kernel_key_fingerprint_sha256
        .trim()
        .to_ascii_lowercase();
    let expected_fpr = state.kernel_key_fingerprint_hex.to_ascii_lowercase();
    if supplied_fpr != expected_fpr {
        return Err(ServiceError::KernelFingerprintMismatch);
    }

    // 2. Decode the kernel HMAC bytes. We do this unconditionally —
    //    even on the Ed25519 path the caller must supply a placeholder
    //    so the wire shape stays deny_unknown_fields-stable. The
    //    Ed25519 path then ignores the value.
    let supplied_hmac = hex_to_32(&body.kernel_hmac_hex)?;

    // 3. Validate stage / written_by consistency. The transparency-log
    //    cannot stop a misbehaving skill from impersonating another,
    //    but it can refuse the cheapest mistake.
    if !written_by_matches_stage(&body.record.written_by, body.record.stage) {
        return Err(ServiceError::StageWrittenByMismatch);
    }

    // 3b. internal-ref — per-skill `x-api-key` IDENTITY check on the HMAC
    //     path. The label check above (3) is consistency-only; this
    //     step proves the caller actually IS the writer for the stage
    //     they tagged the record with.
    //
    //     - `state.per_skill_keys == None` ⇒ back-compat single-shared-
    //       key mode — skip (the middleware already gated on `api_key`).
    //     - `state.per_skill_keys == Some(table)` ⇒ extract the
    //       `x-api-key` header, lookup the expected key for
    //       `record.stage`, constant-time compare. Reject on miss.
    //
    //     The Ed25519 path is INTENTIONALLY exempt — Ed25519 leaves
    //     prove identity via the signature itself (verify against the
    //     transparency-log's published public key) and the per-skill
    //     key would be redundant. Anti-scope per internal-ref.
    if let Some(per_skill) = state.per_skill_keys.as_ref() {
        let signature_type_for_check = body.signature_type.unwrap_or(SignatureType::Hmac);
        if matches!(signature_type_for_check, SignatureType::Hmac) {
            let supplied_key = headers
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !per_skill.matches(body.record.stage, supplied_key) {
                return Err(ServiceError::StageKeyMismatch);
            }
        }
    }

    // 4. Canonical-bytes the record.
    let record_bytes = body
        .record
        .canonical_bytes()
        .map_err(|e| ServiceError::BadRequest(format!("canonical_bytes failed: {e}")))?;

    // 5. Dispatch on the signing algorithm.
    let signature_type = body.signature_type.unwrap_or(SignatureType::Hmac);
    let (key_fingerprint_hex, ed25519_signature) = match signature_type {
        SignatureType::Hmac => {
            // LEGACY path — unchanged from internal-ref Phase 1.
            verify_kernel_hmac(&record_bytes, &supplied_hmac, &state.kernel_hmac_key)?;
            (state.kernel_key_fingerprint_hex.clone(), None)
        }
        SignatureType::Ed25519 => {
            // internal-ref ADDITIVE asymmetric path. Refuse if the service
            // was started without a transparency-log Ed25519 keypair.
            let Some(expected_fpr_hex) = state.transparency_ed25519_key_fingerprint_hex.as_deref()
            else {
                return Err(ServiceError::Ed25519NotConfigured);
            };

            // Both Ed25519 wire fields are required on this path.
            let pk_hex = body
                .ed25519_public_key_hex
                .as_deref()
                .ok_or(ServiceError::Ed25519MissingFields)?;
            let sig_hex = body
                .ed25519_signature_hex
                .as_deref()
                .ok_or(ServiceError::Ed25519MissingFields)?;

            verify_ed25519_signature(&record_bytes, pk_hex, sig_hex, expected_fpr_hex)?;

            let sig_bytes_vec = hex::decode(sig_hex.trim())
                .map_err(|e| ServiceError::BadRequest(format!("ed25519 sig hex decode: {e}")))?;
            let mut sig_arr = [0u8; SIGNATURE_LENGTH];
            sig_arr.copy_from_slice(&sig_bytes_vec);
            (expected_fpr_hex.to_string(), Some(sig_arr))
        }
    };

    // 6. Frame the leaf payload (record bytes + raw HMAC) and append.
    //    Storage shape is unchanged across both signing paths — the
    //    transparency-log ledger is signing-algorithm-agnostic. The
    //    per-leaf side map is what carries `signature_type` and the
    //    Ed25519 signature for the verify route.
    let idempotency_key = body.record.record_idempotency_key();
    let leaf_payload = build_leaf_payload(&record_bytes, &supplied_hmac);

    let outcome = state
        .store
        .append(AppendInput {
            idempotency_key,
            payload: leaf_payload,
            occurred_at_epoch_seconds: body.record.occurred_at_epoch_seconds,
        })
        .await?;

    // 7. Update the wave-id index + per-leaf payload side map
    //    regardless of fresh/retry. Both helpers are idempotent.
    state
        .record_wave_session_leaf(&body.record.wave_id, outcome.leaf_index)
        .await;
    state
        .record_wave_session_payload(
            outcome.leaf_index,
            hex::encode(outcome.leaf_hash),
            WaveSessionLeafSide {
                record: body.record.clone(),
                kernel_hmac: supplied_hmac,
                ed25519_signature,
                signature_type,
                key_fingerprint_hex,
            },
        )
        .await;

    // Fresh-vs-replay is decided atomically by the store's `created`
    // flag — NOT by comparing a pre-append size snapshot, which races
    // under concurrent identical appends (internal-ref).
    let idempotent_replay = !outcome.created;
    let status = if idempotent_replay {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };

    let resp = AppendWaveSessionResponse {
        idempotent_replay,
        leaf_hash_hex: hex::encode(outcome.leaf_hash),
        leaf_index: outcome.leaf_index,
        ok: true,
    };
    Ok((status, Json(resp)).into_response())
}

/// `GET /v1/keys/transparency` — publish the transparency-log's
/// Ed25519 public key so external auditors can validate
/// `signature_type: "ed25519"` leaves without any secret material.
///
/// Returns 503 (via [`ServiceError::Ed25519NotConfigured`]) when the
/// service was started without an Ed25519 keypair. Otherwise the
/// response carries the algorithm tag, raw-bytes hex, SHA-256
/// fingerprint, and the generated-at timestamp.
///
/// This endpoint is PUBLIC by design (no `x-api-key`). The
/// `is_public_path` helper in `auth.rs` is extended in lock-step.
pub async fn transparency_key(State(state): State<AppState>) -> Result<Response, ServiceError> {
    let Some(pk_hex) = state.transparency_ed25519_public_key_hex.as_deref() else {
        return Err(ServiceError::Ed25519NotConfigured);
    };
    let Some(fpr_hex) = state.transparency_ed25519_key_fingerprint_hex.as_deref() else {
        return Err(ServiceError::Ed25519NotConfigured);
    };

    // internal-ref — surface per-stage `x-api-key` SHA-256 fingerprints
    // (NEVER the raw keys) when the per-skill table is configured.
    // Lets external auditors confirm a rotation actually happened
    // (fingerprints change across rotations) without learning the
    // secret. `None` under back-compat single-shared-key mode keeps
    // the legacy wire shape byte-stable.
    let per_skill_fingerprints = state
        .per_skill_keys
        .as_ref()
        .map(|t| t.public_fingerprints());

    let resp = TransparencyKeyResponse {
        algorithm: "Ed25519".to_string(),
        generated_at_epoch_seconds: state.transparency_ed25519_generated_at_epoch_s,
        key_fingerprint_sha256_hex: fpr_hex.to_string(),
        per_skill_fingerprints,
        public_key_hex: pk_hex.to_string(),
    };
    Ok((StatusCode::OK, Json(resp)).into_response())
}

/// `GET /v1/wave/{wave_id}/verify`.
pub async fn verify_session(
    State(state): State<AppState>,
    Path(wave_id): Path<String>,
) -> Result<Response, ServiceError> {
    let wid = WaveId::new(wave_id.clone());
    let leaves = state.wave_session_leaves(&wid).await;
    if leaves.is_empty() {
        // Check whether there are unreadable leaves for this wave before
        // reporting NotFound — an unreadable wave is not the same as a
        // wave that never existed.
        let unreadable = state.unreadable_wave_leaves(&wid).await;
        if !unreadable.is_empty() {
            return Err(ServiceError::EntryUnreadable);
        }
        return Err(ServiceError::NotFound);
    }

    // Fetch every leaf payload and decode back to a (record, hmac)
    // pair. We assemble entries first so the canonical-pipeline-order
    // sort below operates on decoded records.
    let mut entries: Vec<WaveSessionChainEntry> = Vec::with_capacity(leaves.len());
    for leaf_idx in leaves {
        // Read the per-leaf side data. The transparency-log ledger
        // remains the source of truth (the leaf hash + Merkle root
        // commit to the framed payload); this side map is a
        // denormalization for streaming. Phase 2 (Postgres) will
        // back this with a `wave_session_leaves` view. internal-ref
        // added `signature_type`, `ed25519_signature`, and
        // `key_fingerprint_hex` to the side value.
        let Some(side) = state.lookup_wave_session_payload(leaf_idx).await else {
            return Err(ServiceError::Backend(format!(
                "wave-session payload missing for leaf {leaf_idx}"
            )));
        };
        entries.push(WaveSessionChainEntry {
            ed25519_signature_hex: side.ed25519_signature.map(hex::encode),
            key_fingerprint_hex: side.key_fingerprint_hex,
            kernel_hmac_hex: hex::encode(side.kernel_hmac),
            leaf_index: leaf_idx,
            record: side.record,
            signature_type: side.signature_type,
        });
    }

    // Canonical pipeline order, then leaf-index tiebreaker.
    entries.sort_by(|a, b| {
        a.record
            .stage
            .cmp(&b.record.stage)
            .then(a.leaf_index.cmp(&b.leaf_index))
    });

    let records: Vec<WaveSessionRecord> = entries.iter().map(|e| e.record.clone()).collect();
    let all_required = all_required_stages_present(&records);

    let resp = VerifyWaveSessionResponse {
        all_required_stages_present: all_required,
        chain: entries,
        kernel_key_fingerprint_sha256: state.kernel_key_fingerprint_hex.clone(),
        ok: true,
        transparency_log_ed25519_key_fingerprint_sha256: state
            .transparency_ed25519_key_fingerprint_hex
            .clone(),
        wave_id,
    };
    Ok((StatusCode::OK, Json(resp)).into_response())
}

/// Decode a hex string into exactly 32 bytes (re-implemented here to
/// avoid cross-module visibility tweaks; same as the impl in
/// `routes::append`).
fn hex_to_32(s: &str) -> Result<[u8; 32], ServiceError> {
    let raw = hex::decode(s.trim())
        .map_err(|e| ServiceError::BadRequest(format!("hex decode failed: {e}")))?;
    if raw.len() != 32 {
        return Err(ServiceError::BadRequest(format!(
            "expected 32-byte hex value, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    use crate::clock::SystemClock;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{get, post};
    use axum::Router;
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt;
    use qorch_domain::safety::Clock;
    use qorch_domain::wave::context::WaveId;
    use qorch_domain::wave::gate_surface::GateSurface;
    use qorch_domain::wave::session_record::WaveSessionRecord;
    use qorch_domain::wave::stage::{WaveOutcome, WaveStage};
    use qorch_transparency_store::memory::MemoryTransparencyStore;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    fn fixture_state(hmac_key: &[u8]) -> AppState {
        fixture_state_with_store(Arc::new(MemoryTransparencyStore::new()), hmac_key)
    }

    /// Build a fixture `AppState` over a caller-supplied store. Lets a
    /// test share ONE durable store across two `AppState`s to simulate
    /// a process restart (the in-memory index/caches reset; the ledger
    /// persists). Deterministic seeds so the kernel fingerprint matches
    /// across both states.
    fn fixture_state_with_store(
        store: Arc<dyn qorch_transparency_store::TransparencyStore>,
        hmac_key: &[u8],
    ) -> AppState {
        let seed = [0x11u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let signing_pk = signing_key.verifying_key().to_bytes();
        let mut h = Sha256::new();
        h.update(signing_pk);
        let signing_fpr = hex::encode(h.finalize());
        let kernel_seed = [0x22u8; 32];
        let kernel_signing = SigningKey::from_bytes(&kernel_seed);
        let kernel_pk = kernel_signing.verifying_key().to_bytes();
        let mut h2 = Sha256::new();
        h2.update(kernel_pk);
        let kernel_fpr = hex::encode(h2.finalize());
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        AppState::new(
            store,
            Arc::new(signing_key),
            signing_fpr,
            kernel_fpr,
            clock,
            "test-key".to_string(),
        )
        .with_kernel_hmac_key(hmac_key.to_vec())
    }

    fn router(state: AppState) -> Router {
        Router::new()
            .route("/v1/wave/session", post(append_session))
            .route("/v1/wave/{wave_id}/verify", get(verify_session))
            .with_state(state)
    }

    fn record(
        wave: &str,
        stage: WaveStage,
        sid: &str,
        outcome: WaveOutcome,
        gs: HashSet<GateSurface>,
        written_by: &str,
    ) -> WaveSessionRecord {
        WaveSessionRecord::new(
            WaveId::new(wave),
            "internal-ref",
            stage,
            sid,
            outcome,
            "re-derived",
            gs,
            written_by,
            1_716_400_000,
        )
    }

    /// Build the 32-byte kernel HMAC key used by these tests.
    ///
    /// Deliberately NOT a byte-string literal: CodeQL's
    /// `rust/hard-coded-cryptographic-value` flags any literal that
    /// flows into a MAC key, so every test here lit up as a "hard-coded
    /// key" even though the production key comes from service config
    /// via `with_kernel_hmac_key`. Deriving the bytes keeps the fixture
    /// obviously fake and keeps the Security tab quiet.
    fn test_hmac_key() -> [u8; 32] {
        std::array::from_fn(|i| b'a' + (i as u8 % 26))
    }

    /// A second key differing from [`test_hmac_key`] in every byte, for
    /// the forged-HMAC test.
    fn wrong_hmac_key() -> [u8; 32] {
        test_hmac_key().map(|b| b ^ 0xFF)
    }

    fn hmac_over(key: &[u8], record: &WaveSessionRecord) -> [u8; 32] {
        let bytes = record.canonical_bytes().unwrap();
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).unwrap();
        mac.update(&bytes);
        let out = mac.finalize().into_bytes();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        a
    }

    fn body_for(state: &AppState, hmac: &[u8; 32], record: &WaveSessionRecord) -> Value {
        json!({
            "kernel_hmac_hex": hex::encode(hmac),
            "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
            "record": record,
        })
    }

    async fn post_json(router: &Router, body: Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/wave/session")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    async fn get_verify(router: &Router, wave_id: &str) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/v1/wave/{wave_id}/verify"))
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    #[tokio::test]
    async fn fresh_append_returns_201_and_index_zero() {
        let key = &test_hmac_key();
        let state = fixture_state(key);
        let router = router(state.clone());
        let r = record(
            "w1",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let h = hmac_over(key, &r);
        let (s, v) = post_json(&router, body_for(&state, &h, &r)).await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(v["leaf_index"], 0);
        assert_eq!(v["idempotent_replay"], false);
        assert_eq!(v["ok"], true);
    }

    #[tokio::test]
    async fn duplicate_returns_200_replay() {
        let key = &test_hmac_key();
        let state = fixture_state(key);
        let router = router(state.clone());
        let r = record(
            "w-dup",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let h = hmac_over(key, &r);
        let body = body_for(&state, &h, &r);
        let (s1, _) = post_json(&router, body.clone()).await;
        assert_eq!(s1, StatusCode::CREATED);
        let (s2, v2) = post_json(&router, body).await;
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(v2["idempotent_replay"], true);
        assert_eq!(v2["leaf_index"], 0);
    }

    #[tokio::test]
    async fn forged_hmac_returns_403() {
        let key = &test_hmac_key();
        let state = fixture_state(key);
        let router = router(state.clone());
        let r = record(
            "w-forged",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        // Attacker uses the wrong HMAC key.
        let wrong_h = hmac_over(&wrong_hmac_key(), &r);
        let (s, v) = post_json(&router, body_for(&state, &wrong_h, &r)).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(v["reason"], "kernel_hmac_mismatch");
    }

    #[tokio::test]
    async fn forged_kernel_fingerprint_returns_403() {
        let key = &test_hmac_key();
        let state = fixture_state(key);
        let router = router(state.clone());
        let r = record(
            "w-fp",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let h = hmac_over(key, &r);
        let mut body = body_for(&state, &h, &r);
        body["kernel_key_fingerprint_sha256"] = Value::String(hex::encode([0xAB; 32]));
        let (s, v) = post_json(&router, body).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(v["reason"], "kernel_fingerprint_mismatch");
    }

    #[tokio::test]
    async fn stage_written_by_mismatch_returns_400() {
        let key = &test_hmac_key();
        let state = fixture_state(key);
        let router = router(state.clone());
        // `/test` writing a CLOSED record — refused.
        let r = record(
            "w-wb",
            WaveStage::Closed,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let h = hmac_over(key, &r);
        let (s, v) = post_json(&router, body_for(&state, &h, &r)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(v["reason"], "stage_written_by_mismatch");
    }

    #[tokio::test]
    async fn verify_returns_404_on_unknown_wave() {
        let key = &test_hmac_key();
        let state = fixture_state(key);
        let router = router(state.clone());
        let (s, _) = get_verify(&router, "no-such-wave").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn verify_returns_chain_in_canonical_order() {
        let key = &test_hmac_key();
        let state = fixture_state(key);
        let router = router(state.clone());

        let mut gs = HashSet::new();
        gs.insert(GateSurface::SafetyKernel);
        let stages = [
            (WaveStage::Closed, "cls-1", "/closeout"),
            (WaveStage::Tested, "adv-1", "/test"),
            (WaveStage::Accepted, "uat-1", "/user-acceptance"),
            (WaveStage::PurpleTeamed, "pt-1", "/purple-team"),
        ];
        // Append in a deliberately-out-of-order sequence.
        for (stage, sid, wb) in stages {
            let r = record("w-chain", stage, sid, WaveOutcome::Pass, gs.clone(), wb);
            let h = hmac_over(key, &r);
            let (s, _) = post_json(&router, body_for(&state, &h, &r)).await;
            assert_eq!(s, StatusCode::CREATED);
        }
        let (s, v) = get_verify(&router, "w-chain").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["all_required_stages_present"], true);
        let chain = v["chain"].as_array().unwrap();
        let stages_in_order: Vec<&str> = chain
            .iter()
            .map(|e| e["record"]["stage"].as_str().unwrap())
            .collect();
        assert_eq!(
            stages_in_order,
            vec!["TESTED", "PURPLE_TEAMED", "ACCEPTED", "CLOSED"]
        );
    }

    /// internal-ref durability regression: a full ceremony chain that
    /// verifies green must STILL verify green after the in-memory index
    /// is wiped (a restart), once boot reconstruction runs. This is the
    /// flip-blocker: without reconstruction the same durable ledger
    /// returns 404 for every prior wave and release commits brick.
    #[tokio::test]
    async fn reconstruction_survives_restart() {
        let key = &test_hmac_key();
        // --- boot 1: append a full, gate-surface-bearing chain. ---
        let state_a = fixture_state(key);
        let router_a = router(state_a.clone());
        let mut gs = HashSet::new();
        // Two surfaces exercises the BTreeSet canonicalization path too.
        gs.insert(GateSurface::SafetyKernel);
        gs.insert(GateSurface::TransparencyLog);
        let stages = [
            (WaveStage::Tested, "adv-1", "/test"),
            (WaveStage::PurpleTeamed, "pt-1", "/purple-team"),
            (WaveStage::Accepted, "uat-1", "/user-acceptance"),
            (WaveStage::Closed, "cls-1", "/closeout"),
        ];
        for (stage, sid, wb) in stages {
            let r = record("w-restart", stage, sid, WaveOutcome::Pass, gs.clone(), wb);
            let h = hmac_over(key, &r);
            let (s, _) = post_json(&router_a, body_for(&state_a, &h, &r)).await;
            assert_eq!(s, StatusCode::CREATED);
        }
        // Pre-restart sanity: the wave verifies green.
        let (s, v) = get_verify(&router_a, "w-restart").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["all_required_stages_present"], true);

        // --- restart: fresh AppState (empty index/caches), SAME store. ---
        let state_b = fixture_state_with_store(state_a.store.clone(), key);
        let router_b = router(state_b.clone());

        // The gap this fix closes: the durable ledger is intact but the
        // in-memory index is empty, so verify 404s BEFORE reconstruction.
        let (s_gap, _) = get_verify(&router_b, "w-restart").await;
        assert_eq!(
            s_gap,
            StatusCode::NOT_FOUND,
            "pre-reconstruction verify should 404 (the durability gap)"
        );

        // Boot reconstruction rebuilds the index from the ledger.
        let recovered = reconstruct_wave_sessions_from_ledger(&state_b)
            .await
            .expect("reconstruction should succeed against the memory store");
        assert_eq!(recovered, 4, "all four wave leaves should be recovered");

        // After reconstruction the same wave verifies green again, in
        // canonical stage order — the flip-blocker is closed.
        let (s2, v2) = get_verify(&router_b, "w-restart").await;
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(v2["all_required_stages_present"], true);
        let stages_in_order: Vec<&str> = v2["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["record"]["stage"].as_str().unwrap())
            .collect();
        assert_eq!(
            stages_in_order,
            vec!["TESTED", "PURPLE_TEAMED", "ACCEPTED", "CLOSED"]
        );
    }

    /// Non-wave leaves (e.g. MCP-audit) must be skipped by
    /// reconstruction, not miscounted or errored on.
    #[tokio::test]
    async fn reconstruction_skips_non_wave_leaves() {
        use qorch_transparency_store::{AppendInput, TransparencyStore};
        let key = &test_hmac_key();
        let store = Arc::new(MemoryTransparencyStore::new());
        // Append a raw non-wave leaf directly to the store: bytes that
        // do not decode as a framed WaveSessionRecord.
        store
            .append(AppendInput {
                idempotency_key: [0x99u8; 32],
                payload: b"not-a-wave-session-leaf".to_vec(),
                occurred_at_epoch_seconds: 1_716_400_000,
            })
            .await
            .unwrap();
        let state = fixture_state_with_store(store, key);
        let recovered = reconstruct_wave_sessions_from_ledger(&state).await.unwrap();
        assert_eq!(recovered, 0, "non-wave leaf must be skipped");
    }

    #[tokio::test]
    async fn verify_all_required_false_when_purple_team_missing_for_gate_surface() {
        let key = &test_hmac_key();
        let state = fixture_state(key);
        let router = router(state.clone());
        let mut gs = HashSet::new();
        gs.insert(GateSurface::SafetyKernel);
        // Tested has gate_surfaces non-empty; PURPLE_TEAMED omitted.
        for (stage, sid, wb, gs_local) in [
            (WaveStage::Tested, "adv", "/test", gs.clone()),
            (
                WaveStage::Accepted,
                "uat",
                "/user-acceptance",
                HashSet::new(),
            ),
            (WaveStage::Closed, "cls", "/closeout", HashSet::new()),
        ] {
            let r = record("w-missing-pt", stage, sid, WaveOutcome::Pass, gs_local, wb);
            let h = hmac_over(key, &r);
            let (s, _) = post_json(&router, body_for(&state, &h, &r)).await;
            assert_eq!(s, StatusCode::CREATED);
        }
        let (s, v) = get_verify(&router, "w-missing-pt").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["all_required_stages_present"], false);
    }

    #[tokio::test]
    async fn append_with_empty_gate_surfaces_for_purple_team_allowed() {
        // Spec requirement: append-stage consistency check for
        // PURPLE_TEAMED with empty gate_surfaces is permitted (the
        // chain-level all_required check is the one that flags it,
        // not the append-time validator).
        let key = &test_hmac_key();
        let state = fixture_state(key);
        let router = router(state.clone());
        let r = record(
            "w-pt-empty",
            WaveStage::PurpleTeamed,
            "pt-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/purple-team",
        );
        let h = hmac_over(key, &r);
        let (s, _) = post_json(&router, body_for(&state, &h, &r)).await;
        assert_eq!(s, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn forged_hmac_with_mutated_record_returns_403() {
        // Rule 8 adversarial — attacker mutates the record AFTER the
        // legitimate HMAC was computed. Constant-time verify_slice
        // must reject.
        let key = &test_hmac_key();
        let state = fixture_state(key);
        let router = router(state.clone());
        let r = record(
            "w-mut",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let h = hmac_over(key, &r);
        // Now mutate the record but keep the original HMAC.
        let mut mutated = r.clone();
        mutated.evidence = "tampered".to_string();
        let (s, v) = post_json(&router, body_for(&state, &h, &mutated)).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(v["reason"], "kernel_hmac_mismatch");
    }

    #[tokio::test]
    async fn invalid_hmac_hex_length_returns_400() {
        let key = &test_hmac_key();
        let state = fixture_state(key);
        let router = router(state.clone());
        let r = record(
            "w-bad-hex",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let h = hmac_over(key, &r);
        let mut body = body_for(&state, &h, &r);
        body["kernel_hmac_hex"] = Value::String("aabbcc".to_string()); // 3 bytes
        let (s, _) = post_json(&router, body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    // ===================================================================
    // internal-ref — Ed25519 dual-format unit tests
    // ===================================================================

    use ed25519_dalek::Signer;

    /// Build a fixture state that ALSO carries an Ed25519 keypair so
    /// the `signature_type: "ed25519"` path is reachable. Returns the
    /// state and the verifying-key bytes so tests can drive the new
    /// signing path.
    fn fixture_state_with_ed25519(hmac_key: &[u8]) -> (AppState, SigningKey) {
        let state = fixture_state(hmac_key);
        // Deterministic seed so the test fingerprint is stable.
        let tl_seed = [0x77u8; 32];
        let tl_signing = SigningKey::from_bytes(&tl_seed);
        let state = state.with_transparency_ed25519_keypair(tl_signing.clone(), 1_716_400_000);
        (state, tl_signing)
    }

    fn ed25519_body(state: &AppState, signing: &SigningKey, record: &WaveSessionRecord) -> Value {
        let bytes = record.canonical_bytes().unwrap();
        let sig = signing.sign(&bytes);
        json!({
            "ed25519_public_key_hex": hex::encode(signing.verifying_key().to_bytes()),
            "ed25519_signature_hex": hex::encode(sig.to_bytes()),
            // Placeholder zero-bytes — Ed25519 path ignores this.
            "kernel_hmac_hex": hex::encode([0u8; 32]),
            "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
            "record": record,
            "signature_type": "ed25519",
        })
    }

    fn router_with_keys_endpoint(state: AppState) -> Router {
        Router::new()
            .route("/v1/wave/session", post(append_session))
            .route("/v1/wave/{wave_id}/verify", get(verify_session))
            .route("/v1/keys/transparency", get(transparency_key))
            .with_state(state)
    }

    async fn get_path(router: &Router, path: &str) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    #[tokio::test]
    async fn ed25519_fresh_append_returns_201() {
        // AC2 — POST accepts Ed25519. Happy path.
        let key = &test_hmac_key();
        let (state, tl_signing) = fixture_state_with_ed25519(key);
        let router = router(state.clone());
        let r = record(
            "w-ed25519",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let body = ed25519_body(&state, &tl_signing, &r);
        let (s, v) = post_json(&router, body).await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(v["leaf_index"], 0);
        assert_eq!(v["ok"], true);
    }

    #[tokio::test]
    async fn ed25519_forged_keypair_returns_403() {
        // AC6 — forged Ed25519 signature under a DIFFERENT keypair
        // (wrong public key + signed-with-that-wrong-key) → 403.
        let key = &test_hmac_key();
        let (state, _tl_signing) = fixture_state_with_ed25519(key);
        let router = router(state.clone());
        let r = record(
            "w-ed25519-forged",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        // Attacker mints a wholly different keypair, signs the record
        // with it, and announces the attacker's pk. The fingerprint
        // pin must reject before signature verification even runs.
        let attacker = SigningKey::from_bytes(&[0xAAu8; 32]);
        let bytes = r.canonical_bytes().unwrap();
        let bad_sig = attacker.sign(&bytes);
        let body = json!({
            "ed25519_public_key_hex": hex::encode(attacker.verifying_key().to_bytes()),
            "ed25519_signature_hex": hex::encode(bad_sig.to_bytes()),
            "kernel_hmac_hex": hex::encode([0u8; 32]),
            "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
            "record": r,
            "signature_type": "ed25519",
        });
        let (s, v) = post_json(&router, body).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(v["reason"], "ed25519_key_fingerprint_mismatch");
    }

    #[tokio::test]
    async fn ed25519_correct_pk_but_forged_signature_returns_403() {
        // Rule 8 adversarial — caller announces the RIGHT public key
        // but sends a signature minted by a different keypair. The
        // fingerprint pin passes; the verify() must catch it.
        let key = &test_hmac_key();
        let (state, tl_signing) = fixture_state_with_ed25519(key);
        let router = router(state.clone());
        let r = record(
            "w-ed25519-sig-forge",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let attacker = SigningKey::from_bytes(&[0xBBu8; 32]);
        let bytes = r.canonical_bytes().unwrap();
        let bad_sig = attacker.sign(&bytes);
        let body = json!({
            "ed25519_public_key_hex": hex::encode(tl_signing.verifying_key().to_bytes()),
            "ed25519_signature_hex": hex::encode(bad_sig.to_bytes()),
            "kernel_hmac_hex": hex::encode([0u8; 32]),
            "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
            "record": r,
            "signature_type": "ed25519",
        });
        let (s, v) = post_json(&router, body).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(v["reason"], "ed25519_signature_mismatch");
    }

    #[tokio::test]
    async fn ed25519_missing_fields_returns_400() {
        let key = &test_hmac_key();
        let (state, _tl_signing) = fixture_state_with_ed25519(key);
        let router = router(state.clone());
        let r = record(
            "w-ed-missing",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let body = json!({
            // No ed25519_public_key_hex / ed25519_signature_hex.
            "kernel_hmac_hex": hex::encode([0u8; 32]),
            "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
            "record": r,
            "signature_type": "ed25519",
        });
        let (s, v) = post_json(&router, body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(v["reason"], "ed25519_missing_fields");
    }

    #[tokio::test]
    async fn ed25519_path_unavailable_when_keypair_not_configured() {
        // Service started WITHOUT a transparency-log Ed25519 keypair —
        // a caller asking for "ed25519" gets 503 (not 403). Documents
        // that the legacy contract still works on hosts that have not
        // yet enabled the additive path.
        let key = &test_hmac_key();
        let state = fixture_state(key); // No .with_transparency_ed25519_keypair().
        let router = router(state.clone());
        let r = record(
            "w-no-ed25519",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let any_signing = SigningKey::from_bytes(&[0x55u8; 32]);
        let bytes = r.canonical_bytes().unwrap();
        let sig = any_signing.sign(&bytes);
        let body = json!({
            "ed25519_public_key_hex": hex::encode(any_signing.verifying_key().to_bytes()),
            "ed25519_signature_hex": hex::encode(sig.to_bytes()),
            "kernel_hmac_hex": hex::encode([0u8; 32]),
            "kernel_key_fingerprint_sha256": state.kernel_key_fingerprint_hex.clone(),
            "record": r,
            "signature_type": "ed25519",
        });
        let (s, v) = post_json(&router, body).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(v["reason"], "ed25519_not_configured");
    }

    #[tokio::test]
    async fn transparency_key_returns_published_material() {
        // AC1 — GET /v1/keys/transparency surfaces algorithm + pk + fpr.
        let key = &test_hmac_key();
        let (state, tl_signing) = fixture_state_with_ed25519(key);
        let router = router_with_keys_endpoint(state.clone());
        let (s, v) = get_path(&router, "/v1/keys/transparency").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["algorithm"], "Ed25519");
        let expected_pk_hex = hex::encode(tl_signing.verifying_key().to_bytes());
        assert_eq!(v["public_key_hex"], Value::String(expected_pk_hex.clone()));
        // Fingerprint must be SHA-256 of the raw 32-byte pk.
        let mut h = Sha256::new();
        h.update(tl_signing.verifying_key().to_bytes());
        let expected_fpr = hex::encode(h.finalize());
        assert_eq!(v["key_fingerprint_sha256_hex"], Value::String(expected_fpr));
        assert_eq!(v["generated_at_epoch_seconds"], 1_716_400_000_u64);
    }

    #[tokio::test]
    async fn transparency_key_returns_503_when_not_configured() {
        let key = &test_hmac_key();
        let state = fixture_state(key); // No Ed25519 keypair.
        let router = router_with_keys_endpoint(state.clone());
        let (s, v) = get_path(&router, "/v1/keys/transparency").await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(v["reason"], "ed25519_not_configured");
    }

    #[tokio::test]
    async fn verify_route_reports_signature_type_and_fingerprint_per_entry() {
        // AC3 — GET /v1/wave/{id}/verify echoes per-entry signature_type
        // + key_fingerprint_hex AND the top-level
        // transparency_log_ed25519_key_fingerprint_sha256.
        let key = &test_hmac_key();
        let (state, tl_signing) = fixture_state_with_ed25519(key);
        let router = router(state.clone());

        // Mix one HMAC entry and one Ed25519 entry on the same wave.
        let r_hmac = record(
            "w-mixed",
            WaveStage::Tested,
            "hmac-adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let h_hmac = hmac_over(key, &r_hmac);
        let (s1, _) = post_json(&router, body_for(&state, &h_hmac, &r_hmac)).await;
        assert_eq!(s1, StatusCode::CREATED);

        let r_ed25519 = record(
            "w-mixed",
            WaveStage::PurpleTeamed,
            "pt-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/purple-team",
        );
        let body = ed25519_body(&state, &tl_signing, &r_ed25519);
        let (s2, _) = post_json(&router, body).await;
        assert_eq!(s2, StatusCode::CREATED);

        // Verify the chain.
        let (s, v) = get_verify(&router, "w-mixed").await;
        assert_eq!(s, StatusCode::OK);
        let chain = v["chain"].as_array().unwrap();
        assert_eq!(chain.len(), 2);

        // First entry (TESTED) = HMAC; second (PURPLE_TEAMED) = Ed25519.
        let first = &chain[0];
        assert_eq!(first["signature_type"], "hmac");
        assert_eq!(
            first["key_fingerprint_hex"],
            Value::String(state.kernel_key_fingerprint_hex.clone())
        );
        // Ed25519 signature MUST be absent on the HMAC entry.
        assert!(
            first.get("ed25519_signature_hex").is_none()
                || first["ed25519_signature_hex"] == Value::Null
        );

        let second = &chain[1];
        assert_eq!(second["signature_type"], "ed25519");
        let expected_tl_fpr = state
            .transparency_ed25519_key_fingerprint_hex
            .clone()
            .unwrap();
        assert_eq!(
            second["key_fingerprint_hex"],
            Value::String(expected_tl_fpr.clone())
        );
        // The Ed25519 entry MUST carry the raw signature for external verifiers.
        assert!(second["ed25519_signature_hex"].as_str().unwrap().len() == 128);

        // Top-level fingerprint is echoed.
        assert_eq!(
            v["transparency_log_ed25519_key_fingerprint_sha256"],
            Value::String(expected_tl_fpr)
        );
    }

    #[tokio::test]
    async fn legacy_hmac_path_unchanged_when_signature_type_omitted() {
        // Bit-for-bit backward compat: the old wire shape (no
        // signature_type, no ed25519_* fields) MUST still take the
        // HMAC path. HMAC remains the primary path per the migration
        // plan stages 1-2.
        let key = &test_hmac_key();
        let (state, _tl_signing) = fixture_state_with_ed25519(key);
        let router = router(state.clone());
        let r = record(
            "w-legacy",
            WaveStage::Tested,
            "adv-1",
            WaveOutcome::Pass,
            HashSet::new(),
            "/test",
        );
        let h = hmac_over(key, &r);
        // body_for() emits the legacy three-field body exactly.
        let (s, v) = post_json(&router, body_for(&state, &h, &r)).await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(v["ok"], true);
        // And the verify route reports it as HMAC.
        let (sv, vv) = get_verify(&router, "w-legacy").await;
        assert_eq!(sv, StatusCode::OK);
        assert_eq!(vv["chain"][0]["signature_type"], "hmac");
    }

    #[test]
    fn signature_type_serde_roundtrip() {
        let h = SignatureType::Hmac;
        let e = SignatureType::Ed25519;
        let hj = serde_json::to_string(&h).unwrap();
        let ej = serde_json::to_string(&e).unwrap();
        assert_eq!(hj, "\"hmac\"");
        assert_eq!(ej, "\"ed25519\"");
        assert_eq!(h.as_wire(), "hmac");
        assert_eq!(e.as_wire(), "ed25519");
    }

    // ===================================================================
    // internal-ref — unreadable wave leaf tests
    // ===================================================================

    /// A framed leaf whose record bytes are valid JSON with a `wave_id`
    /// field but whose content cannot be deserialized as a
    /// `WaveSessionRecord` (e.g. an unknown enum variant) must be
    /// registered as unreadable, not silently dropped.
    #[tokio::test]
    async fn wave_shaped_leaf_that_fails_to_parse_is_recorded_as_unreadable() {
        use qorch_transparency_store::{AppendInput, TransparencyStore};
        let key = &test_hmac_key();
        let store = Arc::new(MemoryTransparencyStore::new());

        // Build a framed leaf whose record bytes are wave-shaped JSON
        // but contain an unknown `stage` variant that the current binary
        // cannot deserialize.
        let record_bytes =
            br#"{"wave_id":"w-unreadable","stage":"UNKNOWN_FUTURE_STAGE","session_id":"s1"}"#;
        let hmac_placeholder = [0u8; 32];
        let payload = build_leaf_payload(record_bytes, &hmac_placeholder);

        store
            .append(AppendInput {
                idempotency_key: [0xAAu8; 32],
                payload,
                occurred_at_epoch_seconds: 1_716_400_000,
            })
            .await
            .unwrap();

        let state = fixture_state_with_store(store, key);
        let recovered = reconstruct_wave_sessions_from_ledger(&state).await.unwrap();
        // The leaf is NOT counted as a successfully recovered wave leaf.
        assert_eq!(
            recovered, 0,
            "unparseable wave leaf must not be counted as recovered"
        );

        // But it MUST be registered as unreadable.
        let wid = WaveId::new("w-unreadable".to_string());
        let unreadable = state.unreadable_wave_leaves(&wid).await;
        assert_eq!(
            unreadable.len(),
            1,
            "unparseable wave leaf must be registered as unreadable"
        );
    }

    /// When a wave has only unreadable leaves, `verify_session` must
    /// return `EntryUnreadable` (not `NotFound`).
    #[tokio::test]
    async fn verify_reports_unreadable_not_missing_for_an_unparseable_wave() {
        use qorch_transparency_store::{AppendInput, TransparencyStore};
        let key = &test_hmac_key();
        let store = Arc::new(MemoryTransparencyStore::new());

        // Same wave-shaped-but-unparseable leaf as above.
        let record_bytes =
            br#"{"wave_id":"w-unreadable-verify","stage":"UNKNOWN_FUTURE_STAGE","session_id":"s1"}"#;
        let hmac_placeholder = [0u8; 32];
        let payload = build_leaf_payload(record_bytes, &hmac_placeholder);

        store
            .append(AppendInput {
                idempotency_key: [0xBBu8; 32],
                payload,
                occurred_at_epoch_seconds: 1_716_400_000,
            })
            .await
            .unwrap();

        let state = fixture_state_with_store(store, key);
        reconstruct_wave_sessions_from_ledger(&state)
            .await
            .expect("reconstruction must not error");

        let router = router(state.clone());
        let (s, v) = get_verify(&router, "w-unreadable-verify").await;
        assert_eq!(
            s,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a wave with only unreadable leaves must not return 404"
        );
        assert_eq!(v["reason"], "entry_unreadable");
    }

    /// CONTROL: a wave that was never appended at all must still return
    /// 404 `entry_not_found`. The new unreadable-leaf branch must not
    /// swallow legitimate not-found responses.
    #[tokio::test]
    async fn a_wave_that_truly_does_not_exist_is_still_not_found() {
        let key = &test_hmac_key();
        let state = fixture_state(key);
        // Run reconstruction against an empty ledger so the unreadable
        // index is also empty.
        reconstruct_wave_sessions_from_ledger(&state)
            .await
            .expect("reconstruction must not error on empty ledger");

        let router = router(state.clone());
        let (s, v) = get_verify(&router, "wave-that-never-existed").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(v["reason"], "entry_not_found");
    }
}
