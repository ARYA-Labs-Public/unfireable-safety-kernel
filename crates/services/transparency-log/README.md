# qorch-transparency-log

An append-only Merkle transparency log served over HTTP (axum + rustls).
It implements RFC-6962 inclusion and consistency proofs over a Merkle tree
of appended entries, and signs tree heads with Ed25519. The service listens
on internal port 8100, published as host port 8102 (ADR-014 Phase 3 §3,
internal-ref).

Storage is abstracted behind `qorch-transparency-store`'s
`TransparencyStore` trait, with in-memory and Postgres implementations. The
binary applies the schema on boot via `sqlx::migrate!`; there is no separate
migration step to run before starting the service.

## Why this exists

The kernel POSTs every successful authorization decision to `/v1/append`,
and it does so **fail-closed**: if the append fails, the kernel will not
return a signed token. This crate is the log that receives those appends.
It lives in this repo because this is the canonical safety-kernel repo; the
public repo receives it through the IP-filter cut, never by direct push.

## Routes

| Method | Path                          | Notes                                             |
|--------|-------------------------------|----------------------------------------------------|
| GET    | `/health`                     | public                                              |
| POST   | `/v1/append`                  | requires `x-api-key`; the kernel's append path      |
| GET    | `/v1/verify/{entry_id}`       | inclusion proof for one entry                       |
| GET    | `/v1/sth`                     | Ed25519 signed tree head                            |
| GET    | `/v1/consistency`             | RFC-6962 consistency proof                          |
| POST   | `/v1/wave/session`            | ceremony wave-session record append                 |
| GET    | `/v1/wave/{wave_id}/verify`   | chain verification for a wave                       |
| POST   | `/v1/audit/mcp`               | MCP audit-record append (ADR-016)                   |
| GET    | `/v1/keys/transparency`       | published Ed25519 public key — public by design; it's a public key |

The wave-session routes (`/v1/wave/session`, `/v1/wave/{wave_id}/verify`)
serve ARYA's internal engineering ceremony. A deployment that only needs a
generic transparency log simply never calls them.

## Configuration

The service currently reads its configuration from `QORCH_TRANSPARENCY_*`
environment variables. These names are inherited from the monorepo
deployment this crate was relocated from, and they are still what the live
systemd unit and helm chart set. Renaming the prefix is deliberately deferred to a separate change,
so that the cutover of this service is not simultaneously a rename of its
configuration surface. See `src/settings.rs` for the full set of variables
and their defaults.

## Durability

The append-only ledger itself is durable — it is backed by the configured
`TransparencyStore` (in-memory or Postgres). But several structures derived
from the ledger — the wave-session index, the leaf-hash map, and the detail
cache — are held only in memory. On boot, the service rebuilds them from the
ledger via `reconstruct_wave_sessions_from_ledger`.

Without that reconstruction step, every wave-session verification for a
wave recorded before the last restart would return 404, since the in-memory
index backing `/v1/wave/{wave_id}/verify` would be empty even though the
underlying ledger entries were intact. This was the bug fixed by internal-ref.
`reconstruction_survives_restart` is the regression test guarding it.

## TLS

TLS is provided by `rustls` using the **ring** crypto provider, wired up
through `axum-server`'s `tls-rustls-no-provider` feature so the provider is
selected explicitly rather than picked implicitly. `aws-lc-rs`,
`native-tls`, and `openssl` are not used, and `deny.toml` bans all three at
the workspace level.

## Provenance

Relocated from arya-core's `crates/services/arya-core-transparency-service`
(itself relocated from the monorepo's `crates/services/transparency-log`) by
a mechanical rename, token-identical to the source under the inverse of
that rename. `src/clock.rs` carries a local `SystemClock` because this
workspace has no shared adapters crate to supply one.

`migrations/0001_transparency_log.sql` in the store crate is byte-identical
to the file the live ledger was migrated with; `sqlx` pins its checksum in
`_sqlx_migrations` and refuses to boot on a mismatch. Do not reformat or
re-comment it (`tests/migration_checksum_pin.rs` guards this).
