# qorch-transparency-store

ARYA Core append-only Merkle transparency-log adapter (Postgres + in-memory).

## What it does

This crate provides an append-only Merkle transparency-log storage adapter (ADR-014 Phase 3 §5, internal-ref Step 4).

The storage contract is defined by the `TransparencyStore` trait, which lives directly in this crate so consumers can write `Arc<dyn TransparencyStore>` without pulling in a specific implementation. Two implementations are provided:

- **`memory::MemoryTransparencyStore`** — an `Arc<Mutex<...>>`-backed in-memory store. Used by the transparency-log service's unit tests, by the reconciler in dev, and by anyone who wants to wire the trait without standing up Postgres.
- **`postgres::PgTransparencyStore`** — a Postgres-backed production store. It uses `SERIALIZABLE` isolation per ADR-014 Phase 3 §5. Its `INSERT ... ON CONFLICT (idempotency_key) DO UPDATE ... RETURNING` ensures that retried appends return the **existing** row's index rather than minting a new one (ADR §6 idempotency demand).

## Public API

- `trait TransparencyStore` — the storage contract.
- `struct AppendInput` — input for an append operation.
- `struct AppendOutcome` — outcome of an append operation.
- `enum StoreError` — store error type.
- `mod memory` — in-memory implementation.
- `mod postgres` — Postgres implementation.

## Usage

Depend on `TransparencyStore` behind an `Arc<dyn TransparencyStore>` and select an implementation at wiring time — `MemoryTransparencyStore` for tests and dev, `PgTransparencyStore` for production.

## Boundary

This crate imports `sqlx`, `tokio`, and `tracing`, which is permissible because it is an adapter. The `qorch-domain` types it references (`MerkleLeaf`, `InclusionProof`, `VerificationError`) stay pure.
