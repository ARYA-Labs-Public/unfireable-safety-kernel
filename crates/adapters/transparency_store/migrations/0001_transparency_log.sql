--   §5: transparency-log Postgres schema.
--
-- One row per appended entry. `leaf_index` is BIGSERIAL — Postgres
-- assigns it monotonically at INSERT, and serialization of concurrent
-- transactions guarantees no gaps. `idempotency_key` is the kernel's
-- 32-byte fingerprint (SHA-256 of the token bytes per 
-- §6); the UNIQUE constraint is what makes
-- `INSERT... ON CONFLICT (idempotency_key) DO UPDATE... RETURNING`
-- idempotent.

CREATE TABLE transparency_log (
    leaf_index BIGSERIAL PRIMARY KEY,
    leaf_hash BYTEA NOT NULL CHECK (length(leaf_hash) = 32),
    idempotency_key BYTEA NOT NULL CHECK (length(idempotency_key) = 32),
    payload BYTEA NOT NULL,
    occurred_at_epoch_seconds BIGINT NOT NULL,
    inserted_at_epoch_seconds BIGINT NOT NULL,
    UNIQUE (idempotency_key)
);

CREATE INDEX idx_transparency_log_occurred_at
    ON transparency_log (occurred_at_epoch_seconds);
