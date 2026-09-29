//! internal-ref / internal-ref
//!
//! Guards the checksum pin between the on-disk migration file
//! `migrations/0001_transparency_log.sql` and the checksum that `sqlx`
//! recorded in `_sqlx_migrations` for the live `qorch_tlog` production
//! ledger when it was measured on 2026-09-05:
//!
//!     version 1 | "transparency log" | success = true | 2,348 leaves
//!
//! `sqlx::migrate!` recomputes the SHA-384 of each migration file on every
//! boot and compares it against the checksum stored in the database. If the
//! two disagree, the service refuses to start — full stop, no partial
//! degraded mode. That is exactly the right behavior for a service backed by
//! an append-only transparency log, but it means an "innocent" edit to this
//! .sql file (even whitespace or a comment) is a production outage waiting to
//! happen the next time this service deploys against the existing ledger.
//!
//! These tests turn that outage into a red build here, in CI, before anyone
//! merges the edit.

use sha2::{Digest, Sha384};
use std::path::PathBuf;

/// SHA-384 of `migrations/0001_transparency_log.sql`, hex-encoded lowercase,
/// as recorded against the live `qorch_tlog` ledger's `_sqlx_migrations`
/// row for version 1 ("transparency log") on 2026-09-05. 2,348 leaves were
/// present in that ledger at measurement time.
const LIVE_PROD_CHECKSUM_SHA384: &str = "84d23ebd3cc010298067bbf6588fde230a7b363f5bb33136a830121afdd0f032ed8e54dbcba9e6f62932683f5b5668d3";

const MIGRATION_FILENAME: &str = "0001_transparency_log.sql";

fn migrations_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations")
}

fn migration_file_path() -> PathBuf {
    migrations_dir().join(MIGRATION_FILENAME)
}

fn read_migration_bytes() -> Vec<u8> {
    let path = migration_file_path();
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "failed to read migration file at {}: {e}\n\
             This file backs the live `qorch_tlog` production ledger's applied \
             migration (version 1, \"transparency log\", 2,348 leaves as of \
             2026-09-05). If it has moved or been deleted, sqlx will refuse to \
             boot against that ledger. See internal-ref.",
            path.display()
        )
    })
}

fn sha384_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha384::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[test]
fn migration_file_checksum_matches_the_live_ledger() {
    let bytes = read_migration_bytes();
    let actual = sha384_hex(&bytes);

    assert_eq!(
        actual,
        LIVE_PROD_CHECKSUM_SHA384,
        "\n\n\
         SHA-384 of migrations/{filename} no longer matches the checksum recorded \
         against the live `qorch_tlog` production ledger.\n\n\
         The live ledger's `_sqlx_migrations` row for version 1 (\"transparency \
         log\") holds checksum:\n    {expected}\n\
         and success = true over 2,348 leaves, as measured 2026-09-05.\n\n\
         This test computed:\n    {actual}\n\n\
         Someone has edited migrations/{filename} — even a whitespace or comment \
         change is enough to move the hash. `sqlx::migrate!` recomputes this \
         checksum on every boot and compares it against the one already stored \
         in the database; on mismatch it REFUSES TO START. Deploying this change \
         against the live ledger will not silently re-apply anything — it will \
         hard-fail the boot of a service sitting on 2,348 irreplaceable \
         transparency-log leaves.\n\n\
         If the migration genuinely needs to change, that is a new migration \
         file, not an edit to this one. See internal-ref.\n",
        filename = MIGRATION_FILENAME,
        expected = LIVE_PROD_CHECKSUM_SHA384,
        actual = actual,
    );
}

#[test]
fn migration_filename_yields_the_recorded_version_and_description() {
    // sqlx derives (version, description) from the FILENAME, not from the
    // file's contents: `<version>_<description with underscores as
    // spaces>.sql`. The live ledger's applied row identifies this migration
    // as version 1, description "transparency log". If the file were
    // renamed, sqlx would treat it as a *different* migration from the one
    // already recorded — a strictly worse failure than a checksum mismatch,
    // because it can present as "migration not yet applied" against a
    // database that has already applied it under the old name.
    let entries: Vec<_> = std::fs::read_dir(migrations_dir())
        .expect("migrations directory must exist")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "sql")
                .unwrap_or(false)
        })
        .collect();

    let matching = entries
        .iter()
        .find(|e| e.file_name().to_string_lossy() == MIGRATION_FILENAME);

    assert!(
        matching.is_some(),
        "\n\nExpected to find migrations/{expected} — sqlx derives the applied \
         migration's identity (version 1, description \"transparency log\") \
         from exactly this filename. Renaming or removing it makes this crate's \
         migration a different migration from the one recorded against the live \
         `qorch_tlog` ledger's `_sqlx_migrations` table, which is a worse failure \
         than a checksum mismatch: the ledger already contains an applied row \
         under the old name that this file's contents will never be checked \
         against. See internal-ref.\n",
        expected = MIGRATION_FILENAME,
    );

    // Sanity-check the derivation by hand, so the test is not merely
    // asserting a filename constant but the actual sqlx parsing rule.
    let stem = MIGRATION_FILENAME.strip_suffix(".sql").unwrap();
    let (version_str, description_with_underscores) = stem
        .split_once('_')
        .expect("migration filename must be `<version>_<description>.sql`");
    let version: i64 = version_str
        .parse()
        .expect("migration version prefix must be numeric");
    let description = description_with_underscores.replace('_', " ");

    assert_eq!(
        version, 1,
        "the live ledger recorded this migration as version 1"
    );
    assert_eq!(
        description, "transparency log",
        "the live ledger recorded this migration's description as \"transparency log\""
    );
}

#[test]
fn migrations_directory_holds_exactly_one_file() {
    let sql_files: Vec<_> = std::fs::read_dir(migrations_dir())
        .expect("migrations directory must exist")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "sql")
                .unwrap_or(false)
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();

    assert_eq!(
        sql_files.len(),
        1,
        "\n\nExpected exactly one migration file in migrations/, found {count}: \
         {found:?}.\n\n\
         A second .sql file here would be picked up by `sqlx::migrate!` and \
         applied against the live `qorch_tlog` ledger on the very next boot, \
         alongside the 2,348 leaves already recorded there. Adding a migration \
         is a real, deliberate decision — it has to be planned with the internal-ref \
         cutover in mind, reviewed, and rolled out on purpose. It is not \
         something that should be noticed only after this test fails, or worse, \
         only after it has already run against production. See internal-ref.\n",
        count = sql_files.len(),
        found = sql_files,
    );
}

#[test]
fn checksum_is_sensitive_to_content() {
    // Prove the pin actually catches edits, rather than trivially matching
    // any input. Take the real bytes, perturb them by appending a single
    // trailing newline (kept entirely in memory — never written to disk),
    // and confirm the resulting checksum diverges from the live pin.
    let mut mutated = read_migration_bytes();
    mutated.push(b'\n');

    let mutated_checksum = sha384_hex(&mutated);

    assert_ne!(
        mutated_checksum,
        LIVE_PROD_CHECKSUM_SHA384,
        "\n\nAppending a single trailing newline to migrations/{filename} in \
         memory produced the same SHA-384 as the live `qorch_tlog` ledger's \
         recorded checksum. That means this checksum pin cannot distinguish an \
         edited migration file from the one currently on disk, so it would fail \
         to catch exactly the class of change it exists to guard against. See \
         internal-ref.\n",
        filename = MIGRATION_FILENAME,
    );
}
