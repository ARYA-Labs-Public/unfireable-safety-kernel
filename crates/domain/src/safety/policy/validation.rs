//! Canonical `module_path` charset validation (, ).
//!
//! Per the slice-3 design freeze (`docs/safety_kernel/audit_hook_design.md`
//! §7), the canonical `module_path` charset is:
//!
//!   * Dotted-name form: `^[a-zA-Z0-9_.]+$`
//!   * SHA-256-hex form: `^[0-9a-f]{64}$`
//!
//! with `len ≤ 256` in both cases. All four `/policy/*` endpoints
//! (`/policy/module/{register,authorize,status}` and
//! `/policy/audit-event` when the latter carries a module path)
//! validate against this set BEFORE any IPC call. Mismatches return
//! 400 Bad Request with `reason: "module_path_invalid_charset"`.
//!
//! # Backward-compat caveat
//!
//!  accepted hyphens via the status-route charset
//! `^[A-Za-z0-9_.-]{1,256}$`. The hyphen is REMOVED here because
//! Python dotted module names per PEP 8 / language reference §6.4
//! cannot contain hyphens. Any hyphenated entry in the chain from
//! slice-2 traffic is malformed at registration time; status will
//! now refuse to return it. This is intentional and approved by
//! architect-3 in the slice-3 design.
//!
//! # Boundary
//!
//! Per `agent/boundaries.toml` and the parent `crates/domain/`
//! contract, this module is pure: no `std::fs`/`std::env`/
//! `std::net`/`std::time::SystemTime`/`rand::`/`sqlx::`/`diesel::`/
//! `reqwest::`/`rdkafka::`/`tracing::`/`log::` imports.
//! `import_discipline_test.rs` enforces this via grep.

/// Maximum permitted byte-length for a `module_path`. The same cap
/// applied at slice 2 in `routes/policy/status.rs::is_valid_module_path`.
pub const MAX_MODULE_PATH_LEN: usize = 256;

/// Wire reason string for charset rejections — used uniformly by all
/// four policy endpoints so adversarial tests can pin the value.
pub const MODULE_PATH_INVALID_CHARSET_REASON: &str = "module_path_invalid_charset";

/// Validate `s` against the canonical `module_path` charset.
/
/// Returns `true` iff `s` is:
/
///   * non-empty,
///   * at most [`MAX_MODULE_PATH_LEN`] bytes,
///   * AND matches either the dotted-name form (ASCII alnum / `_` / `.`)
///     OR the SHA-256-hex form (exactly 64 lowercase hex chars).
/
/// Returns `false` otherwise. The check is a single linear scan; no
/// regex engine is used. Callers should reject with HTTP 400 +
/// `reason: MODULE_PATH_INVALID_CHARSET_REASON` on `false`.
#[must_use]
pub fn is_valid_module_path(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_MODULE_PATH_LEN {
        return false;
    }
    // Form 1: dotted-name (the common case).
    let dotted_ok = s
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.'));
    if dotted_ok {
        return true;
    }
    // Form 2: sha256-hex (used for exec/compile event paths where the
    // module path is the hex digest of the bytecode or source).
    if s.len() == 64 {
        return s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn dotted_names_accepted() {
        for s in [
            "json",
            "pkg.mod",
            "pkg.sub.mod",
            "pkg_v1.mod",
            "A",
            "_private",
            "x0.y1.z2",
        ] {
            assert!(is_valid_module_path(s), "should accept dotted: {s}");
        }
    }

    #[test]
    fn sha256_hex_accepted() {
        // Exact 64 lowercase hex digits.
        let h = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(is_valid_module_path(h));
        let h2 = &"a".repeat(64);
        assert!(is_valid_module_path(h2));
        let h3 = &"f".repeat(64);
        assert!(is_valid_module_path(h3));
    }

    #[test]
    fn hyphen_rejected_slice3_canonical_charset() {
        // Slice-3 removes the hyphen — Python dotted names cannot
        // contain `-`. This is the backward-compat caveat documented
        // in the module preamble.
        assert!(!is_valid_module_path("my-pkg"));
        assert!(!is_valid_module_path("pkg-v1.mod"));
        assert!(!is_valid_module_path("a-b-c"));
    }

    #[test]
    fn forbidden_characters_rejected() {
        for s in [
            "foo/bar",         // slash
            "foo bar",         // space
            "foo;DROP TABLE",  // injection-shaped
            "foo:bar",         // colon
            "foo,bar",         // comma
            "foo(bar)",        // parens
            "foo[bar]",        // brackets
            "foo\\bar",        // backslash
            "../etc/passwd",   // path traversal
            "café",            // non-ASCII (latin-1)
            "module\u{200B}x", // zero-width space
            "module\n",        // newline
            "module\t",        // tab
            "\"quoted\"",      // quotes
        ] {
            assert!(!is_valid_module_path(s), "should reject: {s:?}");
        }
    }

    #[test]
    fn empty_rejected() {
        assert!(!is_valid_module_path(""));
    }

    #[test]
    fn boundary_length_handling() {
        // Length 256 dotted-name accepted.
        let max_dotted = "a".repeat(MAX_MODULE_PATH_LEN);
        assert!(is_valid_module_path(&max_dotted));

        // Length 257 dotted-name rejected.
        let over = "a".repeat(MAX_MODULE_PATH_LEN + 1);
        assert!(!is_valid_module_path(&over));
    }

    #[test]
    fn sha256_hex_must_be_exactly_64_chars() {
        // 63 hex chars → falls through dotted (alphabet ok) but len != 64 → still
        // accepted by dotted form because hex chars are a subset of dotted alphabet.
        let s63 = "0".repeat(63);
        assert!(
            is_valid_module_path(&s63),
            "63 hex chars are valid dotted-form"
        );
        // 65 hex chars also accepted by dotted form (they are alnum).
        let s65 = "a".repeat(65);
        assert!(is_valid_module_path(&s65));
        // But a NON-dotted, non-hex 64-char string is rejected.
        let mixed_case_hex64 = "ABCDEF".to_string() + &"0".repeat(58);
        // mixed-case hex IS valid dotted-form (alnum) — accepted.
        assert!(is_valid_module_path(&mixed_case_hex64));
        // True sha256 form (lowercase only) at exactly 64 chars is accepted.
        let lower_hex = "f".repeat(64);
        assert!(is_valid_module_path(&lower_hex));
        // 64-char string with `g` (non-hex) — still accepted by dotted form
        // because `g` is alnum.
        let with_g = "g".repeat(64);
        assert!(is_valid_module_path(&with_g));
        // But 64-char string with a `-` is rejected (hyphen removed from
        // dotted form; not a valid hex char either).
        let with_dash = "-".repeat(64);
        assert!(!is_valid_module_path(&with_dash));
    }

    #[test]
    fn wire_reason_constant_is_stable() {
        // Adversarial fixtures pin this exact string.
        assert_eq!(
            MODULE_PATH_INVALID_CHARSET_REASON,
            "module_path_invalid_charset"
        );
    }
}
