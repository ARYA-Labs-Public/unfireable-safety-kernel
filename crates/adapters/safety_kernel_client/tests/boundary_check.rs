//!   — Boundary check for AC10.
//!
//! Per `agent/boundaries.toml` (Jankurai stack profile), `crates/domain`
//! is the only pure-types substrate; adapter crates may freely import
//! `std::fs`, `reqwest`, `tracing`, etc. The Step 2 type-split
//! (Addendum 2a §4) moved `KernelDecision` / `KernelDecisionError` into
//! `crates/domain/src/safety/decision.rs`. The adapter's `src/types.rs`
//! must continue to re-export them and must NOT pull in any of the
//! forbidden-in-domain imports — because adapter-local types here are
//! the surface the domain crate could legitimately consume.
//!
//! This test is the structural enforcement for AC10. It does NOT
//! validate that the adapter as a whole follows boundary rules (that
//! is Jankurai's job at CI level); it asserts a much narrower property:
//!
//!   `src/types.rs` contains zero substrings matching any
//!   `forbidden_domain_imports` token from `agent/boundaries.toml`.
//!
//! If a future refactor moves `tracing::info!` or `std::fs::read` into
//! `types.rs`, this test fails — the offender gets surfaced before
//! the domain crate inherits a sibling-only dep.
//!
//! Run with: `cargo test -p qorch-safety-kernel-client --test boundary_check`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

/// Walk up from `CARGO_MANIFEST_DIR` until a `Cargo.toml` containing
/// `[workspace]` is found. Matches the workspace-root helper used by
/// `tls_smoke.rs`.
fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while p.pop() {
        let candidate = p.join("Cargo.toml");
        if candidate.exists() {
            if let Ok(contents) = fs::read_to_string(&candidate) {
                if contents.contains("[workspace]") {
                    return p;
                }
            }
        }
    }
    panic!("workspace root not found from {:?}", env!("CARGO_MANIFEST_DIR"));
}

/// Forbidden-substring tokens for the domain crate. This list mirrors
/// `agent/boundaries.toml::rust.forbidden_domain_imports` as it stands
/// on this branch. We re-derive it from the file rather than hardcode
/// to keep the two in lockstep; if boundaries.toml is moved, this test
/// fails loudly (which is the correct behaviour).
fn forbidden_tokens() -> Vec<String> {
    let root = workspace_root();
    let toml_path = root.join("agent/boundaries.toml");
    let raw = fs::read_to_string(&toml_path)
        .unwrap_or_else(|e| panic!("read boundaries.toml at {toml_path:?}: {e}"));

    // Tiny TOML scrape — find the `forbidden_domain_imports = [...]`
    // block and pull every quoted string out. We deliberately do NOT
    // pull in a TOML parser dep just for this; a state-machine scan
    // is sufficient and avoids supply-chain risk in the test layer.
    let start = raw
        .find("forbidden_domain_imports")
        .expect("boundaries.toml missing forbidden_domain_imports");
    let open_bracket = raw[start..]
        .find('[')
        .expect("forbidden_domain_imports missing opening [");
    let close_bracket = raw[start + open_bracket..]
        .find(']')
        .expect("forbidden_domain_imports missing closing ]");
    let body = &raw[start + open_bracket + 1..start + open_bracket + close_bracket];

    let mut tokens = Vec::new();
    let mut in_quote = false;
    let mut cur = String::new();
    for ch in body.chars() {
        match ch {
            '"' => {
                if in_quote {
                    if !cur.is_empty() {
                        tokens.push(std::mem::take(&mut cur));
                    }
                    in_quote = false;
                } else {
                    in_quote = true;
                }
            }
            _ if in_quote => cur.push(ch),
            _ => {}
        }
    }
    assert!(
        !tokens.is_empty(),
        "boundaries.toml parsed but yielded zero forbidden tokens — parser drift?"
    );
    tokens
}

/// Strip line + block comments so a forbidden-substring sighting in a
/// doc comment does not cause a false positive. We leave the actual
/// imports / use statements / paths intact.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            // line comment to end of line
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            // block comment
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

#[test]
fn types_rs_contains_no_domain_forbidden_imports() {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let types_path = crate_root.join("src/types.rs");
    let raw = fs::read_to_string(&types_path)
        .unwrap_or_else(|e| panic!("read src/types.rs at {types_path:?}: {e}"));
    let scrubbed = strip_comments(&raw);

    let tokens = forbidden_tokens();
    let mut hits: Vec<(String, usize)> = Vec::new();
    for tok in &tokens {
        // Match substring on the **trimmed** form. boundaries.toml
        // lists `tracing::` (with trailing colons) — that is the form
        // we look for. A bare `tracing` mention in a string literal
        // is allowed; an actual `use tracing::*` is not.
        if scrubbed.contains(tok) {
            // Find the first occurrence's line number for the report.
            let pos = scrubbed.find(tok).unwrap();
            let line = scrubbed[..pos].matches('\n').count() + 1;
            hits.push((tok.clone(), line));
        }
    }
    assert!(
        hits.is_empty(),
        "AC10: src/types.rs contains domain-forbidden imports {hits:?} — \
         types.rs must stay re-exportable into the pure-types substrate"
    );
}

#[test]
fn types_rs_body_field_does_not_include_traceparent() {
    // Structural belt-and-braces for AC8: the AuthorizeRequest body is
    // serialized to JSON without `traceparent` (which lives on the
    // HTTP header instead). We assert by serializing a sample value
    // and grepping for the literal substring.
    use qorch_safety_kernel_client::AuthorizeRequest;
    let req = AuthorizeRequest {
        action: "sio_run_cycles".to_string(),
        params_fingerprint: "f".repeat(64),
        run_id: "run-bc-001".to_string(),
        subject: "worker".to_string(),
        traceparent: Some("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01".to_string()),
    };
    let body = serde_json::to_string(&req).expect("serialize");
    assert!(
        !body.contains("traceparent"),
        "AC8: traceparent leaked into JSON body: {body}"
    );
}

#[test]
fn boundary_token_extraction_self_check() {
    // Sanity check on the TOML scraper — must surface the known
    // tokens. If boundaries.toml drops or renames one of these, the
    // assertion failure is the signal to update this list.
    let tokens = forbidden_tokens();
    for needed in &[
        "std::fs",
        "std::env",
        "std::net",
        "reqwest::",
        "tracing::",
    ] {
        assert!(
            tokens.iter().any(|t| t == *needed),
            "boundaries.toml missing canonical forbidden token {needed:?}; \
             got tokens {tokens:?}"
        );
    }
}
