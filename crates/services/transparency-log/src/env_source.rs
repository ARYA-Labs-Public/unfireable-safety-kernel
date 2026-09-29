//! Environment access abstraction for [`crate::settings::Settings::from_env`].
//!
//! `Settings::from_env` reads thirteen environment variables and decides
//! whether the service boots at all — which signing key it uses, whether TLS
//! is on, whether it refuses to start for want of an API key. Reading
//! `std::env` directly there would leave that decision logic with zero
//! tests, because the process environment is global mutable state that
//! parallel test runs cannot safely share.
//!
//! This module is the seam that makes it testable: an [`EnvSource`] trait
//! that `Settings::from_env` can be written against, a [`SystemEnv`]
//! implementation backed by the real process environment for production use,
//! and a [`MapEnv`] in-memory builder for tests.
//!
//! # Why this duplicates `arya-core-safety-kernel-app::db_env`
//!
//! `crates/adapters/arya-core-safety-kernel-app/src/db_env.rs` already
//! defines exactly this abstraction: an `EnvSource` trait with a single
//! `get(&self, key: &str) -> Option<String>` method, a `SystemEnv`, and a
//! `MapEnv` builder with a `with` method. This module mirrors that shape
//! deliberately — same trait name, same method signature, same two
//! implementations, same builder method name — rather than inventing a
//! different one, so a reader who already knows one knows both.
//!
//! It does not, however, depend on that crate to reuse the trait. Measured,
//! taking `arya-core-safety-kernel-app` as a dependency pulls **14
//! additional crates** into this service's build graph, including the whole
//! safety kernel, `fancy-regex`, and `aho-corasick`, all to reuse a trait
//! with one method. That is a bad trade for a transparency service that has
//! nothing to do with the safety kernel.
//!
//! This duplication is therefore a deliberate, considered trade, not an
//! oversight. If a light shared crate for this kind of small, dependency-free
//! abstraction ever exists, the two copies should consolidate onto it
//! (internal-ref). Until then: this copy is here for dependency-graph hygiene;
//! `db_env`'s copy is the original.

use std::collections::HashMap;
use std::env;

/// A source of environment-variable-shaped configuration.
///
/// Implemented by [`SystemEnv`] for production use (backed by the real
/// process environment) and by [`MapEnv`] for tests (backed by an in-memory
/// map). Code that needs to read configuration should be generic over this
/// trait rather than calling `std::env::var` directly, so it can be tested
/// without touching real process state.
pub trait EnvSource {
    /// Returns the value of `key`, or `None` if it is not set.
    fn get(&self, key: &str) -> Option<String>;
}

/// An [`EnvSource`] backed by the real process environment.
///
/// This is what `Settings::from_env` uses outside of tests: `get` simply
/// delegates to `std::env::var`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEnv;

impl SystemEnv {
    /// Creates a new [`SystemEnv`].
    #[must_use]
    pub const fn new() -> Self {
        SystemEnv
    }
}

impl EnvSource for SystemEnv {
    fn get(&self, key: &str) -> Option<String> {
        env::var(key).ok()
    }
}

/// An in-memory [`EnvSource`] for tests.
///
/// Built with [`MapEnv::with`], which can be chained and which overwrites an
/// earlier value for the same key, mirroring how a real environment behaves
/// when a variable is set more than once.
#[derive(Debug, Default, Clone)]
pub struct MapEnv {
    values: HashMap<String, String>,
}

impl MapEnv {
    /// Returns a new, empty `MapEnv`.
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    /// Sets `key` to `value` and returns `self`, for chaining.
    ///
    /// A later call with the same `key` overwrites the earlier value, the
    /// same as re-exporting a shell variable.
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.values.insert(key.into(), value.into());
        self
    }
}

impl EnvSource for MapEnv {
    fn get(&self, key: &str) -> Option<String> {
        self.values.get(key).cloned()
    }
}

/// Reads `key` from `env` and returns its trimmed value, unless that trimmed
/// value is empty, in which case returns `None`.
///
/// An empty string is treated the same as an absent variable: a shell that
/// exports a variable with no value (`export ARYA_SIGNING_KEY=`) has not
/// configured anything, and a service that accepts `""` as, say, a signing
/// key will fail later and further from the actual cause than one that
/// refuses to start. `Settings::from_env` uses this at all thirteen of its
/// environment-variable call sites; it is public here for that reason.
pub fn trimmed_non_empty<E: EnvSource>(env: &E, key: &str) -> Option<String> {
    let value = env.get(key)?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_env_returns_inserted_value_and_none_for_absent_key() {
        let env = MapEnv::new().with("FOO", "bar");

        assert_eq!(env.get("FOO"), Some("bar".to_string()));
        assert_eq!(env.get("MISSING"), None);
    }

    #[test]
    fn map_env_with_chains_and_overwrites() {
        let env = MapEnv::new().with("A", "1").with("B", "2").with("A", "3");

        assert_eq!(env.get("A"), Some("3".to_string()));
        assert_eq!(env.get("B"), Some("2".to_string()));
    }

    #[test]
    fn trimmed_non_empty_absent_key_is_none() {
        let env = MapEnv::new();

        assert_eq!(trimmed_non_empty(&env, "MISSING"), None);
    }

    #[test]
    fn trimmed_non_empty_empty_string_is_none() {
        let env = MapEnv::new().with("KEY", "");

        assert_eq!(trimmed_non_empty(&env, "KEY"), None);
    }

    #[test]
    fn trimmed_non_empty_whitespace_only_is_none() {
        let env = MapEnv::new().with("KEY", "   \t  ");

        assert_eq!(trimmed_non_empty(&env, "KEY"), None);
    }

    #[test]
    fn trimmed_non_empty_trims_surrounding_whitespace() {
        let env = MapEnv::new().with("KEY", "  value  ");

        assert_eq!(trimmed_non_empty(&env, "KEY"), Some("value".to_string()));
    }

    #[test]
    fn trimmed_non_empty_normal_value_is_returned() {
        let env = MapEnv::new().with("KEY", "value");

        assert_eq!(trimmed_non_empty(&env, "KEY"), Some("value".to_string()));
    }

    // SystemEnv touches real, global process environment state. To keep that
    // hazard confined to a single, easily-auditable place, this is the only
    // test in this module (and, as far as this crate is concerned, the only
    // test anywhere) that sets and removes a real environment variable. The
    // variable name is chosen to be unlikely to collide with anything else
    // read by this process during the test run.
    #[test]
    fn system_env_reads_real_environment_variable() {
        let key = "ARYA_CORE_TRANSPARENCY_SERVICE_ENV_SOURCE_TEST_VAR";
        env::set_var(key, "system-env-value");

        let env = SystemEnv;
        let value = env.get(key);

        env::remove_var(key);

        assert_eq!(value, Some("system-env-value".to_string()));
    }

    // This test exists to reference `SystemEnv::new()` directly, so that if
    // the constructor is ever removed, this file fails to compile with a
    // clear "no such function" error here, rather than some distant call
    // site failing with a baffling "trait bounds were not satisfied" because
    // `SystemEnv` still exists but nothing builds one anymore. It proves the
    // constructor is wired up to the real `EnvSource` impl by reading an
    // environment variable that is guaranteed not to be set and asserting
    // the result is `None`, rather than comparing two zero-sized values that
    // carry no distinguishing content.
    #[test]
    fn system_env_new_reads_absent_variable_as_none() {
        let key = "ARYA_CORE_TRANSPARENCY_SERVICE_ENV_SOURCE_NEW_ABSENT_VAR";

        let env = SystemEnv::new();

        assert_eq!(env.get(key), None);
    }
}
