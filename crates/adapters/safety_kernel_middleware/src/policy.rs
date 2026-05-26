//! Three-tier route policy + resolver trait.
//!
//! Per the middleware classifies every incoming
//! request into one of three tiers:
//!
//! | Tier | Kernel call | Failure mode |
//! |------|-------------|--------------|
//! | [`MiddlewarePolicy::Unrestricted`] | none | n/a |
//! | [`MiddlewarePolicy::Supervised`]   | fire-and-forget (best-effort observability) | log only, never block |
//! | [`MiddlewarePolicy::Gated`]        | synchronous, fail-closed | 503 (Unavailable) / 403 (Denied / Forged) |
//!
//! Only `Gated` routes can reject the request. `Supervised` is for
//! observability of routes that are too cheap to block on but useful
//! to attest; `Unrestricted` is the explicit opt-out for static asset
//! / health-check style endpoints.

use http::Method;
use std::collections::HashMap;
use std::sync::Arc;

/// Three-tier policy assigned per `(method, path)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MiddlewarePolicy {
    /// Pass-through. Middleware does not call the kernel; the request
    /// reaches the handler unchanged. Use for `/health`, `/metrics`,
    /// static assets, etc.
    Unrestricted,
    /// Fire-and-forget kernel call. The middleware does not block on
    /// the result; useful for read-only or low-stakes routes that
    /// nonetheless deserve a transparency-log entry.
    Supervised,
    /// Synchronous kernel call. The middleware awaits
    /// `client.authorize(...)` and rejects the request on any
    /// `Err`/`Deny`. This is the only tier that can short-circuit.
    Gated,
}

/// Resolver that maps an incoming `(method, path)` to a
/// [`MiddlewarePolicy`]. Production resolvers may load from a config
/// file, a Postgres table, or a hot-reloaded handle.
pub trait MiddlewarePolicyResolver: Send + Sync + 'static {
    /// Resolve the policy for a given request.
    fn resolve(&self, method: &Method, path: &str) -> MiddlewarePolicy;
}

/// Convenience resolver that holds a static map of
/// `(method, path) → policy` pairs and falls back to
/// [`MiddlewarePolicy::Unrestricted`] on miss.
///
/// **Default-Unrestricted is intentional**: the safe-by-default
/// pattern for a router is to opt routes IN to gating, not OUT. A
/// route that has no entry here is not protected — production
/// deployments should pair this with a CI check that fails when a
/// `Gated` route is missing.
///
/// Path matching is exact-string only; for prefix or pattern matches
/// use a custom [`MiddlewarePolicyResolver`].
#[derive(Debug, Clone, Default)]
pub struct StaticPolicy {
    table: Arc<HashMap<(Method, String), MiddlewarePolicy>>,
}

impl StaticPolicy {
    /// Build a [`StaticPolicy`] from an iterator of triples.
    #[must_use]
    pub fn from_routes<I>(routes: I) -> Self
    where
        I: IntoIterator<Item = (Method, String, MiddlewarePolicy)>,
    {
        let mut table: HashMap<(Method, String), MiddlewarePolicy> = HashMap::new();
        for (m, p, pol) in routes {
            table.insert((m, p), pol);
        }
        Self {
            table: Arc::new(table),
        }
    }
}

impl MiddlewarePolicyResolver for StaticPolicy {
    fn resolve(&self, method: &Method, path: &str) -> MiddlewarePolicy {
        self.table
            .get(&(method.clone(), path.to_string()))
            .copied()
            .unwrap_or(MiddlewarePolicy::Unrestricted)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn static_policy_resolves_exact_match() {
        let p = StaticPolicy::from_routes([
            (Method::GET, "/public/hello".into(), MiddlewarePolicy::Unrestricted),
            (Method::POST, "/gated/run".into(), MiddlewarePolicy::Gated),
        ]);
        assert_eq!(p.resolve(&Method::GET, "/public/hello"), MiddlewarePolicy::Unrestricted);
        assert_eq!(p.resolve(&Method::POST, "/gated/run"), MiddlewarePolicy::Gated);
    }

    #[test]
    fn static_policy_defaults_unrestricted_on_miss() {
        // Safe-by-default for routers without an entry. Production
        // CI must verify all Gated routes are registered.
        let p = StaticPolicy::from_routes([(
            Method::POST,
            "/gated/run".into(),
            MiddlewarePolicy::Gated,
        )]);
        assert_eq!(p.resolve(&Method::GET, "/no/such/path"), MiddlewarePolicy::Unrestricted);
    }

    #[test]
    fn static_policy_method_sensitive() {
        let p = StaticPolicy::from_routes([(
            Method::POST,
            "/gated/run".into(),
            MiddlewarePolicy::Gated,
        )]);
        // POST is gated; GET on the same path is not.
        assert_eq!(p.resolve(&Method::POST, "/gated/run"), MiddlewarePolicy::Gated);
        assert_eq!(p.resolve(&Method::GET, "/gated/run"), MiddlewarePolicy::Unrestricted);
    }
}
