//! Three-tier route policy + resolver trait.
//!
//! Per the middleware classifies every incoming
//! request into one of three tiers:
//!
//! | Tier | Kernel call | Failure mode |
//! |------|-------------|--------------|
//! | [`MiddlewarePolicy::Unrestricted`] | none | n/a |
//! | [`MiddlewarePolicy::Supervised`]   | synchronous, fail-closed (same as `Gated`) | 503 (Unavailable) / 403 (Denied / Forged) |
//! | [`MiddlewarePolicy::Gated`]        | synchronous, fail-closed | 503 (Unavailable) / 403 (Denied / Forged) |
//!
//! Every tier that calls the kernel fails closed: there is no silent
//! allow. `Supervised` is kept as a name so existing route tables still
//! compile and routes can be labelled. `Unrestricted` is the explicit
//! opt-out for static asset / health-check style endpoints, and must be
//! listed explicitly: an unlisted route is `Gated`.

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
    /// Enforced exactly like [`MiddlewarePolicy::Gated`]. (It was once a
    /// fire-and-forget call that never blocked; that was a silent allow
    /// and was removed.)
    Supervised,
    /// Synchronous kernel call. The middleware awaits
    /// `client.authorize(...)` and rejects the request on any
    /// `Err`/`Deny`.
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
/// [`MiddlewarePolicy::Gated`] on miss.
///
/// **Default-Gated (fail-closed)**: a route that has no entry here is
/// gated, so forgetting to register a route can never leave it
/// unprotected. Routes that must not call the kernel (health checks,
/// static assets) are opted OUT explicitly with `Unrestricted`.
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
            .unwrap_or(MiddlewarePolicy::Gated)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn static_policy_resolves_exact_match() {
        let p = StaticPolicy::from_routes([
            (
                Method::GET,
                "/public/hello".into(),
                MiddlewarePolicy::Unrestricted,
            ),
            (Method::POST, "/gated/run".into(), MiddlewarePolicy::Gated),
        ]);
        assert_eq!(
            p.resolve(&Method::GET, "/public/hello"),
            MiddlewarePolicy::Unrestricted
        );
        assert_eq!(
            p.resolve(&Method::POST, "/gated/run"),
            MiddlewarePolicy::Gated
        );
    }

    #[test]
    fn static_policy_defaults_gated_on_miss() {
        // Fail-closed: an unregistered route is gated, never let through.
        let p = StaticPolicy::from_routes([(
            Method::POST,
            "/gated/run".into(),
            MiddlewarePolicy::Gated,
        )]);
        assert_eq!(
            p.resolve(&Method::GET, "/no/such/path"),
            MiddlewarePolicy::Gated
        );
    }

    #[test]
    fn static_policy_method_sensitive() {
        let p = StaticPolicy::from_routes([
            (Method::POST, "/gated/run".into(), MiddlewarePolicy::Gated),
            (
                Method::GET,
                "/gated/run".into(),
                MiddlewarePolicy::Unrestricted,
            ),
        ]);
        // POST is gated; GET on the same path is explicitly not.
        assert_eq!(
            p.resolve(&Method::POST, "/gated/run"),
            MiddlewarePolicy::Gated
        );
        assert_eq!(
            p.resolve(&Method::GET, "/gated/run"),
            MiddlewarePolicy::Unrestricted
        );
    }
}
