# nginx auth_request integration

How to use nginx's `auth_request` directive as the **network-layer
gate** in front of your gated routes. This is the first of the four
enforcement seams; it catches calls that would otherwise bypass the
application entirely.

See [architecture.md § four defense seams](../architecture.md#the-four-defense-seams) for why this seam
exists and what fails open without it.

## Why this seam

Application middleware (FastAPI, axum) only fires for requests your
application receives. nginx sits in front of the application and
can refuse a request before the upstream is even contacted. That
matters when:

- An operator misconfigures the application and unintentionally
  removes the middleware from a deployment.
- A separate service is mounted behind the same nginx (a sidecar, a
  debug endpoint, a tooling shim) and forgets to wire its own gate.
- A scripted scanner probes gated paths — refusing at the edge keeps
  the upstream off the hot path.

It is the cheapest, coarsest gate. It is **not** sufficient on its
own — see the caveat at the bottom.

## Config snippet

```nginx
http {
    # The kernel's authorize endpoint, reachable only inside the trust
    # boundary (private network or unix socket). Never expose this
    # location publicly.
    upstream safety_kernel {
        server safety-kernel.internal:9000;
        keepalive 16;
    }

    server {
        listen 443 ssl http2;
        server_name api.example.com;

        # Internal subrequest target — nginx forwards the original
        # method/path/headers and short-circuits the parent request
        # on non-2xx.
        location = /_kernel_authorize {
            internal;
            proxy_pass         http://safety_kernel/authorize;
            proxy_pass_request_body off;
            proxy_set_header   Content-Length "";
            proxy_set_header   X-Original-URI    $request_uri;
            proxy_set_header   X-Original-Method $request_method;
            proxy_set_header   X-API-Key         $kernel_worker_key;
            proxy_read_timeout 500ms;
        }

        # Gated routes — every request to /api/v1/write/* and
        # /api/v1/execute/* must pass the auth_request before reaching
        # the upstream.
        location ~ ^/api/v1/(write|execute)/ {
            auth_request /_kernel_authorize;
            auth_request_set $kernel_token $upstream_http_x_kernel_token;

            proxy_pass         http://app_upstream;
            proxy_set_header   X-Kernel-Token $kernel_token;
            proxy_set_header   X-Original-URI $request_uri;
        }

        # Health endpoint — NOT gated. See "Caveat" below.
        location = /health {
            proxy_pass http://app_upstream;
        }
    }
}
```

The `auth_request` directive issues an internal subrequest to
`/_kernel_authorize`. nginx evaluates the response status:

- `2xx` — request continues to the upstream.
- `401` / `403` — request is refused with the same status.
- Any other non-2xx, or upstream connection failure — request fails
  with `500`.

That last bullet is the fail-closed property at this seam: an
unreachable kernel produces a `500`, not a silent allow.

## What this stops

| Attack | Stopped here? |
|---|---|
| Direct call to a gated route from outside | Yes |
| Call that arrived via a misconfigured app missing its middleware | Yes |
| Call that arrived via a sibling service on the same nginx | Yes |
| Per-tool dispatch inside an already-authorized request | No (seam 3) |
| Kernel-unreachable masquerading as transient timeout | No (seam 4) |

## Caveat — this is one of four seams, never the only one

The network gate alone is not sufficient. Reasons:

1. **It cannot see the request body.** Many authorization decisions
   depend on the action arguments, not just the route. nginx forwards
   route shape only.
2. **It cannot gate per-tool calls within a request.** A request that
   passes the route gate may internally call multiple tools; each
   needs its own check (seam 3).
3. **It is bypassed by anything that doesn't go through this nginx.**
   Internal service-to-service traffic, scheduled jobs, and admin
   shells all need their own enforcement.

Wire all four seams. The bypass-attempts counter in your application
will tell you if you missed one — see
[`circuit-breaker.md`](circuit-breaker.md).
