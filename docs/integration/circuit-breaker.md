# Fail-closed circuit breaker

The kernel client SDKs (Rust and Python) wrap every outbound
authorize call in a circuit breaker. This document explains the
state machine, why it is fail-closed, and how to tune it.

This is **seam 4 of four** — see
[architecture.md § four defense seams](../architecture.md#the-four-defense-seams).

## State machine

```
        success                       success
   ┌──────────────┐               ┌──────────────┐
   │              ▼               │              ▼
   │     ┌──────────────┐    ┌────────────────┐
   │     │   Closed     │    │   Half-open    │
   │     │ (normal ops) │    │ (single probe) │
   │     └──────┬───────┘    └────────┬───────┘
   │            │ N consecutive       │ failure
   │            │ failures            │
   │            ▼                     ▼
   │     ┌────────────────────────────────┐
   └─────┤            Open               │
         │ (deny every call immediately) │
         └──────────┬─────────────────────┘
                    │ open_duration elapsed
                    ▼
                Half-open
```

- **Closed**: every authorize call goes to the kernel. On success the
  breaker stays closed; on failure the consecutive-failure counter
  increments. After `failure_threshold` consecutive failures the
  breaker transitions to **Open**.
- **Open**: every authorize call returns `Unavailable` **immediately**,
  without touching the kernel. The breaker stays open for
  `open_duration`. The seam above the breaker (middleware / layer)
  translates `Unavailable` into a `503` response — never a `200`.
- **Half-open**: after `open_duration` elapses, the next single call is
  allowed through as a probe. On success the breaker closes; on
  failure it re-opens for another `open_duration`.

## Why fail-closed

An unreachable kernel must **deny**. If the breaker fell back to
`ALLOW` while the kernel was down, the entire defense collapses the
moment the kernel is briefly unreachable — a property an attacker can
trigger by saturating, killing, or partitioning the kernel.

The breaker exists precisely to make that failure mode loud and safe:

- Loud: every blocked call increments a counter and emits a structured
  log line. Alerting on the counter tells operators the kernel is sick
  long before the on-call gets paged for real outages.
- Safe: blocked calls return `503`. Callers retry or surface the
  failure; they do not silently proceed.

This is also why the breaker is part of the **adapter layer**, not the
application layer. An application-level "if the kernel is down, allow
the call" branch would defeat the entire kernel architecture. The
breaker is the structural guarantee that such a branch cannot exist.

## Tunables

| Parameter | Default | Effect |
|---|---|---|
| `failure_threshold` | `3` | Consecutive failures before the breaker opens. |
| `open_duration` | `10s` | How long the breaker stays open before probing. |
| `request_timeout` | `500ms` | Hard cap on a single authorize call. Timeouts count as failures. |

The defaults are calibrated for a kernel on a private network with
sub-10ms p99 latency. If your kernel sits over a higher-latency link,
raise `request_timeout` first, not the threshold.

## Common misconfigurations

### `failure_threshold` set too high

If you set `failure_threshold` to, say, `100`, you will ride through
**real** outages emitting failed calls that never trip the breaker.
Each of those calls is a fail-closed denial — the application sees
`503` for every gated request during the outage anyway — but the
breaker never opens, so you also pay the full timeout latency on every
call. This makes outages much more expensive than they need to be and
hides the kernel's health from your alerting.

Keep the threshold low (`3`–`5` is correct for most deployments).

### `open_duration` set too short

If the breaker reopens too aggressively, you alternate between Open
and Half-open every few seconds during an extended outage. Each probe
attempt costs a full `request_timeout`. Set `open_duration` to at
least `2 * request_timeout` plus a multi-second buffer (`10s` is the
recommended floor).

### `request_timeout` set too long

Authorize is on the request hot path. A `5s` timeout means a flaky
kernel adds five-second tail latency to every gated request. Keep
`request_timeout` under `1s`; raise the breaker threshold if you need
to tolerate more flakes before opening.

### Catching the `Unavailable` exception and falling back to allow

This is the failure mode the entire architecture is designed to
prevent. Code review must reject any try/except (or Rust `match`)
around the authorize call that produces an `ALLOW`-equivalent on
error. The breaker hands you `Unavailable`; the only correct response
is to surface it.

## Verification

Every deployment exposes counters that let you confirm the breaker is
behaving correctly:

- `safety_kernel_circuit_breaker_state{state=...}` — current state.
- `safety_kernel_circuit_breaker_transitions_total{from,to}` — transitions.
- `safety_kernel_unreachable_total` — calls denied due to kernel-unreachable.

In production, `circuit_breaker_state{state="open"}` should be `0`
except during real incidents, and `unreachable_total` should track
real kernel outages — not arbitrary application errors.
