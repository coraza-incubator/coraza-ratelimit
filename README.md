# coraza-ratelimit

> **⚠️ Experimental — not production-ready.** This is a Coraza incubator
> project. APIs, wire formats, and behaviour may change between minor
> versions. Deploy behind a canary or in shadow mode before pointing
> real traffic at it.

[![CI](https://github.com/coraza-incubator/coraza-ratelimit/actions/workflows/ci.yml/badge.svg)](https://github.com/coraza-incubator/coraza-ratelimit/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/coraza-incubator/coraza-ratelimit.svg)](https://pkg.go.dev/github.com/coraza-incubator/coraza-ratelimit)

A sliding-window rate-limiting action plugin for the [OWASP Coraza](https://coraza.io)
WAF. Supports a single-node in-memory mode and an optional distributed mode
that synchronises counters across a Coraza cluster through a pluggable
backend (Redis is the default reference implementation).

## Credits

Originated as a [Google Summer of Code 2023](https://summerofcode.withgoogle.com/)
project by **Shivansh Verma** ([@VermaShivansh](https://github.com/VermaShivansh))
mentored by the OWASP Coraza team. This repository is a modernized and
hardened rewrite maintained by the OWASP Coraza contributors.

## Install

Requires **Go 1.25+** (inherited from Coraza v3.7).

```bash
go get github.com/coraza-incubator/coraza-ratelimit
```

Importing the package registers the `ratelimit` action with Coraza:

```go
import _ "github.com/coraza-incubator/coraza-ratelimit"
```

## Quick start

```apache
SecRuleEngine On
SecRule ARGS:id "@eq 1" "id:100, phase:1, pass, \
    ratelimit:zone[]=%{REQUEST_HEADERS.host}&events=200&window=1, \
    status:200"
```

## Configuration reference

| Key                   | Type    | Required | Default   | Notes                                                                                         |
| --------------------- | ------- | -------- | --------- | --------------------------------------------------------------------------------------------- |
| `zone[]`              | macro   | yes      | —         | Repeatable. Each zone adds an OR-combined bucket.                                             |
| `events`              | int ≥ 0 | yes      | —         | Allowance per window. `0` blocks every matching request.                                      |
| `window`              | int > 0 | yes      | —         | Sliding window size, in seconds.                                                              |
| `interval`            | int > 0 | no       | —         | Accepted for upstream compatibility; **ignored** since v0.1. Zone cleanup is inline.          |
| `action`              | enum    | no       | `drop`    | `drop`, `deny`, `redirect`.                                                                   |
| `status`              | 100–599 | no       | `429`     | HTTP status when the limit is exceeded.                                                       |
| `max_zones`           | int > 0 | no       | `100000`  | Caps live zone entries per rule. Bounds memory under an attacker who varies the zone key.     |
| `distribute_interval` | int > 0 | no       | —         | Seconds between distributed syncs. Enables distributed mode when set.                         |

### Multi-zone semantics

Multiple `zone[]` entries are combined with **OR**: a request is allowed as
soon as *any one* zone still has budget. Matches nginx `limit_req` and the
typical "allow per-IP *or* per-user" use case.

### Distributed mode

Import a backend and register it before loading rules that use
`distribute_interval`:

```go
import (
    _ "github.com/coraza-incubator/coraza-ratelimit"
    ratelimit "github.com/coraza-incubator/coraza-ratelimit"
    redisstore "github.com/coraza-incubator/coraza-ratelimit/stores/redis"
)

func init() {
    ratelimit.SetDefaultStore(redisstore.New(redisstore.Options{
        Addr: "redis.internal:6379",
    }))
}
```

Available backends:

| Package                                                         | Purpose                                                   |
| --------------------------------------------------------------- | --------------------------------------------------------- |
| `github.com/coraza-incubator/coraza-ratelimit/stores/redis`     | Redis-backed; recommended for cross-host clusters         |
| `github.com/coraza-incubator/coraza-ratelimit/stores/memory`    | In-process; useful for tests or single-binary embeddings  |

Distributed-mode requirements:

* Set the environment variable `coraza_ratelimit_key` to a shared secret
  of 16–30 alphanumeric characters containing at least one letter and one
  digit.
* Every instance must have an identical rule configuration.
* Remote snapshots are stored with a TTL of `2 * window` so keys age out
  automatically when a rule is disabled.

## Production caveats

Before running this against real traffic, read this section.

- **Experimental status.** The whole project is pre-1.0. Expect breaking
  changes.
- **Eventual consistency.** Distributed counters are synced on a ticker, not
  synchronously. Under sustained load, expect 2–3% overage across the
  cluster versus the configured limit.
- **Clock skew.** Sliding windows are driven by `time.Now().Unix()` on each
  instance. Keep hosts NTP-synced. Drift > 1 s loosens limits and can
  double-count on window boundaries.
- **Network partitions.** If a Coraza instance cannot reach its store, it
  falls back to local-only counting for that rule. When connectivity
  returns, state merges with no conflict resolution (counts are monotonic
  add-only within a window), but the loosely-bounded period during the
  partition allows local overage.
- **Redis is a trust boundary.** An attacker with write access to the
  shared Redis key can forge counts. Deploy with TLS and ACLs.
- **Rule reload and goroutines.** Coraza's `Action` interface has no
  `Close` hook, so any goroutine the action spawns outlives the rule.
  We avoid this entirely in **single-node mode**: counter pruning is
  inline and no goroutines are spawned. In **distributed mode**, one
  sync goroutine runs per rule; if you rebuild the WAF in-process (hot
  rule reload), those goroutines persist until the process exits.
  Accumulation is bounded by reload frequency — a handful per day is
  not a concern; tight-loop reloads are. Prefer a process-level restart
  on config change until Coraza upstream exposes an action-close hook.

## Performance

On Apple M4 (`go test -bench=.`):

| Benchmark                    | ns/op |
| ---------------------------- | ----- |
| Single zone, high contention | ~140  |
| 1024 zones, spread           | ~99   |
| `window=3600` (1h)           | ~141  |

The O(1) running-total keeps large windows as cheap as short ones; the
8-way shard fan-out yields ~30% speed-up when traffic spreads.

## Development

```bash
go test -race ./...
go vet ./...
```

Real-Redis integration:

```bash
docker compose up -d redis
go test ./stores/redis/...
```

## License

Apache-2.0. Copyright © OWASP Coraza contributors. See [LICENSE](LICENSE).
