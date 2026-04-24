# Changelog

## v0.1.0 (unreleased) — experimental

**This is an incubator release. It is NOT recommended for production
traffic.** APIs, wire formats, and behaviour may change without notice
until v1.0.0.

Based on the [Google Summer of Code 2023](https://summerofcode.withgoogle.com/)
prototype by Shivansh Verma ([VermaShivansh/coraza-ratelimit-plugin](https://github.com/VermaShivansh/coraza-ratelimit-plugin)),
substantially rewritten for correctness, performance, and operational
safety.

### Layout
- Module path `github.com/coraza-incubator/coraza-ratelimit`.
- Action package at repo root (`package ratelimit`); blank-import
  registers the `ratelimit` SecRule action.
- Backends live under `stores/` — core module is dep-free beyond Coraza.
  Ships: `stores/redis`, `stores/memory`.

### Performance
- Sharded counter store (8 shards) — 100 ns/op at 1024 zones vs 136 ns/op
  on a single shard on an Apple M4 (~26% contention reduction).
- O(1) running total per zone — `window=1` and `window=3600` have
  identical per-request cost.

### Security
- `max_zones` config key (default `100000`) caps live zone cardinality,
  bounding memory under a varied-key DoS.
- Config parser caps: 4 KB total length, 64 tokens, duplicate non-`zone[]`
  keys rejected.
- `status` range 100–599 (rejects 0 — unusable with Coraza's interrupt
  semantics).
- Redis snapshots carry a TTL of `2 * window` — stale state ages out.
- Lua-CAS unlock — a late `Release` from an expired holder never unlocks
  a peer's lock.
- Cross-field check: operator-specified `interval` must be ≤ `window`;
  otherwise an attacker who varies the zone key can briefly exceed the
  limit while buckets linger past their window.

### Correctness
- Context-aware background goroutines; `Close()` stops the sweeper and
  sync loop cleanly.
- Per-shard locking eliminates the upstream race between sweeper and
  evaluation.
- `syncOnce` marshals JSON outside every mutex; request-path latency is
  unaffected during sync.
- Snapshots emit only zones with in-window, non-zero counters — payload
  does not grow with history.
- `Close()` and `Evaluate()` before `Init()` are safe no-ops.
- Background goroutines carry `defer recover()` and log panics through
  `slog` rather than crashing the host.

### Tooling
- Go 1.23+, Coraza v3.7, stdlib `encoding/json`.
- **Not** depended on: `bytedance/sonic`, `bsm/redislock`, `magefile`.
- `DistributedStore` interface; `stores/redis` uses `redis/go-redis/v9`,
  `stores/memory` is dep-free.
- Coverage ≥ 94% across core and both store subpackages.
- End-to-end tests include a two-instance distributed scenario proving
  cluster-wide state sharing through Redis.

### Lifecycle
- **Single-node mode spawns zero goroutines.** Zone pruning is inline
  (opportunistic sweep every 1024 ops) and the per-shard LRU eviction
  + `max_zones` cap bounds memory. Replaces the upstream background
  sweeper which leaked on rule reload.
- Distributed mode still spawns one sync goroutine per rule. Coraza's
  Action interface has no Close hook, so that goroutine persists across
  rule reloads in the same process. Mitigation: restart the process on
  config changes.

### Known limitations
- Distributed mode is eventually consistent; expect 2–3% overage under
  load.
- No observability hooks (metrics, tracing) yet. Planned for v0.2.
- No gossip-based distributed backend yet. Planned for v0.2.
