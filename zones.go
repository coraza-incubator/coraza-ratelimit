// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"hash/fnv"
	"sync"
)

// numShards is a power-of-two shard count. Tuned for edge workloads where a
// handful of CPUs drive many goroutines through Evaluate concurrently.
const numShards = 8

// zoneState tracks one zone's per-second buckets plus a running sum so that
// Evaluate is O(1) instead of O(window).
type zoneState struct {
	buckets map[int64]int64 // unix-second → events in that second
	running int64           // cached sum over all in-window buckets
}

type zoneShard struct {
	mu    sync.Mutex
	zones map[string]*zoneState
	// ops counts successful tryIncrement calls since the last full sweep
	// of this shard. Used to drive opportunistic cleanup without a
	// background goroutine.
	ops int
}

// opportunisticSweepEvery controls how often tryIncrement runs a full
// shard sweep. 1024 is a balance: small enough to bound stale-zone
// accumulation, large enough that the amortized per-op cost is negligible.
const opportunisticSweepEvery = 1024

// zoneStore is the sharded counter store. All operations are safe for
// concurrent use; contention scales with numShards rather than the single
// global mutex used by the original upstream plugin.
type zoneStore struct {
	shards [numShards]zoneShard
}

func newZoneStore() *zoneStore {
	s := &zoneStore{}
	for i := range s.shards {
		s.shards[i].zones = make(map[string]*zoneState)
	}
	return s
}

func (s *zoneStore) shardFor(name string) *zoneShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return &s.shards[h.Sum32()&(numShards-1)]
}

// tryIncrement atomically decides whether the request fits inside the
// sliding window and, if it does, bumps the counter for `now`. Returns true
// when the request is allowed.
//
// maxZones caps the total number of live zones in the shard. When the cap
// would be exceeded, a single arbitrary zone is evicted before the insert —
// a bounded-memory defence against attackers who vary the zone key to
// exhaust RAM.
func (s *zoneStore) tryIncrement(name string, now, window, maxEvents int64, maxZones int) bool {
	sh := s.shardFor(name)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	z, ok := sh.zones[name]
	if !ok {
		if maxZones > 0 && len(sh.zones) >= maxZones/numShards {
			for k := range sh.zones { // map iteration order is random → good enough
				delete(sh.zones, k)
				break
			}
		}
		z = &zoneState{buckets: make(map[int64]int64)}
		sh.zones[name] = z
	}

	// Fold any buckets that have rolled out of the window out of `running`.
	// We only prune when reading so the sweeper's own work stays the same.
	threshold := now - window
	for ts, v := range z.buckets {
		if ts <= threshold {
			z.running -= v
			delete(z.buckets, ts)
		}
	}

	if z.running >= maxEvents {
		return false
	}
	z.buckets[now]++
	z.running++

	// Opportunistic shard sweep: drop empty zones every N ops. Replaces
	// the background sweeper — Coraza's Action interface has no Close
	// hook, so any goroutine we spawn from Init lives until process exit.
	sh.ops++
	if sh.ops >= opportunisticSweepEvery {
		sh.ops = 0
		for name, zs := range sh.zones {
			if len(zs.buckets) == 0 {
				delete(sh.zones, name)
			}
		}
	}
	return true
}

// snapshot returns a JSON-serialisable view of every zone/timestamp that
// still has non-zero events. The returned map is a deep copy so callers may
// mutate or encode it without holding any lock.
func (s *zoneStore) snapshot() map[string]map[int64]int64 {
	out := make(map[string]map[int64]int64)
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for name, z := range sh.zones {
			if len(z.buckets) == 0 {
				continue
			}
			cp := make(map[int64]int64, len(z.buckets))
			for ts, v := range z.buckets {
				if v > 0 {
					cp[ts] = v
				}
			}
			if len(cp) > 0 {
				out[name] = cp
			}
		}
		sh.mu.Unlock()
	}
	return out
}

// merge folds a remote snapshot into the local store. Timestamps older than
// minTS or not newer than lastSync are ignored; everything else is added
// to the running totals for the destination zone.
func (s *zoneStore) merge(remote map[string]map[int64]int64, minTS, lastSync int64) {
	for name, events := range remote {
		sh := s.shardFor(name)
		sh.mu.Lock()
		z, ok := sh.zones[name]
		if !ok {
			z = &zoneState{buckets: make(map[int64]int64)}
			sh.zones[name] = z
		}
		for ts, count := range events {
			// minTS is strict (bucket must still be inside the window).
			// lastSync is strict-less: we intentionally re-merge the
			// boundary second because cluster-wide double-counting on a
			// single-second edge is preferable to losing updates posted
			// by peers during the same sync window — over-enforcement is
			// safer than under-enforcement.
			if ts < lastSync || ts <= minTS {
				continue
			}
			z.buckets[ts] += count
			z.running += count
		}
		sh.mu.Unlock()
	}
}

// total sums every counter across every zone. Test helper.
func (s *zoneStore) total() int64 {
	var n int64
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for _, z := range sh.zones {
			n += z.running
		}
		sh.mu.Unlock()
	}
	return n
}
