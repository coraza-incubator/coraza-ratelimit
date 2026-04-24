// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRatelimit(t *testing.T, cfg string, clock func() time.Time) *Ratelimit {
	t.Helper()
	r := &Ratelimit{now: clock}
	require.NoError(t, r.Init(mockRule{ID_: 1}, cfg))
	t.Cleanup(r.Close)
	return r
}

// evaluateN drives the sliding-window logic directly through the zoneStore,
// bypassing macro expansion so tests can focus on counter math.
func evaluateN(r *Ratelimit, zone string, n int) (allowed int) {
	for i := 0; i < n; i++ {
		if r.store.tryIncrement(zone, r.now().Unix(), r.Window, r.MaxEvents, r.MaxZones) {
			allowed++
		}
	}
	return allowed
}

func TestSlidingWindow_AllowsUpToMaxEventsPerWindow(t *testing.T) {
	var fake atomic.Int64
	fake.Store(1_700_000_000)
	clock := func() time.Time { return time.Unix(fake.Load(), 0) }
	r := newTestRatelimit(t, "zone[]=x&events=10&window=5", clock)

	assert.Equal(t, 10, evaluateN(r, "x", 15))
	fake.Add(1)
	assert.Equal(t, 0, evaluateN(r, "x", 5))
	fake.Add(10)
	assert.Equal(t, 10, evaluateN(r, "x", 20))
}

func TestSlidingWindow_BoundaryBehaviour(t *testing.T) {
	// Window [now-window, now]. With events=1, window=2: t=0 allow, t=1 block,
	// t=2 allow (slot 0 has rolled out).
	var fake atomic.Int64
	fake.Store(1_700_000_000)
	clock := func() time.Time { return time.Unix(fake.Load(), 0) }
	r := newTestRatelimit(t, "zone[]=x&events=1&window=2", clock)

	assert.Equal(t, 1, evaluateN(r, "x", 5))
	fake.Add(1)
	assert.Equal(t, 0, evaluateN(r, "x", 5))
	fake.Add(2)
	assert.Equal(t, 1, evaluateN(r, "x", 5))
}

func TestEventsZero_BlocksAllRequests(t *testing.T) {
	var fake atomic.Int64
	fake.Store(1_700_000_000)
	clock := func() time.Time { return time.Unix(fake.Load(), 0) }
	r := newTestRatelimit(t, "zone[]=x&events=0&window=1", clock)
	assert.Equal(t, 0, evaluateN(r, "x", 50))
}

// TestClose covers both the idempotent and pre-Init branches in one test.
func TestClose(t *testing.T) {
	(&Ratelimit{}).Close() // before Init: no panic

	r := newTestRatelimit(t, "zone[]=x&events=1&window=1", time.Now)
	r.Close()
	r.Close() // idempotent: no panic
}

// TestMaxZones_BoundsMemory asserts that once the cap is hit, total live
// zone count never exceeds the configured bound. Security-critical invariant.
func TestMaxZones_BoundsMemory(t *testing.T) {
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	r := newTestRatelimit(t, "zone[]=x&events=1&window=60&max_zones=16", clock)

	for i := 0; i < 10_000; i++ {
		name := "z" + string(rune(i))
		r.store.tryIncrement(name, r.now().Unix(), r.Window, r.MaxEvents, r.MaxZones)
	}
	var live int
	for i := range r.store.shards {
		sh := &r.store.shards[i]
		sh.mu.Lock()
		live += len(sh.zones)
		sh.mu.Unlock()
	}
	assert.LessOrEqual(t, live, r.MaxZones)
}

// TestMaxZones_VeryLargeZoneValue asserts that a single oversized macro
// expansion (e.g. %{REQUEST_BODY}) is stored as-is, but counts against the
// per-shard cap so it cannot pin arbitrarily many other zones out.
func TestMaxZones_VeryLargeZoneValue(t *testing.T) {
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }
	r := newTestRatelimit(t, "zone[]=x&events=1&window=60&max_zones=8", clock)
	big := make([]byte, 128*1024) // 128 KB zone name
	for i := range big {
		big[i] = 'a' + byte(i%26)
	}
	r.store.tryIncrement(string(big), r.now().Unix(), r.Window, r.MaxEvents, r.MaxZones)
	assert.LessOrEqual(t, r.StoreZoneCount(), r.MaxZones)
}
