// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"strconv"
	"testing"
	"time"
)

func BenchmarkEvaluate_SingleZone(b *testing.B) {
	r := &Ratelimit{now: time.Now}
	_ = r.Init(mockRule{ID_: 1}, "zone[]=x&events=1000000&window=60")
	defer r.Close()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.store.tryIncrement("x", time.Now().Unix(), r.Window, r.MaxEvents, r.MaxZones)
		}
	})
}

// ManyZones simulates per-IP counters: every goroutine picks from a pool of
// N distinct zone keys, exercising the shard fan-out.
func BenchmarkEvaluate_ManyZones(b *testing.B) {
	const nZones = 1024
	names := make([]string, nZones)
	for i := range names {
		names[i] = "ip_" + strconv.Itoa(i)
	}
	r := &Ratelimit{now: time.Now}
	_ = r.Init(mockRule{ID_: 1}, "zone[]=x&events=1000000&window=60")
	defer r.Close()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			r.store.tryIncrement(names[i%nZones], time.Now().Unix(), r.Window, r.MaxEvents, r.MaxZones)
			i++
		}
	})
}

// BenchmarkEvaluate_ManyZones_SingleShard forces all zones into shard 0 by
// hashing them to the same bucket — the purpose is to quantify the
// contention reduction the sharded store delivers. If this runs
// meaningfully slower than BenchmarkEvaluate_ManyZones, the shard fan-out
// is actually doing work.
func BenchmarkEvaluate_ManyZones_SingleShard(b *testing.B) {
	const nZones = 1024
	names := make([]string, nZones)
	for i := range names {
		names[i] = "ip_" + strconv.Itoa(i)
	}
	r := &Ratelimit{now: time.Now}
	_ = r.Init(mockRule{ID_: 1}, "zone[]=x&events=1000000&window=60")
	defer r.Close()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			sh := &r.store.shards[0]
			sh.mu.Lock()
			name := names[i%nZones]
			z, ok := sh.zones[name]
			if !ok {
				z = &zoneState{buckets: make(map[int64]int64)}
				sh.zones[name] = z
			}
			z.buckets[time.Now().Unix()]++
			z.running++
			sh.mu.Unlock()
			i++
		}
	})
}

// LargeWindow exercises the O(1) running-total optimization. With the old
// per-bucket recomputation this benchmark's per-op cost grew linearly with
// the window size.
func BenchmarkEvaluate_LargeWindow(b *testing.B) {
	r := &Ratelimit{now: time.Now}
	_ = r.Init(mockRule{ID_: 1}, "zone[]=x&events=1000000&window=3600")
	defer r.Close()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.store.tryIncrement("x", time.Now().Unix(), r.Window, r.MaxEvents, r.MaxZones)
		}
	})
}
