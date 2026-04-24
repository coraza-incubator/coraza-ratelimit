// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// This file is only compiled during `go test`. It re-registers the
// ratelimit action with a factory that tracks live instances by rule ID,
// letting end-to-end tests observe internal counters without widening the
// production API. It also exposes a few internals to external _test
// packages (distribute_test, e2e_test, coverage_test) that would otherwise
// be unable to reach them.

package ratelimit

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

var (
	testRegMu    sync.Mutex
	testRegistry = map[int]*Ratelimit{}
)

func registerForTest(id int, r *Ratelimit) {
	testRegMu.Lock()
	testRegistry[id] = r
	testRegMu.Unlock()
}

// LookupForTest returns the Ratelimit registered for a given rule ID.
func LookupForTest(id int) *Ratelimit {
	testRegMu.Lock()
	defer testRegMu.Unlock()
	return testRegistry[id]
}

// StoreTotal returns the sum of all counters in the store.
func (e *Ratelimit) StoreTotal() int64 { return e.store.total() }

// StoreZoneCount returns the current live zone count across all shards.
func (e *Ratelimit) StoreZoneCount() int {
	var n int
	for i := range e.store.shards {
		sh := &e.store.shards[i]
		sh.mu.Lock()
		n += len(sh.zones)
		sh.mu.Unlock()
	}
	return n
}

// SetNowForTest overrides the internal clock. Must be called before Init.
func SetNowForTest(r *Ratelimit, now func() time.Time) { r.now = now }

// SyncOnceForTest invokes the unexported syncOnce method.
func SyncOnceForTest(ctx context.Context, r *Ratelimit) error { return r.syncOnce(ctx) }

// InitForTest parses the rule options and wires up internal state without
// starting the sweeper or sync goroutines. Use this in tests that want to
// drive syncOnce manually without racing with the auto-sync.
func InitForTest(r *Ratelimit, rm plugintypes.RuleMetadata, opts string) error {
	r.Action = "drop"
	r.Status = 429
	r.MaxZones = DefaultMaxZones
	if err := r.parseConfig(opts); err != nil {
		return err
	}
	if r.now == nil {
		r.now = time.Now
	}
	r.store = newZoneStore()
	r.ctx, r.cancel = context.WithCancel(context.Background())
	return nil
}

// TryIncrementForTest invokes the unexported zone store for tests that
// exercise the sliding-window math without going through Coraza.
func TryIncrementForTest(r *Ratelimit, name string) bool {
	return r.store.tryIncrement(name, r.now().Unix(), r.Window, r.MaxEvents, r.MaxZones)
}

type testingRatelimit struct{ *Ratelimit }

func (t *testingRatelimit) Init(rm plugintypes.RuleMetadata, opts string) error {
	if err := t.Ratelimit.Init(rm, opts); err != nil {
		return err
	}
	registerForTest(rm.ID(), t.Ratelimit)
	return nil
}

func TestMain(m *testing.M) {
	plugins.RegisterAction("ratelimit", func() plugintypes.Action {
		return &testingRatelimit{Ratelimit: &Ratelimit{}}
	})
	os.Exit(m.Run())
}
