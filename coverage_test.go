// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	ratelimit "github.com/coraza-incubator/coraza-ratelimit"
	memstore "github.com/coraza-incubator/coraza-ratelimit/stores/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEvaluate_BlocksAfterBudget drives Evaluate end-to-end through a mock
// transaction and asserts Interrupt fires after the configured budget.
func TestEvaluate_BlocksAfterBudget(t *testing.T) {
	r := &ratelimit.Ratelimit{}
	require.NoError(t, r.Init(mockRule{ID_: 1}, "zone[]=fixed&events=2&window=60"))
	defer r.Close()

	tx := ratelimit.NewMockTx()
	r.Evaluate(mockRule{ID_: 1}, tx)
	r.Evaluate(mockRule{ID_: 1}, tx)
	r.Evaluate(mockRule{ID_: 1}, tx) // third → interrupt
	assert.True(t, tx.Interrupted)
}

// TestEvaluate_NoOpBeforeInit is the defensive nil-store guard.
func TestEvaluate_NoOpBeforeInit(t *testing.T) {
	r := &ratelimit.Ratelimit{}
	tx := ratelimit.NewMockTx()
	r.Evaluate(mockRule{ID_: 1}, tx)
	assert.False(t, tx.Interrupted)
}

// TestEvaluate_RedirectAction covers the non-default action path through
// the interrupt struct.
func TestEvaluate_RedirectAction(t *testing.T) {
	r := &ratelimit.Ratelimit{}
	require.NoError(t, r.Init(mockRule{ID_: 1}, "zone[]=fixed&events=0&window=1&action=redirect&status=301"))
	defer r.Close()
	tx := ratelimit.NewMockTx()
	r.Evaluate(mockRule{ID_: 1}, tx)
	require.True(t, tx.Interrupted)
	assert.Equal(t, "redirect", tx.Interrupt_.Action)
	assert.Equal(t, 301, tx.Interrupt_.Status)
}

// TestInit_RejectsBadOpts verifies parseConfig errors are wrapped with the
// rule ID for operator diagnostics.
func TestInit_RejectsBadOpts(t *testing.T) {
	r := &ratelimit.Ratelimit{}
	err := r.Init(mockRule{ID_: 42}, "garbage")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rule 42")
}

// TestSyncService_RunsOnTicker drives the full sync loop end-to-end.
func TestSyncService_RunsOnTicker(t *testing.T) {
	store := memstore.New()
	t.Setenv(ratelimit.EnvDistributeKey, "svcticker123456ab")
	ratelimit.SetDefaultStore(store)
	t.Cleanup(func() { ratelimit.SetDefaultStore(nil) })

	var fake atomic.Int64
	fake.Store(1_700_000_000)
	clock := func() time.Time { return time.Unix(fake.Load(), 0) }

	r := &ratelimit.Ratelimit{}
	ratelimit.SetNowForTest(r, clock)
	require.NoError(t, r.Init(mockRule{ID_: 600}, "zone[]=fixed&events=10&window=5&distribute_interval=1"))
	defer r.Close()

	ratelimit.TryIncrementForTest(r, "fixed")
	assert.Eventually(t, func() bool {
		v, _ := store.Get(context.Background(), r.Distributed.UniqueKey)
		return len(v) > 0
	}, 3*time.Second, 20*time.Millisecond)
}

// TestSyncService_SurvivesStoreErrors asserts the loop keeps going despite
// transient errors and does not panic.
func TestSyncService_SurvivesStoreErrors(t *testing.T) {
	t.Setenv(ratelimit.EnvDistributeKey, "flakykey12345678ab")
	flaky := &flakyStore{underlying: memstore.New()}
	flaky.fail.Store(true)
	ratelimit.SetDefaultStore(flaky)
	t.Cleanup(func() { ratelimit.SetDefaultStore(nil) })

	r := &ratelimit.Ratelimit{}
	require.NoError(t, r.Init(mockRule{ID_: 601}, "zone[]=fixed&events=10&window=5&distribute_interval=1"))
	defer r.Close()

	time.Sleep(300 * time.Millisecond) // let some failing cycles run
	flaky.fail.Store(false)
	assert.Eventually(t, func() bool { return flaky.successes.Load() >= 1 }, 3*time.Second, 20*time.Millisecond)
}

type flakyStore struct {
	underlying ratelimit.DistributedStore
	fail       atomic.Bool
	successes  atomic.Int64
}

func (f *flakyStore) Get(ctx context.Context, key string) (string, error) {
	if f.fail.Load() {
		return "", errors.New("boom")
	}
	v, err := f.underlying.Get(ctx, key)
	if err == nil {
		f.successes.Add(1)
	}
	return v, err
}
func (f *flakyStore) SetEx(ctx context.Context, key, value string, ttl time.Duration) error {
	if f.fail.Load() {
		return errors.New("boom")
	}
	return f.underlying.SetEx(ctx, key, value, ttl)
}
func (f *flakyStore) ObtainLock(ctx context.Context, key string) (ratelimit.DistributedLock, error) {
	if f.fail.Load() {
		return nil, errors.New("boom")
	}
	return f.underlying.ObtainLock(ctx, key)
}

// TestSetLogger_RoutesBackgroundLogs verifies that SetLogger installs a
// logger whose output path is actually reached by the background sync
// goroutine.
func TestSetLogger_RoutesBackgroundLogs(t *testing.T) {
	buf := &syncBuffer{}
	ratelimit.SetLogger(newBufLogger(buf))
	t.Cleanup(func() { ratelimit.SetLogger(nil) })

	t.Setenv(ratelimit.EnvDistributeKey, "nologstore123456a")
	ratelimit.SetDefaultStore(nil)
	r := &ratelimit.Ratelimit{}
	require.NoError(t, r.Init(mockRule{ID_: 602}, "zone[]=fixed&events=1&window=1&distribute_interval=1"))
	defer r.Close()

	assert.Eventually(t, func() bool { return buf.Len() > 0 }, 3*time.Second, 50*time.Millisecond)
}
