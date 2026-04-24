// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit_test

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	ratelimit "github.com/coraza-incubator/coraza-ratelimit"
	memstore "github.com/coraza-incubator/coraza-ratelimit/stores/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitDistribute_RequiresEnv(t *testing.T) {
	t.Setenv(ratelimit.EnvDistributeKey, "")
	r := &ratelimit.Ratelimit{}
	err := r.Init(mockRule{ID_: 1}, "zone[]=x&events=1&window=1&distribute_interval=1")
	require.Error(t, err)
}

func TestInitDistribute_InvalidKey(t *testing.T) {
	t.Setenv(ratelimit.EnvDistributeKey, "tooshort")
	r := &ratelimit.Ratelimit{}
	err := r.Init(mockRule{ID_: 1}, "zone[]=x&events=1&window=1&distribute_interval=1")
	require.Error(t, err)
}

func TestInitDistribute_NoStoreConfigured(t *testing.T) {
	t.Setenv(ratelimit.EnvDistributeKey, "abcdefgh12345678")
	ratelimit.SetDefaultStore(nil)
	r := &ratelimit.Ratelimit{}
	// parseConfig succeeds; the failure surfaces when syncOnce runs.
	require.NoError(t, r.Init(mockRule{ID_: 1}, "zone[]=x&events=1&window=1&distribute_interval=2"))
	defer r.Close()
	// The background sync loop logs the error; here we assert the
	// Distributed mode was still marked active (config-layer success).
	assert.True(t, r.Distributed.Active)
}

func TestSyncOnce_MergesRemoteCounts(t *testing.T) {
	store := memstore.New()
	t.Setenv(ratelimit.EnvDistributeKey, "testkey1234567890")
	ratelimit.SetDefaultStore(store)
	t.Cleanup(func() { ratelimit.SetDefaultStore(nil) })

	var fake atomic.Int64
	fake.Store(1_700_000_000)
	clock := func() time.Time { return time.Unix(fake.Load(), 0) }

	r := &ratelimit.Ratelimit{}
	ratelimit.SetNowForTest(r, clock)
	require.NoError(t, ratelimit.InitForTest(r, mockRule{ID_: 501}, "zone[]=fixed&events=10&window=5&distribute_interval=60"))
	defer r.Close()

	// Seed remote before manually triggering a sync.
	seed := map[string]map[int64]int64{"fixed": {fake.Load(): 3}}
	raw, _ := json.Marshal(seed)
	require.NoError(t, store.SetEx(context.Background(), r.Distributed.UniqueKey, string(raw), 0))

	require.NoError(t, ratelimit.SyncOnceForTest(r, context.Background()))
	assert.GreaterOrEqual(t, r.StoreTotal(), int64(3))
}

func TestSyncOnce_IgnoresStaleTimestamps(t *testing.T) {
	store := memstore.New()
	t.Setenv(ratelimit.EnvDistributeKey, "staletest1234567a")
	ratelimit.SetDefaultStore(store)
	t.Cleanup(func() { ratelimit.SetDefaultStore(nil) })

	var fake atomic.Int64
	fake.Store(1_700_000_000)
	clock := func() time.Time { return time.Unix(fake.Load(), 0) }

	r := &ratelimit.Ratelimit{}
	ratelimit.SetNowForTest(r, clock)
	require.NoError(t, ratelimit.InitForTest(r, mockRule{ID_: 502}, "zone[]=fixed&events=10&window=5&distribute_interval=60"))
	defer r.Close()

	old := fake.Load() - 100
	seed := map[string]map[int64]int64{"fixed": {old: 999, fake.Load(): 2}}
	raw, _ := json.Marshal(seed)
	require.NoError(t, store.SetEx(context.Background(), r.Distributed.UniqueKey, string(raw), 0))

	require.NoError(t, ratelimit.SyncOnceForTest(r, context.Background()))
	// Only the fresh count should be merged.
	assert.Equal(t, int64(2), r.StoreTotal())
}

func TestSyncOnce_EmptyRemoteOK(t *testing.T) {
	store := memstore.New()
	t.Setenv(ratelimit.EnvDistributeKey, "emptykey12345678ab")
	ratelimit.SetDefaultStore(store)
	t.Cleanup(func() { ratelimit.SetDefaultStore(nil) })

	r := &ratelimit.Ratelimit{}
	require.NoError(t, ratelimit.InitForTest(r, mockRule{ID_: 503}, "zone[]=fixed&events=10&window=5&distribute_interval=60"))
	defer r.Close()
	require.NoError(t, ratelimit.SyncOnceForTest(r, context.Background()))
}

func TestSyncOnce_RejectsMalformedRemote(t *testing.T) {
	store := memstore.New()
	t.Setenv(ratelimit.EnvDistributeKey, "malformed12345678a")
	ratelimit.SetDefaultStore(store)
	t.Cleanup(func() { ratelimit.SetDefaultStore(nil) })

	r := &ratelimit.Ratelimit{}
	require.NoError(t, ratelimit.InitForTest(r, mockRule{ID_: 504}, "zone[]=fixed&events=10&window=5&distribute_interval=60"))
	defer r.Close()
	require.NoError(t, store.SetEx(context.Background(), r.Distributed.UniqueKey, "{not valid json", 0))
	require.Error(t, ratelimit.SyncOnceForTest(r, context.Background()))
}

func TestSyncOnce_NoStoreErrors(t *testing.T) {
	t.Setenv(ratelimit.EnvDistributeKey, "nostorekey123456a")
	ratelimit.SetDefaultStore(nil)
	r := &ratelimit.Ratelimit{}
	require.NoError(t, ratelimit.InitForTest(r, mockRule{ID_: 505}, "zone[]=fixed&events=10&window=5&distribute_interval=60"))
	defer r.Close()
	err := ratelimit.SyncOnceForTest(r, context.Background())
	require.ErrorIs(t, err, ratelimit.ErrNoStoreConfigured)
}
