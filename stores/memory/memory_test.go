// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package memory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	ratelimit "github.com/coraza-incubator/coraza-ratelimit"
	memstore "github.com/coraza-incubator/coraza-ratelimit/stores/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundTrip(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	require.NoError(t, s.SetEx(ctx, "k", "v", time.Minute))
	got, err := s.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, "v", got)
}

func TestGet_Missing(t *testing.T) {
	s := memstore.New()
	got, err := s.Get(context.Background(), "absent")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestSetEx_TTLExpires(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	require.NoError(t, s.SetEx(ctx, "k", "v", 20*time.Millisecond))
	time.Sleep(50 * time.Millisecond)
	got, _ := s.Get(ctx, "k")
	assert.Empty(t, got)
}

func TestObtainLock_AcquireRelease(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	l, err := s.ObtainLock(ctx, "k")
	require.NoError(t, err)
	require.NoError(t, l.Release(ctx))
	// Re-acquire after release.
	l, err = s.ObtainLock(ctx, "k")
	require.NoError(t, err)
	require.NoError(t, l.Release(ctx))
}

func TestObtainLock_TimesOut(t *testing.T) {
	s := memstore.New()
	held, err := s.ObtainLock(context.Background(), "k")
	require.NoError(t, err)
	defer held.Release(context.Background())
	_, err = s.ObtainLock(context.Background(), "k")
	require.ErrorIs(t, err, ratelimit.ErrLockNotObtained)
}

func TestConcurrentLockContention(t *testing.T) {
	s := memstore.New()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			for j := 0; j < 10; j++ {
				l, err := s.ObtainLock(ctx, "shared")
				if err != nil {
					return
				}
				l.Release(ctx)
			}
		}()
	}
	wg.Wait()
}
