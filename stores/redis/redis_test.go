// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package redis_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	ratelimit "github.com/coraza-incubator/coraza-ratelimit"
	redisstore "github.com/coraza-incubator/coraza-ratelimit/stores/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundTrip(t *testing.T) {
	mr := miniredis.RunT(t)
	s := redisstore.New(redisstore.Options{Addr: mr.Addr()})
	ctx := context.Background()
	require.NoError(t, s.SetEx(ctx, "k", "v", time.Minute))
	got, err := s.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, "v", got)
}

func TestGet_Missing_ReturnsEmpty(t *testing.T) {
	mr := miniredis.RunT(t)
	s := redisstore.New(redisstore.Options{Addr: mr.Addr()})
	got, err := s.Get(context.Background(), "absent")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestSetEx_ZeroTTL_NoExpiry(t *testing.T) {
	mr := miniredis.RunT(t)
	s := redisstore.New(redisstore.Options{Addr: mr.Addr()})
	require.NoError(t, s.SetEx(context.Background(), "k", "v", 0))
	assert.Equal(t, time.Duration(0), mr.TTL("k"))
}

func TestSetEx_NegativeTTL_NoExpiry(t *testing.T) {
	mr := miniredis.RunT(t)
	s := redisstore.New(redisstore.Options{Addr: mr.Addr()})
	require.NoError(t, s.SetEx(context.Background(), "k", "v", -1))
	assert.Equal(t, time.Duration(0), mr.TTL("k"))
}

func TestObtainLock_AcquireRelease(t *testing.T) {
	mr := miniredis.RunT(t)
	s := redisstore.New(redisstore.Options{Addr: mr.Addr(), LockRetryEvery: 5 * time.Millisecond, LockMaxRetries: 5})
	ctx := context.Background()
	l, err := s.ObtainLock(ctx, "k")
	require.NoError(t, err)
	require.NoError(t, l.Release(ctx))
}

func TestObtainLock_TimesOut(t *testing.T) {
	mr := miniredis.RunT(t)
	s := redisstore.New(redisstore.Options{Addr: mr.Addr(), LockTTL: 5 * time.Second, LockRetryEvery: 10 * time.Millisecond, LockMaxRetries: 3})
	ctx := context.Background()
	held, err := s.ObtainLock(ctx, "contended")
	require.NoError(t, err)
	defer held.Release(ctx)

	_, err = s.ObtainLock(ctx, "contended")
	require.ErrorIs(t, err, ratelimit.ErrLockNotObtained)
}

func TestObtainLock_ContextCancelled(t *testing.T) {
	mr := miniredis.RunT(t)
	s := redisstore.New(redisstore.Options{Addr: mr.Addr(), LockTTL: time.Minute, LockRetryEvery: 10 * time.Millisecond, LockMaxRetries: 1000})
	held, err := s.ObtainLock(context.Background(), "k")
	require.NoError(t, err)
	defer held.Release(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	_, err = s.ObtainLock(ctx, "k")
	require.Error(t, err)
}

// TestRelease_CASDoesNotUnlockOthers proves the Lua CAS: a stolen lock (TTL
// expiry + another holder) survives a late Release from the original owner.
func TestRelease_CASDoesNotUnlockOthers(t *testing.T) {
	mr := miniredis.RunT(t)
	s := redisstore.New(redisstore.Options{Addr: mr.Addr(), LockTTL: time.Second})
	ctx := context.Background()
	l, err := s.ObtainLock(ctx, "casKey")
	require.NoError(t, err)

	require.NoError(t, mr.Set("lock_casKey", "stolen"))
	require.NoError(t, l.Release(ctx)) // CAS mismatch → no-op
	v, _ := mr.Get("lock_casKey")
	assert.Equal(t, "stolen", v)
}

func TestNew_Defaults(t *testing.T) {
	// Calling New with zero-value Options must not panic and must apply
	// sensible defaults.
	s := redisstore.New(redisstore.Options{})
	require.NotNil(t, s)
}
