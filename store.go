// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrNoStoreConfigured is returned from the sync loop when distributed mode
// is enabled but no DistributedStore has been registered. Callers should
// import a store subpackage (e.g. stores/redis) and call [SetDefaultStore]
// before loading rules that enable distributed mode.
var ErrNoStoreConfigured = errors.New("ratelimit: distributed mode requires a store (see stores/redis or stores/memory)")

// ErrLockNotObtained is returned by DistributedStore implementations when
// they time out waiting for the distributed lock. Store authors should
// wrap this error so callers can use errors.Is.
var ErrLockNotObtained = errors.New("ratelimit: distributed lock not obtained")

// DistributedLock is the minimal lock handle returned by
// [DistributedStore.ObtainLock]. Release is always invoked by the sync loop
// via defer.
type DistributedLock interface {
	Release(ctx context.Context) error
}

// DistributedStore is the storage backend used by distributed mode. The
// core ratelimit package only depends on this interface; concrete backends
// live in sibling subpackages under stores/.
type DistributedStore interface {
	// Get returns the current snapshot for key, or an empty string if the
	// key does not exist. Implementations must not return a Redis-style
	// "not found" error for a missing key.
	Get(ctx context.Context, key string) (string, error)

	// SetEx writes value to key with the given TTL. A zero or negative TTL
	// means "no expiry". Operators should pass 2 * window for ratelimit
	// usage so stale keys age out automatically.
	SetEx(ctx context.Context, key, value string, ttl time.Duration) error

	// ObtainLock blocks until either the distributed lock is acquired, the
	// store's retry budget is exhausted, or ctx is cancelled. On budget
	// exhaustion it must return an error that wraps [ErrLockNotObtained].
	ObtainLock(ctx context.Context, key string) (DistributedLock, error)
}

// SetDefaultStore registers the store used by Ratelimit instances that do
// not carry their own. Pass nil to unregister.
func SetDefaultStore(s DistributedStore) {
	defaultMu.Lock()
	defaultStoreInstance = s
	defaultMu.Unlock()
}

var (
	defaultMu            sync.Mutex
	defaultStoreInstance DistributedStore
)

func defaultStore() DistributedStore {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	return defaultStoreInstance
}
