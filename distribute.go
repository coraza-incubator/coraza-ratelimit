// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// EnvDistributeKey names the environment variable that supplies the shared
// cluster secret used by distributed mode.
const EnvDistributeKey = "coraza_ratelimit_key"

// Distributed holds runtime state for the optional Redis-backed sync mode.
// Callers should treat it as read-only after Init.
type Distributed struct {
	Active       bool
	SyncInterval time.Duration
	UniqueKey    string

	lastSync int64
	store    DistributedStore
}

func (e *Ratelimit) initDistribute(syncInterval time.Duration) error {
	key := os.Getenv(EnvDistributeKey)
	if key == "" {
		return fmt.Errorf("environment variable %s must be set to enable distributed mode", EnvDistributeKey)
	}
	if err := validateDistributionKey(key); err != nil {
		return err
	}
	e.Distributed.Active = true
	e.Distributed.UniqueKey = key
	e.Distributed.SyncInterval = syncInterval
	return nil
}

func (e *Ratelimit) syncService() {
	// Catch panics inside the sync goroutine so a single round-trip bug
	// cannot take the whole host down. Log the stack and exit the loop —
	// Evaluate continues to work in local-only mode until the rule is
	// reloaded.
	defer func() {
		if r := recover(); r != nil {
			logPkg().Error("ratelimit sync panic", "panic", r)
		}
	}()

	if err := e.syncOnce(e.ctx); err != nil {
		logPkg().Error("initial ratelimit sync failed", "err", err)
	}
	ticker := time.NewTicker(e.Distributed.SyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			if err := e.syncOnce(e.ctx); err != nil {
				logPkg().Error("ratelimit sync failed", "err", err)
			}
		}
	}
}

// syncOnce performs a single round of merge-through-redis:
//  1. acquire the distributed lock
//  2. read the remote snapshot
//  3. merge timestamps that are newer than lastSync and still inside the window
//  4. emit a fresh snapshot with TTL 2*window so stale keys are auto-evicted
//  5. release the lock
//
// The local lock is held only around merge + snapshot; JSON marshalling
// happens outside every mutex so Evaluate latency is not affected.
func (e *Ratelimit) syncOnce(ctx context.Context) error {
	store := e.Distributed.store
	if store == nil {
		store = defaultStore()
	}
	if store == nil {
		return ErrNoStoreConfigured
	}

	lock, err := store.ObtainLock(ctx, e.Distributed.UniqueKey)
	if err != nil {
		return fmt.Errorf("obtain lock: %w", err)
	}
	defer func() { _ = lock.Release(ctx) }()

	raw, err := store.Get(ctx, e.Distributed.UniqueKey)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}

	var remote map[string]map[int64]int64
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &remote); err != nil {
			return fmt.Errorf("decode remote zones: %w", err)
		}
	}

	now := e.now().Unix()
	minTS := now - e.Window

	if remote != nil {
		e.store.merge(remote, minTS, e.Distributed.lastSync)
	}
	snap := e.store.snapshot()

	encoded, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("encode local zones: %w", err)
	}

	// TTL = 2*window gives enough slack for a slow instance to come online
	// and see recent state, but ensures stale keys age out automatically
	// when the rule is disabled or reconfigured.
	ttl := time.Duration(e.Window*2) * time.Second
	if err := store.SetEx(ctx, e.Distributed.UniqueKey, string(encoded), ttl); err != nil {
		return fmt.Errorf("set: %w", err)
	}

	e.Distributed.lastSync = now
	return nil
}
