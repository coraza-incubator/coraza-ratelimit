// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package memory is an in-process [ratelimit.DistributedStore]. It is
// intended for tests and for single-binary topologies that embed multiple
// Coraza instances in one process. It has no cross-host semantics; for
// real distribution use stores/redis (or, in the future, stores/gossip).
package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	ratelimit "github.com/coraza-incubator/coraza-ratelimit"
)

// New returns a fresh in-process store.
func New() ratelimit.DistributedStore {
	return &store{
		data:  map[string]entry{},
		locks: map[string]bool{},
	}
}

type entry struct {
	value    string
	expireAt time.Time // zero = no TTL
}

type store struct {
	mu    sync.Mutex
	data  map[string]entry
	locks map[string]bool
}

func (s *store) Get(ctx context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok {
		return "", nil
	}
	if !e.expireAt.IsZero() && time.Now().After(e.expireAt) {
		delete(s.data, key)
		return "", nil
	}
	return e.value, nil
}

func (s *store) SetEx(ctx context.Context, key, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := entry{value: value}
	if ttl > 0 {
		e.expireAt = time.Now().Add(ttl)
	}
	s.data[key] = e
	return nil
}

func (s *store) ObtainLock(ctx context.Context, key string) (ratelimit.DistributedLock, error) {
	lockKey := "lock_" + key
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		s.mu.Lock()
		if !s.locks[lockKey] {
			s.locks[lockKey] = true
			s.mu.Unlock()
			return &lock{store: s, key: lockKey}, nil
		}
		s.mu.Unlock()
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("memory: %w", ratelimit.ErrLockNotObtained)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

type lock struct {
	store *store
	key   string
}

func (l *lock) Release(ctx context.Context) error {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	delete(l.store.locks, l.key)
	return nil
}
