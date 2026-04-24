// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package redis is a [ratelimit.DistributedStore] backed by Redis. Import
// this package when distributed mode is enabled and register a store with
// [ratelimit.SetDefaultStore]:
//
//	store := redisstore.New(redisstore.Options{Addr: "redis.internal:6379"})
//	ratelimit.SetDefaultStore(store)
package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	ratelimit "github.com/coraza-incubator/coraza-ratelimit"
	redisv9 "github.com/redis/go-redis/v9"
)

// Options configures [New]. The zero value targets localhost:6379 for
// compatibility with the original upstream defaults.
type Options struct {
	Addr     string
	Password string
	DB       int

	// LockTTL is how long Redis will hold the distributed lock if the
	// holder dies. Keep it comfortably above the expected worst-case sync
	// duration; too low causes split-brain merges, too high amplifies the
	// impact of a crashed holder.
	LockTTL time.Duration

	// LockRetryEvery is the interval between SET NX attempts while waiting.
	LockRetryEvery time.Duration

	// LockMaxRetries bounds the total wait time at
	// LockRetryEvery * LockMaxRetries before returning ErrLockNotObtained.
	LockMaxRetries int
}

// New constructs a [ratelimit.DistributedStore] backed by Redis.
func New(opts Options) ratelimit.DistributedStore {
	if opts.Addr == "" {
		opts.Addr = "localhost:6379"
	}
	if opts.LockTTL == 0 {
		opts.LockTTL = 1500 * time.Millisecond
	}
	if opts.LockRetryEvery == 0 {
		opts.LockRetryEvery = 60 * time.Millisecond
	}
	if opts.LockMaxRetries == 0 {
		opts.LockMaxRetries = 50
	}
	return &store{
		client: redisv9.NewClient(&redisv9.Options{
			Addr:     opts.Addr,
			Password: opts.Password,
			DB:       opts.DB,
		}),
		opts: opts,
	}
}

type store struct {
	client *redisv9.Client
	opts   Options
}

func (s *store) Get(ctx context.Context, key string) (string, error) {
	v, err := s.client.Get(ctx, key).Result()
	if errors.Is(err, redisv9.Nil) {
		return "", nil
	}
	return v, err
}

func (s *store) SetEx(ctx context.Context, key, value string, ttl time.Duration) error {
	if ttl < 0 {
		ttl = 0
	}
	return s.client.Set(ctx, key, value, ttl).Err()
}

// releaseScript is the textbook CAS unlock: delete the lock key only when
// it still holds our token. Prevents a process that over-ran its TTL from
// accidentally unlocking a lock the new holder is now using.
const releaseScript = `if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end`

type lock struct {
	client *redisv9.Client
	key    string
	token  string
}

func (l *lock) Release(ctx context.Context) error {
	return redisv9.NewScript(releaseScript).Run(ctx, l.client, []string{l.key}, l.token).Err()
}

func (s *store) ObtainLock(ctx context.Context, key string) (ratelimit.DistributedLock, error) {
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	lockKey := "lock_" + key
	deadline := time.Now().Add(time.Duration(s.opts.LockMaxRetries) * s.opts.LockRetryEvery)
	for {
		ok, err := s.client.SetNX(ctx, lockKey, token, s.opts.LockTTL).Result()
		if err != nil {
			return nil, err
		}
		if ok {
			return &lock{client: s.client, key: lockKey, token: token}, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("redis: %w", ratelimit.ErrLockNotObtained)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(s.opts.LockRetryEvery):
		}
	}
}

func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
