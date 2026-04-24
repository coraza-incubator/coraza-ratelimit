// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// DefaultMaxZones is the per-rule ceiling on the number of live zone entries
// when the user does not specify `max_zones`. It exists to bound memory
// growth under an adversary who varies the zone key (spoofed Host headers,
// random query parameters).
const DefaultMaxZones = 100000

func init() {
	plugins.RegisterAction("ratelimit", newRatelimit)
}

func newRatelimit() plugintypes.Action {
	return &Ratelimit{}
}

// Ratelimit is the Coraza action that enforces a sliding-window rate limit.
//
// Internals — the counter store, background goroutines, distributed state —
// are all unexported. Only the configuration fields populated from the
// action options string are exposed, and even those are read-only once
// [Init] has returned.
type Ratelimit struct {
	MaxEvents int64
	Window    int64
	Action    string
	Status    int
	MaxZones  int

	ZoneMacros  []macro.Macro
	Distributed Distributed

	store  *zoneStore
	ctx    context.Context
	cancel context.CancelFunc
	now    func() time.Time
}

// Init parses the rule options and starts the sweeper (and, if distributed
// mode is enabled, the Redis sync loop).
func (e *Ratelimit) Init(rm plugintypes.RuleMetadata, opts string) error {
	e.Action = "drop"
	e.Status = 429
	e.MaxZones = DefaultMaxZones

	if err := e.parseConfig(opts); err != nil {
		return fmt.Errorf("ratelimit: rule %d: %w", rm.ID(), err)
	}
	if e.now == nil {
		e.now = time.Now
	}
	e.store = newZoneStore()
	e.ctx, e.cancel = context.WithCancel(context.Background())

	// No sweeper goroutine: zone pruning is inline in tryIncrement. The
	// only goroutine we spawn is the distributed sync loop, and only when
	// distributed mode is enabled. See README "Production caveats" for
	// the rationale — Coraza's Action interface has no Close hook, so any
	// goroutine outlives rule reloads.
	if e.Distributed.Active {
		go e.syncService()
	}
	return nil
}

// Close stops the background goroutines. Safe to call more than once and
// before Init.
func (e *Ratelimit) Close() {
	if e.cancel != nil {
		e.cancel()
	}
}

// Evaluate records the current request against every configured zone and
// interrupts the transaction when every zone is over budget. Multiple zones
// combine with OR: a single zone with remaining budget is enough to let the
// request through.
func (e *Ratelimit) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	if e.store == nil || e.now == nil {
		return
	}
	logger := tx.DebugLogger().With(
		debuglog.Str("action", "ratelimit"),
		debuglog.Int("rule_id", r.ID()),
	)
	now := e.now().Unix()
	allowed := false
	for _, zm := range e.ZoneMacros {
		name := zm.Expand(tx)
		if name == "" {
			name = "misc"
		}
		if e.store.tryIncrement(name, now, e.Window, e.MaxEvents, e.MaxZones) {
			allowed = true
		}
	}
	if allowed {
		return
	}
	logger.Debug().Msg("ratelimit exceeded")
	tx.Interrupt(&types.Interruption{
		RuleID: r.ID(),
		Status: e.Status,
		Action: e.Action,
	})
}

// Type reports the action type required by the Coraza engine.
func (e *Ratelimit) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

