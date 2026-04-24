// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
)

// Hardening caps on the action-options string. These are not a security
// boundary (rule files are operator-controlled) but they stop accidental
// pathological configs from becoming pathological parsers.
const (
	maxConfigLen    = 4096
	maxConfigTokens = 64
)

// parseConfig decodes the action options string and populates the receiver
// with the resulting configuration. All validation runs here so Evaluate
// can assume sane values.
//
// Syntax matches upstream: key=value pairs joined by '&'.
func (e *Ratelimit) parseConfig(config string) error {
	if len(config) > maxConfigLen {
		return fmt.Errorf("config too long: %d bytes (max %d)", len(config), maxConfigLen)
	}

	tokens := strings.Split(config, "&")
	if len(tokens) > maxConfigTokens {
		return fmt.Errorf("too many tokens: %d (max %d)", len(tokens), maxConfigTokens)
	}

	required := map[string]bool{"zone[]": false, "events": false, "window": false}
	seen := map[string]bool{}

	for _, token := range tokens {
		key, value, found := strings.Cut(token, "=")
		if !found || key == "" || value == "" || strings.Contains(value, "=") {
			return fmt.Errorf("invalid token %q: expected key=value", token)
		}

		// zone[] is the only repeatable key.
		if key != "zone[]" {
			if seen[key] {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[key] = true
		}

		switch key {
		case "zone[]":
			m, err := macro.NewMacro(value)
			if err != nil {
				return fmt.Errorf("invalid macro %q: %w", value, err)
			}
			e.ZoneMacros = append(e.ZoneMacros, m)
			required["zone[]"] = true

		case "events":
			v, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return fmt.Errorf("events: invalid integer %q", value)
			}
			if v < 0 {
				return errors.New("events: must be >= 0")
			}
			e.MaxEvents = v
			required["events"] = true

		case "window":
			v, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return fmt.Errorf("window: invalid integer %q", value)
			}
			if v <= 0 {
				return errors.New("window: must be > 0")
			}
			e.Window = v
			required["window"] = true

		case "interval":
			// Accepted for backward compatibility with the upstream
			// plugin; the value is ignored. Zone cleanup is now inline
			// (see zones.go: opportunisticSweepEvery) and no background
			// sweeper goroutine is spawned. Validate the token so old
			// configs don't silently accept garbage.
			if v, err := strconv.Atoi(value); err != nil || v <= 0 {
				return fmt.Errorf("interval: invalid integer %q (note: interval is accepted but ignored since v0.1)", value)
			}

		case "action":
			switch value {
			case "drop", "deny", "redirect":
				e.Action = value
			default:
				return fmt.Errorf("action: must be one of drop|deny|redirect, got %q", value)
			}

		case "status":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("status: invalid integer %q", value)
			}
			// v0.2 breaking change: floor raised from 0 to 100. A status of 0
			// causes Coraza's HTTP layer to silently fall through and defeats
			// the point of the action.
			if v < 100 || v > 599 {
				return fmt.Errorf("status: must be in 100-599, got %d", v)
			}
			e.Status = v

		case "max_zones":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("max_zones: invalid integer %q", value)
			}
			if v <= 0 {
				return errors.New("max_zones: must be > 0")
			}
			e.MaxZones = v

		case "distribute_interval":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("distribute_interval: invalid integer %q", value)
			}
			if v <= 0 {
				return errors.New("distribute_interval: must be > 0")
			}
			if err := e.initDistribute(time.Duration(v) * time.Second); err != nil {
				return fmt.Errorf("distribute_interval: %w", err)
			}

		default:
			return fmt.Errorf("unknown key %q", key)
		}
	}

	for key, ok := range required {
		if !ok {
			return fmt.Errorf("missing required key %q", key)
		}
	}

	return nil
}

// validateDistributionKey enforces the shape of the shared cluster key used
// to namespace Redis entries: 16-30 alphanumeric characters with at least
// one letter and one digit.
func validateDistributionKey(key string) error {
	if n := len(key); n < 16 || n > 30 {
		return errors.New("distribute key must be between 16 and 30 characters")
	}
	var hasDigit, hasLetter bool
	for _, r := range key {
		switch {
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsLetter(r):
			hasLetter = true
		default:
			return fmt.Errorf("distribute key contains non-alphanumeric character %q", r)
		}
	}
	if !hasDigit {
		return errors.New("distribute key must contain at least one digit")
	}
	if !hasLetter {
		return errors.New("distribute key must contain at least one letter")
	}
	return nil
}
