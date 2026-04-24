// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"log/slog"
	"os"
	"sync/atomic"
)

var pkgLogger atomic.Pointer[slog.Logger]

// SetLogger installs a package-level [slog.Logger] used by background
// goroutines that do not have access to a transaction debug logger (the
// sweeper and the Redis sync loop). Passing nil restores the default which
// writes warnings and errors to stderr.
func SetLogger(l *slog.Logger) {
	if l == nil {
		l = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}
	pkgLogger.Store(l)
}

func logPkg() *slog.Logger {
	if l := pkgLogger.Load(); l != nil {
		return l
	}
	l := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	pkgLogger.Store(l)
	return l
}
