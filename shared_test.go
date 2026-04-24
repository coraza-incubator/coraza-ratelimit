// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit_test

import (
	"bytes"
	"log/slog"
	"sync"

	ratelimit "github.com/coraza-incubator/coraza-ratelimit"
)

// mockRule is a tiny RuleMetadata usable by external _test files.
type mockRule struct{ ID_ int }

func (m mockRule) ID() int       { return m.ID_ }
func (m mockRule) ParentID() int { return 0 }
func (m mockRule) Status() int   { return 0 }

var _ = ratelimit.MockTx{} // ensure the test-only export is reachable

// syncBuffer is a concurrency-safe *bytes.Buffer for capturing slog output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func newBufLogger(w *syncBuffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, nil))
}
