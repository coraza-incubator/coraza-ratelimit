// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetLogger_Custom(t *testing.T) {
	buf := &bytes.Buffer{}
	l := slog.New(slog.NewTextHandler(buf, nil))
	SetLogger(l)
	t.Cleanup(func() { SetLogger(nil) })

	logPkg().Info("hello", "k", "v")
	assert.Contains(t, buf.String(), "hello")
	assert.Contains(t, buf.String(), "k=v")
}

func TestSetLogger_NilRestoresDefault(t *testing.T) {
	SetLogger(nil)
	require.NotNil(t, logPkg())
}
