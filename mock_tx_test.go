// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// MockRule is a minimal RuleMetadata for unit tests. Exported so external
// _test packages in this module can reuse it.
type MockRule struct{ ID_ int }

func (m MockRule) ID() int       { return m.ID_ }
func (m MockRule) ParentID() int { return 0 }
func (m MockRule) Status() int   { return 0 }

// internal alias used by internal tests.
type mockRule = MockRule

// MockTx implements plugintypes.TransactionState with just enough behaviour
// for Evaluate. All other methods return safe zero values.
type MockTx struct {
	Interrupted bool
	Interrupt_  *types.Interruption
}

func NewMockTx() *MockTx { return &MockTx{} }

func (m *MockTx) ID() string                                              { return "mock" }
func (m *MockTx) Variables() plugintypes.TransactionVariables             { return nil }
func (m *MockTx) Collection(variables.RuleVariable) collection.Collection { return nil }
func (m *MockTx) DebugLogger() debuglog.Logger                            { return debuglog.Default() }
func (m *MockTx) Capturing() bool                                         { return false }
func (m *MockTx) CaptureField(int, string)                                {}
func (m *MockTx) LastPhase() types.RulePhase                              { return 0 }
func (m *MockTx) Interrupt(i *types.Interruption) {
	m.Interrupted = true
	m.Interrupt_ = i
}

var _ plugintypes.TransactionState = (*MockTx)(nil)

// internal alias
type mockTx = MockTx

func newMockTx(_ string) *mockTx { return NewMockTx() }
