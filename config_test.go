// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfig_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{"missing zone", "events=200&window=1", true},
		{"literal zone ok", "zone[]=fixed&events=200&window=1", false},
		{"bad macro", "zone[]=%{REQUEST_HEADERS.authority&window=1&events=1", true},
		{"missing events", "zone[]=%{REQUEST_HEADERS.authority}&window=1", true},
		{"events zero ok", "zone[]=%{REQUEST_HEADERS.host}&events=0&window=1", false},
		{"events not int", "zone[]=%{REQUEST_HEADERS.host}&events=abc&window=1", true},
		{"missing window", "zone[]=%{REQUEST_HEADERS.host}&events=100", true},
		{"window zero", "zone[]=%{REQUEST_HEADERS.host}&events=100&window=0", true},
		{"window not int", "zone[]=%{REQUEST_HEADERS.host}&events=100&window=ab", true},
		{"minimal required", "zone[]=%{REQUEST_HEADERS.host}&events=100&window=2", false},
		{"double amp mid", "zone[]=%{REQUEST_HEADERS.host}&&events=100&window=2", true},
		{"trailing amp", "zone[]=%{REQUEST_HEADERS.host}&events=100&window=2&", true},
		{"leading amp", "&zone[]=%{REQUEST_HEADERS.host}&events=100&window=2", true},
		{"interval zero", "zone[]=x&events=100&window=2&interval=0", true},
		{"interval not int", "zone[]=x&events=100&window=2&interval=ab", true},
		{"bad action", "zone[]=x&events=100&window=2&action=foo", true},
		{"action drop", "zone[]=x&events=100&window=2&action=drop&status=429", false},
		{"action deny", "zone[]=x&events=100&window=2&action=deny&status=403", false},
		{"action redirect", "zone[]=x&events=100&window=2&action=redirect&status=301", false},
		{"status negative", "zone[]=x&events=100&window=2&status=-1", true},
		{"status too big", "zone[]=x&events=100&window=2&status=600", true},
		{"status too small", "zone[]=x&events=100&window=2&status=99", true},
		{"status 100", "zone[]=x&events=100&window=2&status=100", false},
		{"status 599", "zone[]=x&events=100&window=2&status=599", false},
		{"status not int", "zone[]=x&events=100&window=2&status=abc", true},
		{"double equals", "zone[]=%{REQUEST_HEADERS.host}=&events=100=&window2", true},
		{"distribute zero", "zone[]=x&events=1&window=1&distribute_interval=0", true},
		{"unknown key", "zone[]=x&events=1&window=1&foo=bar", true},
		{"negative events", "zone[]=x&events=-1&window=1", true},
		{"duplicate events", "zone[]=x&events=1&events=2&window=1", true},
		{"max_zones ok", "zone[]=x&events=1&window=1&max_zones=50", false},
		{"max_zones zero", "zone[]=x&events=1&window=1&max_zones=0", true},
		{"multiple zones ok", "zone[]=x&zone[]=y&events=1&window=1", false},
		{"interval accepted but ignored", "zone[]=x&events=1&window=5&interval=5", false},
		{"interval zero still rejected", "zone[]=x&events=1&window=5&interval=0", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Ratelimit{}
			err := r.parseConfig(tc.config)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseConfig_AppliesDefaults(t *testing.T) {
	r := &Ratelimit{Action: "drop", Status: 429}
	require.NoError(t, r.parseConfig("zone[]=x&events=10&window=5"))
	assert.Equal(t, int64(10), r.MaxEvents)
	assert.Equal(t, int64(5), r.Window)
	assert.Len(t, r.ZoneMacros, 1)
}

func TestValidateDistributionKey(t *testing.T) {
	cases := []struct {
		key     string
		wantErr bool
	}{
		{"abcdefgh12345678", false},
		{"short1", true},
		{"ThisKeyIsWayTooLongForTheValidator12345", true},
		{"abcdefghijklmnop", true},      // no digit
		{"1234567890123456", true},      // no letter
		{"abcdefgh1234567!", true},      // non-alnum
		{"Abcdefghij1234567890", false}, // mixed
	}
	for _, tc := range cases {
		err := validateDistributionKey(tc.key)
		if tc.wantErr {
			assert.Errorf(t, err, "key=%q", tc.key)
		} else {
			assert.NoErrorf(t, err, "key=%q", tc.key)
		}
	}
}
