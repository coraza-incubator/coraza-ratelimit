// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package ratelimit_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	ratelimit "github.com/coraza-incubator/coraza-ratelimit"
	redisstore "github.com/coraza-incubator/coraza-ratelimit/stores/redis"
	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newWAFServer(t *testing.T, directives string) *httptest.Server {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	require.NoError(t, err)
	return httptest.NewServer(txhttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})))
}

// TestE2E_FullHTTPLoadEnforcesLimit fires 200 concurrent requests at a real
// Coraza WAF and asserts exactly the configured budget passes.
func TestE2E_FullHTTPLoadEnforcesLimit(t *testing.T) {
	directives := `SecRuleEngine On
SecRule ARGS:id "@eq 1" "id:100, phase:1, pass, ratelimit:zone[]=%{REQUEST_HEADERS.host}&events=50&window=60&action=deny&status=429"`

	srv := newWAFServer(t, directives)
	defer srv.Close()
	url := fmt.Sprintf("%s/?id=1", srv.URL)

	var ok, blocked atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := srv.Client().Get(url)
			if err != nil {
				return
			}
			resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusOK:
				ok.Add(1)
			case 429:
				blocked.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(50), ok.Load())
	assert.Equal(t, int64(150), blocked.Load())
}

// TestE2E_WindowRollover uses real wall-clock time to prove the window slides.
func TestE2E_WindowRollover(t *testing.T) {
	directives := `SecRuleEngine On
SecRule ARGS:id "@eq 1" "id:101, phase:1, pass, ratelimit:zone[]=%{REQUEST_HEADERS.host}&events=5&window=1&action=deny&status=429"`

	srv := newWAFServer(t, directives)
	defer srv.Close()
	url := fmt.Sprintf("%s/?id=1", srv.URL)

	get := func() int {
		resp, err := srv.Client().Get(url)
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < 5; i++ {
		assert.Equal(t, http.StatusOK, get())
	}
	assert.Equal(t, 429, get())
	time.Sleep(1200 * time.Millisecond)
	assert.Equal(t, http.StatusOK, get())
}

// TestE2E_MultiZoneOR verifies OR semantics across zones.
func TestE2E_MultiZoneOR(t *testing.T) {
	directives := `SecRuleEngine On
SecRule ARGS:id "@eq 1" "id:102, phase:1, pass, ratelimit:zone[]=%{REQUEST_HEADERS.host}&zone[]=%{ARGS.category}&events=3&window=60&action=deny&status=429"`

	srv := newWAFServer(t, directives)
	defer srv.Close()

	get := func(cat string) int {
		resp, err := srv.Client().Get(fmt.Sprintf("%s/?id=1&category=%s", srv.URL, cat))
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < 3; i++ {
		assert.Equal(t, http.StatusOK, get("a"))
	}
	assert.Equal(t, http.StatusOK, get("b"))
	assert.Equal(t, 429, get("a"))
}

// TestE2E_MaxZonesBoundsAttack proves the max_zones cap actually defends
// against an attacker who varies the zone key. There is no background
// sweeper: pruning is inline in tryIncrement, and the per-shard LRU
// eviction in the store is what bounds memory.
func TestE2E_MaxZonesBoundsAttack(t *testing.T) {
	directives := `SecRuleEngine On
SecRule ARGS:cli "@rx ." "id:103, phase:1, pass, ratelimit:zone[]=%{ARGS.cli}&events=1&window=60&max_zones=64&action=deny&status=429"`

	srv := newWAFServer(t, directives)
	defer srv.Close()

	// 5000 unique zone keys against a rule with max_zones=64.
	for i := 0; i < 5000; i++ {
		resp, err := srv.Client().Get(fmt.Sprintf("%s/?cli=attacker_%d", srv.URL, i))
		require.NoError(t, err)
		resp.Body.Close()
	}
	r := ratelimit.LookupForTest(103)
	require.NotNil(t, r)
	// Memory is bounded by max_zones. If the cap failed we'd see ~5000.
	assert.LessOrEqual(t, r.StoreZoneCount(), 64)
}

// TestE2E_Distributed_TwoInstancesShareState — the honest proof that
// distributed mode actually shares state: two independent Coraza WAFs
// pointed at the same miniredis enforce a combined limit.
func TestE2E_Distributed_TwoInstancesShareState(t *testing.T) {
	mr := miniredis.RunT(t)
	ratelimit.SetDefaultStore(redisstore.New(redisstore.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { ratelimit.SetDefaultStore(nil) })
	t.Setenv(ratelimit.EnvDistributeKey, "sharedkey12345678a")

	directives := `SecRuleEngine On
SecRule ARGS:id "@eq 1" "id:104, phase:1, pass, ratelimit:zone[]=cluster&events=10&window=60&action=deny&status=429&distribute_interval=1"`

	srvA := newWAFServer(t, directives)
	defer srvA.Close()
	srvB := newWAFServer(t, directives)
	defer srvB.Close()

	get := func(srv *httptest.Server) int {
		resp, err := srv.Client().Get(fmt.Sprintf("%s/?id=1", srv.URL))
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}

	for i := 0; i < 6; i++ {
		assert.Equal(t, http.StatusOK, get(srvA))
		assert.Equal(t, http.StatusOK, get(srvB))
	}

	time.Sleep(2500 * time.Millisecond) // 2 sync ticks

	blocked := false
	for i := 0; i < 5; i++ {
		if get(srvA) == 429 {
			blocked = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	assert.True(t, blocked)
}

// TestE2E_RejectsInvalidConfig surfaces bad rule options at WAF load time.
func TestE2E_RejectsInvalidConfig(t *testing.T) {
	_, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(
		`SecRuleEngine On
SecRule ARGS:id "@eq 1" "id:105, phase:1, pass, ratelimit:events=10"`,
	))
	require.Error(t, err)
}
