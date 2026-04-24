// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Command example-distributed demonstrates wiring a Redis-backed
// [DistributedStore] into Coraza before rule load.
//
//	coraza_ratelimit_key=abcdefgh12345678 go run .
package main

import (
	"log"
	"net/http"

	ratelimit "github.com/coraza-incubator/coraza-ratelimit"
	redisstore "github.com/coraza-incubator/coraza-ratelimit/stores/redis"
	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
)

const directives = `
SecRuleEngine On
SecRule ARGS:id "@eq 1" "id:1, phase:1, pass, \
    ratelimit:zone[]=cluster&events=100&window=10&action=deny&status=429&distribute_interval=2, \
    status:200"
`

func main() {
	ratelimit.SetDefaultStore(redisstore.New(redisstore.Options{Addr: "localhost:6379"}))

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		log.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", txhttp.WrapHandler(waf, handler)))
}
