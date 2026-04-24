// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Command example runs a tiny HTTP server guarded by Coraza with the
// ratelimit action enabled. Hit it with `hey -n 500 -c 50 http://localhost:8080/?id=1`
// and observe 429 responses after the configured budget is exhausted.
package main

import (
	"log"
	"net/http"

	_ "github.com/coraza-incubator/coraza-ratelimit"
	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
)

const directives = `
SecRuleEngine On
SecRule ARGS:id "@eq 1" "id:1, phase:1, pass, \
    ratelimit:zone[]=%{REQUEST_HEADERS.host}&events=50&window=10&action=deny&status=429, \
    status:200"
`

func main() {
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
