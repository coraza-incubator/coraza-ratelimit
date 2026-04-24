// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package ratelimit implements a Coraza WAF action plugin that enforces
// sliding-window rate limits on requests identified by one or more
// configurable "zones".
//
// # Experimental
//
// This project is a Coraza incubator. It is NOT recommended for
// production traffic. APIs, wire formats, and behaviour may change
// between minor versions without deprecation.
//
// # Usage
//
// Importing this package with a blank identifier registers the
// "ratelimit" action with Coraza:
//
//	import _ "github.com/coraza-incubator/coraza-ratelimit"
//
// The action is then available inside SecRule directives:
//
//	SecRule ARGS:id "@eq 1" "id:1, \
//	    ratelimit:zone[]=%{REQUEST_HEADERS.host}&events=200&window=1, \
//	    pass, status:200"
//
// To enable distributed mode, register a [DistributedStore] at startup:
//
//	import redisstore "github.com/coraza-incubator/coraza-ratelimit/stores/redis"
//
//	func init() {
//	    ratelimit.SetDefaultStore(redisstore.New(redisstore.Options{
//	        Addr: "redis.internal:6379",
//	    }))
//	}
//
// See the README for the full configuration reference and operational
// caveats.
package ratelimit
