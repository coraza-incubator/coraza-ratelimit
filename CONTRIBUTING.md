# Contributing

Thanks for wanting to help. This project is a Coraza incubator — small,
focused, and under active churn.

## Code of Conduct

This project follows the [OWASP Code of Conduct](https://owasp.org/www-policy/operational/code-of-conduct).

## Before you file an issue

1. Run `go test -race ./...` and confirm the suite passes on `main`.
2. If you have a reproduction, include the exact SecRule, Go and Coraza
   versions, and any relevant environment (Redis topology, memberlist
   config).
3. Security issues: **do not file a public issue**. See [SECURITY.md](SECURITY.md).

## Development

```bash
go test -race ./...                                # unit + race
go test -bench=. -benchmem -benchtime=1s -run=^$  # benchmarks
go vet ./...
golangci-lint run
```

Integration tests against a real Redis:

```bash
docker compose up -d redis
INTEGRATION_REDIS=1 go test ./stores/redis/...
```

## Coding conventions

- Keep the core `ratelimit` package dep-free beyond Coraza. New backends go
  under `stores/`.
- Every exported identifier needs a GoDoc comment.
- Breaking changes to the action options syntax or to the `DistributedStore`
  interface need a CHANGELOG entry and a bump to the minor version while we
  are pre-1.0.
- No `log` package usage — transaction-scoped logs go through
  `tx.DebugLogger()`, background goroutines through the package `slog`.
- No goroutines without context-aware shutdown.
- No panics in background goroutines without a `defer recover()` that
  surfaces the stack via `logPkg()`.

## Pull requests

- One logical change per PR.
- Tests are mandatory for behavioural changes.
- Run `go mod tidy` and commit the result.
- Update `CHANGELOG.md` under the unreleased heading.

## License

By submitting code you agree your contribution is licensed under
Apache-2.0 (see [LICENSE](LICENSE)) and may carry the `OWASP Coraza
contributors` copyright notice.
