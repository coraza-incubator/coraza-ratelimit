# Security Policy

## Status

**coraza-ratelimit is experimental and is not recommended for production
traffic.** It is a Coraza incubator project under active development. APIs,
wire formats, and behaviour may change between minor versions without
deprecation.

If you choose to deploy this plugin to protect real traffic, do so behind a
canary or shadow mode first, and set conservative limits.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to **security@coraza.io**.

Include:

- a description of the issue and why you believe it is a vulnerability
- a minimal reproduction (SecRule, code snippet, or attack traffic)
- the version / commit hash you tested against
- any known mitigations or workarounds

Do **not** open a public GitHub issue for suspected vulnerabilities.

## Scope

In scope:

- The `ratelimit` action and its config parser
- The `DistributedStore` interface and the `stores/redis` / `stores/memory`
  implementations shipped in this repository
- Cross-instance state leakage or corruption in distributed mode

Out of scope:

- Issues that require a malicious operator-controlled SecRule file (rule
  files are a trusted input — an attacker with write access to rules has
  already bypassed the WAF).
- Performance-only issues without a security impact. Report those as normal
  GitHub issues.
- Anything in Coraza core itself; report those to the upstream Coraza
  project.

## Threat model

`ratelimit` is designed to limit request rates per operator-chosen zone
keys. The threat model we defend against:

- An untrusted HTTP client varying the zone-key inputs (headers, query
  arguments) to evade the limit or to inflate memory. The `max_zones` cap
  and the sweeper mitigate both.
- A compromised single Coraza instance in distributed mode. The Lua-CAS
  lock prevents it from unlocking a lock held by a peer; the TTL on the
  Redis key prevents stale state from persisting forever.

We do **not** currently defend against:

- Redis instance compromise. An attacker with Redis write access can
  freely forge zone snapshots. Deploy Redis with TLS and authentication.
- Network partitions longer than the sync TTL. Expect 2–3% overage during
  re-convergence.
- Wall-clock skew between Coraza instances. Keep instances NTP-synced to
  within one second; otherwise sliding-window boundaries drift.

## Public disclosure

Once a fix is prepared and a release is tagged, we will coordinate a public
advisory via GitHub Security Advisories and credit reporters who wish to
be named.
