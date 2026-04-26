# Security Regression Checklist

Use this checklist before merging changes that touch privileged network state,
tunnels, generated infrastructure scripts, or release automation.

## Required Gates

Run these locally for security-sensitive changes:

```bash
make ci
cd go && go test -race -count=1 ./...
cd go && go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4 run
cd go && go run honnef.co/go/tools/cmd/staticcheck@latest ./...
cd go && go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

For release changes, also verify the tag workflow publishes all four archives
and `checksums.sha256`.

## Review Matrix

| Area | Regression to prevent | Expected control |
| --- | --- | --- |
| Privileged temp files | Root processes following attacker-controlled symlinks or clobbering fixed paths | Use unique temp files from `os.CreateTemp` or an exclusive `O_NOFOLLOW` flow; remove files after use |
| Cleanup and restore | UI exits before deferred restore finishes | Wait for the mutating pipeline to complete before reporting that state was restored |
| Public proxy endpoints | Cloudflare Worker becomes an unauthenticated open proxy | Require `nowifi_token` client-side and `X-Nowifi-Token` server-side; redact tokens in logs/config output |
| Test isolation | Unit tests read real user config or deploy real Cloudflare state | Inject config/deploy/verify dependencies and keep tests on temp homes or mocks |
| MAC restore | Bypass mutates MAC without a captured restore target | Abort mutating bypass when guard setup cannot capture original restore state |
| TTL and hop limit | Stealth mode restores IPv4 TTL but leaves IPv6 hop limit changed | Store and restore both IPv4 TTL and IPv6 hop limit |
| Bootstrap downloads | Cloud-init executes unchecked remote binaries as root | Pin version and verify SHA-256 before install |
| Generated URLs and logs | Secrets leak through config display, logs, or result details | Redact `nowifi_token` and provider tokens in every user-visible path |
| GitHub Actions | CI warnings hide real failures or cache the wrong module | Use Node 24-capable actions and point Go caches at `go/go.sum` |

## Existing Regression Coverage

| Finding | Coverage |
| --- | --- |
| PF temp file safety | Manual review gate plus `darwin.go` implementation using unique temp files |
| TUI cleanup wait | Manual review gate around `runAuditTUI`/`runAuditPipeline` synchronization |
| Worker auth | `TestCloudflareWorkerJS_RequiresToken`, CF Worker URL validation tests, config redaction tests |
| CF test isolation | `TestTryCFWorkers_NoURL` uses injected dependencies; telemetry/config tests use temp homes |
| Missing MAC restore target | Guard setup failure tests and audit abort behavior review gate |
| IPv6 hop limit restore | Guard stealth-state tests plus `darwin.go` state restoration review gate |
| VPS checksum verification | `TestCloudInitScript_ContainsChisel` asserts checksum verification before install |

## Operator Notes

- Cloudflare Workers URLs are bearer credentials because the `nowifi_token`
  query parameter is copied into `X-Nowifi-Token` requests. Treat the full URL
  as secret and rotate it with `nowifi server rotate-token` if exposed.
- VPS bootstrap currently pins chisel `v1.10.1` and verifies its SHA-256 before
  root installation. Update the version and checksum together.
- Probe-only and `diagnose` modes must remain read-only: no network mutation,
  audit-record writes, Worker deploys, or tunnel startup.
