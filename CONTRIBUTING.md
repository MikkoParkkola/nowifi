# Contributing to nowifi

Thanks for your interest in contributing to nowifi.

## Getting Started

```bash
git clone https://github.com/MikkoParkkola/nowifi.git
cd nowifi/go
go build ./...
go test ./...
make lint
```

## Development

### Prerequisites

- Go 1.22+
- macOS or Linux
- For testing bypass techniques: a WiFi interface and a captive portal network

### Project Structure

```
cmd/nowifi/          Entry point
internal/
  bypass/            19 bypass techniques (split by category)
    detect/            Portal detection + vendor fingerprinting
    probe/             Pre-auth leak enumeration
    platform/          OS abstraction (darwin.go / linux.go)
    inflight/          Airline portal intelligence profiles
    crack/             WPA cracking pipeline
    tunnel/            Tunnel management (chisel, iodine, hans, etc.)
    guard/             State restoration on exit
    ...
```

### Running Tests

```bash
go test ./...                    # All tests
go test -race ./...              # With race detector
go test -cover ./...             # With coverage
go test ./internal/bypass/...    # Single package
```

### Code Style

- `go vet` must pass
- `staticcheck` should pass
- `govulncheck` should report no actionable vulnerabilities
- No TODO/FIXME/HACK markers in committed code
- All exported functions must have GoDoc comments
- All user inputs reaching `exec.Command` must be validated using `platform.Validate*` functions

### Adding a New Bypass Technique

1. Add the technique function in the appropriate `bypass_*.go` file:
   - `bypass_network.go` — Network-level (IPv6, CONNECT, VPN, whitelist)
   - `bypass_portal.go` — Portal manipulation (CNA spoof, JS bypass, creds)
   - `bypass_mac.go` — MAC/DHCP (clone, rotate)
   - `bypass_tunnel.go` — Tunnel-based (DNS, ICMP, QUIC, CF Workers, NTP, DoH)
2. Add the Method constant in `bypass.go`
3. Add the technique to the ordered list in `RunBypasses`
4. Add tests in `bypass_test.go`
5. Update README.md technique table

### Adding an Airline Profile

Edit `internal/inflight/inflight.go`:
1. Add provider constant (if new provider)
2. Add `PortalProfile` to the `Profiles` map
3. Add detection tests in `inflight_test.go`

## Pull Requests

- One feature/fix per PR
- Include tests for new functionality
- Update README if user-facing behavior changes
- All CI checks must pass

## License

By contributing, you agree that your contributions will be licensed under AGPL-3.0.
