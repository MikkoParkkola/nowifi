# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.16.3] - 2026-10-09

### Security

- Go toolchain 1.26.9, so the release bottle includes the ten stdlib CVE
  fixes in the `go` command and the `crypto/tls`, `html/template`,
  `net/http`, `net/textproto` and `os` packages that landed in Go 1.26.9
  and 1.27.2 on 2026-10-08. `govulncheck` reports no vulnerable call paths
  from this module.
- `golang.org/x/net` 0.57.0 to 0.60.0, clearing five advisories
  (GO-2026-6603/6610/6611/6612/6617) the CI OSV scan flags at module level.

[0.16.3]: https://github.com/MikkoParkkola/nowifi/releases/tag/v0.16.3

## [0.16.2] - 2026-09-04

### Security

- Go toolchain 1.26.6 and `golang.org/x/crypto` 0.56.0, so the release
  bottle includes the stdlib and crypto fixes that landed on `main` after
  v0.16.1.

### Changed

- `go install` binaries now report the module version instead of `dev` (#54).
- Homebrew 6.0 tap-trust step documented (#56).

[0.16.2]: https://github.com/MikkoParkkola/nowifi/releases/tag/v0.16.2

## [0.16.1] - 2026-06-21

GitHub Release [0.16.1] shipped without a changelog section. This entry
records that cut so later notes can refer to it.

[0.16.1]: https://github.com/MikkoParkkola/nowifi/releases/tag/v0.16.1

## [0.16.0] - 2026-05-31 — the self-improving loop

### Added

- `nowifi forensics` — offline, read-only, local-only capture of which egress
  channels survive captive-portal enforcement (#41).
- Gateway attack-surface recon: Kong admin-plane exposure detection with an
  optional nmap sweep (#45), and pax-api recon that distinguishes a real
  enforcement API from the SPA's catch-all 200s (#44).
- `nowifi report` — automatic, consent-gated, deferred GitHub-issue report when
  a bypass fails offline; nothing is uploaded without explicit consent and MACs
  are redacted to vendor IDs first (#42).
- `icmp_tunnel` added to the Panasonic / Nordic-Sky recommended order, validated
  reaching the internet under enforcement on a real flight (#39).

### Changed

- Documented the forensics and report commands; `report_failures` is now
  toggleable (#43).
- `golang.org/x/crypto` 0.51 to 0.52 (#38).

### Fixed

- Corrected flight-connect bugs and an inaccurate `mac_clone` comment (#40).

[0.16.0]: https://github.com/MikkoParkkola/nowifi/releases/tag/v0.16.0

## [0.15.1] - 2026-05-21

### Changed

- Dependency bumps: `quic-go` (#36), `golang.org/x/net` 0.53 to 0.54 (#35),
  `golang.org/x/term` 0.42 to 0.43 (#34), `cosign-installer` 4.1.1 to
  4.1.2 (#33).

[0.15.1]: https://github.com/MikkoParkkola/nowifi/releases/tag/v0.15.1

## [0.15.0] - 2026-04-30

### Added

- libp2p provider for P2P tunnel peers (server mode).
- Captive-resistant `HasInternet` quorum verifier, so bypass detection is not
  fooled by a portal that answers every probe (#31).

### Changed

- Release signatures now use sigstore bundles; the SBOM generator runs on the
  host architecture; signed release artifacts are published.

### Documentation

- README explains antivirus false positives for chisel / hysteria / cloudflared.

[0.15.0]: https://github.com/MikkoParkkola/nowifi/releases/tag/v0.15.0

## [0.14.3] - 2026-04-26

### Changed
- CI now uses Node 24-capable GitHub Actions (`actions/checkout@v6`,
  `actions/setup-go@v6`, and `golangci/golangci-lint-action@v9` with
  `golangci-lint` pinned to `v2.11.4`) and points Go cache keys at
  `go/go.sum`, removing the non-fatal workflow warnings from the 0.14.2
  release.
- Release artifact upload/download now use Node 24-capable artifact actions.
- Migrated the golangci-lint config to the v2 schema used by the upgraded
  action.
- Release jobs now create the GitHub Release before uploading assets, so fresh
  tags publish archives without manual recovery.

### Security
- Added a security regression checklist covering privileged temp files, cleanup
  ordering, authenticated Cloudflare Workers, test isolation, MAC restore
  preconditions, IPv6 hop-limit restoration, checked VPS downloads, token
  redaction, and release integrity.
- Added Dependabot coverage for GitHub Actions and the Go module to keep CI and
  dependency updates visible.

[0.14.3]: https://github.com/MikkoParkkola/nowifi/releases/tag/v0.14.3

## [0.14.2] - 2026-04-26

### Security
- Fixed stealth PF rule loading to use unique temporary files instead of a fixed
  `/tmp` path when running with elevated privileges.
- Fixed TUI cleanup ordering so audit exit waits for the mutating pipeline and
  restore guard before reporting that network state is restored.
- Hardened the deployed Cloudflare Worker with a generated token and client-side
  URL validation, preventing accidental open-proxy deployment.
- Isolated CF Worker bypass tests from real user config and real Cloudflare
  deployment state by injecting config/deploy/verify dependencies.
- Abort mutating bypass work when guard setup cannot capture the original MAC
  restore target.
- Store and restore the original IPv6 hop limit alongside IPv4 TTL during
  stealth mode.
- Verify the pinned chisel download checksum in VPS cloud-init before executing
  it as root.

[0.14.2]: https://github.com/MikkoParkkola/nowifi/releases/tag/v0.14.2

## [0.14.1] - 2026-04-22

### Fixed
- **Tunnel correctness pass** (PR #30, four squashed fixes):
  * CONNECT-IP now aligned with the HTTP/3 stream-datagram protocol —
    fixes silent packet loss when the server sat behind an HTTP/3
    front-end that strict-checked the datagram framing.
  * TUN `Read` no longer truncates oversized packets; ifname lookup
    is panic-guarded so a missing interface returns an error instead
    of crashing the tunnel goroutine.
  * IPv6 SNI is honoured on dial; `Stop()` is no longer racy with
    in-flight datagrams; the DoQ resolver's worker pool is bounded
    so a query storm cannot fork unbounded goroutines.
  * H2 CONNECT path now does an ALPN probe before assuming HTTP/2,
    surfaces upstream errors instead of swallowing them, and
    URL-escapes the host header.
- CI ldflag target was `cli.version` but the binary reads
  `main.version`; switching the symbol now produces correct
  `nowifi --version` output in release artifacts.

### Internal
- Coverage uplift: `internal/server/udpws` 95.6 %, `internal/server`
  84.7 % — locks in the udpws / server interfaces against the
  next round of refactors.

[0.14.1]: https://github.com/MikkoParkkola/nowifi/releases/tag/v0.14.1

## [0.14.0] - 2026-04-17

### Added
- Zero-config UDP transport over Cloudflare Quick Tunnel via new `--udp`
  flag on `nowifi server create -p cloudflare-quick`. The server end
  multiplexes UDP datagrams over the Quick Tunnel WebSocket, so a client
  behind a TCP-only captive portal can speak real UDP to arbitrary hosts.
  Real-world e2e: 100/100 datagrams round-tripped through live
  trycloudflare.com at 38.9 ms median RTT.
- Provider registry — pluggable architecture for tunnel providers.
  Adding a new provider no longer requires touching the `server` command
  plumbing; providers self-register and expose a common capability surface.
- GitHub Codespaces provider (opt-in). Set `NOWIFI_CODESPACE_REPO` and
  `nowifi server create -p codespaces` provisions a Codespace as a
  tunnel endpoint — useful when you already have a Codespaces quota and
  don't want to spin up a VPS.
- `nowifi server client` subcommand — the client side of the udpws
  protocol. Pairs with `nowifi server create -p cloudflare-quick --udp`
  on the server side to form a full UDP-over-WS tunnel.
- Recipe doc: `docs/recipes/vpn-over-quick-tunnel.md` covering five
  strategies for carrying a VPN through a TCP-only portal
  (Cloudflare Quick + `--udp`, chisel-legacy, OpenVPN TCP, wstunnel,
  Tailscale, ZeroTier) with trade-offs.

### Changed
- `cloudflare-quick` provider now holds the foreground on SIGINT/SIGTERM
  so `Ctrl+C` shuts the tunnel down cleanly instead of orphaning the
  `cloudflared` child process.

[0.14.0]: https://github.com/MikkoParkkola/nowifi/releases/tag/v0.14.0
