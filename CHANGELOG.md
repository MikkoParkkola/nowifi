# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
