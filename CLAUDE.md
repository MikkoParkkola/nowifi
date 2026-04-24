# nowifi — agent onboarding + project instructions

> **This file is the source of truth for agents working on nowifi.** `AGENTS.md` in this repo is the public install-facing guide for end-user agents (same pattern as `trvl`). They are intentionally diverged; do not symlink.

**Status**: v0.14.1 · Go 1.26.2 · AGPL-3.0 · single binary · public · active

## Product Vision

nowifi is a **captive-portal bypass + WiFi-recovery CLI**. One command, 43 techniques, browser works immediately. It detects captive portals (hotels / airports / cafes), probes for weaknesses, and runs bypass techniques automatically — most-powerful-first, stopping on the first that works. `Ctrl+C` restores everything.

Secondary surface: `nowifi crack` runs an ordered 8-technique WPA/WPA2 pipeline (PMKID → WPS Pixie-Dust → handshake capture → dictionary/smart cracking → WPS PIN → online brute force), stopping as soon as a password is recovered.

Scope boundary: nowifi is **not an MCP server**. It is a standalone CLI tool. `AGENTS.md` explicitly documents this. Keep the MCP-free shape.

## Current Status

- **v0.14.1** with CF Quick Tunnel + UDP-over-QUIC server modes
- **43 techniques** total: 35 captive-portal bypass + 8 WPA cracking
- **Build**: Go 1.26.2 · Bubbletea TUI · Cobra CLI · quic-go · systray
- **Distribution**: Homebrew tap · direct binaries on darwin-arm64 / darwin-amd64 / linux-amd64 / linux-arm64
- **CI**: cross-compile all targets from ubuntu-latest (recent consolidation)
- **Coverage**: udpws 95.6% · server 84.7% (recent #30 lift)
- **Telemetry**: opt-in anonymous usage reporting (zero-cost path)

## Plan Forward (near-term, technical)

- **Server-mode maturation**: CF Worker auto-deploy in setup (landed); provider registry + zero-config Quick Tunnel (landed #e715a3f); UDP-over-QUIC carried by `--udp` flag
- **Tunnel portfolio growth**: WARP bootstrap (#33), portal self-relay (#34), TURN relay (#35) — zero-config relay pattern continues
- **Technique breadth**: airline-aware technique ordering landed; similar context-aware ordering for other venue types
- **Release hygiene**: homebrew formula + ldflags version pinning occasionally drifts; single-PR parity is the norm

## Decisions Locked (do not re-litigate)

| Decision | Rationale | Do not |
|---|---|---|
| **Single Go binary, no runtime deps** | One-command install; zero toolchain burden on users | Split into client/server distribution that requires separate installs |
| **Most-powerful-first technique ordering** | User goal is "browser works now"; wasting time on low-yield techniques fails the goal | Use alphabetical, random, weakness-last ordering |
| **`Ctrl+C` restores everything** | Trust signal; users run with `sudo` | Leave residual network state on termination |
| **NOT an MCP server** | Scope boundary; MCP tooling is a different product category | Add MCP surface without explicit user direction |
| **AGPL-3.0 license** | Copyleft; derivative network services must share source | Relicense without explicit user direction |
| **Go 1.26.2 toolchain pinning** | CI reproducibility; tied to quic-go + charmbracelet libs | Bump Go version without testing UDP/QUIC paths |
| **Legitimate-use framing** | Bypass + cracking tools need clear purpose statement | Remove the responsible-use caveats from README/AGENTS.md |
| **Zero-cost telemetry is opt-in** | Privacy-by-default | Make telemetry opt-out; avoid send-by-default patterns |

## Anti-Patterns (things agents get wrong in this repo)

- **Adding MCP tooling "for completeness"** — nowifi is explicitly standalone CLI; MCP is out of scope (see `AGENTS.md` line 3).
- **Randomizing technique order** — defeats the performance story. Most-powerful-first is the design.
- **Leaking state on `Ctrl+C`** — every technique must have a restore-on-cancel path; the user runs with `sudo`.
- **Making telemetry opt-out** — zero-cost is an invariant; opt-in stays.
- **Tap / Homebrew version drift** — formula sync commits land after every release; forgetting the sync blocks users. Single-PR parity.
- **Breaking `--udp` flag semantics** — UDP-over-QUIC is a shipped mode; regressions break server parity.

## Guidance for Agents

- **Before adding a technique**: profile its success rate on a real captive portal (or document the tested scenario). Low-yield techniques go at the bottom of the ordering, not out of the suite.
- **Venue-aware ordering**: airline pattern exists; mirror for hotels / cafes / conference networks when the data supports it.
- **Coverage**: maintain udpws 95%+, server 80%+. Regressions are blocking.
- **Release flow**: bump version → tag → GitHub Release workflow cross-compiles all targets → homebrew formula sync PR → verify `nowifi --version` matches on each platform.
- **Security disclosure**: the repo has `SECURITY.md` (recent contributor template addition); point reporters there.

## Where to Look

| You want to… | Read |
|---|---|
| Onboard a human user | `README.md` |
| Onboard a fresh AI assistant to USE nowifi | `AGENTS.md` (intentionally diverged — different audience) |
| Understand bypass techniques | `go/` + technique-specific modules |
| Server mode (tunnel + UDP) | recent commits e715a3f, d09dc0e, e4712db |
| TUI + UX | `charmbracelet/bubbletea` + `lipgloss` modules under `go/` |
| Release process | CI workflow `.github/workflows/ci.yml` |
