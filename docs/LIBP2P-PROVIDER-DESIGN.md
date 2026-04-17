# Design: libp2p P2P Provider

**Status**: Proposed (deferred)
**Author**: nowifi design review
**Date**: 2026-04-17
**Validation verdict**: PIVOT — core stack production-ready; WSS fallback work required before shipping
**Supersedes**: nothing (additive provider alongside existing cascade)

## 1. Context

Today's nowifi tunnel cascade (`cloudflare_quick` → `github_codespace` → `cloudflare_worker`) terminates every session on infrastructure operated by a third party (Cloudflare, GitHub, both US corporations subject to subpoena). For authorized penetration testing this is fine, but three gaps remain:

- **Third-party dependency**: if Cloudflare rate-limits anonymous tunnels or adds friction, the whole cascade degrades.
- **Hop count**: CF Quick Tunnel adds a CF edge + CF routing + our udpws wrapper. Direct peer-to-peer would halve latency and remove CF from the data path entirely.
- **Attribution surface**: source IP is logged at CF's edge. Direct P2P between the two peers — both operated by the user — keeps data out of any logged intermediary.

A decentralized, native-UDP, account-free P2P transport would close all three gaps. Research (see "Validation" below) identified `go-libp2p` with DCUtR (Direct Connection Upgrade through Relay) as the only credible 2026 candidate meeting the zero-config + native-UDP constraints.

## 2. Goals

- **Native UDP** end-to-end between peers — WireGuard and other UDP protocols ride without encapsulation penalty.
- **Zero account, zero payment** — anyone running two copies of nowifi can pair them.
- **Short pairing** — a human-friendly code (3-word mnemonic or 6-digit number), not a multihash or URL.
- **<15s from command to connected** — comparable to CF Quick Tunnel spinup.
- **Works on >70% of real-world NAT pairs** — DCUtR hole-punch success rate baseline.
- **Survives captive portals** (Phase 2 goal) — WSS-over-443 fallback for UDP-blocked environments.

## 3. Non-goals

- **Not a replacement** for existing providers. Shipped as an opt-in fourth provider in the cascade.
- **Not anonymizing** — same as all other nowifi providers: peer IPs are visible to each other. Document clearly.
- **Not a content-distribution network** — we use libp2p's P2P primitives, not IPFS filesystem semantics.
- **Not a persistent identity system** — peer IDs are ephemeral per session, regenerated each run.

## 4. Architecture

### 4.1 Stack

```
┌──────────────────────────────────────────────────────────────┐
│  nowifi udpws bridge (UDP ↔ libp2p stream)                    │
├──────────────────────────────────────────────────────────────┤
│  go-libp2p stream (muxed over transport)                      │
├──────────────────────────────────────────────────────────────┤
│  Transport priority chain:                                    │
│    1. QUIC/UDP (native)          ← ideal path                 │
│    2. WSS /:443 (Phase 2)        ← captive-portal fallback    │
│    3. TCP /:443 (Phase 3)        ← last-resort degraded       │
├──────────────────────────────────────────────────────────────┤
│  Connection establishment:                                    │
│    a. Bootstrap to public libp2p nodes (bootstrap.libp2p.io)  │
│    b. Relay briefly through circuit-relay-v2 public relays    │
│    c. DCUtR upgrade → direct peer-to-peer UDP                 │
└──────────────────────────────────────────────────────────────┘
```

### 4.2 Pairing

On server-side `nowifi server create -p libp2p`:

1. Generate an ephemeral Ed25519 keypair → peer ID.
2. Connect to public bootstrap nodes, announce rendezvous via libp2p pubsub on topic `nowifi-pair-<pairing-code-hash>`.
3. Print pairing code to user: three English words from a curated wordlist of ~2048 items (Syncthing-style), e.g. `autumn-river-oyster`. 11 bits per word × 3 = 33 bits of entropy, adequate for 5-minute-lived rendezvous topics.
4. Wait for peer; timeout after 5 minutes.

On client-side `nowifi server client --pair autumn-river-oyster`:

1. Hash the pairing code, subscribe to same rendezvous topic.
2. Exchange peer IDs + multiaddrs.
3. Establish libp2p connection, attempt DCUtR upgrade to direct.
4. Bridge local UDP port ↔ libp2p stream via the existing `udpws` package (reused: its UDP↔byte-stream logic is transport-agnostic; we just swap WS for libp2p).

### 4.3 Reuse of existing code

- **`udpws` package** → extract the UDP-framing logic into a transport-neutral `udppipe` package. Both WS (existing) and libp2p (new) implementations feed into the same UDP bridge.
- **Provider registry** → new `provider_libp2p.go` registers as `libp2p`. No changes to `provider.go`.
- **Guardrails** → G1 (auth-assertion) + G3 (no-anonymity disclosure) identical to CF Quick Tunnel. Add G3-libp2p variant noting "your peer IP is visible to the other peer and briefly to the circuit relay".

## 5. Security

| Threat | Mitigation |
|---|---|
| Pairing code brute-force | 5-minute TTL + 33-bit entropy = ~1 guess per 2.6 × 10^8 attempts over 5min. Rate-limit same-topic subscriptions. |
| Man-in-the-middle during pairing | libp2p's Noise protocol authenticates peer IDs cryptographically after the initial rendezvous — a MITM at the DHT layer cannot impersonate without breaking Ed25519. |
| Malicious circuit relay | Circuit-relay-v2 traffic is end-to-end encrypted via Noise. A malicious relay can drop traffic (DoS) but cannot read or tamper. |
| Public-relay abuse by nowifi users | Documented AUP limit: brief bootstrap use only. DCUtR upgrade forces direct connection within seconds, minimizing relay footprint. Precedent: Syncthing, Berty, and similar tools operate within AUP. |
| Pairing code shared accidentally | Single-use: topic is deleted after first successful peer connection. |

## 6. Phased rollout

### Phase 1 — MVP (2 weeks, open networks only)

- go-libp2p node embedded in nowifi binary
- QUIC-only transport (native UDP)
- DCUtR hole-punching
- Pubsub-based pairing with 3-word codes
- Full udpws reuse via `udppipe` abstraction
- Unit tests + loopback integration tests
- Documented as "works on home WiFi, mobile, most café WiFi"

**Ships when**: >70% hole-punch success on a panel of 20 real-world NAT pairs.

### Phase 2 — WSS fallback (1 week, captive-portal survival)

- Add WSS transport to the priority chain
- Connection attempt order: QUIC(UDP) → WSS(443) → fail
- Test against at least one real captive-portal environment (airport, coffee chain)
- Documented as "works on most networks including many captive portals"

**Ships when**: working WSS handshake through a captive portal with no config.

### Phase 3 — TCP degraded path (optional)

- Add plain TCP/:443 as last-resort transport
- Document as "may work on extreme-filtered networks, expect 30%+ packet loss in worst cases"

**Ships when**: anyone asks for it.

## 7. CLI UX

```bash
# Server side
$ nowifi server create -p libp2p --udp-target 51820
I confirm I am authorized to test this network. [yes/NO]: yes
Note: your peer IP will be visible to the paired peer.
Pairing code: autumn-river-oyster
Waiting for peer... (expires in 5 minutes)

# Peer side
$ nowifi server client --pair autumn-river-oyster --udp-local 127.0.0.1:51820
Connected. Direct UDP path established. Peer IP: 198.51.100.42
Local UDP bridge: 127.0.0.1:51820 → peer:51820
```

Short. Both sides see the same surface as the existing CF Quick Tunnel UX; only the pairing flow differs (code instead of URL).

## 8. Open questions

1. **Wordlist source**: Syncthing's wordlist? BIP39? PGP-word? Need to pick one and vendor it (~5 KB).
2. **Rendezvous strategy**: pubsub vs DHT-PutValue/GetValue for the pairing rendezvous. Pubsub is simpler, DHT is more robust against temporary peer churn. Prototype both.
3. **Binary size budget**: research estimates 8-14 MB added. Current nowifi binary is ~25 MB. A ~50% increase is acceptable for a opt-in provider but not a default. Consider a build-tag split (`nowifi-lite` without libp2p).
4. **TURN-like behavior**: if DCUtR fails, stay on the circuit relay? Or declare failure and fall back to the next cascade provider? Likely declare failure — relay throughput is capped and not what users signed up for.
5. **Peer identity caching**: optionally persist per-pair peer IDs to `~/.nowifi/peers.json` so repeat pairings skip the rendezvous step. Nice-to-have for Phase 2.

## 9. Validation summary

From the re-validation run on 2026-04-17:

| Claim | Status | Source |
|---|---|---|
| Public bootstrap + circuit-relay-v2 stable, free, no AUP block | 🟢 | specs.libp2p.io/dcutr/, Syncthing precedent |
| DCUtR hole-punch 70-85% NAT pairs | 🟡 | Protocol Labs measurements (exact paper unretrievable) |
| Binary size 8-14 MB | 🟡 | Component-wise estimate |
| Pairing via short codes precedent | 🟢 | Syncthing device IDs, Magic Wormhole |
| DCUtR production-ready | 🟢 | go-libp2p v0.28+ (Feb 2023), default-enabled |
| Automatic WSS fallback | 🔴 | Transports exist, no auto-prioritization — must be built |

**Net**: the hard blocker is captive-portal survival, which requires the Phase 2 work. Phase 1 on its own is still valuable for open networks.

## 10. Decision log

- **2026-04-17** — Proposed. Deferred pending Phase 1 implementation capacity (~2 weeks). No commitment to ship.

## 11. References

- DCUtR spec: https://github.com/libp2p/specs/blob/master/relay/DCUtR.md
- go-libp2p: https://github.com/libp2p/go-libp2p
- Circuit relay v2: https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md
- Syncthing device IDs: https://docs.syncthing.net/dev/device-ids.html
- Magic Wormhole PAKE: https://github.com/magic-wormhole/magic-wormhole
