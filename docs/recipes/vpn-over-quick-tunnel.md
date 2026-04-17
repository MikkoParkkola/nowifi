# VPN over Cloudflare Quick Tunnel

Bring up WireGuard or OpenVPN through a zero-config public HTTPS endpoint —
no VPS, no static IP, under ten seconds to a running tunnel.

> **Threat model note — read first**
> Cloudflare logs the source IP of any Quick Tunnel you open. Tunnels are
> **not anonymous**. Use only against networks you are authorized to assess.
> See [G3 disclosure](#9-threat-model-note) at the bottom for the full text.

---

## 1. What this gives you

A Cloudflare Quick Tunnel (`cloudflared tunnel --url`) creates an ephemeral
HTTPS/WebSocket endpoint at `<random-name>.trycloudflare.com` that proxies
TCP traffic to a port on your local machine. No Cloudflare account, no DNS
delegation, no billing — free, disposable, rotates on each start.

Combined with nowifi's existing `chisel` binary (already downloaded by
`nowifi tools -d`) you get a full WireGuard-capable relay in two commands.

---

## 2. What works / what doesn't

The Quick Tunnel is a **TCP pipe** at the Cloudflare edge layer. Raw UDP
datagrams never reach your local port.

| Transport | Works? | Notes |
|-----------|--------|-------|
| `chisel` reverse tunnel | ✅ | Already in nowifi; WebSocket over HTTPS |
| OpenVPN `--proto tcp-client` | ✅ | Must use TCP mode; port 443 preferred |
| WireGuard-over-TCP via `wstunnel` | ✅ | UDP frames wrapped in WebSocket |
| WireGuard-over-TCP via `udp2raw` | ✅ | UDP frames wrapped in fake TCP |
| Tailscale peer tunnel | ✅ | Tailscale relay or direct path; requires account |
| ZeroTier virtual network | ✅ | L2 overlay; native UDP; requires account |
| Raw UDP WireGuard (standard) | ❌ | UDP blocked at CF edge |
| OpenVPN UDP (`--proto udp`) | ❌ | UDP blocked at CF edge |
| QUIC / DTLS | ❌ | UDP blocked at CF edge |

---

## 3. Recipe A — WireGuard via built-in UDP-over-WebSocket (`--udp`)

The recommended path. No extra tools required — nowifi includes an in-process
UDP-over-WebSocket bridge (`udpws`) that tunnels raw WireGuard UDP datagrams
through the Quick Tunnel without any additional relay software.

### Architecture

```
Remote peer
  wg-quick up  →  127.0.0.1:51820 (WireGuard)
  nowifi server client --url <qt-url> --udp-local 127.0.0.1:51820
      └─ UDP client  →  wss://<qt-url>/udp  (WebSocket/HTTPS via CF edge)
                                                      ↓ WebSocket
Attacker laptop (nowifi host)
  cloudflared ──► nowifi udpws bridge  →  WireGuard 0.0.0.0:51820
```

### Attacker/laptop side

```bash
# 1. Open Quick Tunnel in UDP mode — starts the in-process WebSocket bridge
nowifi server create -p cloudflare-quick --udp --target udp://127.0.0.1:51820
#   → prints: https://shiny-river-42.trycloudflare.com
#             UDP bridge: ws://127.0.0.1:<port>/udp
#             Client cmd: nowifi server client --url https://shiny-river-42.trycloudflare.com ...

# 2. Bring up WireGuard (interface listens on 51820)
sudo wg-quick up wg0
```

### Remote peer / client side

```bash
# 1. Start the UDP-over-WebSocket client (run the command printed above)
nowifi server client --url https://shiny-river-42.trycloudflare.com \
  --udp-local 127.0.0.1:51820

# 2. Configure WireGuard to reach the laptop via the local UDP listener
#    In your peer's wg0.conf:
#      [Peer]
#      Endpoint = 127.0.0.1:51820   # same port as --udp-local
#      ...

sudo wg-quick up wg0
```

All WireGuard UDP datagrams travel as WebSocket binary frames through the
Quick Tunnel. The CF URL rotates each time `cloudflared` restarts; re-run
`nowifi server create --udp` to get a new URL and restart the client command.

---

## 3b. Recipe A-legacy — WireGuard-over-chisel (no `--udp` flag)

Use this if the `--udp` bridge is unavailable or you prefer `chisel`.
`chisel` ships with nowifi and implements a TCP/WebSocket reverse tunnel.

### Attacker/laptop side

```bash
# 1. Open the Quick Tunnel pointing at chisel's listen port
nowifi server create -p cloudflare-quick --target http://localhost:8080
#   → prints: https://shiny-river-42.trycloudflare.com  (keep this URL)

# 2. Start chisel server (reverse mode, port 8080)
chisel server -p 8080 --reverse

# 3. Bring up WireGuard normally (interface listens on 51820)
sudo wg-quick up wg0
```

### Remote peer / client side

```bash
# 1. Connect chisel — forward remote port 51820 → laptop's localhost:51820
chisel client https://shiny-river-42.trycloudflare.com R:51820:localhost:51820

# 2. Configure WireGuard to reach the laptop via the forwarded port
#    In your peer's wg0.conf:
#      [Peer]
#      Endpoint = 127.0.0.1:51820
#      ...

sudo wg-quick up wg0
```

---

## 4. Recipe B — OpenVPN TCP mode

OpenVPN works directly without chisel when the server side listens on TCP.

```bash
# Server (attacker laptop) — listen on TCP 443 via Quick Tunnel
nowifi server create -p cloudflare-quick --target tcp://localhost:443

# OpenVPN server config additions:
#   proto tcp-server
#   port 443
#   tls-crypt ta.key       # obfuscation layer — recommended; CF may TLS-inspect
#   cipher AES-256-GCM

openvpn --config server.conf

# Client (remote peer)
#   proto tcp-client
#   remote shiny-river-42.trycloudflare.com 443 tcp
#   tls-crypt ta.key

openvpn --config client.conf
```

**Note on TLS inspection**: Cloudflare's edge terminates HTTPS. OpenVPN's
`--tls-crypt` adds an HMAC obfuscation layer before the TLS handshake, which
makes the traffic look less like OpenVPN to intermediate DPI. Use it.

---

## 5. Recipe C — wstunnel (cleaner UDP encapsulation)

`wstunnel` wraps UDP traffic inside WebSocket frames, giving a cleaner UDP
tunnel than `udp2raw` with no raw-socket privileges required.

```bash
# Install
brew install wstunnel          # macOS
# or: cargo install wstunnel   # from source

# Server side (attacker laptop)
nowifi server create -p cloudflare-quick --target http://localhost:8080
wstunnel server --server wss://0.0.0.0:8080

# Client side (remote peer)
# Forward UDP 51820 → server's localhost:51820 via WebSocket
wstunnel client --udp-listen 127.0.0.1:51820 \
  --remote-host wss://shiny-river-42.trycloudflare.com:443/udp/127.0.0.1/51820

# WireGuard peer config: Endpoint = 127.0.0.1:51820
sudo wg-quick up wg0
```

This gives you standard UDP WireGuard semantics end-to-end while the
Quick Tunnel carries only TCP/WebSocket.

---

## 6. Recipe D — Tailscale exit node / peer tunnel

If you already have Tailscale or ZeroTier deployed, you can skip the
chisel/wstunnel layer entirely. Both overlay networks traverse NAT and captive
portals using their own relay infrastructure. The Quick Tunnel still acts as
the initial bootstrap path that punches through the portal, but once the
device is reachable over the overlay, all subsequent VPN traffic rides the
Tailscale DERP or ZeroTier planet/moon relay — not the cloudflared process.
This makes the setup more resilient to Quick Tunnel expiry and avoids the
TCP-inside-TCP overhead of the chisel path.

Tailscale wraps WireGuard in HTTPS/DERP for NAT traversal and does not
require you to forward raw UDP through the Quick Tunnel at all.

### Peer-to-peer path (no exit node)

```bash
# On attacker laptop — ensure tailscaled is running and authenticated
tailscale up --accept-routes

# On remote peer — join the same tailnet
tailscale up --authkey <tskey-auth-...> --accept-routes

# Communicate by tailnet IP (100.x.y.z), no Quick Tunnel needed for data path.
# Quick Tunnel is only needed if the captive portal blocks tailscale.net DERP.
```

If the captive portal blocks Tailscale's DERP relays, front them with the
Quick Tunnel:

```bash
# Laptop: expose DERP port 3478 (STUN/UDP) or fall back to 443 (TCP)
nowifi server create -p cloudflare-quick --target http://localhost:3478
# Set HTTPS_PROXY or route DERP traffic through the tunnel URL as needed.
# (Tailscale custom DERP maps are out of scope here; see tailscale.com/kb/1118)
```

### Full-tunnel exit node

```bash
# Designate the attacker laptop as an exit node
sudo tailscale up --advertise-exit-node

# On remote peer — route all traffic through the laptop
tailscale up --exit-node=<laptop-tailnet-ip> --exit-node-allow-lan-access

# All internet traffic now exits via the laptop, even from behind the portal.
```

**DERP fallback note**: when direct WireGuard UDP is blocked, Tailscale
automatically falls back to its DERP (WebSocket/HTTPS) relay network.
No manual configuration is required — this is automatic when `tailscaled`
cannot establish a direct path.

---

## 7. Recipe E — ZeroTier virtual network

ZeroTier creates a Layer-2 Ethernet overlay (virtual LAN) across arbitrary
networks. The control plane uses TCP (HTTPS to `my.zerotier.com`); the data
plane is native UDP on port 9993.

```bash
# On attacker laptop
zerotier-cli join <network-id>
zerotier-cli listnetworks   # wait for "OK PRIVATE" or "OK PUBLIC"

# On remote peer
zerotier-cli join <network-id>
# Authorize the new member in the ZeroTier Central web UI (or via API)

# Once authorized, peers communicate at their ZeroTier-assigned IPs (10.x.y.z)
# Use these IPs in your WireGuard Endpoint, SSH config, or VPN server config.
```

**Port 9993 blocked**: if the captive portal drops UDP 9993, ZeroTier falls
back to TCP-encapsulated transport via the `zerotier-tcp-relay` service. This
is slower but functional. Alternatively, expose port 9993 via the Quick Tunnel
(TCP only — ZeroTier will use its TCP fallback path over the tunnel):

```bash
nowifi server create -p cloudflare-quick --target tcp://localhost:9993
# ZeroTier peers connecting through this URL will use TCP relay mode.
```

**Requires account**: ZeroTier requires a free `my.zerotier.com` account to
authorize members. Self-hosted controller alternatives (`ztncui`,
`zerotier-one` with local controller) exist but are out of scope here.

---

## 8. Troubleshooting

**Quick Tunnel URL rotates on reconnect**
Each `cloudflared` start generates a new random subdomain. If the tunnel
process dies, run `nowifi server create -p cloudflare-quick` again and update
the client's chisel/wstunnel/OpenVPN remote address. Use
`nowifi server list` to see current active tunnel names.

**Cloudflare rate limits (error 1016 / 524)**
The free Quick Tunnel tier has undocumented rate limits on long-lived
WebSocket connections. If you hit them, reconnect the tunnel. For sustained
workloads consider `nowifi server create -p digitalocean` (a real VPS at
$0.007/hr) instead.

**Captive portal blocking `*.trycloudflare.com`**
Some portals whitelist by domain pattern. If `trycloudflare.com` is blocked,
fall back to the cascade:
```bash
# GitHub Codespace relay (requires NOWIFI_CODESPACE_REPO)
export NOWIFI_CODESPACE_REPO=yourgithub/nowifi-codespace-relay
nowifi server create -p github-codespace

# Or Cloudflare Worker (requires CF account)
nowifi server create -p cloudflare
```

**chisel handshake timeout**
If `chisel client` exits with "handshake timeout", the Quick Tunnel is still
starting. Wait 10–15 s for cloudflared to print the URL before running the
chisel client command.

**WireGuard `RTNETLINK` errors on Linux**
The chisel forwarded port is only on `127.0.0.1`. Make sure your WireGuard
peer's `Endpoint` in `wg0.conf` is `127.0.0.1:51820`, not the Quick Tunnel
hostname directly.

---

## 9. Threat model note

> Note: Cloudflare logs the source IP of any tunnel you open. Tunnels are
> not anonymous. Use only against networks you are authorized to assess.

The Quick Tunnel provider enforces an explicit authorization assertion (G1)
before spawning `cloudflared`: you must type `yes` at the prompt and the
event is appended to `~/.nowifi/audit.log` (SHA-256 of the target, never
the plaintext URL). This is a procedural control, not a technical one —
it does not make the tunnel anonymous.
