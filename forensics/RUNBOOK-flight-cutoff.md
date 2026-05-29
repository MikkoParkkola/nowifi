# Flight cutoff runbook — Panasonic "Nordic Sky" (Finnair)

Captured with full access 2026-05-29. Gateway `172.19.248.1`, your iface `en0`,
MAC-based enforcement, Kong gateway, Ku/Ka satellite (~800ms RTT).
Provider profile already in nowifi (`panasonic_avionics`).

## THE MOMENT ACCESS DIES — run this first

```bash
cd ~/github/nowifi/forensics
sudo bash flight-connect.sh
```

It walks the ladder and stops at the first rung that restores real internet:

1. **Tailscale exit-node = spark** (Amsterdam, over DERP/:443). *Proven reachable
   while authed: `pong from spark via DERP(ams)`.* No server setup — spark is
   already an exit node. This is the most likely whole-flight win because it
   rides :443, which captive portals usually leave open.
2. **`nowifi`** auto-bypass (your tool, 43 techniques, Panasonic-ordered:
   mac_clone_idle → dns_tunnel → doh → ntp → quic).
3. **MAC-clone an idle paid device** — 26 were on the subnet; inherits a session.
4. **iodine DNS tunnel** — needs your iodined server (see prereqs).
5. **chisel/SOCKS over :443** — needs your chisel server.

Fastest manual whole-flight bet if you only try one thing:
```bash
sudo /Applications/Tailscale.app/Contents/MacOS/Tailscale set --exit-node=spark --exit-node-allow-lan-access=true
curl ifconfig.me   # should show an Amsterdam/Vodafone IP if it worked
# revert: sudo tailscale set --exit-node=
```

## Collect intel (run UNDER enforcement, even if bypass fails)

```bash
cd ~/github/nowifi/forensics
bash captive-forensics.sh --baseline baseline-20260529T182215Z.txt --json
```

Produces `holes-<ts>.txt` + `.json`: every channel still OPEN under enforcement,
each mapped to a nowifi technique + a ready command. Diff vs the full-access
baseline to see exactly what the portal closed vs left open.

## Baseline captured at full access (the gold for "next time")

- **UDP/53 external recursion OPEN** via portal resolver AND 8.8.8.8/1.1.1.1 → DNS tunnel viable
- **ICMP echo to internet OPEN** (ttl=105) → ptunnel covert channel (NOT in nowifi's Panasonic order — a gap to add)
- **UDP/123 NTP OPEN** → ntp covert channel
- **TCP 443/53/22 egress OPEN** while authed (re-test at cutoff — survivors are your tunnels)
- **No IPv6** → confirms nowifi's "ipv6 ineffective" for this provider
- **26 authed devices** on `172.19.248.0/24` → MAC-clone pool
- **Squid + Kong** in the path (`Via:` headers)

## Server-side prereqs (for rungs 4–5 — set up later, on the ground)

The independent tunnels need a far-side server. spark is behind CGNAT (only
reachable via tailnet/DERP), so it can't host an authoritative-NS iodined or a
public :443 directly. For true independence next time, stand up a cheap VPS:
- **iodine**: delegate `t.yourdomain.com` NS → VPS running `iodined`; then
  `export NOWIFI_IODINE_DOMAIN=t.yourdomain.com NOWIFI_IODINE_PW=...`
- **chisel**: VPS `chisel server -p 443 --reverse`; then
  `export NOWIFI_CHISEL_SERVER=https://yourvps:443`

## Toolkit installed this session (while online)

`iodine` (/opt/homebrew/sbin), `socat`, `ptunnel`, `dns2tcp`, `cloudflared`,
`nowifi v0.15.0`. (`chisel`/`sshuttle`/`gost` may still be finishing — check
`command -v`.) These CANNOT be downloaded after cutoff — that's why we did it now.

## Cleanup after the flight
```bash
sudo tailscale set --exit-node=         # stop routing via Amsterdam
sudo ifconfig en0 ether <your-real-mac> # if you cloned a MAC (printed by the script)
```
