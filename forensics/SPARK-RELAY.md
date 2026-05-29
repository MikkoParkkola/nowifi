# Spark relay — LIVE endpoints (set up 2026-05-29, PROVEN working)

The chisel SOCKS tunnel through spark **works right now**: traffic exits in
Amsterdam (31.151.218.51) vs satellite direct (205.220.x). Verified twice.

## Client binary
`~/go/bin/chisel` (jpillora chisel, built to match spark's server 1.10.1)
Auth: `mikko:7d3aae159ffb6b61a272063c`

## A. chisel SOCKS over tailnet — PROVEN (works while Tailscale/DERP is up)
```bash
~/go/bin/chisel client --auth mikko:7d3aae159ffb6b61a272063c http://100.85.108.8:8090 socks
# SOCKS5 on 127.0.0.1:1080. Verify:
xh --proxy all:socks5://127.0.0.1:1080 GET https://ifconfig.me/ip   # -> 31.151.218.51
```
Point your browser (or macOS System Settings -> Network -> Proxies -> SOCKS) at
`127.0.0.1:1080` and everything routes through Amsterdam.

## B. chisel SOCKS over Cloudflare quick tunnel — independent of tailnet (fallback; WS data flaky)
```bash
~/go/bin/chisel client --auth mikko:7d3aae159ffb6b61a272063c \
  https://friendly-perspective-forth-austin.trycloudflare.com socks
```

## C. Tailscale exit-node — whole-system (not just SOCKS-aware apps)
```bash
sudo /Applications/Tailscale.app/Contents/MacOS/Tailscale set --exit-node=spark --exit-node-allow-lan-access=true
# revert: sudo tailscale set --exit-node=
```

## Server side (running on spark now, survives the flight)
- `chisel server --port 8090 --socks5 --auth <above>`  (nohup; log ~/.nowifi-relay/chisel.log)
- `cloudflared tunnel --url http://localhost:8090`       (quick tunnel; log ~/.nowifi-relay/quicktunnel.log)
- spark egress IP: 31.151.218.51 (Vodafone Amsterdam)

## REALITY CHECK on cutoff survival
A, B, C all currently ride channels that depend on reaching spark:
- A + C ride the **Tailscale transport** (DERP relay over :443). If the portal
  blocks Tailscale DERP at cutoff, both fail.
- B rides **Cloudflare anycast** (trycloudflare.com over :443) — independent of
  Tailscale, the best bet if DERP is blocked, but its WS data path was flaky in
  testing.
The unknown only the cutoff reveals: which of {Tailscale-DERP-:443,
Cloudflare-:443} the portal leaves open. Run `captive-forensics.sh` at cutoff to
find out, then pick the matching tunnel above.
