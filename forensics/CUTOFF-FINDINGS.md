# Cutoff-run telemetry — Finnair flight 2026-05-29 (analyzed post-run)

## VERDICT: the tunnel mechanism survived enforcement; CF quick-tunnel is dead.

### chisel SOCKS over tailnet -> spark  (PROVEN, self-healing)
- 21:21:08 Connected, latency **1.06s** (satellite Ku/Ka)
- held the connection **~76 min** through the restricted window
- 22:37:49 reset-by-peer -> **auto-reconnected in 2s** at 63ms (network changed/landed)
- IMPLICATION: Tailscale/DERP relay over :443 **passes Finnair/Panasonic enforcement**.
  The `--keepalive 25s --max-retry-count -1` flags made it self-heal. This is the
  working bypass: spark exit over the :443/DERP channel.
- CONFIRM w/ operator: did apps routed via socks5://127.0.0.1:1080 actually load
  pages during the limited period? (connection persisted; data-flow-under-limit
  is the one thing the log can't prove by itself.)

### chisel SOCKS over Cloudflare quick-tunnel  (FAILED — drop it)
- continuous `websocket: bad handshake` then `tls: handshake failure`
- trycloudflare quick-tunnels do NOT proxy chisel's WS upgrade reliably
- FIX: use a **named Cloudflare Tunnel** on a real hostname (no Access policy)
  with `cloudflared access tcp`, NOT a quick-tunnel. Or WARP.

## Net learning for next time
1. Primary = chisel/exit-node over Tailscale DERP-:443 — it works, keep it.
2. Independent fallback must be a NAMED CF tunnel or a public-VPS channel
   (UDP/53 iodine, :443 chisel) — the quick-tunnel is not it.
3. Keep the keepalive+infinite-retry flags — they recovered a real reset.
