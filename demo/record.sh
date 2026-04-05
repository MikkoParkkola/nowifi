#!/bin/bash
# Simulated nowifi demo for recording
# Run with: asciinema rec demo.cast -c ./demo/record.sh
# Convert with: agg demo.cast demo.gif --theme mocha

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

clear

# Typing effect
type_cmd() {
    echo -n "$ "
    for ((i=0; i<${#1}; i++)); do
        echo -n "${1:$i:1}"
        sleep 0.05
    done
    echo
    sleep 0.3
}

type_cmd "sudo ./nowifi"
echo

sleep 0.5
echo -e "${BOLD}nowifi v0.5.0 — No WiFi? Now WiFi.${NC}"
echo
sleep 0.3

# Phase 1
echo -ne "1. WiFi  "
sleep 0.4
echo -e "Inflight WiFi on en0 (ch 116, -64dBm)"
sleep 0.3

# Phase 2
echo -ne "2. Portal  "
sleep 0.6
echo -e "captive portal detected (${BOLD}inflight_portal${NC})"
sleep 0.3

# Phase 3
echo -ne "3. Probing  "
sleep 1.2
echo -e "done (8 open ports, DNS open)"
sleep 0.3

# Phase 4
echo -ne "4. Bypass  "
sleep 0.8
echo -e "${GREEN}1 technique(s) succeeded${NC}"
sleep 0.3

# Phase 5
echo -ne "5. Stealth  "
sleep 0.4
echo -e "TTL normalized, traffic scrubbed"
sleep 0.5

echo
echo -e "  ┌─────────────────────────────────────────────────┐"
echo -e "  │  ${BOLD}Technique #6: MAC clone (idle)${NC}                   │"
echo -e "  │  ${GREEN}SUCCESS${NC} — Full internet by cloning idle device  │"
echo -e "  │  MAC be:67:83:82:88:17 (172.19.0.229)          │"
echo -e "  │  Severity: ${RED}Critical${NC}                              │"
echo -e "  └─────────────────────────────────────────────────┘"
echo
sleep 0.8

echo -e "  ${GREEN}CONNECTED${NC}  Maintaining session (bypass: mac_clone_idle)"
echo -e "  ${DIM}INFO${NC}  Checking every 30s — Ctrl+C to disconnect"
echo
sleep 1

# Simulated watch output
for ts in "00:12:30" "00:13:00" "00:13:30" "00:14:00"; do
    echo -e "  ${DIM}${ts}${NC}  ${GREEN}OK${NC}  Connected ($(echo $ts | sed 's/00://;s/^0//'))"
    sleep 0.6
done

sleep 0.5
echo -e "  ${DIM}00:42:00${NC}  ${RED}DOWN${NC}  Session dropped after 30m0s"
sleep 0.3
echo -e "  ${DIM}00:42:00${NC}  ${YELLOW}RENEW${NC}  Re-establishing connection..."
sleep 0.8
echo -e "  ${DIM}00:42:04${NC}  ${GREEN}OK${NC}  Reconnected via MAC rotate (a2:b4:c6:d8:e0:f2)"
sleep 1

echo
echo -e "  ${DIM}# Connected for the entire flight. Zero manual intervention.${NC}"
sleep 2
