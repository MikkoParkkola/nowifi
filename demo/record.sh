#!/bin/bash
# Simulated nowifi TUI demo for recording
# Run with: vhs demo.tape (uses this script)

set -e

# Colors matching the Bubbletea TUI palette
CYAN='\033[1;38;5;45m'
GREEN='\033[1;38;5;48m'
RED='\033[1;38;5;204m'
YELLOW='\033[1;38;5;220m'
DIM='\033[38;5;103m'
WHITE='\033[1;38;5;255m'
BORDER='\033[38;5;60m'
BOLD='\033[1m'
NC='\033[0m'

clear

# Typing effect
type_cmd() {
    echo -n "$ "
    for ((i=0; i<${#1}; i++)); do
        echo -n "${1:$i:1}"
        sleep 0.04
    done
    echo
    sleep 0.3
}

type_cmd "sudo nowifi"
sleep 0.5

# Draw the TUI dashboard
draw_dashboard() {
    local wifi_status="$1"
    local portal_status="$2"
    local probes="$3"
    local bypass_log="$4"
    local session="$5"
    local status_msg="$6"

    # Header panel
    echo -e "${BORDER}╭────────────────────────────────────────────────────────────────────────╮${NC}"
    echo -e "${BORDER}│${NC} ${CYAN}  _ __   _____      _(_)/ _(_)${NC}                                         ${BORDER}│${NC}"
    echo -e "${BORDER}│${NC} ${CYAN} | '_ \\ / _ \\ \\ /\\ / / | |_| |${NC}                                         ${BORDER}│${NC}"
    echo -e "${BORDER}│${NC} ${CYAN} | | | | (_) \\ V  V /| |  _| |${NC}                                         ${BORDER}│${NC}"
    echo -e "${BORDER}│${NC} ${CYAN} |_| |_|\\___/ \\_/\\_/ |_|_| |_|${NC}                                         ${BORDER}│${NC}"
    echo -e "${BORDER}│${NC} ${DIM}No WiFi? Now WiFi.${NC}  ${WHITE}v0.5.1${NC}                                          ${BORDER}│${NC}"
    echo -e "${BORDER}╰────────────────────────────────────────────────────────────────────────╯${NC}"

    # System + Network panels
    echo -e "${BORDER}╭──────────────────────────────────╮${NC} ${BORDER}╭──────────────────────────────────╮${NC}"
    echo -e "${BORDER}│${NC} ${CYAN}SYSTEM${NC}                             ${BORDER}│${NC} ${BORDER}│${NC} ${CYAN}NETWORK${NC}                            ${BORDER}│${NC}"
    echo -e "${BORDER}│${NC} ${GREEN}◉${NC} WiFi   ${WHITE}Inflight WiFi${NC} ${DIM}-64dBm${NC}    ${BORDER}│${NC} ${BORDER}│${NC} ${DIM}Gateway${NC}  ${WHITE}$wifi_status${NC}  ${BORDER}│${NC}"
    echo -e "${BORDER}│${NC} ${GREEN}◉${NC} Portal ${YELLOW}captive${NC} ${DIM}(inflight)${NC}      ${BORDER}│${NC} ${BORDER}│${NC} ${DIM}Clients${NC}  ${WHITE}17 devices${NC}              ${BORDER}│${NC}"
    echo -e "${BORDER}│${NC} ${GREEN}◉${NC} Vendor ${WHITE}panasonic_avionics${NC}       ${BORDER}│${NC} ${BORDER}│${NC} ${DIM}RTT${NC}      ${RED}720ms${NC}                   ${BORDER}│${NC}"
    echo -e "${BORDER}╰──────────────────────────────────╯${NC} ${BORDER}╰──────────────────────────────────╯${NC}"

    # Probes panel
    echo -e "${BORDER}╭────────────────────────────────────────────────────────────────────────╮${NC}"
    echo -e "${BORDER}│${NC} ${CYAN}PROBES${NC}                                                                 ${BORDER}│${NC}"
    echo -e "${BORDER}│${NC} $probes  ${BORDER}│${NC}"
    echo -e "${BORDER}╰────────────────────────────────────────────────────────────────────────╯${NC}"

    # Bypass panel
    echo -e "${BORDER}╭────────────────────────────────────────────────────────────────────────╮${NC}"
    echo -e "${BORDER}│${NC} ${CYAN}BYPASS${NC}                                                                 ${BORDER}│${NC}"
    echo -e "$bypass_log"
    echo -e "${BORDER}╰────────────────────────────────────────────────────────────────────────╯${NC}"

    # Session panel
    echo -e "$session"

    # Status line
    echo -e "                       ${DIM}$status_msg${NC}"
}

# Phase 1: Initial scan
clear
draw_dashboard \
    "172.16.128.1           " \
    "" \
    "${DIM}· DNS   · ICMP   · IPv6   · HTTPS   · QUIC   · NTP   · DoH${NC}            " \
    "${BORDER}│${NC} ${DIM}scanning...${NC}                                                            ${BORDER}│${NC}" \
    "${BORDER}╭────────────────────────────────────────────────────────────────────────╮${NC}
${BORDER}│${NC} ${CYAN}SESSION${NC}                                                                ${BORDER}│${NC}
${BORDER}│${NC} ${DIM}○ waiting...${NC}                                                            ${BORDER}│${NC}
${BORDER}│${NC} ${DIM}░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░${NC}           ${BORDER}│${NC}
${BORDER}╰────────────────────────────────────────────────────────────────────────╯" \
    "Probing network leaks..."
sleep 2

# Phase 2: Probes complete
clear
draw_dashboard \
    "172.16.128.1           " \
    "" \
    "${GREEN}✓${NC} DNS   ${GREEN}✓${NC} ICMP   ${RED}✗${NC} IPv6   ${GREEN}✓${NC} HTTPS   ${RED}✗${NC} QUIC   ${GREEN}✓${NC} NTP   ${GREEN}✓${NC} DoH  " \
    "${BORDER}│${NC} ${RED}✗${NC} ipv6_bypass ${DIM}-- No IPv6 connectivity${NC}                                   ${BORDER}│${NC}
${BORDER}│${NC} ${RED}✗${NC} chisel_tunnel ${DIM}-- No server configured${NC}                                  ${BORDER}│${NC}
${BORDER}│${NC} ${YELLOW}⠋${NC} ${YELLOW}mac_clone_idle${NC}${DIM}...${NC}                                                     ${BORDER}│${NC}" \
    "${BORDER}╭────────────────────────────────────────────────────────────────────────╮${NC}
${BORDER}│${NC} ${CYAN}SESSION${NC}                                                                ${BORDER}│${NC}
${BORDER}│${NC} ${DIM}○ bypassing...${NC}                                                          ${BORDER}│${NC}
${BORDER}│${NC} ${DIM}░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░${NC}           ${BORDER}│${NC}
${BORDER}╰────────────────────────────────────────────────────────────────────────╯" \
    "Running bypass techniques..."
sleep 2

# Phase 3: Connected!
clear
draw_dashboard \
    "172.16.128.1           " \
    "" \
    "${GREEN}✓${NC} DNS   ${GREEN}✓${NC} ICMP   ${RED}✗${NC} IPv6   ${GREEN}✓${NC} HTTPS   ${RED}✗${NC} QUIC   ${GREEN}✓${NC} NTP   ${GREEN}✓${NC} DoH  " \
    "${BORDER}│${NC} ${RED}✗${NC} ipv6_bypass ${DIM}-- No IPv6 connectivity${NC}                                   ${BORDER}│${NC}
${BORDER}│${NC} ${RED}✗${NC} chisel_tunnel ${DIM}-- No server configured${NC}                                  ${BORDER}│${NC}
${BORDER}│${NC} ${GREEN}✓${NC} ${GREEN}mac_clone_idle${NC} ${DIM}-- Full internet by cloning idle device${NC}              ${BORDER}│${NC}" \
    "${GREEN}╔════════════════════════════════════════════════════════════════════════╗${NC}
${GREEN}║${NC} ${CYAN}SESSION${NC}                                                                ${GREEN}║${NC}
${GREEN}║${NC} ${GREEN}◉ CONNECTED${NC}  ${WHITE}00:00:14${NC}  ${DIM}Stealth: TTL${NC} ${GREEN}✓${NC}  ${DIM}PF${NC} ${GREEN}✓${NC}                          ${GREEN}║${NC}
${GREEN}║${NC} ${GREEN}████████████████${NC}${DIM}░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░${NC}  ${DIM}mac_clone${NC} ${GREEN}║${NC}
${GREEN}╚════════════════════════════════════════════════════════════════════════╝${NC}" \
    "Maintaining session (bypass: mac_clone_idle)"
sleep 3

# Phase 4: Session drop + reconnect
clear
draw_dashboard \
    "172.16.128.1           " \
    "" \
    "${GREEN}✓${NC} DNS   ${GREEN}✓${NC} ICMP   ${RED}✗${NC} IPv6   ${GREEN}✓${NC} HTTPS   ${RED}✗${NC} QUIC   ${GREEN}✓${NC} NTP   ${GREEN}✓${NC} DoH  " \
    "${BORDER}│${NC} ${RED}✗${NC} ipv6_bypass ${DIM}-- No IPv6 connectivity${NC}                                   ${BORDER}│${NC}
${BORDER}│${NC} ${GREEN}✓${NC} ${GREEN}mac_clone_idle${NC} ${DIM}-- Full internet by cloning idle device${NC}              ${BORDER}│${NC}
${BORDER}│${NC} ${YELLOW}⠋${NC} ${YELLOW}reconnecting${NC} ${DIM}-- session expired, rotating MAC...${NC}                  ${BORDER}│${NC}" \
    "${YELLOW}╔════════════════════════════════════════════════════════════════════════╗${NC}
${YELLOW}║${NC} ${CYAN}SESSION${NC}                                                                ${YELLOW}║${NC}
${YELLOW}║${NC} ${YELLOW}◉ RECONNECTING${NC}  ${WHITE}00:30:02${NC}  ${DIM}(1 renewal)${NC}                                  ${YELLOW}║${NC}
${YELLOW}║${NC} ${YELLOW}██████████████████████████████████████████████████${NC}${DIM}░░░░░░░░░░░░░░${NC}        ${YELLOW}║${NC}
${YELLOW}╚════════════════════════════════════════════════════════════════════════╝${NC}" \
    "Session dropped — reconnecting..."
sleep 2

# Phase 5: Reconnected
clear
draw_dashboard \
    "172.16.128.1           " \
    "" \
    "${GREEN}✓${NC} DNS   ${GREEN}✓${NC} ICMP   ${RED}✗${NC} IPv6   ${GREEN}✓${NC} HTTPS   ${RED}✗${NC} QUIC   ${GREEN}✓${NC} NTP   ${GREEN}✓${NC} DoH  " \
    "${BORDER}│${NC} ${GREEN}✓${NC} ${GREEN}mac_clone_idle${NC} ${DIM}-- Full internet by cloning idle device${NC}              ${BORDER}│${NC}
${BORDER}│${NC} ${GREEN}✓${NC} ${GREEN}mac_rotate${NC} ${DIM}-- Reconnected via new MAC (a2:b4:c6:d8:e0:f2)${NC}         ${BORDER}│${NC}
${BORDER}│${NC}                                                                      ${BORDER}│${NC}" \
    "${GREEN}╔════════════════════════════════════════════════════════════════════════╗${NC}
${GREEN}║${NC} ${CYAN}SESSION${NC}                                                                ${GREEN}║${NC}
${GREEN}║${NC} ${GREEN}◉ CONNECTED${NC}  ${WHITE}00:30:08${NC}  ${DIM}(1 renewal) Stealth: TTL${NC} ${GREEN}✓${NC}  ${DIM}PF${NC} ${GREEN}✓${NC}              ${GREEN}║${NC}
${GREEN}║${NC} ${GREEN}██████████████████████████████████████████████████████${NC}${DIM}░░░░░░░░░░${NC}        ${GREEN}║${NC}
${GREEN}╚════════════════════════════════════════════════════════════════════════╝${NC}" \
    "Maintaining session (1 renewal, 0 failures)"
sleep 3

# Phase 6: Exit report
clear
echo
echo -e "  All changes restored. Network is back to original state."
echo
echo -e "  ${WHITE}${BOLD}Security Findings:${NC}"
echo
echo -e "  ${GREEN}✓${NC} [${RED}CRITICAL${NC}] ${WHITE}mac_clone_idle${NC}"
echo -e "    ${DIM}Impact:${NC} Full internet by cloning idle device MAC be:67:83:82:88:17"
echo -e "    ${DIM}PoC:${NC}    Portal uses MAC-only auth. Targeted idle device to avoid collision."
echo -e "    ${DIM}Fix:${NC}    Use 802.1X. Enable client isolation. Bind sessions to MAC+IP+DHCP."
echo
echo -e "  ${GREEN}✓${NC} [${YELLOW}HIGH${NC}] ${WHITE}mac_rotate${NC}"
echo -e "    ${DIM}Impact:${NC} Fresh session with new random MAC address"
echo -e "    ${DIM}PoC:${NC}    Portal grants new session quota per MAC."
echo -e "    ${DIM}Fix:${NC}    Rate-limit new MAC registrations. Detect MAC rotation patterns."
echo
sleep 4
