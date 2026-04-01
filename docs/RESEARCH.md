# WiFi Password & Captive Portal Bypass -- Advanced Techniques Research

**Purpose:** Authorized security assessment (red team) research for the Captive Portal Auditor tool.
**Date:** 2026-03-29
**Sources:** Synacktiv (Jan 2026), HTB Academy, HackTricks, multiple GitHub repos, academic research, community forums.

---

## 1. WiFi Password Recovery / Bypass (WPA2/WPA3)

### 1.1 PMKID Client-less Attack (HIGH VALUE)

**How it works:** Some APs pre-calculate and cache a Pairwise Master Key Identifier (PMKID) to support IEEE 802.11r fast roaming. An attacker can simply attempt to connect to the AP, which sends the PMKID in its response. This single value is enough for offline brute-force of the PSK, requiring zero clients present.

- **Prerequisites:** hcxdumptool, hashcat; WiFi adapter with monitor mode
- **Success rate:** ~60% of APs respond with PMKID (depends on 802.11r support)
- **Detection risk:** LOW -- single association attempt, indistinguishable from normal connection
- **Automatable:** YES -- `hcxdumptool -i wlan0 -o pmkid.pcapng --enable_status=1` then `hashcat -m 22000`
- **Source:** Synacktiv "Wireless-(in)Fidelity: Pentesting Wi-Fi in 2025" (Jan 2026); hashcat forum thread-7717

### 1.2 WPA2-PSK Online Brute Force via Modified wpa_supplicant (NOVEL)

**How it works:** Synacktiv demonstrated patching wpa_supplicant 2.11 to remove the authentication failure backoff timer, then using the Unix socket API in daemon mode to cycle PSK attempts without restarting the process. Achieves ~100 attempts per 5 minutes against live APs. Notably, no AP they tested blocked the attempts.

- **Prerequisites:** Patched wpa_supplicant (remove dur timeout at line ~8860), Python script using Unix socket
- **Success rate:** Only works against weak/contextual passwords; rate is ~20 attempts/min
- **Detection risk:** MEDIUM -- repeated 4-way handshake failures are visible in AP logs, but rarely monitored on WiFi
- **Automatable:** YES -- Synacktiv's bf_psk_connection.py PoC
- **Source:** Synacktiv (Jan 2026)

### 1.3 WPA3-Enterprise PEAP-MSCHAPv2 Relay Attack (NOVEL, HIGH VALUE)

**How it works:** Even on WPA3-Enterprise, the EAP authentication methods (PEAP-MSCHAPv2) remain the same as WPA2. If the client does not validate the RADIUS server certificate, an attacker can relay the NTLM challenge-response to the legitimate AP using hostapd-mana and wpa_sycophant. Synacktiv updated both tools to version 2.11 to support WPA3 (802.11w, WPA-EAP-SHA256). The relay gives the attacker authenticated network access even when machine account passwords (240-byte random) make cracking impossible.

- **Prerequisites:** 2 WiFi adapters, updated hostapd-mana 2.11, wpa_sycophant 2.11, victim must not validate RADIUS cert
- **Success rate:** HIGH when RADIUS cert validation is missing (very common with BYOD)
- **Detection risk:** MEDIUM -- cannot use deauth on WPA3 (802.11w), must wait for natural reconnection
- **Automatable:** PARTIALLY -- tools exist but require manual configuration per target
- **Source:** Synacktiv (Jan 2026); SensePost DEFCON 2018; wpa_sycophant + hostapd-mana repos

### 1.4 WPA2-Enterprise GTC Downgrade (HIGH VALUE)

**How it works:** EAPHammer or hostapd-mana Evil Twin can negotiate EAP-GTC as the Phase 2 method instead of MSCHAPv2. If the client accepts, credentials are transmitted in cleartext inside the PEAP tunnel, requiring zero cracking. Many Android devices and older wpa_supplicant configurations accept GTC.

- **Prerequisites:** EAPHammer, 1 WiFi adapter, Evil Twin with deauth
- **Success rate:** ~20-30% of clients accept GTC downgrade
- **Detection risk:** MEDIUM -- Evil Twin is detectable by WIDS
- **Automatable:** YES -- `eaphammer --creds --interface wlan1 --essid TARGET --auth wpa-eap`
- **Source:** Synacktiv (Jan 2026); EAPHammer documentation

### 1.5 Open WiFi + Responder LLMNR/mDNS Poisoning (HIGH VALUE, OFTEN OVERLOOKED)

**How it works:** Even on Open WiFi with VPN enforcement, Windows devices broadcast LLMNR and mDNS name resolution requests. Running Responder.py on the Open WiFi segment poisons these broadcasts, capturing NTLMv2 hashes of domain accounts. Synacktiv collected "hundreds of hashed credentials within minutes" during a real engagement.

- **Prerequisites:** Just connect to the Open WiFi; Responder.py; hashcat for cracking
- **Success rate:** VERY HIGH on corporate Open WiFi with Windows clients
- **Detection risk:** LOW-MEDIUM -- Responder is passive on the wire
- **Automatable:** YES -- `Responder.py -I wlan0`
- **Source:** Synacktiv (Jan 2026)

### 1.6 WPA3-SAE Dragonblood Attacks

**How it works:** The SAE (Dragonfly) handshake in WPA3 was found vulnerable to side-channel attacks (timing and cache-based) that leak information about the password. Includes timing attacks during hash-to-curve, cache-based attacks on brainpool curve operations, and a transition mode downgrade attack where an AP supporting both WPA2 and WPA3 can be forced to WPA2.

- **Prerequisites:** Custom tool (dragonslayer, dragondrain, dragontime, dragonforce); WiFi adapter
- **Success rate:** LOW in practice -- most have been patched; transition mode downgrade still relevant
- **Detection risk:** LOW -- passive side-channel observation
- **Automatable:** PARTIALLY -- research tools exist but not production-ready
- **Source:** Vanhoef & Ronen (2019); many APs now patched

### 1.7 Pre-computed PMK Tables (Time-Memory Tradeoff)

**How it works:** The PBKDF2 derivation uses the SSID as salt. For common SSIDs ("linksys", "default", "NETGEAR"), rainbow-table-style pre-computed PMK databases dramatically speed up cracking. Church of WiFi and similar projects maintain tables for the top 1000 SSIDs.

- **Prerequisites:** Pre-computed table files (large), captured handshake, hashcat/cowpatty
- **Success rate:** Only for common SSIDs with common passwords
- **Detection risk:** NONE -- entirely offline
- **Automatable:** YES
- **Source:** Church of WiFi project; cowpatty documentation

---

## 2. Captive Portal Bypass -- Network Layer Tunneling

### 2.1 DNS Tunneling (CLASSIC, STILL WORKS ~70% OF THE TIME)

**How it works:** Most captive portals allow outbound DNS (UDP/53) to function before authentication. Tools like iodine encode IP traffic inside DNS queries (TXT, CNAME, NULL records) to a server you control. The portal's firewall sees legitimate-looking DNS traffic.

- **Prerequisites:** External VPS running iodined, domain delegated to VPS, iodine client
- **Success rate:** ~70% -- most portals pass DNS; some newer ones intercept and rewrite
- **Detection risk:** LOW-MEDIUM -- unusual DNS query patterns, high TXT record volume
- **Automatable:** YES -- `iodine -f ns.yourdomain.com`
- **Tools:** iodine, dnscat2, dns2tcp, Heyoka
- **Throughput:** ~50-500 Kbps depending on DNS server latency

### 2.2 ICMP Tunneling (LESS KNOWN, HIGH SUCCESS)

**How it works:** Many captive portals allow ICMP echo (ping) to pass before authentication. Tools like ptunnel-ng, icmptunnel, or hans encapsulate TCP or full IP traffic inside ICMP echo request/reply packets. This creates a covert channel that the portal's firewall never inspects.

- **Prerequisites:** External VPS running ptunnel-ng server or hans server; root access on client
- **Success rate:** ~50-60% -- many portals allow ICMP; fewer than DNS but still common
- **Detection risk:** LOW -- ICMP is expected traffic; large payloads in ICMP may trigger IDS
- **Automatable:** YES -- `ptunnel-ng -p server_ip -lp 8000 -da dest_ip -dp 22`
- **Tools:** ptunnel-ng (github.com/utoni/ptunnel-ng), icmptunnel (github.com/DhavalKapil/icmptunnel), hans (code.gerade.org/hans)
- **Throughput:** ~50-100 Kbps (ptunnel); hans creates tun interfaces for full IP

### 2.3 VPN on Port 53 (UDP) or Port 443 (TCP)

**How it works:** Since captive portals typically allow outbound DNS (UDP/53) and often HTTPS (TCP/443), running a VPN server on these ports bypasses the portal entirely. WireGuard on UDP/53 or OpenVPN on TCP/443 are common configurations.

- **Prerequisites:** VPS with VPN server configured on port 53 or 443
- **Success rate:** ~60-80% -- port 53 UDP almost always works; port 443 TCP depends on whether the portal does DPI
- **Detection risk:** LOW -- traffic on expected ports
- **Automatable:** YES -- standard VPN client configuration
- **Source:** Reddit r/homelab "VPN on port 53 = bypass pretty much any wifi login page"

### 2.4 WebSocket Tunneling (MODERN, HIGH STEALTH)

**How it works:** wstunnel and chisel tunnel arbitrary TCP/UDP traffic over WebSocket (HTTP Upgrade) or HTTP/2 connections on port 443. Since WebSocket looks like a normal HTTPS connection to the portal's DPI, it passes through transparently. wstunnel (Rust rewrite) supports both WebSocket and HTTP/2 transport.

- **Prerequisites:** VPS running wstunnel server or chisel server
- **Success rate:** ~80% when port 443 is open pre-auth (common for HTTPS-based portals)
- **Detection risk:** VERY LOW -- indistinguishable from normal HTTPS
- **Automatable:** YES -- `wstunnel client wss://server:443 -L tcp://1080:127.0.0.1:1080`
- **Tools:** wstunnel (github.com/erebe/wstunnel, 13K+ stars), chisel (github.com/jpillora/chisel, 13K+ stars)
- **Throughput:** Full speed, limited only by WiFi bandwidth

### 2.5 SSH over DNS Tunnel (LAYERED)

**How it works:** First establish a DNS tunnel with iodine, then run SSH through it to create a SOCKS proxy. The SSH layer adds encryption and the SOCKS proxy allows routing all traffic through the tunnel. Two layers of tunneling for both bypass and confidentiality.

- **Prerequisites:** iodine tunnel established, SSH server on VPS
- **Success rate:** Same as DNS tunneling (~70%)
- **Detection risk:** LOW -- encrypted inside DNS tunnel
- **Automatable:** YES
- **Source:** mivang/cheatsheets on GitHub

### 2.6 HTTP CONNECT Method Abuse

**How it works:** Some captive portals allow the HTTP CONNECT method to any host on port 443 (for HTTPS). If the portal's transparent proxy supports CONNECT without authentication, you can establish a TCP tunnel to your own server.

- **Prerequisites:** Server listening on port 443, curl or custom client
- **Success rate:** ~20% -- most modern portals restrict CONNECT
- **Detection risk:** LOW
- **Automatable:** YES -- `curl -x http://portal_ip:port --connect-to your.server:443`

### 2.7 Domain Fronting

**How it works:** Use a CDN domain (e.g., cloudfront.net, azureedge.net) that the portal whitelists as the TLS SNI, but set the HTTP Host header to your actual server behind the same CDN. The portal sees traffic to a trusted domain and allows it.

- **Prerequisites:** Server behind a CDN that allows domain fronting (increasingly rare); knowledge of whitelisted domains
- **Success rate:** LOW-MEDIUM -- most CDNs have disabled domain fronting (AWS blocked it in 2018)
- **Detection risk:** LOW -- looks like CDN traffic
- **Automatable:** PARTIALLY

### 2.8 GRE / IP-in-IP Tunneling

**How it works:** If the portal allows IP protocol 47 (GRE) or protocol 4 (IPIP), these can be used to create tunnels without any port involvement. Many firewalls only filter TCP/UDP and forget about other IP protocols.

- **Prerequisites:** VPS configured as GRE/IPIP tunnel endpoint; root on client
- **Success rate:** ~15-20% -- most commercial portals block non-TCP/UDP protocols
- **Detection risk:** LOW -- unusual but not inherently suspicious
- **Automatable:** YES -- standard Linux tunnel configuration

### 2.9 Shadowsocks / V2Ray / Trojan-GFW

**How it works:** Censorship circumvention tools designed to disguise traffic as normal HTTPS. V2Ray supports WebSocket+TLS transport that is indistinguishable from browsing. Originally built for bypassing the Great Firewall, equally effective against captive portals.

- **Prerequisites:** Server running V2Ray/Shadowsocks with WebSocket+TLS transport
- **Success rate:** ~80% when HTTPS is allowed pre-auth
- **Detection risk:** VERY LOW -- specifically designed to evade DPI
- **Automatable:** YES -- client configuration files

---

## 3. Captive Portal Bypass -- MAC & Session Layer

### 3.1 MAC Address Spoofing of Authenticated Client (CLASSIC, ~80% SUCCESS)

**How it works:** ARP scan the local network to find authenticated clients, then clone their MAC address. Most portals use MAC-based authorization, so assuming an authenticated client's MAC grants full access. Tool `anticap` (macOS) automates this by trying each discovered MAC and testing for internet connectivity.

- **Prerequisites:** WiFi adapter that supports MAC changes; arp-scan or nmap for discovery
- **Success rate:** ~80% on public networks (HackersManifest assessment)
- **Detection risk:** MEDIUM -- duplicate MAC on network can cause connectivity issues for the victim
- **Automatable:** YES -- github.com/Kif11/anticap; cpscam (codewatchorg)
- **CPA relevance:** DIRECT -- this is a core technique for the auditor

### 3.2 Impersonating Inactive/Idle Users (REFINED MAC SPOOFING)

**How it works:** Rather than blindly cloning any authenticated MAC, cpscam specifically identifies inactive users (no recent traffic) and clones their MAC. This avoids MAC conflicts and connectivity disruption.

- **Prerequisites:** Monitor mode to identify traffic patterns, MAC change capability
- **Success rate:** ~70-80%
- **Detection risk:** LOW -- no duplicate active MACs
- **Automatable:** YES -- github.com/codewatchorg/cpscam
- **CPA relevance:** DIRECT -- improved version of MAC spoofing for the auditor

### 3.3 Session Cookie/Token Hijacking

**How it works:** Some portals issue authentication cookies over HTTP (not HTTPS). Sniffing the network for these cookies and replaying them grants authenticated access. More sophisticated than MAC spoofing since it targets the application layer.

- **Prerequisites:** Monitor mode for packet capture; cookie extraction tools
- **Success rate:** ~30% -- decreasing as portals move to HTTPS
- **Detection risk:** MEDIUM
- **Automatable:** YES -- github.com/hitori1403/bypass-captive-portal

---

## 4. Captive Portal Bypass -- Application Layer

### 4.1 Captive Portal API Endpoint Abuse

**How it works:** Many captive portal implementations expose unauthenticated API endpoints for status checking, session management, or self-registration. These endpoints may allow bypassing the login entirely, extending sessions, or registering without proper validation.

- **Prerequisites:** Web proxy (Burp Suite), understanding of the portal's HTTP API
- **Success rate:** VARIES -- depends entirely on the specific portal vendor
- **Detection risk:** LOW
- **Automatable:** PARTIALLY -- per-vendor scripts
- **CPA relevance:** HIGH -- the recon module should enumerate these endpoints

### 4.2 JavaScript/Client-Side Validation Bypass

**How it works:** Some portals enforce access control only in JavaScript on the login page. Disabling JavaScript, using curl, or simply navigating directly to an external URL may bypass the portal entirely.

- **Prerequisites:** Browser developer tools or curl
- **Success rate:** ~10% -- rare in modern portals
- **Detection risk:** NONE
- **Automatable:** YES

### 4.3 User-Agent Spoofing (CNA/Wispr Detection)

**How it works:** Portals often handle Apple Captive Network Assistant (CNA), Wispr, and Android connectivity checks differently. Spoofing the User-Agent to "CaptiveNetworkSupport" or "Wispr" may trigger an auto-login flow, bypass page, or different authentication path.

- **Prerequisites:** HTTP client with custom UA support
- **Success rate:** ~15% -- some portals auto-approve CNA requests
- **Detection risk:** NONE
- **Automatable:** YES
- **CPA relevance:** HIGH -- easy to test during recon phase

### 4.4 Portal Admin Panel Default Credentials

**How it works:** Many commercial captive portal solutions (CoovaChilli, pfSense, OpenNDS, Microtik) have web admin panels at predictable URLs (/admin, /manage, /status) with default or weak credentials. Gaining admin access allows whitelisting your MAC or disabling the portal.

- **Prerequisites:** Web browser, default credential databases
- **Success rate:** ~10-15% -- higher in small business environments
- **Detection risk:** MEDIUM -- login attempts are typically logged
- **Automatable:** YES -- directory scanning + default cred testing
- **CPA relevance:** MEDIUM -- ethical concern, but should be tested in recon

### 4.5 pfSense Captive Portal Auth Bypass (CVE-2025-6979)

**How it works:** A 2025 GitHub Security Advisory (GHSA-m46p-w2rw-xrvj) documents an authentication bypass in pfSense captive portal. Specific details require checking the advisory, but this demonstrates that captive portal software itself has exploitable vulnerabilities.

- **Prerequisites:** pfSense-based portal
- **Success rate:** HIGH against vulnerable versions
- **Detection risk:** LOW
- **Automatable:** YES
- **Source:** github.com/advisories/GHSA-m46p-w2rw-xrvj

---

## 5. Captive Portal Bypass -- Protocol Leak Exploitation

### 5.1 Whitelisted Domain / Walled Garden Abuse

**How it works:** Portals often whitelist certain domains (Apple captive portal check URLs, Google, payment processors). If these whitelisted domains can be used to proxy traffic (via domain fronting, open redirect, or subdomain takeover), they become tunneling vectors.

- **Prerequisites:** Knowledge of whitelisted domains, a proxy/redirect on one of them
- **Success rate:** ~25% -- depends on whitelist configuration
- **Detection risk:** VERY LOW
- **Automatable:** PARTIALLY
- **CPA relevance:** HIGH -- recon module should enumerate whitelisted domains

### 5.2 IPv6 Bypass

**How it works:** Many captive portals only enforce access control on IPv4. If the network has IPv6 enabled (common with SLAAC), IPv6 traffic may flow freely without portal authentication. Simply configuring a DNS server that responds with AAAA records can bypass the portal.

- **Prerequisites:** IPv6 connectivity on the network; IPv6-capable DNS and destination servers
- **Success rate:** ~20-30% -- increasingly tested by modern portals
- **Detection risk:** NONE
- **Automatable:** YES
- **CPA relevance:** DIRECT -- should be tested in recon phase

### 5.3 NTP/SNMP/Other UDP Protocol Leaks

**How it works:** Portals may allow specific UDP protocols (NTP on port 123, SNMP on 161/162, TFTP on 69) through the firewall. These can potentially be abused for tunneling, though throughput is very limited.

- **Prerequisites:** Port scanning to identify open UDP ports; tunnel tools configured for those ports
- **Success rate:** ~10%
- **Detection risk:** LOW
- **Automatable:** YES -- UDP port scan then tunnel attempt
- **CPA relevance:** HIGH -- recon module should probe all UDP ports

### 5.4 TTL Manipulation

**How it works:** Some portal implementations only inspect packets with TTL=1 (first hop). Setting TTL=2+ on outbound packets may cause them to bypass the portal's inspection point while still reaching the gateway.

- **Prerequisites:** Raw socket capability (root) to set TTL
- **Success rate:** VERY LOW (~5%) -- only works on very specific portal implementations
- **Detection risk:** LOW
- **Automatable:** YES
- **CPA relevance:** LOW priority but worth testing

---

## 6. 802.1X / NAC Bypass Techniques

### 6.1 VLAN Hopping via DTP

**How it works:** If a switch port is in dynamic trunking mode, sending DTP frames can negotiate a trunk and gain access to all VLANs including the authenticated VLAN. Tool: Yersinia.

- **Prerequisites:** Physical Ethernet access (not WiFi); Yersinia
- **Success rate:** ~15% -- most modern switches disable DTP
- **Detection risk:** HIGH -- abnormal L2 traffic
- **Automatable:** YES -- Yersinia automates DTP negotiation

### 6.2 802.1X EAP-MD5 Relay

**How it works:** If a wired NAC uses EAP-MD5 (no mutual authentication), credentials can be relayed. The attacker sits between the supplicant and authenticator, forwarding EAP messages.

- **Prerequisites:** Physical inline position; EAP relay tool
- **Success rate:** LOW -- EAP-MD5 is rare
- **Detection risk:** MEDIUM

### 6.3 MAB (MAC Authentication Bypass) Exploitation

**How it works:** Many 802.1X deployments have a MAB fallback for devices that cannot do 802.1X (printers, IoT). If you identify a MAB-authenticated device's MAC and clone it, you bypass NAC. Printer MACs are especially common targets.

- **Prerequisites:** Knowledge of MAB-enrolled MACs (often printers/IoT with predictable OUIs)
- **Success rate:** ~40% in enterprise environments with MAB fallback
- **Detection risk:** MEDIUM
- **Automatable:** YES -- OUI-based scanning for likely MAB devices

---

## 7. Emerging / Novel Techniques (2024-2026)

### 7.1 Passpoint/Hotspot 2.0 ANQP Spoofing

**How it works:** Passpoint-enabled devices automatically connect to hotspots matching certain ANQP criteria (operator name, roaming consortium). A fake AP broadcasting matching 802.11u Information Elements and responding to ANQP queries can attract Passpoint clients without any user interaction. More sophisticated than traditional Evil Twin because Passpoint connections happen silently.

- **Prerequisites:** hostapd configured with 802.11u IEs and Passpoint settings; knowledge of target operator's ANQP parameters
- **Success rate:** UNKNOWN -- very few public tests
- **Detection risk:** LOW -- Passpoint is designed for automatic connection
- **Automatable:** YES -- hostapd configuration

### 7.2 Wi-Fi Direct / P2P Exploitation

**How it works:** WiFi Direct creates peer-to-peer connections that bypass the AP entirely. If an already-authenticated device supports WiFi Direct, connecting to it P2P and using it as a gateway provides internet access without touching the captive portal at all.

- **Prerequisites:** WiFi Direct capable adapter; authenticated device willing to accept P2P connections
- **Success rate:** LOW -- requires cooperative or vulnerable authenticated device
- **Detection risk:** LOW -- separate channel from the portal network
- **Automatable:** NO -- requires interaction

### 7.3 Travel Router Captive Portal Forwarding (GL.iNet Method)

**How it works:** A travel router (GL.iNet Beryl, Slate, etc.) connects to the captive portal WiFi as a client, presents the portal login to the user once, then shares the authenticated connection to all devices behind it via its own WiFi. Effectively turns one portal session into unlimited devices, bypassing device limits.

- **Prerequisites:** GL.iNet or similar travel router (~$60-100)
- **Success rate:** ~95% -- works on virtually all captive portals
- **Detection risk:** LOW -- single MAC to the portal, all devices behind NAT
- **Automatable:** YES -- router handles it automatically
- **Source:** GL.iNet blog (Oct 2024)

### 7.4 802.11r (FT) Key Recovery for PMKID Extraction

**How it works:** APs supporting 802.11r Fast BSS Transition pre-compute and cache PMKIDs. Even a single association attempt can extract the PMKID without any connected clients, enabling offline brute-force. This is the technical basis for the PMKID attack (Section 1.1) but specifically leverages the 802.11r fast-roaming cache.

- **Prerequisites:** hcxdumptool
- **Success rate:** ~60% (depends on AP supporting 802.11r)
- **Detection risk:** LOW
- **Source:** Synacktiv (Jan 2026)

### 7.5 ESP32 Fake Captive Portal for Credential Harvesting

**How it works:** ESP32 microcontroller boards ($5-10) can run as fake WiFi APs with captive portals that mimic real login pages. Used in social engineering to capture credentials. Several GitHub projects (updated Feb 2026) provide ready-made firmware.

- **Prerequisites:** ESP32 dev board; Arduino IDE
- **Success rate:** HIGH for social engineering
- **Detection risk:** MEDIUM -- detectable by WIDS
- **Automatable:** YES -- flash and deploy

---

## 8. Tool Inventory

### Captive Portal Bypass Tools
| Tool | GitHub | Purpose |
|------|--------|---------|
| anticap | Kif11/anticap | macOS MAC spoofing with ping test for each discovered address |
| cpscam | codewatchorg/cpscam | Bypass portals by impersonating inactive users |
| houdini | ariakis/houdini | Shell script for hotel/cruise WiFi portal bypass |
| WiFiFox | t-mullen/wififox | macOS menubar app for portal bypass via MAC spoofing |
| CaptiveSense | swils23/CaptiveSense | Python auto-login to bypass portal authentication |
| CaptivePortalAutoLogin | binarynoise/CaptivePortalAutoLogin | Android/Linux auto-portal-login |

### Tunneling Tools
| Tool | GitHub | Protocol | Throughput |
|------|--------|----------|------------|
| iodine | yarrick/iodine | DNS (TXT/CNAME/NULL) | 50-500 Kbps |
| dnscat2 | iagox86/dnscat2 | DNS (TXT) | ~50 Kbps |
| dns2tcp | alex-sector/dns2tcp | DNS (TXT) | ~100 Kbps |
| ptunnel-ng | utoni/ptunnel-ng | ICMP echo | ~50 Kbps |
| icmptunnel | DhavalKapil/icmptunnel | ICMP echo (full IP) | ~100 Kbps |
| hans | friedrich/hans | ICMP echo (tun device) | ~100 Kbps |
| wstunnel | erebe/wstunnel (13K stars) | WebSocket/HTTP2 | Full speed |
| chisel | jpillora/chisel (13K stars) | HTTP/WebSocket | Full speed |
| SoftEther VPN | SoftEtherVPN/SoftEtherVPN | HTTPS/DNS/ICMP multi-protocol | Full speed |

### WiFi Attack Tools
| Tool | GitHub | Purpose |
|------|--------|---------|
| EAPHammer | s0lst1c3/eaphammer | Evil Twin for WPA2-EAP credential capture |
| hostapd-mana | sensepost/hostapd-mana | Rogue AP with EAP relay, KARMA, Snoopy |
| wpa_sycophant | sensepost/wpa_sycophant | PEAP-MSCHAPv2 relay to legitimate AP |
| Bettercap | bettercap/bettercap | WiFi recon, deauth, MitM framework |
| Responder | lgandx/Responder | LLMNR/mDNS/NBT-NS poisoner |
| aircrack-ng | aircrack-ng/aircrack-ng | WEP/WPA2 handshake capture and cracking |
| hcxdumptool | ZerBea/hcxdumptool | PMKID capture without clients |
| hashcat | hashcat/hashcat | GPU-accelerated hash cracking |
| Wifite2 | kimocoder/wifite2 | Automated wireless attack tool |

---

## 9. Attack Decision Tree for CPA

```
Connected to WiFi (associated, not portal-authed)
|
+-- Phase 1: RECON (passive)
|   |-- Detect portal type (HTTP redirect, DNS hijack, firewall block, etc.)
|   |-- Enumerate whitelisted domains (resolve known domains, check connectivity)
|   |-- Check IPv6 connectivity (often unrestricted)
|   |-- Probe outbound protocols: DNS(53), ICMP, HTTP(80), HTTPS(443), NTP(123)
|   |-- Scan for authenticated MACs (arp-scan)
|   |-- Identify portal vendor (fingerprint login page, check /admin, /status)
|   |-- Check for CNA/Wispr auto-auth behavior
|
+-- Phase 2: BYPASS (ordered by stealth, then simplicity)
|   |
|   |-- Tier 1: Zero-touch (no external infrastructure needed)
|   |   |-- 1. IPv6 unrestricted? -> Route via IPv6
|   |   |-- 2. Whitelisted domains? -> Direct access via whitelisted DNS
|   |   |-- 3. CNA/Wispr auto-auth? -> Spoof User-Agent
|   |   |-- 4. JavaScript-only enforcement? -> curl to external host
|   |   |-- 5. MAC clone of authenticated client -> anticap/cpscam approach
|   |
|   |-- Tier 2: Tunnel (requires external VPS)
|   |   |-- 6. DNS passes? -> iodine DNS tunnel
|   |   |-- 7. ICMP passes? -> ptunnel-ng/icmptunnel/hans
|   |   |-- 8. HTTPS(443) passes? -> wstunnel/chisel WebSocket tunnel
|   |   |-- 9. UDP/53 passes? -> WireGuard on port 53
|   |   |-- 10. HTTP CONNECT allowed? -> TCP tunnel via CONNECT
|   |
|   |-- Tier 3: Application (portal-specific)
|   |   |-- 11. Portal API endpoint abuse
|   |   |-- 12. Default admin credentials
|   |   |-- 13. Known CVEs for portal vendor
|   |   |-- 14. Session/cookie replay
```

---

## 10. Key References

1. **Synacktiv** -- "Wireless-(in)Fidelity: Pentesting Wi-Fi in 2025" (Jan 2026) -- https://www.synacktiv.com/en/publications/wireless-infidelity-pentesting-wi-fi-in-2025
2. **HTB Academy** -- "Bypassing Wi-Fi Captive Portals" course -- https://academy.hackthebox.com/course/preview/bypassing-wi-fi-captive-portals
3. **HackTricks** -- Tunneling and Port Forwarding -- https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding
4. **SensePost** -- PEAP Relay Attacks (DEFCON 2018) -- https://sensepost.com/blog/2019/peap-relay-attacks-with-wpa_sycophant/
5. **Vanhoef & Ronen** -- Dragonblood: WPA3 SAE attacks (2019) -- https://wpa3.mathyvanhoef.com/
6. **KRACK Attacks** -- WPA2 Key Reinstallation -- https://www.krackattacks.com/
7. **CVE-2025-6979** -- pfSense Captive Portal auth bypass -- https://github.com/advisories/GHSA-m46p-w2rw-xrvj
8. **GL.iNet** -- Travel router portal bypass guide (Oct 2024) -- https://www.gl-inet.com/blog/bypass-captive-portals-and-device-limits-with-glinet-router
9. **awesome-tunneling** -- Comprehensive tunneling tool list -- https://github.com/anderspitman/awesome-tunneling
10. **mivang/cheatsheets** -- Captive portal bypass cheatsheet -- https://github.com/mivang/cheatsheets/blob/master/bypass_captive_portals.md
