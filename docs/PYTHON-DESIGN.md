# Captive Portal Auditor (CPA) -- Architecture Design Document

## 1. Problem Statement

Public WiFi captive portals are pervasive infrastructure that gate internet access behind
login walls, time limits, bandwidth caps, and device restrictions. Most implementations
contain well-known architectural weaknesses that an attacker can exploit trivially. Portal
operators often believe these gates provide meaningful access control when they provide
only the illusion of it.

CPA is a single-command red team tool that connects to a gated WiFi network, automatically
identifies the portal type and restriction model, attempts bypass techniques in order of
simplicity and stealth, and produces a vulnerability report with severity ratings and
remediation guidance for the operator.

## 2. Threat Model

```
Attacker: Unauthenticated user on the WiFi L2 segment (associated but not portal-authed)
Target:   The captive portal enforcement mechanism (NOT backend systems behind it)
Goal:     Unrestricted internet access without completing the portal gate
Boundary: L2 WiFi segment only. No attacks against other users, backend infra, or upstream ISP.
```

**What CPA does NOT do:**
- Attack other WiFi clients (no ARP spoofing, no deauth, no evil twin)
- Attempt credential theft or brute-force against portal login systems
- Perform denial of service against the portal
- Exfiltrate data from the portal operator's network
- Bypass WPA2/WPA3 encryption (assumes the user has the PSK or it is open)

## 3. Architecture Overview

```
                          +---------------------------+
                          |       cpa (CLI entry)     |
                          |  click-based, single cmd  |
                          +------+--------+-----------+
                                 |        |
                    +------------+        +------------+
                    |                                   |
          +---------v---------+              +----------v---------+
          |   Orchestrator    |              |   Reporter         |
          |   (phase runner)  |              |   (findings->doc)  |
          +---+----+----+----++              +--------------------+
              |    |    |    |
    +---------+ +--+  +-+-+ +--------+
    |           |     |     |        |
+---v---+ +----v-+ +-v---+ +v-----+ +v--------+
| Recon | |Bypass| |Perst| |NetCtl| |Platform  |
| Module| |Engine| |Mngr | |Layer | |Abstraction|
+-------+ +------+ +-----+ +------+ +----------+
```

### Module Dependency Graph

```
cpa.cli
  -> cpa.orchestrator
       -> cpa.recon          (Phase 1: detect portal, enumerate leaks)
       -> cpa.bypass         (Phase 2: attempt bypasses, ordered)
       -> cpa.persist        (Phase 3: maintain access)
       -> cpa.reporter       (Phase 4: generate report)
  -> cpa.net                 (low-level network operations)
       -> cpa.net.mac        (MAC address operations)
       -> cpa.net.dns        (DNS probing and tunneling)
       -> cpa.net.icmp       (ICMP probing and tunneling)
       -> cpa.net.http       (HTTP client with captive portal awareness)
       -> cpa.net.dhcp       (DHCP lease operations)
       -> cpa.net.probe      (port scanning, protocol probing)
  -> cpa.platform            (OS-specific abstractions)
       -> cpa.platform.macos (networksetup, airport, ifconfig)
       -> cpa.platform.linux (iw, ip, nmcli)
  -> cpa.models              (dataclasses for findings, portal types, etc.)
  -> cpa.config              (scope, ethical guardrails, tool config)
```

## 4. Module Breakdown

### 4.1 `cpa.cli` -- Command-Line Interface

Single entry point. User runs one command after connecting to WiFi.

```
cpa audit                  # Full auto: recon -> bypass -> report
cpa audit --recon-only     # Phase 1 only (passive, no bypass attempts)
cpa audit --technique mac  # Try only a specific technique
cpa audit --no-persist     # Skip Phase 3 (don't maintain access)
cpa audit --stealth        # Conservative timing, avoid IDS triggers
cpa report <session-id>    # Re-generate report from saved session
cpa status                 # Show current portal detection state
```

**CLI Framework:** `click` (already well-known, clean API, no bloat)

**Output modes:**
- `--format text` (default): colored terminal output with progress
- `--format json`: machine-readable NDJSON for piping
- `--format report`: full markdown report to file

**Privilege escalation:** CPA detects when it needs root and uses `sudo` with
explanation to the user. It never runs entirely as root -- only specific operations
(MAC spoofing, raw sockets, DHCP operations) escalate.

### 4.2 `cpa.orchestrator` -- Phase Runner

Controls execution flow across the four phases. Maintains a `Session` object that
accumulates findings, technique results, and timing data.

```python
@dataclass
class Session:
    id: str                          # UUID
    started: datetime
    interface: str                   # e.g., "en0"
    original_mac: str                # preserved for restore
    portal: PortalFingerprint | None
    techniques_tried: list[TechniqueResult]
    findings: list[Finding]
    phase: Phase                     # RECON | BYPASS | PERSIST | REPORT
```

**Orchestrator responsibilities:**
1. Confirm user consent (unless `--yes` flag)
2. Snapshot current network state (MAC, IP, DNS, routes)
3. Run Phase 1 (recon) -- always runs
4. Run Phase 2 (bypass) -- tries techniques in priority order, stops on first success
5. Run Phase 3 (persist) -- only if bypass succeeded and `--no-persist` not set
6. Run Phase 4 (report) -- always runs
7. Restore original network state on exit (SIGINT handler, atexit)

**State restoration is critical.** CPA must ALWAYS restore the original MAC address,
DNS settings, and routing table on exit, whether normal, error, or signal. This is
implemented via both `atexit` and signal handlers for SIGINT/SIGTERM.

### 4.3 `cpa.recon` -- Portal Reconnaissance

Passive and semi-active techniques to understand what we are dealing with.

#### 4.3.1 Portal Detection

```python
class PortalType(Enum):
    HTTP_REDIRECT   = "http_redirect"    # 302 to login page
    DNS_HIJACK      = "dns_hijack"       # All DNS resolves to portal IP
    FIREWALL_BLOCK  = "firewall_block"   # TCP RST or DROP for non-portal
    RADIUS_GATED    = "radius_gated"     # 802.1X-based (uncommon for public)
    TRANSPARENT     = "transparent"      # Transparent proxy (HTTP intercept)
    WALLED_GARDEN   = "walled_garden"    # Whitelist model (some sites work)
    NONE            = "none"             # No portal detected (open network)
```

**Detection algorithm:**

```
1. HTTP probe: GET http://detectportal.firefox.com/canonical.html
   - 200 + "success" body -> no portal (NONE)
   - 302/307 redirect -> HTTP_REDIRECT (capture redirect URL)
   - 200 but wrong body -> TRANSPARENT proxy injecting content

2. DNS probe: resolve known-good domains (google.com, cloudflare.com)
   - Compare against known IPs
   - All resolving to same IP -> DNS_HIJACK
   - NXDOMAIN for everything -> DNS blocked entirely
   - Correct resolution -> DNS is clean (portal uses firewall)

3. TCP probe: attempt connections to known IPs on port 80, 443
   - RST -> FIREWALL_BLOCK (active rejection)
   - Timeout -> FIREWALL_BLOCK (passive drop)
   - Connect + TLS mismatch -> TRANSPARENT proxy with cert injection

4. Captive portal API check (OS-native):
   - macOS: http://captive.apple.com/hotspot-detect.html
   - Fallback: http://connectivitycheck.gstatic.com/generate_204
```

#### 4.3.2 Portal Fingerprinting

Identify the vendor/product from the portal login page.

```python
@dataclass
class PortalFingerprint:
    vendor: str              # "cisco_meraki", "aruba", "ruckus", "unifi", etc.
    product: str | None      # Specific product if identifiable
    version: str | None      # Version if leaked
    portal_url: str          # The login page URL
    portal_ip: str           # IP of the portal server
    auth_methods: list[str]  # ["email", "social_google", "sms", "room_number"]
    session_model: str       # "mac_based", "ip_based", "cookie_based", "token_based"
    restrictions: dict       # {"time_limit": "30m", "bandwidth": "5mbps", "devices": 3}
```

**Fingerprint database** (signatures matched against portal HTML/headers):

| Vendor | URL Pattern | Header Signatures | HTML Markers |
|--------|-------------|-------------------|--------------|
| Cisco Meraki | `/splash/` | `X-Frame-Options: meraki` | `meraki-splash` class |
| Aruba/HPE | `/cgi-bin/login` | `Server: Aruba` | `aruba_` prefixed IDs |
| Ruckus | `/login.html` | Ruckus cookie patterns | `ruckus-` CSS classes |
| UniFi | `/guest/s/` | `X-UniFi` header | `unifi-portal` |
| Mikrotik | `/login` | `Server: Mikrotik` | `mikrotik` in form action |
| FortiNet | `/fgtauth` | `Server: FortiGate` | `ftnt_` prefixed fields |
| pfSense | `/index.php?zone=` | `Server: pfSense` | `captiveportal` form |
| OpenNDS | `/opennds_preauth/` | | `openNDS` in body |
| CoovaChilli | `/json/status` | | `coova` references |
| Custom/Unknown | (heuristic) | | (generic form detection) |

#### 4.3.3 Leak Enumeration

Systematically test what protocols/ports are open pre-authentication.

```python
@dataclass
class LeakProfile:
    dns_udp_53: bool          # Standard DNS (most common leak)
    dns_tcp_53: bool          # TCP DNS
    doh_443: bool             # DNS-over-HTTPS to known resolvers
    dot_853: bool             # DNS-over-TLS
    icmp: bool                # Ping passes through
    ipv6: bool                # IPv6 completely unfiltered
    ntp_123: bool             # NTP port open
    ipsec_500: bool           # IPSec/IKE port
    openvpn_1194: bool        # OpenVPN default
    wireguard_51820: bool     # WireGuard default
    http_alt_ports: list[int] # 8080, 8443, etc.
    whitelisted_domains: list[str]  # Domains that resolve and connect pre-auth
    whitelisted_ips: list[str]      # IPs reachable pre-auth
```

**Leak discovery method:**

```
For each protocol/port:
  1. Attempt connection to a known external server we control (or public service)
  2. Send a canary payload that we can verify was received
  3. For DNS: resolve a unique subdomain of a domain we control, check server logs
  4. For ICMP: ping with specific payload, check if reply comes from real target
  5. For TCP ports: connect to a known service, verify banner/response
  6. For IPv6: attempt to reach IPv6-only service
  7. For whitelisted domains: iterate common whitelist targets
     (apple.com, google.com, microsoft.com, facebook.com, captive portal check URLs)
```

**External canary server requirement:** For the most reliable leak detection, CPA
optionally accepts a `--canary-server` parameter pointing to a controlled server that
logs incoming connections. Without it, CPA uses heuristics (connecting to public services
and verifying response correctness).

### 4.4 `cpa.bypass` -- Bypass Engine

Ordered list of techniques. Each technique is a self-contained class implementing a
common interface.

```python
class Technique(Protocol):
    name: str
    description: str
    stealth: StealthLevel          # LOW_NOISE, MEDIUM_NOISE, HIGH_NOISE
    requires_root: bool
    requires_external: list[str]   # External tool dependencies
    platforms: list[str]           # ["macos", "linux"]

    def prerequisites_met(self, session: Session) -> PrereqResult:
        """Check if this technique can be attempted given current recon data."""

    def attempt(self, session: Session) -> TechniqueResult:
        """Execute the bypass. Returns success/failure with details."""

    def cleanup(self, session: Session) -> None:
        """Undo any changes made during attempt."""
```

```python
@dataclass
class TechniqueResult:
    technique: str
    success: bool
    duration: timedelta
    details: str                 # Human-readable explanation
    evidence: str | None         # Proof (e.g., external IP, resolved domain)
    noise_generated: str         # What the portal operator would see in logs
    finding: Finding | None      # Vulnerability finding if successful
```

#### Technique Catalog (Priority Order)

**Priority 1: MAC Rotation** (stealth: LOW, root: YES, external: none)

```
Theory: Most captive portals track sessions by MAC address. Spoofing a new MAC
        presents as a "new device" and gets a fresh unauthenticated session, which
        may include a free tier (e.g., 30 min free before requiring login).

Algorithm:
  1. Record current MAC
  2. Disassociate from WiFi
  3. Generate random locally-administered MAC (bit 1 of first octet = 1)
  4. Set new MAC via platform abstraction
  5. Reassociate to same SSID
  6. Wait for DHCP lease
  7. Test internet connectivity
  8. If portal still blocks: try again with different MAC (max 3 attempts)
  9. If portal allows: SUCCESS -- portal tracks by MAC only

macOS implementation:
  sudo ifconfig en0 down
  sudo ifconfig en0 ether XX:XX:XX:XX:XX:XX
  sudo ifconfig en0 up
  networksetup -setairportnetwork en0 "$SSID" ["$PSK"]

Variations to test:
  - Random MAC: tests if ANY new MAC gets access
  - OUI-matched MAC: use same OUI as real adapter (subtler)
  - Known-good MAC: if we observed an authenticated device's MAC via monitor mode

Detection risk: LOW. MAC changes are normal. Some portals log MAC-to-IP bindings
               but rarely alert on new MACs.
```

**Priority 2: DNS Tunnel** (stealth: MEDIUM, root: YES, external: iodine/dnscat2)

```
Theory: Most portals allow DNS (UDP/53) pre-auth because the portal itself needs
        DNS to function, and blocking DNS breaks the captive portal redirect. A DNS
        tunnel encodes TCP traffic inside DNS queries/responses.

Prerequisite: LeakProfile.dns_udp_53 == True

Algorithm:
  1. Verify DNS leak exists (from recon)
  2. Check if iodine client is available
  3. Configure iodine to connect to user's tunnel server
     (CPA does NOT provide the server -- user must have one)
  4. Establish tunnel
  5. Route traffic through tunnel interface
  6. Verify internet access through tunnel
  7. Measure throughput (DNS tunnels are slow: typically 50-500 Kbps)

If no external tunnel server:
  - Test if DoH (DNS-over-HTTPS) to 1.1.1.1 or 8.8.8.8 works
  - If DoH works, this is itself a finding (encrypted DNS bypasses content filtering)

Detection risk: MEDIUM. High DNS query volume is anomalous. Rate-aware portals
                may throttle or block after sustained DNS traffic.
```

**Priority 3: ICMP Tunnel** (stealth: MEDIUM, root: YES, external: hans/icmptunnel)

```
Theory: ICMP echo (ping) is often allowed pre-auth for diagnostics. ICMP tunnel
        tools encode TCP payloads inside ping packets.

Prerequisite: LeakProfile.icmp == True

Algorithm:
  1. Verify ICMP leak (from recon)
  2. Check for hans or icmptunnel binary
  3. Connect to user's ICMP tunnel server
  4. Verify connectivity
  5. Measure throughput (typically 10-100 Kbps)

Detection risk: MEDIUM. Sustained large ICMP packets are anomalous but rarely
                monitored on public WiFi.
```

**Priority 4: IPv6 Bypass** (stealth: LOW, root: NO, external: none)

```
Theory: Many portals only implement filtering on IPv4. If the network provides IPv6
        (via SLAAC or DHCPv6), it may be completely unfiltered.

Prerequisite: IPv6 address obtained on interface

Algorithm:
  1. Check if interface has a global IPv6 address
  2. Attempt to reach IPv6-only services (ipv6.google.com, v6.testmyipv6.com)
  3. If reachable: full IPv6 bypass confirmed
  4. Test if IPv4 traffic can be tunneled over IPv6 (6to4, Teredo)

Detection risk: LOW. Normal IPv6 traffic. Most portal operators don't monitor IPv6.
```

**Priority 5: Open Port Discovery** (stealth: MEDIUM, root: NO, external: none)

```
Theory: Portal firewalls may not block all outbound ports. Common oversights:
        port 53 (DNS), 123 (NTP), 500 (IKE), 443 (sometimes), 8080, 8443.

Algorithm:
  1. For each candidate port [53, 67, 68, 80, 123, 443, 500, 993, 995,
     1194, 1723, 4500, 5060, 8080, 8443, 51820]:
     - Attempt TCP connect to known external IP on that port
     - Timeout: 3 seconds per port
  2. Record which ports succeed
  3. If any non-standard port is open, this enables VPN-over-allowed-port

Detection risk: MEDIUM. Port scanning generates connection attempts that may be
                logged. CPA spaces probes over 30+ seconds in stealth mode.
```

**Priority 6: HTTP Header Manipulation** (stealth: LOW, root: NO, external: none)

```
Theory: Some portals whitelist requests based on User-Agent (e.g., allowing
        CaptiveNetworkSupport, wispr), specific HTTP headers, or referrer domains.

Algorithm:
  1. Try requests with captive portal User-Agents:
     - "CaptiveNetworkSupport/1.0 wispr"
     - "Microsoft NCSI"
     - "Mozilla/5.0 (X11; Linux) AppleWebKit/537.36 (captive-check)"
  2. Try requests with whitelisted domain as Host header
  3. Try requests via HTTP CONNECT to the portal IP
  4. Try with X-Forwarded-For / X-Real-IP headers set to portal gateway IP

Detection risk: LOW. These are normal HTTP requests with unusual headers.
```

**Priority 7: Captive Portal Auto-Login** (stealth: LOW, root: NO, external: none)

```
Theory: Many free-tier portals require only an email address or clicking "accept
        terms." Automating this is not a bypass per se, but tests whether the
        portal validates input (e.g., accepts fake emails, has no rate limit on
        registration).

Algorithm:
  1. Fetch portal login page
  2. Parse form fields (email, phone, name, room number, etc.)
  3. Submit with generated data:
     - Email: random@example.com (RFC 2606 reserved domain)
     - Phone: 555-0100 to 555-0199 (NANP reserved for fiction)
     - Name: "Test User"
  4. Check if submission grants access
  5. If rate-limited: record the rate limit parameters
  6. If email validation required: note as stronger control

Detection risk: LOW. Single form submission. No brute-force.
```

**Priority 8: DHCP Lease Manipulation** (stealth: LOW, root: YES, external: none)

```
Theory: Some portals track by IP address instead of (or in addition to) MAC.
        Releasing and renewing DHCP lease may yield a new IP that hasn't been
        seen by the portal, getting a fresh session.

Algorithm:
  1. Record current IP
  2. Release DHCP lease: sudo ipconfig set en0 NONE (macOS)
  3. Request new lease: sudo ipconfig set en0 DHCP
  4. Check if new IP differs from old
  5. Test internet connectivity
  6. Also try: request lease with different DHCP client-id / hostname

macOS specifics:
  - ipconfig set en0 BOOTP  (then back to DHCP) forces full re-negotiation
  - Can also manipulate via /var/db/dhcpclient/

Detection risk: LOW. DHCP renewals are normal network operations.
```

**Priority 9: VPN Over Allowed Protocol** (stealth: LOW, root: YES, external: VPN server)

```
Theory: If any non-HTTP port is open (discovered in Priority 5), a VPN can be
        configured to use that port. WireGuard can run on any UDP port. OpenVPN
        can run on TCP 443 to look like HTTPS.

Prerequisite: Open port discovered in Priority 5, user has VPN server

Algorithm:
  1. Check which open ports were found
  2. If user provided VPN config (--vpn-config):
     - Modify config to use discovered open port
     - Attempt connection
     - Verify full tunnel established
  3. If no VPN config: report the finding (open port exists, VPN would work)

Detection risk: LOW to MEDIUM. VPN traffic on standard ports looks normal.
                VPN on unusual ports (e.g., 123) may be flagged by DPI.
```

**Priority 10: Whitelist Abuse** (stealth: LOW, root: NO, external: none)

```
Theory: Portals whitelist certain domains so the captive portal detection and
        login flow works. Common whitelisted domains:
        - captive.apple.com, apple.com (Apple CNA)
        - connectivitycheck.gstatic.com (Android/Chrome)
        - msftncsi.com, msftconnecttest.com (Windows)
        - portal vendor's own domains
        If these are fully whitelisted (not just specific paths), they can be
        used to tunnel traffic via domain fronting or as SOCKS proxies.

Algorithm:
  1. Test connectivity to common whitelisted domains
  2. For each reachable domain:
     - Test if full domain is whitelisted or just specific paths
     - Test if HTTPS is allowed (enables domain fronting)
     - Test if WebSocket connections work through them
  3. If cloud provider domains are whitelisted (*.amazonaws.com, *.cloudfront.net):
     - This enables domain fronting through cloud CDNs
  4. Report whitelisted domains and their exploitability

Detection risk: LOW. Accessing whitelisted domains is expected behavior.
```

### 4.5 `cpa.persist` -- Persistence Manager

Only runs if a bypass succeeded. Maintains access over time.

```python
class PersistenceManager:
    """Keep the bypass alive."""

    def start(self, session: Session, technique: TechniqueResult) -> None:
        """Start persistence for the successful technique."""

    def stop(self) -> None:
        """Stop persistence and restore original state."""
```

**Persistence strategies by technique:**

| Technique | Persistence Method |
|-----------|--------------------|
| MAC rotation | Monitor for session expiry (HTTP probe every 60s), rotate MAC on detection |
| DNS tunnel | Keepalive packets, reconnect on tunnel drop |
| ICMP tunnel | Keepalive pings, reconnect on drop |
| IPv6 bypass | Monitor IPv6 connectivity, alert if lost |
| Open port VPN | VPN client handles reconnection natively |
| DHCP manipulation | Re-release/renew if portal re-blocks |

**Session expiry detection:**

```
Every 60 seconds:
  1. HTTP GET to http://detectportal.firefox.com/canonical.html
  2. If response != "success" body -> portal has re-captured us
  3. Trigger re-bypass with same technique
  4. If technique no longer works -> try next technique in priority list
```

**Bandwidth shaping** (optional, `--stealth` mode):

```
If portal has bandwidth detection:
  - Rate-limit tunnel traffic to stay under detection threshold
  - Use tc (Linux) or pfctl/dnctl (macOS) to shape traffic
  - Default: cap at 80% of detected limit
```

### 4.6 `cpa.reporter` -- Report Generator

Produces structured output from the session data.

```python
@dataclass
class Finding:
    id: str                       # CPA-001, CPA-002, etc.
    title: str
    severity: Severity            # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str                 # "access_control", "network_filtering", etc.
    technique: str                # Which technique exploited this
    description: str              # What the vulnerability is
    evidence: str                 # Proof of exploitation
    impact: str                   # What an attacker could do
    remediation: str              # How to fix it
    cwe: str | None               # CWE reference if applicable
    mitre: str | None             # MITRE ATT&CK technique ID
```

#### Finding Catalog

| ID | Title | Severity | Trigger |
|----|-------|----------|---------|
| CPA-001 | MAC-only session tracking | HIGH | MAC rotation bypasses portal |
| CPA-002 | DNS traffic allowed pre-auth | MEDIUM | UDP/53 open before login |
| CPA-003 | DNS tunneling possible | HIGH | Full TCP-over-DNS tunnel works |
| CPA-004 | ICMP traffic allowed pre-auth | MEDIUM | Ping works before login |
| CPA-005 | ICMP tunneling possible | HIGH | Full TCP-over-ICMP tunnel works |
| CPA-006 | IPv6 not filtered | HIGH | Full IPv6 internet access pre-auth |
| CPA-007 | Non-standard ports unfiltered | MEDIUM | Outbound ports open pre-auth |
| CPA-008 | Weak input validation on portal | LOW | Accepts fake email/phone |
| CPA-009 | No rate limit on registration | MEDIUM | Unlimited registrations from same device |
| CPA-010 | IP-only session tracking | MEDIUM | DHCP renewal gets fresh session |
| CPA-011 | Excessive domain whitelist | MEDIUM | Non-essential domains reachable pre-auth |
| CPA-012 | Cloud domain fronting possible | HIGH | CDN domains whitelisted, fronting works |
| CPA-013 | Captive portal header bypass | MEDIUM | Spoofed UA/headers skip portal |
| CPA-014 | No HTTPS on portal login | HIGH | Portal credentials sent in clear text |
| CPA-015 | Session cookie not httponly/secure | MEDIUM | Session token extractable via JS |
| CPA-016 | Portal version disclosure | INFO | Version info leaked in headers/HTML |
| CPA-017 | SSL/TLS intercept detected | HIGH | Portal MITMs HTTPS connections |
| CPA-018 | No session timeout | MEDIUM | Authenticated session never expires |
| CPA-019 | DNS-over-HTTPS not blocked | MEDIUM | DoH bypasses DNS filtering |
| CPA-020 | Captive portal on HTTP only | MEDIUM | Portal redirect over plain HTTP |

#### Report Formats

**Terminal report** (default):
```
========================================
  Captive Portal Audit Report
  Session: a1b2c3d4 | 2026-03-29 14:30
  Network: "Hilton_Guest" (WPA2)
  Portal:  Cisco Meraki (HTTP redirect)
========================================

FINDINGS (4 critical, 2 high, 3 medium, 1 info)

[CRITICAL] CPA-001: MAC-only session tracking
  Spoofing a new MAC address grants full internet access without
  completing portal authentication. No additional controls (IP binding,
  802.1X, session tokens) are in place.
  Remediation: Implement 802.1X per-device authentication or bind
  sessions to both MAC and IP with server-side session tokens.

[HIGH] CPA-006: IPv6 not filtered
  The network provides IPv6 addresses via SLAAC but does not apply
  any captive portal filtering to IPv6 traffic. Full internet access
  is available over IPv6 without authentication.
  Remediation: Apply the same filtering rules to IPv6 as IPv4, or
  disable IPv6 on the guest network if not needed.

  ... (remaining findings)

TECHNIQUE RESULTS:
  [PASS] MAC Rotation          0.8s   Bypassed portal completely
  [SKIP] DNS Tunnel            --     No external tunnel server configured
  [SKIP] ICMP Tunnel           --     No external tunnel server configured
  [PASS] IPv6 Bypass           0.3s   Full IPv6 access confirmed
  [FAIL] HTTP Header Bypass    1.2s   All header variants blocked
  [PASS] Portal Auto-Login     0.5s   Accepted fake email
  ...

NETWORK PROFILE:
  Gateway:  192.168.1.1
  Portal:   192.168.1.1:443 (Cisco Meraki)
  DNS leak: UDP/53 open, DoH blocked
  ICMP:     Allowed (TTL-limited to 3 hops)
  IPv6:     Full access (SLAAC, no filtering)
  Open ports: 53, 123, 443
```

**Markdown report** (`--format report -o report.md`):
Full penetration test style report with executive summary, technical findings,
evidence screenshots (if enabled), MITRE ATT&CK mapping, and remediation roadmap.

**JSON output** (`--format json`):
NDJSON stream of events during execution + final structured report object.
Suitable for integration with vulnerability management platforms.

### 4.7 `cpa.net` -- Network Operations Layer

Low-level network operations abstracted from the platform.

#### 4.7.1 `cpa.net.mac`

```python
class MacController:
    def get_current_mac(self, interface: str) -> str: ...
    def set_mac(self, interface: str, mac: str) -> None: ...          # requires root
    def generate_random_mac(self, oui: str | None = None) -> str: ... # locally-administered
    def restore_original_mac(self, interface: str) -> None: ...       # requires root
```

#### 4.7.2 `cpa.net.dns`

```python
class DnsProber:
    def resolve(self, domain: str, server: str | None = None) -> list[str]: ...
    def test_dns_leak(self) -> bool: ...
    def test_doh(self, resolver: str = "1.1.1.1") -> bool: ...
    def test_dot(self, resolver: str = "1.1.1.1") -> bool: ...
    def get_portal_dns_server(self) -> str: ...
```

#### 4.7.3 `cpa.net.icmp`

```python
class IcmpProber:
    def ping(self, target: str, count: int = 3, size: int = 64) -> PingResult: ...
    def test_icmp_leak(self) -> bool: ...
    def test_icmp_tunnel_feasibility(self) -> bool: ...  # large payloads, fragmentation
```

#### 4.7.4 `cpa.net.http`

```python
class PortalHttpClient:
    """HTTP client aware of captive portal behavior."""
    def detect_portal(self) -> PortalDetection: ...
    def fetch_portal_page(self) -> PortalPage: ...
    def submit_portal_form(self, data: dict) -> FormResult: ...
    def test_connectivity(self) -> bool: ...       # Can we reach the real internet?
    def test_with_headers(self, headers: dict) -> bool: ...
```

#### 4.7.5 `cpa.net.dhcp`

```python
class DhcpController:
    def get_current_lease(self, interface: str) -> DhcpLease: ...
    def release_lease(self, interface: str) -> None: ...    # requires root
    def renew_lease(self, interface: str) -> None: ...      # requires root
    def request_with_hostname(self, interface: str, hostname: str) -> None: ...
```

#### 4.7.6 `cpa.net.probe`

```python
class PortProber:
    def scan_ports(self, target_ip: str, ports: list[int],
                   timeout: float = 3.0) -> dict[int, bool]: ...
    def test_protocol(self, host: str, port: int, protocol: str) -> bool: ...
```

### 4.8 `cpa.platform` -- OS Abstraction

```python
class Platform(Protocol):
    """OS-specific network operations."""
    def get_wifi_interface(self) -> str: ...
    def get_current_ssid(self) -> str | None: ...
    def get_current_bssid(self) -> str | None: ...
    def get_gateway_ip(self) -> str: ...
    def get_dns_servers(self) -> list[str]: ...
    def set_mac_address(self, interface: str, mac: str) -> None: ...
    def reconnect_wifi(self, interface: str, ssid: str, password: str | None) -> None: ...
    def get_interface_mac(self, interface: str) -> str: ...
    def get_interface_ipv4(self, interface: str) -> str | None: ...
    def get_interface_ipv6(self, interface: str) -> str | None: ...
    def release_dhcp(self, interface: str) -> None: ...
    def renew_dhcp(self, interface: str) -> None: ...
    def flush_dns_cache(self) -> None: ...
```

#### macOS Implementation (`cpa.platform.macos`)

```python
class MacOSPlatform(Platform):
    def get_wifi_interface(self) -> str:
        # Parse: networksetup -listallhardwareports
        # Find "Wi-Fi" entry, return device name (e.g., "en0")

    def get_current_ssid(self) -> str | None:
        # macOS 14+: system_profiler SPAirPortDataType (parsed)
        # Fallback: networksetup -getairportnetwork en0

    def set_mac_address(self, interface: str, mac: str) -> None:
        # sudo ifconfig en0 down
        # sudo ifconfig en0 ether XX:XX:XX:XX:XX:XX
        # sudo ifconfig en0 up

    def reconnect_wifi(self, interface: str, ssid: str, password: str | None) -> None:
        # networksetup -setairportnetwork en0 "SSID" ["password"]

    def release_dhcp(self, interface: str) -> None:
        # sudo ipconfig set en0 NONE

    def renew_dhcp(self, interface: str) -> None:
        # sudo ipconfig set en0 DHCP

    def flush_dns_cache(self) -> None:
        # sudo dscacheutil -flushcache
        # sudo killall -HUP mDNSResponder
```

**macOS privilege notes:**
- `ifconfig ether` requires root
- `networksetup -setairportnetwork` does NOT require root
- `ipconfig set` requires root
- `dscacheutil` does NOT require root, but `killall -HUP mDNSResponder` does
- Raw sockets (ICMP) require root
- `system_profiler` does NOT require root

#### Linux Implementation (`cpa.platform.linux`)

```python
class LinuxPlatform(Platform):
    def set_mac_address(self, interface: str, mac: str) -> None:
        # sudo ip link set dev wlan0 down
        # sudo ip link set dev wlan0 address XX:XX:XX:XX:XX:XX
        # sudo ip link set dev wlan0 up

    def reconnect_wifi(self, interface: str, ssid: str, password: str | None) -> None:
        # nmcli device wifi connect "SSID" [password "password"]

    # ... etc
```

## 5. Privilege Model

CPA follows the principle of least privilege. Most operations run unprivileged.
Only specific operations escalate via `sudo`.

```
UNPRIVILEGED (no root needed):
  - HTTP/HTTPS requests (portal detection, connectivity checks)
  - DNS resolution (via system resolver or direct UDP to port 53)
  - TCP port probing (connect() to external IPs)
  - Portal page fetching and form submission
  - WiFi SSID/BSSID detection (system_profiler, networksetup)
  - IPv6 connectivity testing
  - Report generation

PRIVILEGED (requires sudo):
  - MAC address spoofing (ifconfig ether)
  - DHCP lease release/renew (ipconfig set)
  - Raw ICMP sockets (ping with custom payloads)
  - DNS cache flush (killall -HUP mDNSResponder)
  - Traffic shaping (pfctl, dnctl)
  - Tunnel interface creation (utun for VPN)
```

**Privilege escalation UX:**

```
[*] MAC rotation requires root access.
    Command: sudo ifconfig en0 ether aa:bb:cc:dd:ee:ff
    Purpose: Change WiFi MAC address to test if portal tracks by MAC only
    [Press Enter to authorize with sudo, or 's' to skip this technique]
```

## 6. Ethical and Legal Safeguards

### 6.1 Consent and Scope

```python
CONSENT_BANNER = """
========================================
  Captive Portal Auditor (CPA)
  Security Assessment Tool
========================================

WARNING: This tool performs active testing against the WiFi network
you are currently connected to. Ensure you have authorization from
the network operator before proceeding.

Actions this tool will perform:
  - Probe DNS, ICMP, and TCP ports to detect filtering gaps
  - Change your MAC address (will be restored on exit)
  - Submit test data to the captive portal login form
  - Attempt to access the internet without portal authentication

This tool does NOT:
  - Attack other devices on the network
  - Attempt to crack WiFi passwords
  - Perform denial-of-service attacks
  - Intercept other users' traffic

Network: {ssid}
Portal:  {portal_url}

Do you have authorization to test this network? [y/N]
"""
```

### 6.2 Scope Limiting

```python
@dataclass
class AuditScope:
    """Constrain what CPA is allowed to do."""
    target_ssid: str | None = None         # Only test this SSID
    allowed_techniques: list[str] | None = None  # Only try these
    max_duration: timedelta = timedelta(minutes=30)  # Auto-stop
    no_external_connections: bool = False   # Don't connect to anything outside portal
    passive_only: bool = False             # Recon only, no bypass attempts
    stealth_mode: bool = False             # Conservative timing
```

### 6.3 Logging

All actions are logged to `~/.cpa/sessions/<session-id>/audit.log` with timestamps,
commands executed, and results. This provides a defensible record of what was done.

```
2026-03-29T14:30:01Z [RECON ] HTTP probe to detectportal.firefox.com -> 302 redirect to 192.168.1.1
2026-03-29T14:30:02Z [RECON ] DNS probe: google.com resolved to 192.168.1.1 (HIJACKED)
2026-03-29T14:30:03Z [RECON ] Portal fingerprint: Cisco Meraki (X-Frame-Options: meraki)
2026-03-29T14:30:10Z [BYPASS] Technique: mac_rotation (requires sudo)
2026-03-29T14:30:10Z [BYPASS] Original MAC: 84:2f:57:36:cb:80
2026-03-29T14:30:11Z [BYPASS] Set MAC to: 4a:8c:e2:1f:a3:70 (locally-administered)
2026-03-29T14:30:15Z [BYPASS] Reconnected to "Hilton_Guest"
2026-03-29T14:30:16Z [BYPASS] Connectivity test: SUCCESS (external IP: 203.0.113.1)
2026-03-29T14:30:16Z [BYPASS] MAC rotation SUCCEEDED -- portal tracks by MAC only
```

### 6.4 State Restoration Guarantee

```python
class StateGuard:
    """Ensures network state is restored on ANY exit path."""

    def __init__(self, platform: Platform, interface: str):
        self.original_mac = platform.get_interface_mac(interface)
        self.original_dns = platform.get_dns_servers()
        self.interface = interface
        self.platform = platform

        # Register cleanup on ALL exit paths
        atexit.register(self.restore)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def restore(self) -> None:
        """Restore original MAC, DNS, and routing."""
        if self._restored:
            return
        self._restored = True
        log.info(f"Restoring original MAC: {self.original_mac}")
        self.platform.set_mac_address(self.interface, self.original_mac)
        # Restore DNS, routes, etc.

    def _signal_handler(self, signum, frame):
        self.restore()
        sys.exit(128 + signum)
```

## 7. Configuration

### 7.1 Config File (`~/.cpa/config.toml`)

```toml
[general]
default_format = "text"         # text, json, report
stealth_mode = false
max_duration_minutes = 30
session_dir = "~/.cpa/sessions"

[canary]
# Optional: your own server for reliable leak detection
server = ""                     # e.g., "canary.yourdomain.com"
dns_zone = ""                   # e.g., "leak.yourdomain.com"

[tunnel]
# Optional: pre-configured tunnel servers
dns_tunnel_domain = ""          # e.g., "t.yourdomain.com"
dns_tunnel_password = ""
icmp_tunnel_server = ""         # e.g., "203.0.113.10"

[vpn]
# Optional: VPN config for bypass
wireguard_config = ""           # Path to .conf file
openvpn_config = ""             # Path to .ovpn file

[fingerprints]
# Path to custom fingerprint database (extends built-in)
custom_db = ""
```

### 7.2 Environment Variables

```
CPA_STEALTH=1                   # Enable stealth mode
CPA_CANARY_SERVER=host          # Canary server for leak detection
CPA_DNS_TUNNEL=domain           # DNS tunnel domain
CPA_LOG_LEVEL=DEBUG             # Logging verbosity
```

## 8. Dependencies

### Core (always required)

| Package | Purpose | Size |
|---------|---------|------|
| `click` | CLI framework | 200KB |
| `requests` | HTTP client | 150KB |
| `rich` | Terminal output, tables, progress | 500KB |
| `dnspython` | DNS resolution and probing | 300KB |

### Optional (for specific techniques)

| Package | Purpose | Required For |
|---------|---------|--------------|
| `scapy` | Raw packet crafting, ICMP | ICMP probing, advanced recon |
| `beautifulsoup4` | Portal page parsing | Auto-login technique |
| `lxml` | Fast HTML parsing | Auto-login technique |
| `netifaces` | Cross-platform interface info | Linux support |

### External Tools (not Python packages)

| Tool | Purpose | Required For | Install |
|------|---------|--------------|---------|
| `iodine` | DNS tunnel client | DNS tunnel technique | `brew install iodine` |
| `hans` | ICMP tunnel client | ICMP tunnel technique | Build from source |
| `nmap` | Port scanning (optional, CPA has built-in) | Advanced port scan | `brew install nmap` |
| `tshark` | Packet analysis (optional) | Deep protocol analysis | `brew install wireshark` |

**CPA must function with ONLY the core dependencies.** Optional packages enable
additional techniques. Missing optional deps cause the technique to be skipped
with an INFO message, not an error.

## 9. Project Structure

```
captive-portal-auditor/
  pyproject.toml
  README.md
  LICENSE                        # MIT
  src/
    cpa/
      __init__.py
      __main__.py               # python -m cpa
      cli.py                    # Click CLI definition
      orchestrator.py           # Phase runner
      models.py                 # Dataclasses (Session, Finding, etc.)
      config.py                 # Config loading, scope, guardrails
      recon/
        __init__.py
        detector.py             # Portal detection algorithm
        fingerprint.py          # Vendor fingerprinting
        leaks.py                # Leak enumeration (DNS, ICMP, ports, IPv6)
        signatures.py           # Fingerprint signature database
      bypass/
        __init__.py
        engine.py               # Technique runner (priority ordering)
        base.py                 # Technique protocol/base class
        mac_rotation.py         # Priority 1
        dns_tunnel.py           # Priority 2
        icmp_tunnel.py          # Priority 3
        ipv6_bypass.py          # Priority 4
        port_discovery.py       # Priority 5
        header_manipulation.py  # Priority 6
        auto_login.py           # Priority 7
        dhcp_manipulation.py    # Priority 8
        vpn_over_allowed.py     # Priority 9
        whitelist_abuse.py      # Priority 10
      persist/
        __init__.py
        manager.py              # Persistence manager
        session_monitor.py      # Connectivity monitoring
        mac_rotator.py          # Auto-rotate on session expiry
      net/
        __init__.py
        mac.py                  # MAC address operations
        dns.py                  # DNS probing
        icmp.py                 # ICMP probing
        http.py                 # Portal-aware HTTP client
        dhcp.py                 # DHCP operations
        probe.py                # Port/protocol probing
      platform/
        __init__.py
        base.py                 # Platform protocol definition
        macos.py                # macOS (networksetup, airport, ifconfig)
        linux.py                # Linux (ip, iw, nmcli)
        detect.py               # Auto-detect current platform
      reporter/
        __init__.py
        terminal.py             # Rich terminal output
        markdown.py             # Full markdown report
        json_reporter.py        # NDJSON stream + JSON report
        findings_db.py          # Finding catalog (CPA-001 through CPA-020)
  tests/
    conftest.py
    test_recon/
      test_detector.py
      test_fingerprint.py
      test_leaks.py
    test_bypass/
      test_mac_rotation.py
      test_dns_tunnel.py
      test_ipv6_bypass.py
      ...
    test_net/
      test_mac.py
      test_dns.py
      test_http.py
      ...
    test_platform/
      test_macos.py
      test_linux.py
    test_reporter/
      test_terminal.py
      test_markdown.py
    test_orchestrator.py
    test_cli.py
    fixtures/                    # Captured portal pages, DNS responses, etc.
      meraki_splash.html
      aruba_login.html
      unifi_guest.html
```

## 10. Execution Flow (Detailed)

```
User runs: cpa audit

1. CLI ENTRY
   |-- Parse arguments
   |-- Load config (~/.cpa/config.toml)
   |-- Detect platform (macOS/Linux)
   |-- Auto-detect WiFi interface
   |-- Check: are we connected to WiFi? (fail fast if not)
   |
2. CONSENT
   |-- Display consent banner with SSID and detected portal
   |-- Wait for user confirmation (unless --yes)
   |-- Display scope summary
   |
3. STATE SNAPSHOT
   |-- Record: interface, MAC, IP, DNS, routes, SSID, BSSID
   |-- Register StateGuard (atexit + signal handlers)
   |-- Create session directory
   |-- Start audit log
   |
4. PHASE 1: RECONNAISSANCE (always runs)
   |
   |-- 4a. Portal Detection
   |   |-- HTTP probe (detectportal.firefox.com)
   |   |-- DNS probe (resolve google.com, compare IPs)
   |   |-- TCP probe (connect to known IPs on 80/443)
   |   |-- Determine PortalType enum value
   |   |-- If NONE: "No captive portal detected. Network appears open." -> exit
   |
   |-- 4b. Portal Fingerprinting
   |   |-- Fetch portal page (follow redirects)
   |   |-- Match against signature database
   |   |-- Extract auth methods, session model hints
   |   |-- Check portal security (HTTPS, cookie flags, version disclosure)
   |
   |-- 4c. Leak Enumeration
   |   |-- DNS: test UDP/53, TCP/53, DoH, DoT to external resolvers
   |   |-- ICMP: ping external hosts with various payload sizes
   |   |-- IPv6: check for global address, test IPv6 connectivity
   |   |-- Ports: probe candidate ports to external IP
   |   |-- Domains: test common whitelist targets
   |
   |-- 4d. Print recon summary
   |
   |-- If --recon-only: generate report -> exit
   |
5. PHASE 2: BYPASS ATTEMPTS (unless --recon-only)
   |
   |-- For each technique in priority order:
   |   |-- Check prerequisites (does recon data support this technique?)
   |   |-- Check if technique is allowed by scope
   |   |-- Check if external dependencies exist
   |   |-- If all checks pass:
   |   |   |-- Print: "Attempting: {technique.name}..."
   |   |   |-- If requires_root: prompt for sudo (or use cached)
   |   |   |-- Execute technique.attempt()
   |   |   |-- Record TechniqueResult
   |   |   |-- If SUCCESS:
   |   |   |   |-- Verify: can we reach the real internet?
   |   |   |   |-- Record Finding
   |   |   |   |-- If --stop-on-first: stop trying more techniques
   |   |   |   |-- Default: continue trying remaining techniques (for completeness)
   |   |   |-- If FAILURE:
   |   |   |   |-- Clean up any partial changes
   |   |   |   |-- Record failure reason
   |   |   |   |-- Continue to next technique
   |   |-- If prerequisites not met: SKIP with reason
   |
6. PHASE 3: PERSISTENCE (only if bypass succeeded and --no-persist not set)
   |
   |-- Select persistence strategy for most effective bypass
   |-- Start session monitor (background thread)
   |-- Print: "Access maintained. Press Ctrl+C to stop and generate report."
   |-- Wait for user interrupt or --max-duration timeout
   |
7. PHASE 4: REPORT
   |
   |-- Compile all findings
   |-- Calculate severity scores
   |-- Generate report in requested format
   |-- Save session data to ~/.cpa/sessions/<id>/
   |-- Print report to terminal
   |-- If --output: write to file
   |
8. CLEANUP
   |-- StateGuard.restore() (MAC, DNS, routes)
   |-- Print: "Original network state restored."
   |-- Exit 0 (findings found) or 1 (error) or 2 (no portal detected)
```

## 11. Testing Strategy

### Unit Tests (offline, no network)

- **Fingerprinting**: Feed captured HTML from fixtures/ into fingerprint engine, verify vendor detection
- **Finding generation**: Verify correct finding IDs, severities, remediation text
- **MAC generation**: Verify locally-administered bit set, OUI matching
- **Config parsing**: Verify TOML loading, defaults, validation
- **Report rendering**: Verify terminal, markdown, JSON output correctness
- **Platform detection**: Mock subprocess calls, verify command construction

### Integration Tests (require network, run manually)

- **Portal detection against known portals**: Spin up a test portal (e.g., CoovaChilli
  in Docker) and verify detection
- **MAC spoofing on loopback**: Verify the command construction (actual spoofing tested
  manually)
- **DNS probing against local DNS server**: Verify leak detection logic

### Manual Testing Protocol

```
1. Connect to target WiFi (hotel, airport, etc.)
2. Run: cpa audit --recon-only (safe, passive)
3. Review recon output for accuracy
4. Run: cpa audit (with authorization)
5. Verify findings match manual assessment
6. Verify state restoration (MAC address back to original)
```

## 12. IDS/IPS Evasion Considerations

CPA is designed to minimize its footprint on the portal operator's monitoring.

| Technique | Normal Traffic Pattern | CPA's Pattern | Detection Risk |
|-----------|----------------------|---------------|----------------|
| MAC rotation | New device joins WiFi | Same | Negligible |
| DNS probing | Device resolves domains | Slightly more diverse | Low |
| Port scanning | None | Sequential connects | Medium |
| ICMP probing | Occasional pings | Slightly more | Low |
| DNS tunnel | Low DNS volume | Very high DNS volume | High |
| Form submission | 1 login attempt | 1 login attempt | Negligible |

**Stealth mode** (`--stealth`) mitigations:
- Port scanning: random order, 5-second inter-probe delay, jitter
- DNS probing: mix canary queries with normal resolution
- ICMP: standard 64-byte payloads only, normal ping intervals
- All probes: randomized timing with 0.5-2.0x jitter multiplier
- DNS tunnel: rate-limited to avoid volume-based detection

## 13. Future Extensions (Not in Initial Release)

- **Monitor mode**: Passive observation of other clients' traffic to learn whitelisted
  MACs, portal behavior, session durations (requires monitor mode support)
- **Automated captive portal exploitation**: Beyond form submission, handle JavaScript-
  based portals with headless browser (playwright/selenium)
- **Portal credential spraying**: Test common default credentials on portal admin panels
  (separate authorization required)
- **Rogue AP detection**: Identify if the portal itself is a rogue AP
- **WISPr protocol support**: Automated authentication via WISPr XML API (used by some
  commercial hotspot operators)
- **Integration with Fray**: WAF bypass for portal web application layer
- **Mobile hotspot chaining**: Use phone as authenticated client, share via hotspot

## 14. Implementation Priority

### Phase A: MVP (functional recon + MAC rotation)

```
Week 1:
  - cpa.cli (basic Click structure)
  - cpa.platform.macos (interface detection, MAC spoofing)
  - cpa.models (all dataclasses)
  - cpa.net.http (portal detection)
  - cpa.net.dns (DNS leak check)
  - cpa.recon.detector (portal type detection)
  - cpa.recon.fingerprint (top 5 vendors)
  - cpa.bypass.mac_rotation
  - cpa.reporter.terminal (basic output)
  - cpa.config (consent banner, state guard)
  - Tests for all above
```

### Phase B: Full Recon + Core Bypasses

```
Week 2:
  - cpa.net.icmp (ICMP probing)
  - cpa.net.probe (port scanning)
  - cpa.recon.leaks (full leak enumeration)
  - cpa.bypass.ipv6_bypass
  - cpa.bypass.port_discovery
  - cpa.bypass.header_manipulation
  - cpa.bypass.auto_login
  - cpa.bypass.dhcp_manipulation
  - cpa.recon.fingerprint (all vendors)
  - cpa.reporter.markdown
  - cpa.reporter.json_reporter
```

### Phase C: Tunneling + Persistence

```
Week 3:
  - cpa.bypass.dns_tunnel (iodine integration)
  - cpa.bypass.icmp_tunnel (hans integration)
  - cpa.bypass.vpn_over_allowed
  - cpa.bypass.whitelist_abuse
  - cpa.persist.manager
  - cpa.persist.session_monitor
  - cpa.persist.mac_rotator
  - cpa.platform.linux
  - Full test suite
```

## 15. Security of CPA Itself

CPA handles sensitive data (MAC addresses, network credentials, session tokens).

- **No telemetry**: CPA never phones home
- **Local storage only**: All session data in `~/.cpa/sessions/` (mode 0700)
- **No credential storage**: WiFi passwords passed via argument or env, never persisted
- **Audit log integrity**: Logs are append-only during session, checksummed at end
- **Dependency pinning**: All dependencies pinned to exact versions in `pyproject.toml`
- **No eval/exec**: No dynamic code execution from portal content

## 16. pyproject.toml Skeleton

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "captive-portal-auditor"
version = "0.1.0"
description = "Red team tool for assessing captive portal security"
requires-python = ">=3.11"
license = "MIT"
dependencies = [
    "click>=8.1",
    "requests>=2.31",
    "rich>=13.0",
    "dnspython>=2.4",
]

[project.optional-dependencies]
full = [
    "scapy>=2.5",
    "beautifulsoup4>=4.12",
    "lxml>=5.0",
]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "ruff>=0.3",
    "mypy>=1.9",
]

[project.scripts]
cpa = "cpa.cli:main"

[tool.ruff]
target-version = "py311"
line-length = 100

[tool.mypy]
python_version = "3.11"
strict = true

[tool.pytest.ini_options]
testpaths = ["tests"]
```

---

## Appendix A: Portal Vendor Signature Database

```python
SIGNATURES: list[PortalSignature] = [
    PortalSignature(
        vendor="cisco_meraki",
        url_patterns=[r"/splash/", r"splash\.meraki\.com"],
        header_patterns={"X-Frame-Options": r"meraki"},
        html_patterns=[r"meraki-splash", r"Meraki\s+cloud"],
        cookie_patterns=[r"_meraki_"],
    ),
    PortalSignature(
        vendor="aruba_clearpass",
        url_patterns=[r"/cgi-bin/login", r"/auth/"],
        header_patterns={"Server": r"Aruba"},
        html_patterns=[r"aruba_", r"clearpass"],
        cookie_patterns=[],
    ),
    PortalSignature(
        vendor="ruckus_cloudpath",
        url_patterns=[r"/user/login"],
        header_patterns={},
        html_patterns=[r"ruckus", r"cloudpath"],
        cookie_patterns=[r"ruckus"],
    ),
    PortalSignature(
        vendor="unifi",
        url_patterns=[r"/guest/s/", r"/portal/"],
        header_patterns={},
        html_patterns=[r"unifi-portal", r"UniFi"],
        cookie_patterns=[r"UNIFISES"],
    ),
    PortalSignature(
        vendor="mikrotik",
        url_patterns=[r"/login"],
        header_patterns={"Server": r"Mikrotik"},
        html_patterns=[r"mikrotik", r"RouterOS"],
        cookie_patterns=[],
    ),
    PortalSignature(
        vendor="fortinet",
        url_patterns=[r"/fgtauth", r"/captive-portal/"],
        header_patterns={"Server": r"FortiGate"},
        html_patterns=[r"ftnt_", r"fortinet", r"FortiGuard"],
        cookie_patterns=[r"APSCOOKIE"],
    ),
    PortalSignature(
        vendor="pfsense",
        url_patterns=[r"/index\.php\?zone="],
        header_patterns={},
        html_patterns=[r"captiveportal", r"pfSense"],
        cookie_patterns=[],
    ),
    PortalSignature(
        vendor="opennds",
        url_patterns=[r"/opennds_preauth/"],
        header_patterns={},
        html_patterns=[r"openNDS", r"opennds"],
        cookie_patterns=[],
    ),
    PortalSignature(
        vendor="coovachilli",
        url_patterns=[r"/json/status", r"/prelogin"],
        header_patterns={},
        html_patterns=[r"coova", r"chilli"],
        cookie_patterns=[],
    ),
    PortalSignature(
        vendor="nomadix",
        url_patterns=[r"/nomadix/"],
        header_patterns={},
        html_patterns=[r"Nomadix", r"nomadix"],
        cookie_patterns=[],
    ),
    PortalSignature(
        vendor="guest_internet",
        url_patterns=[r"/login\.html"],
        header_patterns={},
        html_patterns=[r"Guest\s*Internet", r"gis-redirect"],
        cookie_patterns=[],
    ),
    PortalSignature(
        vendor="zyxel",
        url_patterns=[r"/portal/"],
        header_patterns={},
        html_patterns=[r"ZyXEL", r"zyxel"],
        cookie_patterns=[],
    ),
]
```

## Appendix B: Remediation Guidance Database

```python
REMEDIATION: dict[str, str] = {
    "CPA-001": """
        MAC-only session tracking is fundamentally weak. Remediation options:
        1. BEST: Implement 802.1X (WPA2/3-Enterprise) for per-device authentication
        2. GOOD: Bind sessions to MAC + IP + server-side token (triple binding)
        3. MINIMUM: Add rate limiting on new MAC registrations per time window
           (e.g., max 3 new MACs per hour from same AP)
        Note: MAC randomization (iOS 14+, Android 10+) already breaks MAC-only
        tracking for legitimate users, so this weakness affects usability too.
    """,
    "CPA-002": """
        DNS (UDP/53) must be allowed pre-auth for portal redirect to work, but
        it should be restricted:
        1. Only allow DNS to the portal's own DNS server (captive DNS)
        2. Block all external DNS (8.8.8.8, 1.1.1.1, etc.) pre-auth
        3. Implement DNS query rate limiting (e.g., 10 queries/sec)
        4. Block DNS TXT records over 512 bytes (tunnel signature)
        5. Deploy DNS-layer IDS to detect tunneling patterns
    """,
    "CPA-006": """
        IPv6 filtering must match IPv4 filtering:
        1. Apply identical captive portal rules to IPv6 traffic
        2. If IPv6 is not needed on the guest network, disable it entirely
           (disable Router Advertisements, disable DHCPv6)
        3. Use IPv6 firewall rules that mirror IPv4 rules
        4. Test both address families when deploying portal changes
    """,
    # ... (full remediation for all CPA-001 through CPA-020)
}
```

## Appendix C: MITRE ATT&CK Mapping

| CPA Technique | ATT&CK Technique | Tactic |
|---------------|-------------------|--------|
| Portal detection | T1016 System Network Configuration Discovery | Discovery |
| Leak enumeration | T1046 Network Service Discovery | Discovery |
| Vendor fingerprinting | T1082 System Information Discovery | Discovery |
| MAC rotation | T1036.005 Masquerading: Match Legitimate Name | Defense Evasion |
| DNS tunnel | T1572 Protocol Tunneling | Command and Control |
| ICMP tunnel | T1572 Protocol Tunneling | Command and Control |
| IPv6 bypass | T1008 Fallback Channels | Command and Control |
| VPN over allowed port | T1572 Protocol Tunneling | Command and Control |
| Whitelist abuse | T1090.004 Domain Fronting | Command and Control |
| DHCP manipulation | T1557.003 DHCP Spoofing | Credential Access |
| Header manipulation | T1036 Masquerading | Defense Evasion |
| Session persistence | T1205 Traffic Signaling | Persistence |
