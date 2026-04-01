"""Leak enumeration: test what protocols/ports are open pre-authentication.

Stealth features:
- Randomized port order (no sequential pattern for IDS to detect)
- Jitter between probes (50-200ms, looks like app traffic not scanning)
- Parallel async probes in small batches (4-8 concurrent, not 1000)
- SYN-only TCP probes (half-open, minimal footprint) where possible
- Short timeouts (1.5s) — we only need to detect if port passes through
- DNS beacon query attempted first (1 query vs many probes)
"""

from __future__ import annotations

import random
import socket
import subprocess
import time
from dataclasses import dataclass, field


@dataclass
class DnsProbeResult:
    is_open: bool = False
    resolvers: list[dict[str, str]] = field(default_factory=list)
    details: str = ""


@dataclass
class IcmpProbeResult:
    is_open: bool = False
    targets_reached: list[str] = field(default_factory=list)
    details: str = ""


@dataclass
class Ipv6ProbeResult:
    is_open: bool = False
    address: str = ""
    details: str = ""


@dataclass
class HttpsProbeResult:
    is_open: bool = False
    url: str = ""
    details: str = ""


@dataclass
class WhitelistResult:
    domain: str
    is_open: bool = False
    status_code: int = 0
    redirected: bool = False
    details: str = ""


@dataclass
class PortProbeResult:
    port: int
    protocol: str  # "tcp" or "udp"
    is_open: bool = False
    service: str = ""
    details: str = ""


@dataclass
class ProbeResults:
    dns: DnsProbeResult = field(default_factory=DnsProbeResult)
    icmp: IcmpProbeResult = field(default_factory=IcmpProbeResult)
    ipv6: Ipv6ProbeResult = field(default_factory=Ipv6ProbeResult)
    cloudflare: HttpsProbeResult = field(default_factory=HttpsProbeResult)
    whitelists: list[WhitelistResult] = field(default_factory=list)
    open_ports: list[PortProbeResult] = field(default_factory=list)
    tunnel_server_ports: list[PortProbeResult] = field(default_factory=list)
    quic: PortProbeResult = field(default_factory=lambda: PortProbeResult(port=443, protocol="udp", service="QUIC"))
    ntp: PortProbeResult = field(default_factory=lambda: PortProbeResult(port=123, protocol="udp", service="NTP"))
    doh: PortProbeResult = field(default_factory=lambda: PortProbeResult(port=443, protocol="doh", service="DoH"))


# Well-known port descriptions
PORT_SERVICES: dict[int, str] = {
    53: "DNS",
    80: "HTTP",
    123: "NTP",
    443: "HTTPS",
    500: "IKE/IPSec",
    853: "DNS-over-TLS",
    993: "IMAPS",
    995: "POP3S",
    1194: "OpenVPN",
    1723: "PPTP",
    4500: "IPSec NAT-T",
    5223: "Apple Push",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    51820: "WireGuard",
    41641: "Tailscale",
}


def probe_all(
    interface: str = "en0",
    stealth: bool = True,
    tunnel_server_ip: str = "",
) -> ProbeResults:
    """Run all probes to enumerate what's open pre-auth.

    Stealth mode: randomized order, jitter, small batches.
    Fast mode: parallel, no jitter, larger batches.
    """
    results = ProbeResults()

    results.dns = probe_dns(stealth=stealth)
    if stealth:
        time.sleep(random.uniform(0.3, 0.8))

    results.icmp = probe_icmp(stealth=stealth)
    if stealth:
        time.sleep(random.uniform(0.3, 0.8))

    results.ipv6 = probe_ipv6(interface=interface)
    if stealth:
        time.sleep(random.uniform(0.2, 0.5))

    results.cloudflare = probe_https("https://1.1.1.1", label="Cloudflare")
    if stealth:
        time.sleep(random.uniform(0.2, 0.5))

    results.whitelists = probe_whitelists(stealth=stealth)
    if stealth:
        time.sleep(random.uniform(0.3, 0.8))

    results.open_ports = probe_ports(stealth=stealth)

    # UDP-specific probes (QUIC, NTP)
    results.quic = probe_quic(stealth=stealth)
    if stealth:
        time.sleep(random.uniform(0.1, 0.3))
    results.ntp = probe_ntp(stealth=stealth)
    if stealth:
        time.sleep(random.uniform(0.1, 0.3))
    results.doh = probe_doh(stealth=stealth)

    # If a tunnel server is configured, stealth-scan it for reachable ports
    if tunnel_server_ip:
        if stealth:
            time.sleep(random.uniform(0.3, 0.8))
        results.tunnel_server_ports = probe_tunnel_server(tunnel_server_ip, stealth=stealth)

    return results


def probe_dns(stealth: bool = True) -> DnsProbeResult:
    """Test if external DNS resolvers are reachable."""
    result = DnsProbeResult()
    resolvers = [
        ("1.1.1.1", "Cloudflare"),
        ("8.8.8.8", "Google"),
        ("9.9.9.9", "Quad9"),
    ]

    test_domain = "example.com"
    open_resolvers: list[dict[str, str]] = []

    for resolver_ip, resolver_name in resolvers:
        if stealth:
            time.sleep(random.uniform(0.2, 0.8))

        try:
            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.nameservers = [resolver_ip]
            resolver.timeout = 5
            resolver.lifetime = 5

            answers = resolver.resolve(test_domain, "A")
            ips = [str(rdata) for rdata in answers]
            if ips:
                open_resolvers.append({
                    "ip": resolver_ip,
                    "name": resolver_name,
                    "resolved": ", ".join(ips),
                })
        except Exception:
            continue

    if open_resolvers:
        result.is_open = True
        result.resolvers = open_resolvers
        names = ", ".join(r["name"] for r in open_resolvers)
        result.details = f"External DNS reachable: {names}"
    else:
        result.details = "No external DNS resolvers reachable"

    return result


def probe_icmp(stealth: bool = True) -> IcmpProbeResult:
    """Test if ICMP (ping) reaches external hosts."""
    result = IcmpProbeResult()
    targets = [
        ("1.1.1.1", "Cloudflare"),
        ("8.8.8.8", "Google DNS"),
    ]

    reached: list[str] = []

    for ip, name in targets:
        if stealth:
            time.sleep(random.uniform(0.3, 0.8))

        try:
            proc = subprocess.run(
                ["ping", "-c", "1", "-W", "3", ip],
                capture_output=True, text=True, timeout=5,
            )
            if proc.returncode == 0:
                reached.append(f"{name} ({ip})")
        except (subprocess.TimeoutExpired, OSError):
            continue

    if reached:
        result.is_open = True
        result.targets_reached = reached
        result.details = f"ICMP open to: {', '.join(reached)}"
    else:
        result.details = "ICMP blocked to external hosts"

    return result


def probe_ipv6(interface: str = "en0") -> Ipv6ProbeResult:
    """Test if IPv6 traffic bypasses the portal."""
    result = Ipv6ProbeResult()

    # Check if we have a global IPv6 address
    from . import platform as platform_mac
    ipv6_addr = platform_mac.get_ipv6_address(interface)

    if not ipv6_addr:
        result.details = "No global IPv6 address on interface"
        return result

    result.address = ipv6_addr

    # Try to connect to Google's IPv6 address
    ipv6_targets = [
        ("2607:f8b0:4004:800::200e", 80, "google.com"),
        ("2606:4700::6810:85e5", 80, "cloudflare.com"),
    ]

    for addr, port, name in ipv6_targets:
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((addr, port))
            sock.close()
            result.is_open = True
            result.details = f"IPv6 unfiltered! Connected to {name} [{addr}]"
            return result
        except (socket.error, OSError):
            continue

    # Fallback: try HTTP over IPv6
    try:
        import requests
        resp = requests.get("http://ipv6.google.com", timeout=5)
        if resp.status_code == 200:
            result.is_open = True
            result.details = "IPv6 HTTP connectivity confirmed via ipv6.google.com"
            return result
    except Exception:
        pass

    result.details = f"IPv6 address {ipv6_addr} present but no external connectivity"
    return result


def probe_https(url: str, label: str = "") -> HttpsProbeResult:
    """Test if HTTPS to a specific URL works."""
    result = HttpsProbeResult(url=url)
    try:
        import requests
        resp = requests.get(url, timeout=10, allow_redirects=False)
        # If we get a real response (not a redirect to portal), HTTPS is open
        if resp.status_code < 400:
            result.is_open = True
            result.details = f"{label or url}: HTTP {resp.status_code}"
        else:
            result.details = f"{label or url}: HTTP {resp.status_code} (blocked)"
    except Exception as e:
        result.details = f"{label or url}: connection failed ({type(e).__name__})"
    return result


def probe_whitelists(stealth: bool = True) -> list[WhitelistResult]:
    """Test commonly whitelisted domains for pre-auth access."""
    import requests

    targets = [
        ("captive.apple.com", "http://captive.apple.com/hotspot-detect.html"),
        ("connectivitycheck.gstatic.com", "http://connectivitycheck.gstatic.com/generate_204"),
        ("clients3.google.com", "http://clients3.google.com/generate_204"),
        ("www.msftconnecttest.com", "http://www.msftconnecttest.com/connecttest.txt"),
        ("cloudflare.com", "https://cloudflare.com"),
        ("1.1.1.1", "https://1.1.1.1"),
        ("www.apple.com", "https://www.apple.com"),
        ("www.google.com", "https://www.google.com"),
        ("login.microsoftonline.com", "https://login.microsoftonline.com"),
        ("facebook.com", "https://facebook.com"),
    ]

    results: list[WhitelistResult] = []

    for domain, url in targets:
        if stealth:
            time.sleep(random.uniform(0.2, 0.6))

        wr = WhitelistResult(domain=domain)
        try:
            resp = requests.get(url, timeout=8, allow_redirects=True)
            wr.status_code = resp.status_code

            # Check if we got redirected to a portal (not a normal redirect)
            if resp.url != url and _looks_like_portal_redirect(resp.url, url):
                wr.redirected = True
                wr.details = f"Redirected to portal: {resp.url}"
            elif resp.status_code < 400:
                wr.is_open = True
                wr.details = f"Accessible (HTTP {resp.status_code})"
            else:
                wr.details = f"HTTP {resp.status_code}"
        except requests.ConnectionError:
            wr.details = "Connection refused/failed"
        except requests.Timeout:
            wr.details = "Timeout"
        except Exception as e:
            wr.details = f"Error: {type(e).__name__}"

        results.append(wr)

    return results


def probe_ports(
    target_ip: str = "1.1.1.1",
    stealth: bool = True,
) -> list[PortProbeResult]:
    """Scan for open outbound TCP ports with stealth.

    Stealth mode:
    - Randomized port order (defeats sequential scan detection)
    - Parallel batches of 4 with jitter (looks like app traffic)
    - Short timeout (1.5s — enough to detect passthrough, not linger)
    - Only tests commonly-allowed ports (not suspicious full scan)

    Fast mode (--fast):
    - Parallel batches of 8, no jitter
    - Still randomized order
    """
    candidate_ports = list(TUNNEL_CANDIDATE_PORTS)
    random.shuffle(candidate_ports)  # Always randomize order

    batch_size = 4 if stealth else 8
    timeout = 1.5 if stealth else 1.0
    results: list[PortProbeResult] = []

    for i in range(0, len(candidate_ports), batch_size):
        batch = candidate_ports[i:i + batch_size]

        # Probe batch in parallel using asyncio
        batch_results = _probe_batch_sync(batch, target_ip, timeout)
        results.extend(batch_results)

        # Jitter between batches in stealth mode
        if stealth and i + batch_size < len(candidate_ports):
            time.sleep(random.uniform(0.1, 0.4))

    # Sort results by port number for display
    results.sort(key=lambda r: r.port)
    return results


# Ports commonly allowed through firewalls/captive portals
# Ordered by likelihood of being open pre-auth
TUNNEL_CANDIDATE_PORTS = [
    53, 80, 443,         # Almost always open
    123, 853,            # NTP, DoT — often open
    8080, 8443,          # HTTP alt — common
    500, 4500,           # IPSec — sometimes open for VPN
    993, 995,            # IMAPS, POP3S — sometimes open
    1194, 1723,          # OpenVPN, PPTP — sometimes open
    5223,                # Apple Push — often whitelisted
    51820, 41641,        # WireGuard, Tailscale — rarely open
    22, 25, 587, 465,    # SSH, SMTP — sometimes open
    143, 110,            # IMAP, POP3 — sometimes open
    5060, 5061,          # SIP — sometimes open for VoIP
    3478, 3479,          # STUN/TURN — sometimes open for WebRTC
]


def _probe_batch_sync(ports: list[int], target_ip: str, timeout: float) -> list[PortProbeResult]:
    """Probe a batch of ports in parallel using threads (avoids asyncio complexity)."""
    import concurrent.futures

    results: list[PortProbeResult] = []

    def probe_one(port: int) -> PortProbeResult:
        pr = PortProbeResult(
            port=port,
            protocol="tcp",
            service=PORT_SERVICES.get(port, "unknown"),
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result_code = sock.connect_ex((target_ip, port))
            sock.close()
            if result_code == 0:
                pr.is_open = True
                pr.details = f"TCP/{port} ({pr.service}) open"
            else:
                pr.details = f"TCP/{port} closed"
        except (socket.error, OSError) as e:
            pr.details = f"TCP/{port} error: {type(e).__name__}"
        return pr

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports)) as executor:
        futures = {executor.submit(probe_one, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    return results


def probe_tunnel_server(
    server_ip: str,
    stealth: bool = True,
) -> list[PortProbeResult]:
    """Stealth scan YOUR tunnel server to find which ports pass through the portal.

    This is the key scan: which ports can reach your server from behind the portal?
    Uses the same stealth techniques but scans a broader set of ports since
    we know the server is ours (not adversarial).

    Strategy:
    1. Try DNS beacon first (one DNS TXT query — zero scan footprint)
    2. If DNS blocked, fall back to smart parallel probe
    """
    # Phase 1: DNS beacon — try to get server's port list via DNS
    # (Only works if external DNS is reachable — often blocked pre-auth)
    beacon_ports = _try_dns_beacon(server_ip)
    if beacon_ports:
        # Verify the beacon ports actually pass through (DNS might be intercepted)
        results = _probe_batch_sync(beacon_ports, server_ip, 2.0)
        open_results = [r for r in results if r.is_open]
        if open_results:
            return results

    # Phase 2: Smart scan — test ports in priority order
    # Start with most-likely-open, stop early once we find enough
    priority_ports = [
        # Tier 1: almost always allowed (test first)
        443, 80, 8443, 8080,
        # Tier 2: often allowed
        53, 123, 853, 5223,
        # Tier 3: sometimes allowed
        993, 995, 587, 465, 22,
        # Tier 4: VPN ports (often blocked but worth trying)
        500, 4500, 1194, 1723, 51820,
        # Tier 5: uncommon (last resort)
        3478, 5060, 5061, 41641, 143, 110, 25,
    ]
    random.shuffle(priority_ports[:4])   # Randomize within tier 1
    random.shuffle(priority_ports[4:8])  # Randomize within tier 2

    results: list[PortProbeResult] = []
    batch_size = 4 if stealth else 8

    for i in range(0, len(priority_ports), batch_size):
        batch = priority_ports[i:i + batch_size]
        batch_results = _probe_batch_sync(batch, server_ip, 1.5)
        results.extend(batch_results)

        # Early exit: found at least 1 open port — enough for a tunnel
        if any(r.is_open for r in batch_results):
            # Do one more batch to find alternatives, then stop
            if i + batch_size < len(priority_ports):
                next_batch = priority_ports[i + batch_size:i + batch_size * 2]
                if next_batch:
                    results.extend(_probe_batch_sync(next_batch, server_ip, 1.5))
            break

        if stealth:
            time.sleep(random.uniform(0.1, 0.3))

    results.sort(key=lambda r: r.port)
    return results


def _try_dns_beacon(server_ip: str) -> list[int]:
    """Try to get tunnel server's available ports via DNS TXT record.

    Query: TXT record for 'ports.<domain>' or a known beacon domain.
    Returns list of ports if beacon found, empty list otherwise.
    This is the zero-footprint alternative to port scanning.
    """
    try:
        import dns.resolver
        # Try resolving via external DNS (may be blocked pre-auth)
        for resolver_ip in ["1.1.1.1", "8.8.8.8"]:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                resolver.timeout = 3
                resolver.lifetime = 3
                # Convention: TXT record at _nowifi.<reverse-ip>.nowifish.com
                # For now, just try a direct approach
                answers = resolver.resolve(f"_nowifi.{server_ip.replace('.', '-')}.nowifish.com", "TXT")
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if txt.startswith("ports="):
                        return [int(p) for p in txt[6:].split(",") if p.isdigit()]
            except Exception:
                continue
    except ImportError:
        pass
    return []


def _looks_like_portal_redirect(final_url: str, original_url: str) -> bool:
    """Heuristic to detect if a redirect is a captive portal intercept vs normal redirect."""
    from urllib.parse import urlparse

    orig_host = urlparse(original_url).hostname or ""
    final_host = urlparse(final_url).hostname or ""

    # If redirected to a completely different domain, likely a portal
    if orig_host and final_host and orig_host not in final_host and final_host not in orig_host:
        return True

    # Common portal redirect patterns
    portal_patterns = ["login", "portal", "captive", "auth", "hotspot", "splash", "guest"]
    final_lower = final_url.lower()
    for pattern in portal_patterns:
        if pattern in final_lower:
            return True

    return False


def probe_udp_port(target_ip: str, port: int, timeout: float = 2.0) -> bool:
    """Probe a single UDP port by sending a minimal packet and checking for response.

    Used to detect if UDP/443 (QUIC) or UDP/123 (NTP) passes through the portal.
    Sends a minimal valid packet for the protocol to maximize response chance.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        if port == 443:
            # Send QUIC Initial packet header (minimal, triggers version negotiation)
            # This is a valid QUIC long header with an unknown version
            quic_probe = bytes([
                0xC0,  # Long header, fixed bit
                0x00, 0x00, 0x00, 0x01,  # Version 1
                0x08,  # DCID length
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  # DCID
                0x00,  # SCID length
                0x00, 0x00,  # Token length
                0x00, 0x04,  # Length
                0x00, 0x00, 0x00, 0x00,  # Minimal payload
            ])
            sock.sendto(quic_probe, (target_ip, port))
        elif port == 123:
            # Send valid NTP client request (mode 3, version 4)
            ntp_probe = b'\x23' + b'\x00' * 47  # 48-byte NTP request
            sock.sendto(ntp_probe, (target_ip, port))
        else:
            # Generic UDP probe
            sock.sendto(b'\x00', (target_ip, port))

        try:
            data, _ = sock.recvfrom(4096)
            sock.close()
            return len(data) > 0  # Any response = port is open/reachable
        except socket.timeout:
            sock.close()
            return False  # No response within timeout
    except (socket.error, OSError):
        return False


def probe_quic(target_ip: str = "1.1.1.1", stealth: bool = True) -> PortProbeResult:
    """Test if UDP/443 (QUIC/HTTP3) passes through the portal.

    Most captive portals only filter TCP. UDP/443 is used by HTTP/3 and
    is increasingly common, making it hard for portals to block without
    breaking legitimate traffic.
    """
    result = PortProbeResult(port=443, protocol="udp", service="QUIC/HTTP3")

    if stealth:
        time.sleep(random.uniform(0.1, 0.3))

    if probe_udp_port(target_ip, 443, timeout=2.0):
        result.is_open = True
        result.details = f"UDP/443 (QUIC) open to {target_ip}"
    else:
        result.details = "UDP/443 (QUIC) blocked"

    return result


def probe_ntp(stealth: bool = True) -> PortProbeResult:
    """Test if NTP (UDP/123) reaches external NTP servers.

    NTP is almost universally allowed because devices need accurate time.
    If it passes through, it can be used as a tunnel channel.
    """
    result = PortProbeResult(port=123, protocol="udp", service="NTP")

    ntp_servers = ["pool.ntp.org", "time.google.com", "time.cloudflare.com"]

    for server in ntp_servers:
        if stealth:
            time.sleep(random.uniform(0.1, 0.3))
        try:
            ip = socket.gethostbyname(server)
        except socket.gaierror:
            continue

        if probe_udp_port(ip, 123, timeout=2.0):
            result.is_open = True
            result.details = f"NTP open to {server} ({ip})"
            return result

    result.details = "NTP (UDP/123) blocked to all tested servers"
    return result


def probe_doh(stealth: bool = True) -> PortProbeResult:
    """Test if DNS-over-HTTPS endpoints are reachable.

    DoH goes over HTTPS to Cloudflare/Google DNS, which are often
    whitelisted by captive portals. Unlike plain DNS tunneling,
    DoH is encrypted end-to-end.
    """
    import requests

    result = PortProbeResult(port=443, protocol="doh", service="DNS-over-HTTPS")

    doh_endpoints = [
        ("https://cloudflare-dns.com/dns-query?name=example.com&type=A", "Cloudflare DoH"),
        ("https://dns.google/resolve?name=example.com&type=A", "Google DoH"),
    ]

    for url, name in doh_endpoints:
        if stealth:
            time.sleep(random.uniform(0.1, 0.3))
        try:
            resp = requests.get(
                url,
                headers={"Accept": "application/dns-json"},
                timeout=5,
            )
            if resp.status_code == 200:
                result.is_open = True
                result.details = f"DoH reachable via {name}"
                return result
        except Exception:
            continue

    result.details = "DoH endpoints not reachable"
    return result
