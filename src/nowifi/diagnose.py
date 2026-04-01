"""Diagnosis mode — full analysis without exploitation.

Scans the network, detects portal, probes all protocols, and reports
which bypass methods WOULD work — without actually exploiting anything.
No MAC changes, no tunnels, no proxy changes. Read-only assessment.
"""

from __future__ import annotations

from dataclasses import dataclass
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .detect import PortalInfo
from .probe import ProbeResults


@dataclass
class MethodAssessment:
    name: str
    number: int
    feasible: bool
    confidence: str  # HIGH, MEDIUM, LOW
    reason: str
    prerequisites: str
    risk: str  # Detection risk


def assess_methods(portal: PortalInfo, probes: ProbeResults, has_tools: dict[str, bool] | None = None) -> list[MethodAssessment]:
    """Assess which bypass methods would work based on probe results.

    This is a READ-ONLY analysis. Nothing is exploited.
    """
    if has_tools is None:
        has_tools = _check_tools()

    methods: list[MethodAssessment] = []

    # 1. IPv6
    methods.append(MethodAssessment(
        name="IPv6 bypass", number=1,
        feasible=probes.ipv6.is_open,
        confidence="HIGH" if probes.ipv6.is_open else "N/A",
        reason=probes.ipv6.details or "IPv6 not available",
        prerequisites="None — just use IPv6",
        risk="None",
    ))

    # 2. HTTPS tunnel (chisel)
    https_open = probes.cloudflare.is_open or any(w.is_open for w in probes.whitelists)
    methods.append(MethodAssessment(
        name="HTTPS tunnel (chisel)", number=2,
        feasible=https_open and has_tools.get("chisel", False),
        confidence="HIGH" if https_open else "N/A",
        reason="HTTPS to Cloudflare reachable" if https_open else "HTTPS blocked pre-auth",
        prerequisites="chisel binary" + (" [INSTALLED]" if has_tools.get("chisel") else " [MISSING]"),
        risk="Very low — looks like normal HTTPS",
    ))

    # 3. CNA User-Agent spoof
    methods.append(MethodAssessment(
        name="CNA User-Agent spoof", number=3,
        feasible=True,  # Always worth trying
        confidence="LOW",
        reason="Always testable — some portals auto-approve Apple CNA requests",
        prerequisites="None",
        risk="None",
    ))

    # 4. JS-only bypass
    methods.append(MethodAssessment(
        name="JS-only enforcement bypass", number=4,
        feasible=True,
        confidence="LOW",
        reason="Worth testing — some portals enforce auth only in JavaScript",
        prerequisites="None",
        risk="None",
    ))

    # 5. HTTP CONNECT
    methods.append(MethodAssessment(
        name="HTTP CONNECT abuse", number=5,
        feasible=True,
        confidence="LOW",
        reason="Tests if portal proxy allows CONNECT tunneling",
        prerequisites="None",
        risk="Low",
    ))

    # 6-7. MAC clone
    from . import platform_mac
    arp = platform_mac.get_arp_table()
    gateway = platform_mac.get_gateway("en0")
    our_mac = platform_mac.get_current_mac("en0")
    candidates = [e for e in arp if e.interface == "en0" and e.ip != gateway
                  and not e.mac.startswith("ff:ff") and e.mac != our_mac and len(e.mac) >= 10]

    methods.append(MethodAssessment(
        name="MAC clone (idle device)", number=6,
        feasible=len(candidates) > 0,
        confidence="HIGH" if len(candidates) >= 3 else "MEDIUM" if candidates else "N/A",
        reason=f"{len(candidates)} candidate device(s) on network" if candidates else "No other devices found",
        prerequisites="sudo (for MAC change)",
        risk="Medium — duplicate MAC can disrupt target device",
    ))

    methods.append(MethodAssessment(
        name="MAC clone (any device)", number=7,
        feasible=len(candidates) > 0,
        confidence="HIGH" if len(candidates) >= 3 else "MEDIUM" if candidates else "N/A",
        reason=f"{len(candidates)} candidate(s)" if candidates else "No other devices",
        prerequisites="sudo",
        risk="Medium",
    ))

    # 8. DNS tunnel
    methods.append(MethodAssessment(
        name="DNS tunnel (iodine)", number=8,
        feasible=probes.dns.is_open and has_tools.get("iodine", False),
        confidence="HIGH" if probes.dns.is_open else "N/A",
        reason=probes.dns.details or "DNS blocked",
        prerequisites="iodine + VPS with domain" + (" [INSTALLED]" if has_tools.get("iodine") else " [MISSING]"),
        risk="Low-Medium — unusual DNS patterns",
    ))

    # 9. ICMP tunnel
    methods.append(MethodAssessment(
        name="ICMP tunnel (hans/ptunnel)", number=9,
        feasible=probes.icmp.is_open and has_tools.get("hans", False),
        confidence="HIGH" if probes.icmp.is_open else "N/A",
        reason=probes.icmp.details or "ICMP blocked",
        prerequisites="hans/ptunnel + VPS" + (" [INSTALLED]" if has_tools.get("hans") else " [MISSING]"),
        risk="Low — looks like ping traffic",
    ))

    # 10. VPN on port 53
    port53_open = any(p.port == 53 and p.is_open for p in probes.open_ports) or probes.dns.is_open
    methods.append(MethodAssessment(
        name="VPN on port 53", number=10,
        feasible=port53_open and has_tools.get("wg-quick", False),
        confidence="MEDIUM" if port53_open else "N/A",
        reason="UDP/53 reachable" if port53_open else "Port 53 blocked",
        prerequisites="WireGuard + VPS on port 53" + (" [INSTALLED]" if has_tools.get("wg-quick") else " [MISSING]"),
        risk="Low — traffic on expected port",
    ))

    # 11-15. Remaining
    open_wl = [w for w in probes.whitelists if w.is_open]
    methods.append(MethodAssessment(
        name="Whitelist domain abuse", number=11,
        feasible=len(open_wl) > 0,
        confidence="MEDIUM" if open_wl else "N/A",
        reason=f"{len(open_wl)} whitelisted domain(s) reachable" if open_wl else "No whitelists found",
        prerequisites="Tunnel endpoint on whitelisted domain",
        risk="Very low",
    ))

    methods.append(MethodAssessment(
        name="Session cookie replay", number=12,
        feasible=portal.is_captive,  # Only relevant if there's a portal
        confidence="LOW",
        reason="Requires HTTP (not HTTPS) portal cookies — decreasing in prevalence",
        prerequisites="Monitor mode WiFi adapter for passive sniffing",
        risk="Low — passive observation",
    ))

    methods.append(MethodAssessment(
        name="Portal admin default creds", number=13,
        feasible=portal.is_captive,
        confidence="LOW",
        reason=f"Portal vendor: {portal.vendor or 'unknown'}" if portal.is_captive else "No portal",
        prerequisites="None",
        risk="Medium — login attempts may be logged",
    ))

    methods.append(MethodAssessment(
        name="MAC rotate (fresh identity)", number=14,
        feasible=True,
        confidence="HIGH",
        reason="Always works — gives new device identity. Useful for time/quota reset post-auth.",
        prerequisites="sudo",
        risk="None",
    ))

    methods.append(MethodAssessment(
        name="DHCP rotate", number=15,
        feasible=True,
        confidence="LOW",
        reason="Release/renew for new IP. Rarely bypasses portal alone.",
        prerequisites="sudo",
        risk="None",
    ))

    # 16. QUIC tunnel
    methods.append(MethodAssessment(
        name="QUIC tunnel (Hysteria2)", number=16,
        feasible=probes.quic.is_open and has_tools.get("hysteria", False),
        confidence="HIGH" if probes.quic.is_open else "N/A",
        reason=probes.quic.details or "QUIC blocked",
        prerequisites="hysteria binary + server" + (" [INSTALLED]" if has_tools.get("hysteria") else " [MISSING]"),
        risk="Very low — looks like HTTP/3",
    ))

    # 17. CF Workers proxy
    methods.append(MethodAssessment(
        name="CF Workers proxy", number=17,
        feasible=https_open,
        confidence="MEDIUM" if https_open else "N/A",
        reason="Cloudflare reachable — Workers proxy possible" if https_open else "CF blocked",
        prerequisites="Deployed CF Worker (free tier)",
        risk="Very low — trusted CDN traffic",
    ))

    # 18. NTP tunnel
    methods.append(MethodAssessment(
        name="NTP tunnel", number=18,
        feasible=probes.ntp.is_open,
        confidence="HIGH" if probes.ntp.is_open else "N/A",
        reason=probes.ntp.details or "NTP blocked",
        prerequisites="ntpescape + VPS" + (" [INSTALLED]" if has_tools.get("ntpescape") else " [MISSING]"),
        risk="Very low — NTP is expected traffic",
    ))

    # 19. DoH tunnel
    methods.append(MethodAssessment(
        name="DoH tunnel", number=19,
        feasible=probes.doh.is_open and has_tools.get("cloudflared", False),
        confidence="MEDIUM" if probes.doh.is_open else "N/A",
        reason=probes.doh.details or "DoH blocked",
        prerequisites="cloudflared or dnscrypt-proxy" + (" [INSTALLED]" if has_tools.get("cloudflared") else " [MISSING]"),
        risk="Low — encrypted DNS to trusted providers",
    ))

    return methods


def _check_tools() -> dict[str, bool]:
    """Check which external tools are installed."""
    import shutil
    import os
    tools = ["chisel", "iodine", "hans", "hysteria", "ntpescape", "cloudflared",
             "dnscrypt-proxy", "hashcat", "hcxdumptool", "wg-quick", "aircrack-ng"]
    result = {}
    for t in tools:
        path = shutil.which(t)
        if not path:
            # Also check ~/bin/ and ~/.nowifi/bin/
            for extra in [os.path.expanduser(f"~/bin/{t}"), os.path.expanduser(f"~/.nowifi/bin/{t}")]:
                if os.path.isfile(extra) and os.access(extra, os.X_OK):
                    path = extra
                    break
        result[t] = path is not None
    return result


def print_diagnosis(
    portal: PortalInfo,
    probes: ProbeResults,
    methods: list[MethodAssessment],
    tools: dict[str, bool],
) -> None:
    """Print a comprehensive diagnosis report."""
    console = Console()
    console.print()

    # Portal info
    captive = "[bold red]YES[/bold red]" if portal.is_captive else "[bold green]NO[/bold green]"
    console.print(Panel(
        f"[bold]SSID:[/bold] {portal.ssid or 'N/A'}\n"
        f"[bold]Gateway:[/bold] {portal.gateway or 'N/A'}\n"
        f"[bold]Captive Portal:[/bold] {captive}\n"
        f"[bold]Type:[/bold] {portal.portal_type.value}\n"
        f"[bold]Vendor:[/bold] {portal.vendor or 'Unknown'}\n"
        f"[bold]Auth:[/bold] {', '.join(portal.auth_methods) or 'N/A'}",
        title="[bold cyan]nowifi — Network Diagnosis[/bold cyan]",
        border_style="cyan",
    ))

    # Protocol probes
    probe_table = Table(title="Protocol Analysis", border_style="blue")
    probe_table.add_column("Protocol", style="bold")
    probe_table.add_column("Status", justify="center")
    probe_table.add_column("Details")

    def _icon(v: bool) -> str:
        return "[green]OPEN[/green]" if v else "[red]CLOSED[/red]"

    probe_table.add_row("DNS (UDP/53)", _icon(probes.dns.is_open), probes.dns.details)
    probe_table.add_row("ICMP (ping)", _icon(probes.icmp.is_open), probes.icmp.details)
    probe_table.add_row("IPv6", _icon(probes.ipv6.is_open), probes.ipv6.details)
    probe_table.add_row("HTTPS (Cloudflare)", _icon(probes.cloudflare.is_open), probes.cloudflare.details)
    probe_table.add_row("QUIC (UDP/443)", _icon(probes.quic.is_open), probes.quic.details)
    probe_table.add_row("NTP (UDP/123)", _icon(probes.ntp.is_open), probes.ntp.details)
    probe_table.add_row("DoH (HTTPS)", _icon(probes.doh.is_open), probes.doh.details)

    for wl in probes.whitelists[:5]:
        probe_table.add_row(f"  {wl.domain}", _icon(wl.is_open), wl.details)

    open_ports = [p for p in probes.open_ports if p.is_open]
    if open_ports:
        probe_table.add_row("Open Ports", f"[green]{len(open_ports)}[/green]",
                           ", ".join(f"{p.port}/{p.service}" for p in open_ports))
    else:
        probe_table.add_row("Open Ports", "[red]0[/red]", "All scanned ports blocked")

    console.print(probe_table)
    console.print()

    # Method feasibility
    method_table = Table(title="Bypass Method Feasibility (READ-ONLY — nothing exploited)", border_style="yellow")
    method_table.add_column("#", justify="right", width=3)
    method_table.add_column("Method", style="bold")
    method_table.add_column("Feasible", justify="center")
    method_table.add_column("Confidence")
    method_table.add_column("Reason")
    method_table.add_column("Risk")

    feasible_count = 0
    for m in methods:
        if m.feasible:
            feasible_count += 1
            feas = "[bold green]YES[/bold green]"
            conf_color = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "cyan"}.get(m.confidence, "dim")
            conf = f"[{conf_color}]{m.confidence}[/{conf_color}]"
        else:
            feas = "[dim]no[/dim]"
            conf = "[dim]-[/dim]"
        method_table.add_row(str(m.number), m.name, feas, conf, m.reason, m.risk)

    console.print(method_table)
    console.print()

    # Tools
    tool_table = Table(title="External Tools", border_style="dim")
    tool_table.add_column("Tool")
    tool_table.add_column("Status", justify="center")

    for name, installed in sorted(tools.items()):
        status = "[green]installed[/green]" if installed else "[red]missing[/red]"
        tool_table.add_row(name, status)

    console.print(tool_table)
    console.print()

    # Summary
    if feasible_count > 0:
        console.print(Panel(
            f"[bold]{feasible_count}[/bold] of 19 bypass methods are feasible on this network.\n"
            f"Run [bold]sudo nowifi[/bold] to exploit the best one automatically.",
            title=f"[bold yellow]Assessment: {feasible_count} methods available[/bold yellow]",
            border_style="yellow",
        ))
    else:
        console.print(Panel(
            "[green]No bypass methods appear feasible. Portal is well-configured.[/green]",
            title="[bold green]Assessment: Secure[/bold green]",
            border_style="green",
        ))
    console.print()
