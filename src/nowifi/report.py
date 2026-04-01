"""Reporting: terminal, markdown, and JSON output."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .bypass import BypassResult, Severity
from .detect import PortalInfo
from .probe import ProbeResults


def _severity_style(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "dim",
    }.get(severity, "dim")


def _bool_icon(val: bool) -> str:
    return "[green]OPEN[/green]" if val else "[red]CLOSED[/red]"


def _severity_icon(severity: Severity) -> str:
    icons = {
        Severity.CRITICAL: "[bold red]CRIT[/bold red]",
        Severity.HIGH: "[red]HIGH[/red]",
        Severity.MEDIUM: "[yellow]MED[/yellow]",
        Severity.LOW: "[cyan]LOW[/cyan]",
        Severity.INFO: "[dim]INFO[/dim]",
    }
    return icons.get(severity, "[dim]?[/dim]")


def print_terminal_report(
    portal_info: PortalInfo,
    probe_results: ProbeResults,
    bypass_results: list[BypassResult],
) -> None:
    """Print a rich terminal report."""
    console = Console()
    console.print()

    # Header
    vendor_str = portal_info.vendor or "Unknown"
    captive_str = "[bold red]YES[/bold red]" if portal_info.is_captive else "[bold green]NO[/bold green]"

    console.print(Panel(
        f"[bold]SSID:[/bold] {portal_info.ssid or 'N/A'}\n"
        f"[bold]Gateway:[/bold] {portal_info.gateway or 'N/A'}\n"
        f"[bold]Captive Portal:[/bold] {captive_str}\n"
        f"[bold]Portal Type:[/bold] {portal_info.portal_type.value}\n"
        f"[bold]Vendor:[/bold] {vendor_str}\n"
        f"[bold]Auth Methods:[/bold] {', '.join(portal_info.auth_methods) or 'N/A'}\n"
        f"[bold]Portal URL:[/bold] {portal_info.portal_url or 'N/A'}",
        title="[bold cyan]nowifi — WiFi Security Audit[/bold cyan]",
        border_style="cyan",
    ))

    # Probe Results
    probe_table = Table(title="Leak Enumeration", border_style="blue")
    probe_table.add_column("Protocol", style="bold")
    probe_table.add_column("Status", justify="center")
    probe_table.add_column("Details")

    probe_table.add_row("DNS (UDP/53)", _bool_icon(probe_results.dns.is_open), probe_results.dns.details)
    probe_table.add_row("ICMP (ping)", _bool_icon(probe_results.icmp.is_open), probe_results.icmp.details)
    probe_table.add_row("IPv6", _bool_icon(probe_results.ipv6.is_open), probe_results.ipv6.details)
    probe_table.add_row("HTTPS (Cloudflare)", _bool_icon(probe_results.cloudflare.is_open), probe_results.cloudflare.details)
    probe_table.add_row("QUIC (UDP/443)", _bool_icon(probe_results.quic.is_open), probe_results.quic.details)
    probe_table.add_row("NTP (UDP/123)", _bool_icon(probe_results.ntp.is_open), probe_results.ntp.details)
    probe_table.add_row("DoH (HTTPS)", _bool_icon(probe_results.doh.is_open), probe_results.doh.details)

    # Whitelisted domains
    for wl in probe_results.whitelists:
        probe_table.add_row(f"  {wl.domain}", _bool_icon(wl.is_open), wl.details)

    # Open ports
    open_ports = [p for p in probe_results.open_ports if p.is_open]
    if open_ports:
        ports_str = ", ".join(f"{p.port}/{p.service}" for p in open_ports)
        probe_table.add_row("Open Ports", f"[green]{len(open_ports)}[/green]", ports_str)
    else:
        probe_table.add_row("Open Ports", "[red]0[/red]", "All scanned ports blocked")

    console.print(probe_table)
    console.print()

    # Bypass Results
    bypass_table = Table(title="Bypass Attempts", border_style="red")
    bypass_table.add_column("Technique", style="bold")
    bypass_table.add_column("Result", justify="center")
    bypass_table.add_column("Severity", justify="center")
    bypass_table.add_column("Impact / Details")

    for r in bypass_results:
        result_str = "[bold green]SUCCESS[/bold green]" if r.success else "[dim]failed[/dim]"
        sev_str = _severity_icon(r.severity) if r.success else "[dim]-[/dim]"
        detail = r.impact if r.success else r.details
        bypass_table.add_row(r.method.value, result_str, sev_str, detail)

    console.print(bypass_table)
    console.print()

    # Findings summary
    successful = [r for r in bypass_results if r.success]
    if successful:
        console.print(Panel(
            "\n".join(
                f"[{_severity_style(r.severity)}]{r.severity.value.upper()}[/{_severity_style(r.severity)}]: "
                f"{r.method.value} — {r.impact}\n"
                f"  [dim]Remediation: {r.remediation}[/dim]"
                for r in successful
            ),
            title=f"[bold red]Findings ({len(successful)} vulnerabilities)[/bold red]",
            border_style="red",
        ))
    else:
        console.print(Panel(
            "[green]No bypass techniques succeeded. Portal appears well-configured.[/green]",
            title="[bold green]No Findings[/bold green]",
            border_style="green",
        ))

    # Active tunnels
    active = [r for r in bypass_results if r.tunnel_handle and r.tunnel_handle.active]
    if active:
        t = active[0]
        console.print(Panel(
            f"[bold green]Tunnel active:[/bold green] {t.method.value}\n"
            f"SOCKS5 proxy: [bold]localhost:{t.tunnel_handle.local_port}[/bold]\n"
            f"Use: [bold]export ALL_PROXY=socks5://127.0.0.1:{t.tunnel_handle.local_port}[/bold]",
            title="[bold green]Active Tunnel[/bold green]",
            border_style="green",
        ))

    console.print()


def generate_markdown_report(
    portal_info: PortalInfo,
    probe_results: ProbeResults,
    bypass_results: list[BypassResult],
) -> str:
    """Generate a markdown pentest report."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Captive Portal Security Assessment Report",
        "",
        f"**Date:** {ts}",
        f"**SSID:** {portal_info.ssid or 'N/A'}",
        f"**Gateway:** {portal_info.gateway or 'N/A'}",
        f"**Portal Vendor:** {portal_info.vendor or 'Unknown'}",
        f"**Portal Type:** {portal_info.portal_type.value}",
        "",
        "## Leak Enumeration",
        "",
        "| Protocol | Status | Details |",
        "|----------|--------|---------|",
        f"| DNS (UDP/53) | {'OPEN' if probe_results.dns.is_open else 'CLOSED'} | {probe_results.dns.details} |",
        f"| ICMP | {'OPEN' if probe_results.icmp.is_open else 'CLOSED'} | {probe_results.icmp.details} |",
        f"| IPv6 | {'OPEN' if probe_results.ipv6.is_open else 'CLOSED'} | {probe_results.ipv6.details} |",
        f"| HTTPS (CF) | {'OPEN' if probe_results.cloudflare.is_open else 'CLOSED'} | {probe_results.cloudflare.details} |",
        f"| QUIC (UDP/443) | {'OPEN' if probe_results.quic.is_open else 'CLOSED'} | {probe_results.quic.details} |",
        f"| NTP (UDP/123) | {'OPEN' if probe_results.ntp.is_open else 'CLOSED'} | {probe_results.ntp.details} |",
        f"| DoH (HTTPS) | {'OPEN' if probe_results.doh.is_open else 'CLOSED'} | {probe_results.doh.details} |",
    ]

    for wl in probe_results.whitelists:
        lines.append(f"| {wl.domain} | {'OPEN' if wl.is_open else 'CLOSED'} | {wl.details} |")

    lines += [
        "",
        "## Bypass Results",
        "",
        "| Technique | Result | Severity | Impact |",
        "|-----------|--------|----------|--------|",
    ]

    for r in bypass_results:
        result = "SUCCESS" if r.success else "failed"
        sev = r.severity.value.upper() if r.success else "-"
        detail = r.impact if r.success else r.details
        lines.append(f"| {r.method.value} | {result} | {sev} | {detail} |")

    successful = [r for r in bypass_results if r.success]
    if successful:
        lines += ["", "## Findings & Remediation", ""]
        for i, r in enumerate(successful, 1):
            lines += [
                f"### {i}. {r.method.value} ({r.severity.value.upper()})",
                "",
                f"**Impact:** {r.impact}",
                "",
                f"**Details:** {r.details}",
                "",
                f"**Remediation:** {r.remediation}",
                "",
            ]

    lines += [
        "---",
        "*Generated by nowifi v0.1.0*",
    ]

    return "\n".join(lines)


def generate_json_report(
    portal_info: PortalInfo,
    probe_results: ProbeResults,
    bypass_results: list[BypassResult],
) -> str:
    """Generate NDJSON report."""
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "portal": {
            "is_captive": portal_info.is_captive,
            "type": portal_info.portal_type.value,
            "vendor": portal_info.vendor,
            "ssid": portal_info.ssid,
            "gateway": portal_info.gateway,
            "url": portal_info.portal_url,
            "auth_methods": portal_info.auth_methods,
        },
        "probes": {
            "dns": {"open": probe_results.dns.is_open, "details": probe_results.dns.details},
            "icmp": {"open": probe_results.icmp.is_open, "details": probe_results.icmp.details},
            "ipv6": {"open": probe_results.ipv6.is_open, "details": probe_results.ipv6.details},
            "cloudflare": {"open": probe_results.cloudflare.is_open, "details": probe_results.cloudflare.details},
            "quic": {"open": probe_results.quic.is_open, "details": probe_results.quic.details},
            "ntp": {"open": probe_results.ntp.is_open, "details": probe_results.ntp.details},
            "doh": {"open": probe_results.doh.is_open, "details": probe_results.doh.details},
            "whitelists": [{"domain": w.domain, "open": w.is_open} for w in probe_results.whitelists],
            "open_ports": [{"port": p.port, "service": p.service} for p in probe_results.open_ports if p.is_open],
        },
        "bypasses": [
            {
                "method": r.method.value,
                "success": r.success,
                "severity": r.severity.value,
                "impact": r.impact,
                "details": r.details,
                "remediation": r.remediation,
            }
            for r in bypass_results
        ],
    }
    return json.dumps(report, indent=2)
