"""CLI entry point for nowifi.

Default command: just run `sudo nowifi` — it does everything automatically.
"""

from __future__ import annotations

import re
import socket
import subprocess
import sys
from urllib.parse import urlparse

import click
from rich.console import Console

from . import __version__
from .bypass import AuditConfig, run_bypasses
from .detect import detect_portal
from . import platform as platform_mac
from .platform import StateGuard, get_gateway, get_wifi_info
from .probe import probe_all
from .report import print_terminal_report

console = Console()

DEFAULT_TUNNEL = "https://spark.raxor.ai"

# --- Input validation ---

_IFACE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9]{0,15}$")
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")


def _validate_interface(value: str) -> str:
    """Validate network interface name (e.g., en0, en1, utun0)."""
    if not _IFACE_RE.match(value):
        raise click.BadParameter(f"Invalid interface name: {value!r}. Expected format: en0, en1, utun0, etc.")
    return value


def _validate_url(value: str, param_name: str) -> str:
    """Validate URL format (must be http:// or https://)."""
    if not value:
        return value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise click.BadParameter(f"Invalid URL for {param_name}: {value!r}. Must start with http:// or https://")
    if not parsed.hostname:
        raise click.BadParameter(f"Invalid URL for {param_name}: {value!r}. Missing hostname.")
    return value


def _validate_ip(value: str, param_name: str) -> str:
    """Validate IPv4 address format."""
    if not value:
        return value
    if not _IP_RE.match(value):
        raise click.BadParameter(f"Invalid IP address for {param_name}: {value!r}. Expected format: 1.2.3.4")
    # Verify each octet is 0-255
    octets = value.split(".")
    if any(int(o) > 255 for o in octets):
        raise click.BadParameter(f"Invalid IP address for {param_name}: {value!r}. Octets must be 0-255.")
    return value


def _validate_domain(value: str, param_name: str) -> str:
    """Validate domain name format."""
    if not value:
        return value
    if len(value) > 253:
        raise click.BadParameter(f"Domain too long for {param_name}: {value!r}.")
    if not _DOMAIN_RE.match(value):
        raise click.BadParameter(f"Invalid domain for {param_name}: {value!r}.")
    return value


def _validate_server_address(value: str, param_name: str) -> str:
    """Validate server address (IP, IP:port, hostname, or hostname:port)."""
    if not value:
        return value
    # Strip port if present
    host = value.rsplit(":", 1)[0] if ":" in value and not value.startswith("[") else value
    # Accept IP or domain
    if _IP_RE.match(host):
        _validate_ip(host, param_name)
    elif not _DOMAIN_RE.match(host):
        raise click.BadParameter(f"Invalid server address for {param_name}: {value!r}.")
    return value


def _validate_port(value: int) -> int:
    """Validate TCP/UDP port number."""
    if not (1 <= value <= 65535):
        raise click.BadParameter(f"Port must be 1-65535, got {value}.")
    return value


def _status(val: bool) -> str:
    return "[green]OPEN[/green]" if val else "[red]CLOSED[/red]"


def _run_full_audit(interface: str, tunnel_server: str, dns_domain: str, icmp_server: str,
                    cf_workers: str, quic_server: str, ntp_server: str,
                    stealth: bool, probe_only: bool):
    """Core audit logic — shared between `nowifi` (default) and `nowifi audit`."""
    # Validate all inputs before any privileged operations
    interface = _validate_interface(interface)
    tunnel_server = _validate_url(tunnel_server, "--tunnel-server")
    dns_domain = _validate_domain(dns_domain, "--dns-domain")
    icmp_server = _validate_ip(icmp_server, "--icmp-server")
    cf_workers = _validate_url(cf_workers, "--cf-workers")
    quic_server = _validate_server_address(quic_server, "--quic-server")
    ntp_server = _validate_ip(ntp_server, "--ntp-server")

    console.print(f"\n[bold cyan]nowifi v{__version__}[/bold cyan] — No WiFi? Now WiFi.\n")

    # --- Phase 1: WiFi info ---
    console.print("[bold]1. WiFi[/bold]", highlight=False, end="  ")
    wifi = get_wifi_info(interface)
    if not wifi:
        console.print(f"[red]Not connected on {interface}[/red]")
        sys.exit(1)
    gateway = get_gateway(interface)
    console.print(f"[cyan]{wifi.ssid}[/cyan]  gw:{gateway}")

    # --- Phase 2: Portal detection ---
    console.print("[bold]2. Portal[/bold]", highlight=False, end="  ")
    portal = detect_portal(interface)
    portal.ssid = wifi.ssid
    portal.gateway = gateway

    if portal.is_captive:
        vendor = f" ({portal.vendor})" if portal.vendor else ""
        console.print(f"[red]CAPTIVE[/red] {portal.portal_type.value}{vendor}")
    else:
        console.print("[green]OPEN[/green] — no portal detected")

    # --- Phase 3: Leak enumeration ---
    console.print("[bold]3. Probing[/bold]", highlight=False, end="  ")

    # Extract tunnel server IP from URL for direct port scanning
    tunnel_ip = ""
    if tunnel_server:
        try:
            from urllib.parse import urlparse
            host = urlparse(tunnel_server).hostname or ""
            if host:
                tunnel_ip = socket.gethostbyname(host)
        except Exception:
            pass

    probes = probe_all(interface=interface, stealth=stealth, tunnel_server_ip=tunnel_ip)

    open_ports = [p for p in probes.open_ports if p.is_open]
    open_wl = [w for w in probes.whitelists if w.is_open]
    srv_ports = [p for p in probes.tunnel_server_ports if p.is_open]
    console.print(
        f"DNS:{_status(probes.dns.is_open)} ICMP:{_status(probes.icmp.is_open)} "
        f"IPv6:{_status(probes.ipv6.is_open)} CF:{_status(probes.cloudflare.is_open)} "
        f"QUIC:{_status(probes.quic.is_open)} NTP:{_status(probes.ntp.is_open)} "
        f"DoH:{_status(probes.doh.is_open)} "
        f"ports:{len(open_ports)} wl:{len(open_wl)}"
        + (f" srv:{len(srv_ports)}" if srv_ports else "")
    )

    # --- Phase 4: Bypass (if captive and not probe-only) ---
    bypass_results = []
    if portal.is_captive and not probe_only:
        console.print("[bold]4. Bypass[/bold]", highlight=False, end="  ")

        config = AuditConfig(
            interface=interface,
            tunnel_server=tunnel_server,
            dns_tunnel_domain=dns_domain,
            icmp_tunnel_server=icmp_server,
            cf_workers_url=cf_workers,
            quic_server=quic_server,
            ntp_server=ntp_server,
            stealth=stealth,
        )

        with StateGuard(interface) as guard:
            bypass_results = run_bypasses(probes, config)

            # Register any active tunnels with StateGuard for cleanup
            for r in bypass_results:
                if r.tunnel_handle and r.tunnel_handle.active:
                    guard.register_tunnel(r.tunnel_handle)

            wins = [r for r in bypass_results if r.success]
            if wins:
                console.print(f"[bold green]{len(wins)} bypass(es) succeeded[/bold green]")
                console.print(f"  Method: [bold]{wins[0].method.value}[/bold]")
            else:
                console.print("[yellow]no bypass succeeded[/yellow]")

            # Report
            console.print()
            print_terminal_report(portal, probes, bypass_results)

            # Keep tunnel alive if one is active
            active = [r for r in bypass_results if r.tunnel_handle and r.tunnel_handle.active]
            if active:
                t = active[0]
                console.print(f"\n[bold green]BYPASS ACTIVE[/bold green] — {t.method.value}")
                if t.tunnel_handle.local_port:
                    console.print("  System SOCKS proxy auto-configured — browser works now.")
                console.print("  [dim]Ctrl+C to stop and restore all network settings.[/dim]\n")
                try:
                    t.tunnel_handle.process.wait()
                except KeyboardInterrupt:
                    console.print("\n[yellow]Restoring network state...[/yellow]")
            elif wins:
                # Non-tunnel bypass (MAC clone, IPv6, etc.) — internet works directly
                console.print(f"\n[bold green]INTERNET ACTIVE[/bold green] — {wins[0].method.value}")
                console.print("  Browser works now. Ctrl+C to restore original network state.\n")
                try:
                    import time as _t
                    while True:
                        _t.sleep(1)
                except KeyboardInterrupt:
                    console.print("\n[yellow]Restoring network state...[/yellow]")
            # StateGuard restores MAC, proxy, DNS, tunnels on exit
    else:
        if not portal.is_captive:
            console.print("[bold]4. Bypass[/bold]  [dim]skipped (no portal)[/dim]")
        console.print()
        print_terminal_report(portal, probes, [])


@click.group(invoke_without_command=True)
@click.version_option(__version__)
@click.option("--interface", "-i", default="en0", help="WiFi interface")
@click.option("--tunnel-server", "-t", default=DEFAULT_TUNNEL, help="Chisel tunnel endpoint")
@click.option("--dns-domain", "-d", default="", help="DNS tunnel domain")
@click.option("--icmp-server", default="", help="ICMP tunnel server IP")
@click.option("--cf-workers", default="", help="Cloudflare Workers proxy URL")
@click.option("--quic-server", default="", help="QUIC/Hysteria2 server address")
@click.option("--ntp-server", default="", help="NTP tunnel server IP")
@click.option("--stealth/--fast", default=True, help="Stealth (randomized timing) vs fast")
@click.option("--probe-only", "-p", is_flag=True, help="Probe only, don't exploit")
@click.pass_context
def main(ctx, interface, tunnel_server, dns_domain, icmp_server, cf_workers, quic_server, ntp_server, stealth, probe_only):
    """nowifi — No WiFi? Now WiFi.

    \b
    Just run:  sudo nowifi
    That's it. Detects portal, probes leaks, tries 19 bypass techniques
    most-powerful-first, stops on first success. Browser works immediately.
    Ctrl+C restores all network settings.

    \b
    19 techniques (in order):
      1. IPv6 bypass       8. DNS tunnel     15. DHCP rotate
      2. HTTPS tunnel      9. ICMP tunnel    16. QUIC tunnel
      3. CNA UA spoof     10. VPN port 53    17. CF Workers
      4. JS-only bypass   11. Whitelist      18. NTP tunnel
      5. HTTP CONNECT     12. Session cookie 19. DoH tunnel
      6. MAC clone idle   13. Portal creds
      7. MAC clone any    14. MAC rotate
    """
    if ctx.invoked_subcommand is None:
        _run_full_audit(interface, tunnel_server, dns_domain, icmp_server, cf_workers, quic_server, ntp_server, stealth, probe_only)


@main.command()
@click.option("--interface", "-i", default="en0")
@click.option("--tunnel-server", "-t", default=DEFAULT_TUNNEL)
@click.option("--dns-domain", "-d", default="")
@click.option("--icmp-server", default="")
@click.option("--cf-workers", default="", help="Cloudflare Workers proxy URL")
@click.option("--quic-server", default="", help="QUIC/Hysteria2 server address")
@click.option("--ntp-server", default="", help="NTP tunnel server IP")
@click.option("--stealth/--fast", default=True)
@click.option("--probe-only", "-p", is_flag=True)
def audit(interface, tunnel_server, dns_domain, icmp_server, cf_workers, quic_server, ntp_server, stealth, probe_only):
    """Run full audit (same as bare `nowifi`)."""
    _run_full_audit(interface, tunnel_server, dns_domain, icmp_server, cf_workers, quic_server, ntp_server, stealth, probe_only)


@main.command()
@click.option("--interface", "-i", default="en0", help="WiFi interface")
@click.option("--stealth/--fast", default=True)
@click.option("--report", "-r", "report_format", type=click.Choice(["terminal", "markdown", "json"]), default="terminal")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write report to file")
def diagnose(interface, stealth, report_format, output):
    """Diagnose network security without exploiting anything.

    \b
    Scans all protocols, detects portal, checks which of the 19 bypass
    methods WOULD work — without changing any network settings.
    No MAC changes. No tunnels. No proxy. Pure read-only assessment.
    """
    interface = _validate_interface(interface)
    console.print(f"\n[bold cyan]nowifi v{__version__}[/bold cyan] — Diagnosis Mode (read-only)\n")

    wifi = get_wifi_info(interface)
    if not wifi:
        console.print(f"[red]Not connected on {interface}[/red]")
        sys.exit(1)
    gateway = get_gateway(interface)
    console.print(f"  SSID: [cyan]{wifi.ssid}[/cyan]  Gateway: {gateway}")

    console.print("  Detecting portal...", highlight=False)
    from .detect import detect_portal as _detect
    portal = _detect(interface)
    portal.ssid = wifi.ssid
    portal.gateway = gateway

    console.print("  Probing protocols...", highlight=False)
    probes = probe_all(interface=interface, stealth=stealth)

    console.print("  Assessing bypass methods...\n", highlight=False)
    from .diagnose import assess_methods, print_diagnosis, _check_tools
    tools = _check_tools()
    methods = assess_methods(portal, probes, tools)

    if report_format == "terminal":
        print_diagnosis(portal, probes, methods, tools)
    elif report_format == "markdown":
        from datetime import datetime, timezone
        feasible = sum(1 for m in methods if m.feasible)
        lines = [
            "# nowifi Network Diagnosis Report",
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"**SSID:** {portal.ssid}  **Gateway:** {portal.gateway}",
            f"**Portal:** {'YES' if portal.is_captive else 'NO'} ({portal.portal_type.value})",
            "", "## Bypass Feasibility", "",
            "| # | Method | Feasible | Confidence | Reason |",
            "|---|--------|----------|------------|--------|",
        ]
        for m in methods:
            lines.append(f"| {m.number} | {m.name} | {'YES' if m.feasible else 'no'} | {m.confidence if m.feasible else '-'} | {m.reason} |")
        lines += ["", f"**{feasible}/19 methods feasible.**"]
        md = "\n".join(lines)
        if output:
            with open(output, "w") as f:
                f.write(md)
            console.print(f"Report written to {output}")
        else:
            console.print(md)
    elif report_format == "json":
        import json
        data = {
            "portal": {"captive": portal.is_captive, "type": portal.portal_type.value, "vendor": portal.vendor},
            "methods": [{"name": m.name, "feasible": m.feasible, "confidence": m.confidence, "reason": m.reason} for m in methods],
            "tools": tools,
        }
        js = json.dumps(data, indent=2)
        if output:
            with open(output, "w") as f:
                f.write(js)
        else:
            console.print(js)


@main.command()
@click.option("--port", default=8321, help="Dashboard port")
def ui(port):
    """Launch web dashboard in browser (cross-platform GUI)."""
    port = _validate_port(port)
    from .gui_web import run_dashboard
    run_dashboard(port=port)


@main.command()
def menubar():
    """Launch macOS menubar app (background shield icon)."""
    from .gui_menubar import run_menubar
    run_menubar()


@main.command()
@click.option("--interface", "-i", default="en0", help="WiFi interface")
def reset(interface):
    """Reset network to clean state after a crash or forced kill.

    \b
    Run this if nowifi was killed (kill -9, power loss, crash) and your
    network is broken. It undoes everything nowifi might have changed:
      - Restores hardware MAC address
      - Removes system SOCKS proxy
      - Kills orphaned tunnel processes (chisel, iodine, hans)
      - Flushes DNS cache
      - Renews DHCP lease
      - Turns WiFi off and back on (full reset)
    """
    interface = _validate_interface(interface)
    console.print("\n[bold cyan]nowifi[/bold cyan] — Network Reset\n")

    import os
    import signal as sig

    # 1. Kill orphaned tunnel processes
    for proc_name in ["chisel", "iodine", "iodined", "hans", "ptunnel", "wstunnel", "hysteria", "ntpescape", "dnscrypt-proxy"]:
        try:
            result = subprocess.run(
                ["pgrep", "-f", proc_name], capture_output=True, text=True, timeout=3,
            )
            pids = result.stdout.strip().splitlines()
            for pid in pids:
                pid = pid.strip()
                if pid and pid != str(os.getpid()):
                    try:
                        os.kill(int(pid), sig.SIGTERM)
                        console.print(f"  Killed {proc_name} (pid {pid})")
                    except (ProcessLookupError, PermissionError):
                        pass
        except Exception:
            pass

    # 2. Remove system SOCKS proxy
    from .bypass import clear_system_socks_proxy
    clear_system_socks_proxy(interface)
    console.print("  SOCKS proxy disabled")

    # 3. Restore hardware MAC (read from system_profiler if available)
    current_mac = platform_mac.get_current_mac(interface)
    # Try to get the real hardware MAC from system_profiler
    hw_mac = _get_hardware_mac(interface)
    if hw_mac and current_mac and hw_mac.lower() != current_mac.lower():
        platform_mac.set_mac(interface, hw_mac)
        console.print(f"  MAC restored: {current_mac} -> {hw_mac}")
    else:
        console.print(f"  MAC unchanged: {current_mac}")

    # 4. Flush DNS
    platform_mac.flush_dns()
    console.print("  DNS cache flushed")

    # 5. Full WiFi power cycle (most reliable reset)
    console.print("  WiFi power cycling...")
    platform_mac.disconnect_wifi(interface)
    import time
    time.sleep(2)
    platform_mac.connect_wifi(interface)
    time.sleep(3)

    # 6. Renew DHCP
    platform_mac.renew_dhcp(interface)
    console.print("  DHCP renewed")

    # 7. Remove any WireGuard tunnel we might have started
    import shutil
    if shutil.which("wg-quick"):
        try:
            subprocess.run(["sudo", "wg-quick", "down", "wg-nowifi"], capture_output=True, timeout=5)
        except Exception:
            pass

    console.print("\n[bold green]Network reset complete.[/bold green] Try browsing now.\n")


@main.command()
@click.option("--download", "-d", is_flag=True, help="Auto-download missing tools that support it")
def tools(download):
    """List required external tools and their install status."""
    from .toolchain import list_tools, download_tool

    tool_status = list_tools()

    console.print("\n[bold cyan]nowifi[/bold cyan] — External Tools\n")

    for name, info in sorted(tool_status.items()):
        if info["installed"]:
            status = f"[green]installed[/green]  {info['path']}"
        elif info["downloadable"]:
            if download:
                console.print(f"  [yellow]downloading {name}...[/yellow]", end="")
                path = download_tool(name)
                if path:
                    status = f"[green]downloaded[/green]  {path}"
                else:
                    status = "[red]download failed[/red]"
            else:
                status = "[yellow]missing[/yellow] (auto-downloadable: nowifi tools -d)"
        else:
            hint = info.get("install_hint", "")
            status = f"[red]missing[/red]  install: {hint}" if hint else "[red]missing[/red]"

        desc = f"  [dim]{info['description']}[/dim]" if info.get("description") else ""
        console.print(f"  {name:<20} {status}{desc}")

    console.print()


@main.command()
@click.option("--interface", "-i", default="en0", help="WiFi interface (monitor-capable for capture)")
@click.option("--target", "-t", default="", help="Target SSID (empty = scan and pick strongest)")
@click.option("--timeout", default=300, help="Max time for capture phase (seconds)")
@click.option("--wordlist", "-w", default="", help="Path to wordlist file")
@click.option("--scan-only", is_flag=True, help="Only scan for targets, don't crack")
def crack(interface, target, timeout, wordlist, scan_only):
    """Crack WPA/WPA2 passwords (PMKID + handshake capture + hashcat).

    \b
    Pipeline (ordered by effectiveness):
      1. PMKID capture     -- client-less, ~60% of APs vulnerable
      2. Handshake capture -- deauth a client, capture 4-way handshake
      3. Hashcat crack     -- GPU-accelerated dictionary/brute-force
      4. Aircrack-ng       -- CPU fallback if hashcat unavailable

    \b
    On macOS, monitor mode requires an external USB WiFi adapter
    (e.g., Alfa AWUS036ACH). The built-in card does not support it.

    \b
    Examples:
      sudo nowifi crack                           # Scan + crack strongest WPA network
      sudo nowifi crack -t "MyWiFi"               # Target a specific SSID
      sudo nowifi crack --scan-only               # Just scan, don't attack
      sudo nowifi crack -w ~/wordlists/rockyou.txt  # Use specific wordlist
    """
    interface = _validate_interface(interface)
    if wordlist and not wordlist.strip():
        wordlist = ""

    console.print(f"\n[bold cyan]nowifi v{__version__}[/bold cyan] — WPA Cracking\n")

    from .crack import scan_targets, run_crack, find_wordlists

    # --- Scan phase ---
    console.print("[bold]1. Scanning[/bold]", highlight=False, end="  ")
    targets = scan_targets(interface)

    if not targets:
        console.print("[red]No WiFi networks found[/red]")
        console.print("  Check that WiFi is enabled and interface is correct.")
        sys.exit(1)

    wpa_targets = [t for t in targets if "wpa" in t.security.lower()]
    console.print(f"Found [cyan]{len(targets)}[/cyan] networks ({len(wpa_targets)} WPA/WPA2)")

    # Show target list
    from rich.table import Table
    table = Table(border_style="blue", show_lines=False)
    table.add_column("#", style="dim", width=3)
    table.add_column("SSID", style="bold")
    table.add_column("BSSID", style="dim")
    table.add_column("CH", justify="right")
    table.add_column("Signal", justify="right")
    table.add_column("Security")

    for i, t in enumerate(targets[:20], 1):
        signal_color = "green" if t.signal > -60 else "yellow" if t.signal > -75 else "red"
        table.add_row(
            str(i), t.ssid, t.bssid, str(t.channel),
            f"[{signal_color}]{t.signal} dBm[/{signal_color}]",
            t.security,
        )

    console.print(table)

    if scan_only:
        wordlists = find_wordlists()
        if wordlists:
            console.print(f"\n[dim]Available wordlists: {', '.join(wordlists[:3])}[/dim]")
        else:
            console.print("\n[dim]No wordlists found. Install rockyou.txt or use --wordlist[/dim]")
        console.print()
        return

    # --- Crack phase ---
    console.print("\n[bold]2. Cracking[/bold]", highlight=False)
    if target:
        console.print(f"  Target: [cyan]{target}[/cyan]")
    else:
        selected = wpa_targets[0] if wpa_targets else targets[0]
        console.print(f"  Target: [cyan]{selected.ssid}[/cyan] ({selected.bssid}, {selected.signal} dBm)")

    if wordlist:
        console.print(f"  Wordlist: {wordlist}")
    else:
        wordlists = find_wordlists()
        if wordlists:
            console.print(f"  Wordlist: {wordlists[0]} (auto-detected)")
        else:
            console.print("  [yellow]No wordlist found -- hashcat brute-force only[/yellow]")

    console.print()
    results = run_crack(
        interface=interface,
        target_ssid=target,
        timeout=timeout,
        wordlist=wordlist,
    )

    # --- Results ---
    console.print("\n[bold]3. Results[/bold]")

    from rich.panel import Panel

    cracked = [r for r in results if r.success and r.password]
    captures = [r for r in results if r.success and r.capture_file and not r.password]

    if cracked:
        pw = cracked[0]
        console.print(Panel(
            f"[bold green]PASSWORD FOUND[/bold green]\n\n"
            f"  [bold]{pw.password}[/bold]\n\n"
            f"  Method: {pw.method.value}\n"
            f"  Time: {pw.time_elapsed:.1f}s",
            title="[bold green]Cracked[/bold green]",
            border_style="green",
        ))
    elif captures:
        cap = captures[0]
        console.print(Panel(
            f"[yellow]Capture successful but password not cracked[/yellow]\n\n"
            f"  Method: {cap.method.value}\n"
            f"  File: {cap.capture_file}\n"
            f"  {cap.details}\n\n"
            f"  Try a larger wordlist:\n"
            f"  [bold]hashcat -m 22000 {cap.capture_file} /path/to/wordlist.txt[/bold]",
            title="[yellow]Captured[/yellow]",
            border_style="yellow",
        ))
    else:
        console.print(Panel(
            "[red]No password cracked and no captures obtained.[/red]\n\n"
            + "\n".join(f"  {r.method.value}: {r.details}" for r in results),
            title="[red]Failed[/red]",
            border_style="red",
        ))

    # Show all steps
    console.print()
    step_table = Table(title="Crack Pipeline", border_style="blue")
    step_table.add_column("Step", style="bold")
    step_table.add_column("Result", justify="center")
    step_table.add_column("Time", justify="right")
    step_table.add_column("Details")

    for r in results:
        result_str = "[bold green]OK[/bold green]" if r.success else "[dim]fail[/dim]"
        time_str = f"{r.time_elapsed:.1f}s" if r.time_elapsed > 0 else "-"
        detail = r.password if r.password else r.details[:80]
        step_table.add_row(r.method.value, result_str, time_str, detail)

    console.print(step_table)
    console.print()


def _get_hardware_mac(interface: str) -> str:
    """Get the real hardware MAC address (not the spoofed one)."""
    try:
        result = subprocess.run(
            ["networksetup", "-getmacaddress", interface],
            capture_output=True, text=True, timeout=5,
        )
        import re
        m = re.search(r"([0-9a-fA-F:]{17})", result.stdout)
        return m.group(1).lower() if m else ""
    except Exception:
        return ""
