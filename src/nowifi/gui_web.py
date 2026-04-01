"""NiceGUI web dashboard for nowifi. Cross-platform, runs in browser.

Real-time dark-themed dashboard with live probe status, bypass feasibility,
tunnel monitoring, and background task execution.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from nicegui import ui

from . import __version__
from .detect import detect_portal, PortalInfo
from .diagnose import assess_methods, MethodAssessment, _check_tools
from .platform import get_gateway, get_wifi_info, get_current_mac
from .probe import ProbeResults
from .bypass import AuditConfig, BypassResult, run_bypasses
from .tunnel import TunnelHandle


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

@dataclass
class AppState:
    """Mutable state shared between UI timer and background threads."""
    portal: PortalInfo | None = None
    probes: ProbeResults | None = None
    bypasses: list[BypassResult] = field(default_factory=list)
    methods: list[MethodAssessment] = field(default_factory=list)
    status: str = "idle"  # idle | probing | bypassing | diagnosing | scanning | active | error
    active_method: str = ""
    active_tunnel: TunnelHandle | None = None
    socks_port: int = 0
    log_lines: list[str] = field(default_factory=list)
    # WiFi info cached for display
    wifi_ssid: str = ""
    wifi_bssid: str = ""
    wifi_channel: str = ""
    wifi_rssi: int = -99
    gateway_ip: str = ""
    current_mac: str = ""
    original_mac: str = ""
    # Incremental probe tracking (name -> "pending" | "running" | "open" | "closed")
    probe_status: dict[str, str] = field(default_factory=dict)
    # WiFi scan results
    scan_results: list[dict] = field(default_factory=list)


state = AppState()

# Status colors
STATUS_COLORS = {
    "idle": "#6b7280",
    "probing": "#f59e0b",
    "bypassing": "#8b5cf6",
    "diagnosing": "#3b82f6",
    "scanning": "#06b6d4",
    "active": "#22c55e",
    "error": "#ef4444",
}

# Probe display names and order
PROBE_NAMES = [
    ("dns", "DNS (UDP/53)"),
    ("icmp", "ICMP (ping)"),
    ("ipv6", "IPv6"),
    ("cloudflare", "HTTPS (Cloudflare)"),
    ("quic", "QUIC (UDP/443)"),
    ("ntp", "NTP (UDP/123)"),
    ("doh", "DoH (HTTPS)"),
    ("whitelists", "Whitelist domains"),
    ("ports", "Open ports"),
    ("tunnel_server", "Tunnel server"),
]


def _log(msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    state.log_lines.append(f"[{ts}] {msg}")
    if len(state.log_lines) > 300:
        state.log_lines = state.log_lines[-200:]


def _signal_bar(rssi: int) -> tuple[int, str]:
    """Convert RSSI dBm to 0-4 bar count and color."""
    if rssi >= -50:
        return 4, "#22c55e"
    if rssi >= -60:
        return 3, "#84cc16"
    if rssi >= -70:
        return 2, "#f59e0b"
    if rssi >= -80:
        return 1, "#ef4444"
    return 0, "#6b7280"


# ---------------------------------------------------------------------------
# Background task runners
# ---------------------------------------------------------------------------

def _bg_probe_only() -> None:
    """Probe-only background task with incremental status updates."""
    try:
        _gather_wifi_info()
        _log("Detecting portal...")
        state.portal = detect_portal("en0")
        wifi = get_wifi_info("en0")
        if state.portal and wifi:
            state.portal.ssid = wifi.ssid if wifi else ""
            state.portal.gateway = state.gateway_ip
        if state.portal:
            cap = "CAPTIVE" if state.portal.is_captive else "OPEN"
            _log(f"Portal: {cap} ({state.portal.portal_type.value})")

        _run_probes_incremental()
        state.status = "idle"
        _log("Probe complete.")
    except Exception as e:
        state.status = "error"
        _log(f"Error: {e}")


def _bg_diagnose() -> None:
    """Diagnose background task: probe + assess methods (read-only)."""
    try:
        _gather_wifi_info()
        _log("Detecting portal...")
        state.portal = detect_portal("en0")
        wifi = get_wifi_info("en0")
        if state.portal and wifi:
            state.portal.ssid = wifi.ssid if wifi else ""
            state.portal.gateway = state.gateway_ip
        if state.portal:
            cap = "CAPTIVE" if state.portal.is_captive else "OPEN"
            _log(f"Portal: {cap} ({state.portal.portal_type.value})")

        _run_probes_incremental()

        if state.portal and state.probes:
            _log("Assessing bypass methods (read-only)...")
            tools = _check_tools()
            state.methods = assess_methods(state.portal, state.probes, tools)
            feasible = sum(1 for m in state.methods if m.feasible)
            _log(f"Assessment: {feasible}/19 methods feasible")

        state.status = "idle"
        _log("Diagnosis complete.")
    except Exception as e:
        state.status = "error"
        _log(f"Error: {e}")


def _bg_full_audit() -> None:
    """Full audit: probe, diagnose, then attempt bypasses."""
    try:
        _gather_wifi_info()
        _log("Detecting portal...")
        state.portal = detect_portal("en0")
        wifi = get_wifi_info("en0")
        if state.portal and wifi:
            state.portal.ssid = wifi.ssid if wifi else ""
            state.portal.gateway = state.gateway_ip
        if state.portal:
            cap = "CAPTIVE" if state.portal.is_captive else "OPEN"
            _log(f"Portal: {cap} ({state.portal.portal_type.value})")

        _run_probes_incremental()

        # Assess methods for the diagnosis panel
        if state.portal and state.probes:
            tools = _check_tools()
            state.methods = assess_methods(state.portal, state.probes, tools)
            feasible = sum(1 for m in state.methods if m.feasible)
            _log(f"Assessment: {feasible}/19 methods feasible")

        if state.portal and state.portal.is_captive and state.probes:
            state.status = "bypassing"
            _log("Portal is captive. Attempting bypasses...")
            config = AuditConfig(interface="en0", stealth=False)
            state.bypasses = run_bypasses(state.probes, config)
            wins = [r for r in state.bypasses if r.success]
            if wins:
                best = wins[0]
                state.active_method = best.method.value
                state.status = "active"
                if best.tunnel_handle and best.tunnel_handle.active:
                    state.active_tunnel = best.tunnel_handle
                    state.socks_port = best.tunnel_handle.local_port
                _log(f"SUCCESS: {best.method.value} -- {best.impact}")
            else:
                state.status = "idle"
                _log("No bypass succeeded.")
        else:
            state.status = "idle"
            if state.portal and not state.portal.is_captive:
                _log("No captive portal detected. Network appears open.")
            else:
                _log("Probe complete.")
    except Exception as e:
        state.status = "error"
        _log(f"Error: {e}")


def _bg_scan_wifi() -> None:
    """Background WiFi scan using crack module."""
    try:
        from .crack import scan_targets
        _log("Scanning nearby WiFi networks...")
        targets = scan_targets(interface="en0", duration=5)
        state.scan_results = [
            {
                "ssid": t.ssid or "<hidden>",
                "bssid": t.bssid,
                "channel": t.channel,
                "security": t.security,
                "signal": t.signal,
                "clients": len(t.clients),
            }
            for t in targets
        ]
        _log(f"Found {len(targets)} network(s)")
        state.status = "idle"
    except Exception as e:
        state.status = "error"
        _log(f"Scan error: {e}")


def _gather_wifi_info() -> None:
    """Collect WiFi, gateway, MAC info into state."""
    wifi = get_wifi_info("en0")
    if wifi:
        state.wifi_ssid = wifi.ssid
        state.wifi_bssid = wifi.bssid
        state.wifi_channel = wifi.channel
        state.wifi_rssi = wifi.rssi
        _log(f"WiFi: {wifi.ssid} (RSSI: {wifi.rssi} dBm)")
    else:
        _log("WiFi: not connected")

    state.gateway_ip = get_gateway("en0")
    state.current_mac = get_current_mac("en0")
    if not state.original_mac:
        state.original_mac = state.current_mac
    _log(f"Gateway: {state.gateway_ip or 'unknown'}")


def _run_probes_incremental() -> None:
    """Run probes one by one, updating state.probe_status for each."""
    from .probe import (
        probe_dns, probe_icmp, probe_ipv6, probe_https,
        probe_whitelists, probe_ports, probe_quic, probe_ntp, probe_doh,
    )

    # Initialize all as pending
    for key, _ in PROBE_NAMES:
        state.probe_status[key] = "pending"

    results = ProbeResults()

    # DNS
    state.probe_status["dns"] = "running"
    _log("Probing DNS...")
    results.dns = probe_dns(stealth=False)
    state.probe_status["dns"] = "open" if results.dns.is_open else "closed"
    _log(f"  DNS: {'OPEN' if results.dns.is_open else 'CLOSED'} -- {results.dns.details}")

    # ICMP
    state.probe_status["icmp"] = "running"
    _log("Probing ICMP...")
    results.icmp = probe_icmp(stealth=False)
    state.probe_status["icmp"] = "open" if results.icmp.is_open else "closed"
    _log(f"  ICMP: {'OPEN' if results.icmp.is_open else 'CLOSED'} -- {results.icmp.details}")

    # IPv6
    state.probe_status["ipv6"] = "running"
    _log("Probing IPv6...")
    results.ipv6 = probe_ipv6(interface="en0")
    state.probe_status["ipv6"] = "open" if results.ipv6.is_open else "closed"
    _log(f"  IPv6: {'OPEN' if results.ipv6.is_open else 'CLOSED'} -- {results.ipv6.details}")

    # HTTPS (Cloudflare)
    state.probe_status["cloudflare"] = "running"
    _log("Probing HTTPS (Cloudflare)...")
    results.cloudflare = probe_https("https://1.1.1.1", label="Cloudflare")
    state.probe_status["cloudflare"] = "open" if results.cloudflare.is_open else "closed"
    _log(f"  HTTPS: {'OPEN' if results.cloudflare.is_open else 'CLOSED'} -- {results.cloudflare.details}")

    # QUIC
    state.probe_status["quic"] = "running"
    _log("Probing QUIC...")
    results.quic = probe_quic(stealth=False)
    state.probe_status["quic"] = "open" if results.quic.is_open else "closed"
    _log(f"  QUIC: {'OPEN' if results.quic.is_open else 'CLOSED'} -- {results.quic.details}")

    # NTP
    state.probe_status["ntp"] = "running"
    _log("Probing NTP...")
    results.ntp = probe_ntp(stealth=False)
    state.probe_status["ntp"] = "open" if results.ntp.is_open else "closed"
    _log(f"  NTP: {'OPEN' if results.ntp.is_open else 'CLOSED'} -- {results.ntp.details}")

    # DoH
    state.probe_status["doh"] = "running"
    _log("Probing DoH...")
    results.doh = probe_doh(stealth=False)
    state.probe_status["doh"] = "open" if results.doh.is_open else "closed"
    _log(f"  DoH: {'OPEN' if results.doh.is_open else 'CLOSED'} -- {results.doh.details}")

    # Whitelists
    state.probe_status["whitelists"] = "running"
    _log("Probing whitelist domains...")
    results.whitelists = probe_whitelists(stealth=False)
    open_wl = sum(1 for w in results.whitelists if w.is_open)
    state.probe_status["whitelists"] = "open" if open_wl > 0 else "closed"
    _log(f"  Whitelists: {open_wl}/{len(results.whitelists)} accessible")

    # Ports
    state.probe_status["ports"] = "running"
    _log("Probing outbound ports...")
    results.open_ports = probe_ports(stealth=False)
    open_p = sum(1 for p in results.open_ports if p.is_open)
    state.probe_status["ports"] = "open" if open_p > 0 else "closed"
    _log(f"  Ports: {open_p} open")

    # Tunnel server (skip if no server configured)
    state.probe_status["tunnel_server"] = "closed"

    state.probes = results
    _log("All probes complete.")


# ---------------------------------------------------------------------------
# UI construction
# ---------------------------------------------------------------------------

def create_ui() -> None:
    """Build the full real-time NiceGUI dashboard."""

    # -- Dark theme --
    ui.dark_mode().enable()
    ui.query("body").style("background-color: #0f172a; font-family: 'Inter', 'SF Mono', monospace;")
    ui.add_head_html("""
    <style>
        :root {
            --bg-card: #1e293b;
            --bg-surface: #0f172a;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent-green: #22c55e;
            --accent-red: #ef4444;
            --accent-yellow: #f59e0b;
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --accent-cyan: #06b6d4;
        }
        .q-card { background: var(--bg-card) !important; border: 1px solid #334155 !important; }
        .q-table { background: var(--bg-card) !important; }
        .q-table thead th { color: var(--text-secondary) !important; font-size: 0.75rem !important; text-transform: uppercase !important; letter-spacing: 0.05em !important; }
        .q-table tbody td { color: var(--text-primary) !important; border-color: #334155 !important; }
        .q-table tbody tr:hover { background: rgba(51, 65, 85, 0.5) !important; }
        .q-btn { text-transform: none !important; font-weight: 600 !important; }
        .status-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
        .signal-bar { width: 4px; border-radius: 1px; display: inline-block; margin-right: 2px; }
        .nowifi-log .q-textarea .q-field__native { color: #22c55e !important; font-family: 'SF Mono', 'Fira Code', monospace !important; font-size: 0.8rem !important; }
        .probe-badge { padding: 2px 10px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; display: inline-block; min-width: 70px; text-align: center; }
        .badge-open { background: rgba(34, 197, 94, 0.15); color: #22c55e; border: 1px solid rgba(34, 197, 94, 0.3); }
        .badge-closed { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge-running { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); animation: pulse 1.5s infinite; }
        .badge-pending { background: rgba(107, 114, 128, 0.15); color: #6b7280; border: 1px solid rgba(107, 114, 128, 0.3); }
        .badge-feasible { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
        .badge-infeasible { background: rgba(107, 114, 128, 0.15); color: #6b7280; }
        .conf-high { color: #22c55e; }
        .conf-medium { color: #f59e0b; }
        .conf-low { color: #06b6d4; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        @keyframes glow { 0%, 100% { box-shadow: 0 0 4px currentColor; } 50% { box-shadow: 0 0 12px currentColor; } }
    </style>
    """)

    # =========================================================================
    # HEADER
    # =========================================================================
    with ui.header().classes("items-center justify-between").style(
        "background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); "
        "border-bottom: 1px solid #334155; padding: 12px 24px;"
    ):
        with ui.row().classes("items-center gap-3 no-wrap"):
            # Logo / title
            ui.html('<span style="font-size:1.6rem; font-weight:800; letter-spacing:-0.02em; color:#f1f5f9;">no</span>'
                     '<span style="font-size:1.6rem; font-weight:800; letter-spacing:-0.02em; color:#22c55e;">wifi</span>')
            ui.label(f"v{__version__}").classes("text-xs").style("color: #64748b;")
            ui.label("|").style("color: #334155; font-size: 1.2rem;")
            ui.label("No WiFi? Now WiFi.").classes("text-sm").style("color: #94a3b8; font-style: italic;")

        # Live status indicator
        with ui.row().classes("items-center gap-2 no-wrap"):
            status_dot = ui.html('<span class="status-dot" style="background:#6b7280;"></span>')
            status_text = ui.label("Idle").classes("text-sm font-semibold").style("color: #94a3b8;")

    # =========================================================================
    # MAIN CONTENT
    # =========================================================================
    with ui.column().classes("w-full max-w-6xl mx-auto p-4 gap-4"):

        # --- ROW 1: Network Overview + Portal Status ---
        with ui.row().classes("w-full gap-4"):

            # --- Network Overview Card ---
            with ui.card().classes("flex-1").style("min-width: 320px;"):
                ui.label("Network Overview").classes("text-sm font-bold").style(
                    "color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;"
                )
                ui.separator().style("background: #334155;")

                with ui.column().classes("gap-2 mt-2"):
                    # SSID
                    with ui.row().classes("items-center gap-2 no-wrap"):
                        ui.label("SSID").classes("text-xs").style("color: #64748b; width: 80px;")
                        wifi_ssid_lbl = ui.label("--").classes("text-sm font-semibold").style("color: #f1f5f9;")
                    # BSSID
                    with ui.row().classes("items-center gap-2 no-wrap"):
                        ui.label("BSSID").classes("text-xs").style("color: #64748b; width: 80px;")
                        wifi_bssid_lbl = ui.label("--").classes("text-xs").style("color: #94a3b8; font-family: monospace;")
                    # Channel + Signal
                    with ui.row().classes("items-center gap-4 no-wrap"):
                        with ui.row().classes("items-center gap-2 no-wrap"):
                            ui.label("Channel").classes("text-xs").style("color: #64748b; width: 80px;")
                            wifi_channel_lbl = ui.label("--").classes("text-sm").style("color: #f1f5f9;")
                        with ui.row().classes("items-center gap-2 no-wrap"):
                            ui.label("Signal").classes("text-xs").style("color: #64748b;")
                            signal_container = ui.html("--").style("display: inline-flex; align-items: flex-end; gap: 2px;")
                    ui.separator().style("background: #1e293b;")
                    # Gateway
                    with ui.row().classes("items-center gap-2 no-wrap"):
                        ui.label("Gateway").classes("text-xs").style("color: #64748b; width: 80px;")
                        gateway_lbl = ui.label("--").classes("text-sm").style("color: #f1f5f9; font-family: monospace;")
                    # Current MAC
                    with ui.row().classes("items-center gap-2 no-wrap"):
                        ui.label("MAC").classes("text-xs").style("color: #64748b; width: 80px;")
                        mac_lbl = ui.label("--").classes("text-xs").style("color: #94a3b8; font-family: monospace;")
                    # Original MAC
                    with ui.row().classes("items-center gap-2 no-wrap"):
                        ui.label("Original").classes("text-xs").style("color: #64748b; width: 80px;")
                        orig_mac_lbl = ui.label("--").classes("text-xs").style("color: #64748b; font-family: monospace;")

            # --- Portal Status Card ---
            with ui.card().classes("flex-1").style("min-width: 280px;"):
                ui.label("Portal Status").classes("text-sm font-bold").style(
                    "color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;"
                )
                ui.separator().style("background: #334155;")

                with ui.column().classes("gap-2 mt-2"):
                    with ui.row().classes("items-center gap-2 no-wrap"):
                        ui.label("Detected").classes("text-xs").style("color: #64748b; width: 80px;")
                        portal_detected_lbl = ui.label("--").classes("text-sm font-semibold").style("color: #94a3b8;")
                    with ui.row().classes("items-center gap-2 no-wrap"):
                        ui.label("Type").classes("text-xs").style("color: #64748b; width: 80px;")
                        portal_type_lbl = ui.label("--").classes("text-sm").style("color: #94a3b8;")
                    with ui.row().classes("items-center gap-2 no-wrap"):
                        ui.label("Vendor").classes("text-xs").style("color: #64748b; width: 80px;")
                        portal_vendor_lbl = ui.label("--").classes("text-sm").style("color: #94a3b8;")
                    with ui.row().classes("items-center gap-2 no-wrap"):
                        ui.label("Auth").classes("text-xs").style("color: #64748b; width: 80px;")
                        portal_auth_lbl = ui.label("--").classes("text-sm").style("color: #94a3b8;")

        # --- ROW 2: Action Buttons ---
        with ui.card().classes("w-full"):
            with ui.row().classes("w-full items-center gap-3"):
                btn_audit = ui.button("Run Audit", icon="shield", color="#8b5cf6").props("size=lg unelevated")
                btn_diagnose = ui.button("Diagnose", icon="stethoscope", color="#3b82f6").props("unelevated")
                btn_probe = ui.button("Probe Only", icon="radar", color="#06b6d4").props("unelevated")
                btn_scan = ui.button("Scan WiFi", icon="wifi_find", color="#f59e0b").props("unelevated")
                ui.space()
                btn_reset = ui.button("Reset Network", icon="restart_alt", color="#ef4444").props("outline")

        # --- ROW 3: Probe Panel + Active Tunnel (side by side) ---
        with ui.row().classes("w-full gap-4"):

            # --- Protocol Probe Panel ---
            with ui.card().classes("flex-1").style("min-width: 420px;"):
                ui.label("Protocol Probes").classes("text-sm font-bold").style(
                    "color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;"
                )
                ui.separator().style("background: #334155;")

                # Build probe rows as a grid
                probe_badges: dict[str, ui.html] = {}
                probe_details: dict[str, ui.label] = {}

                with ui.column().classes("gap-1 mt-2 w-full"):
                    for key, name in PROBE_NAMES:
                        with ui.row().classes("items-center w-full no-wrap").style("padding: 4px 0;"):
                            ui.label(name).classes("text-sm").style("color: #e2e8f0; width: 180px; flex-shrink: 0;")
                            probe_badges[key] = ui.html(
                                '<span class="probe-badge badge-pending">PENDING</span>'
                            )
                            probe_details[key] = ui.label("").classes("text-xs ml-2").style(
                                "color: #64748b; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"
                            )

            # --- Active Tunnel Card ---
            with ui.card().classes("flex-none").style("width: 320px;"):
                ui.label("Active Tunnel").classes("text-sm font-bold").style(
                    "color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;"
                )
                ui.separator().style("background: #334155;")

                tunnel_status_lbl = ui.label("No active tunnel").classes("text-sm mt-2").style("color: #64748b;")
                tunnel_method_lbl = ui.label("").classes("text-sm font-semibold mt-1").style("color: #22c55e;")
                tunnel_proxy_lbl = ui.label("").classes("text-xs mt-1").style(
                    "color: #94a3b8; font-family: monospace;"
                )

                with ui.row().classes("gap-2 mt-3"):
                    btn_copy_proxy = ui.button("Copy proxy cmd", icon="content_copy", color="#334155").props(
                        "dense outline size=sm"
                    ).style("display: none;")
                    btn_stop_tunnel = ui.button("Stop tunnel", icon="stop_circle", color="#ef4444").props(
                        "dense outline size=sm"
                    ).style("display: none;")

        # --- ROW 4: Bypass Method Feasibility ---
        with ui.card().classes("w-full"):
            ui.label("Bypass Method Feasibility").classes("text-sm font-bold").style(
                "color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;"
            )
            ui.label("Read-only assessment -- nothing exploited").classes("text-xs").style("color: #64748b;")
            ui.separator().style("background: #334155;")

            method_table = ui.table(
                columns=[
                    {"name": "number", "label": "#", "field": "number", "align": "right", "sortable": True,
                     "style": "width: 40px"},
                    {"name": "name", "label": "Method", "field": "name", "align": "left", "sortable": True},
                    {"name": "feasible", "label": "Feasible", "field": "feasible", "align": "center"},
                    {"name": "confidence", "label": "Conf.", "field": "confidence", "align": "center"},
                    {"name": "reason", "label": "Reason", "field": "reason", "align": "left"},
                    {"name": "risk", "label": "Risk", "field": "risk", "align": "left"},
                ],
                rows=[],
                row_key="number",
            ).classes("w-full").style("font-size: 0.85rem;")
            method_table.add_slot(
                "body-cell-feasible",
                """
                <q-td :props="props">
                    <q-badge :color="props.row.feasible === 'YES' ? 'green' : 'grey'" :label="props.row.feasible" />
                </q-td>
                """,
            )
            method_table.add_slot(
                "body-cell-confidence",
                """
                <q-td :props="props">
                    <span :class="{
                        'conf-high': props.row.confidence === 'HIGH',
                        'conf-medium': props.row.confidence === 'MEDIUM',
                        'conf-low': props.row.confidence === 'LOW'
                    }" style="font-weight:600;">{{ props.row.confidence }}</span>
                </q-td>
                """,
            )

        # --- ROW 5: Bypass Results (shown when audit runs) ---
        with ui.card().classes("w-full"):
            ui.label("Bypass Attempts").classes("text-sm font-bold").style(
                "color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;"
            )
            ui.separator().style("background: #334155;")

            bypass_table = ui.table(
                columns=[
                    {"name": "technique", "label": "Technique", "field": "technique", "align": "left"},
                    {"name": "result", "label": "Result", "field": "result", "align": "center"},
                    {"name": "severity", "label": "Severity", "field": "severity", "align": "center"},
                    {"name": "impact", "label": "Impact / Details", "field": "impact", "align": "left"},
                ],
                rows=[],
                row_key="technique",
            ).classes("w-full").style("font-size: 0.85rem;")
            bypass_table.add_slot(
                "body-cell-result",
                """
                <q-td :props="props">
                    <q-badge :color="props.row.result === 'SUCCESS' ? 'green' : 'red-8'" :label="props.row.result" />
                </q-td>
                """,
            )
            bypass_table.add_slot(
                "body-cell-severity",
                """
                <q-td :props="props">
                    <q-badge
                        :color="{CRITICAL:'red',HIGH:'orange',MEDIUM:'yellow-8',LOW:'cyan',INFO:'grey'}[props.row.severity] || 'grey'"
                        :label="props.row.severity" />
                </q-td>
                """,
            )

        # --- ROW 6: WiFi Scan Results (shown after scan) ---
        with ui.card().classes("w-full"):
            ui.label("WiFi Networks").classes("text-sm font-bold").style(
                "color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;"
            )
            ui.separator().style("background: #334155;")

            scan_table = ui.table(
                columns=[
                    {"name": "ssid", "label": "SSID", "field": "ssid", "align": "left", "sortable": True},
                    {"name": "bssid", "label": "BSSID", "field": "bssid", "align": "left"},
                    {"name": "channel", "label": "Ch", "field": "channel", "align": "center", "sortable": True},
                    {"name": "security", "label": "Security", "field": "security", "align": "left"},
                    {"name": "signal", "label": "Signal", "field": "signal", "align": "center", "sortable": True},
                    {"name": "clients", "label": "Clients", "field": "clients", "align": "center"},
                ],
                rows=[],
                row_key="bssid",
            ).classes("w-full").style("font-size: 0.85rem;")

        # --- ROW 7: Live Log ---
        with ui.card().classes("w-full"):
            ui.label("Live Log").classes("text-sm font-bold").style(
                "color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;"
            )
            ui.separator().style("background: #334155;")
            log_area = ui.log(max_lines=80).classes("w-full nowifi-log").style(
                "height: 220px; background: #0a0f1a; border: 1px solid #1e293b; "
                "border-radius: 6px; font-family: 'SF Mono', 'Fira Code', monospace; "
                "font-size: 0.8rem; color: #22c55e;"
            )

    # =========================================================================
    # UI UPDATE TIMER
    # =========================================================================

    def _badge_html(status: str) -> str:
        labels = {"pending": "PENDING", "running": "PROBING...", "open": "OPEN", "closed": "CLOSED"}
        css = {"pending": "badge-pending", "running": "badge-running", "open": "badge-open", "closed": "badge-closed"}
        return f'<span class="probe-badge {css.get(status, "badge-pending")}">{labels.get(status, "?")}</span>'

    def _signal_html(rssi: int) -> str:
        bars, color = _signal_bar(rssi)
        heights = [6, 10, 14, 18]
        parts = []
        for i, h in enumerate(heights):
            c = color if i < bars else "#334155"
            parts.append(f'<span class="signal-bar" style="height:{h}px;background:{c};"></span>')
        return "".join(parts) + f' <span style="color:#94a3b8;font-size:0.75rem;">{rssi} dBm</span>'

    async def update_ui() -> None:
        # -- Status indicator --
        color = STATUS_COLORS.get(state.status, "#6b7280")
        status_dot.content = f'<span class="status-dot" style="background:{color};"></span>'
        status_text.text = state.status.upper()
        status_text.style(f"color: {color};")

        # -- Network info --
        if state.wifi_ssid:
            wifi_ssid_lbl.text = state.wifi_ssid
            wifi_bssid_lbl.text = state.wifi_bssid or "--"
            wifi_channel_lbl.text = state.wifi_channel or "--"
            signal_container.content = _signal_html(state.wifi_rssi)
        if state.gateway_ip:
            gateway_lbl.text = state.gateway_ip
        if state.current_mac:
            mac_lbl.text = state.current_mac
        if state.original_mac:
            orig_mac_lbl.text = state.original_mac
            if state.current_mac and state.current_mac != state.original_mac:
                mac_lbl.style("color: #f59e0b; font-family: monospace;")  # Highlight spoofed
            else:
                mac_lbl.style("color: #94a3b8; font-family: monospace;")

        # -- Portal info --
        if state.portal:
            p = state.portal
            if p.is_captive:
                portal_detected_lbl.text = "CAPTIVE PORTAL"
                portal_detected_lbl.style("color: #ef4444; font-weight: 700;")
            else:
                portal_detected_lbl.text = "No portal"
                portal_detected_lbl.style("color: #22c55e; font-weight: 700;")
            portal_type_lbl.text = p.portal_type.value
            portal_vendor_lbl.text = p.vendor or "Unknown"
            portal_auth_lbl.text = ", ".join(p.auth_methods) if p.auth_methods else "N/A"

        # -- Probe badges --
        for key, _ in PROBE_NAMES:
            ps = state.probe_status.get(key, "pending")
            probe_badges[key].content = _badge_html(ps)
            # Update details from probes
            if state.probes:
                pr = state.probes
                detail_map = {
                    "dns": pr.dns.details,
                    "icmp": pr.icmp.details,
                    "ipv6": pr.ipv6.details,
                    "cloudflare": pr.cloudflare.details,
                    "quic": pr.quic.details,
                    "ntp": pr.ntp.details,
                    "doh": pr.doh.details,
                    "whitelists": f"{sum(1 for w in pr.whitelists if w.is_open)}/{len(pr.whitelists)} accessible" if pr.whitelists else "",
                    "ports": f"{sum(1 for p in pr.open_ports if p.is_open)} open" if pr.open_ports else "",
                    "tunnel_server": "",
                }
                if key in detail_map:
                    probe_details[key].text = detail_map[key]

        # -- Method feasibility table --
        if state.methods:
            rows = []
            for m in state.methods:
                rows.append({
                    "number": m.number,
                    "name": m.name,
                    "feasible": "YES" if m.feasible else "no",
                    "confidence": m.confidence if m.feasible else "-",
                    "reason": m.reason,
                    "risk": m.risk,
                })
            method_table.rows = rows
            method_table.update()

        # -- Bypass results table --
        if state.bypasses:
            rows = []
            for r in state.bypasses:
                rows.append({
                    "technique": r.method.value,
                    "result": "SUCCESS" if r.success else "failed",
                    "severity": r.severity.value.upper() if r.success else "-",
                    "impact": r.impact if r.success else (r.details or ""),
                })
            bypass_table.rows = rows
            bypass_table.update()

        # -- WiFi scan results --
        if state.scan_results:
            scan_table.rows = state.scan_results
            scan_table.update()

        # -- Active tunnel --
        if state.status == "active" and state.active_method:
            tunnel_status_lbl.text = "Tunnel active"
            tunnel_status_lbl.style("color: #22c55e; font-weight: 600;")
            tunnel_method_lbl.text = state.active_method
            if state.socks_port:
                proxy_cmd = f"socks5://127.0.0.1:{state.socks_port}"
                tunnel_proxy_lbl.text = proxy_cmd
                btn_copy_proxy.style("display: inline-flex;")
                btn_stop_tunnel.style("display: inline-flex;")
            else:
                tunnel_proxy_lbl.text = "Direct tunnel (no SOCKS proxy)"
                btn_copy_proxy.style("display: none;")
                btn_stop_tunnel.style("display: inline-flex;")
        else:
            tunnel_status_lbl.text = "No active tunnel"
            tunnel_status_lbl.style("color: #64748b;")
            tunnel_method_lbl.text = ""
            tunnel_proxy_lbl.text = ""
            btn_copy_proxy.style("display: none;")
            btn_stop_tunnel.style("display: none;")

        # -- Push log lines --
        while state.log_lines:
            line = state.log_lines.pop(0)
            log_area.push(line)

        # -- Button enable/disable --
        is_busy = state.status not in ("idle", "error", "active")
        for btn in (btn_audit, btn_diagnose, btn_probe, btn_scan, btn_reset):
            if is_busy:
                btn.props("disable")
            else:
                btn.props(remove="disable")

    ui.timer(0.4, update_ui)

    # =========================================================================
    # ACTION HANDLERS
    # =========================================================================

    def _start_background(task_fn, new_status: str) -> None:
        if state.status not in ("idle", "error", "active"):
            ui.notify("Already running -- please wait", type="warning")
            return
        state.status = new_status
        # Reset relevant state
        state.probe_status.clear()
        threading.Thread(target=task_fn, daemon=True).start()

    btn_audit.on_click(lambda: _start_background(_bg_full_audit, "probing"))
    btn_diagnose.on_click(lambda: _start_background(_bg_diagnose, "diagnosing"))
    btn_probe.on_click(lambda: _start_background(_bg_probe_only, "probing"))
    btn_scan.on_click(lambda: _start_background(_bg_scan_wifi, "scanning"))

    def _do_reset() -> None:
        _log("Resetting network...")
        if state.active_tunnel:
            state.active_tunnel.stop()
            state.active_tunnel = None
            _log("Tunnel stopped.")
        state.active_method = ""
        state.socks_port = 0
        import subprocess
        try:
            subprocess.run(["nowifi", "reset"], capture_output=True, timeout=10)
        except Exception:
            pass
        state.status = "idle"
        _log("Network reset complete.")

    btn_reset.on_click(lambda: threading.Thread(target=_do_reset, daemon=True).start())

    def _stop_tunnel() -> None:
        if state.active_tunnel:
            state.active_tunnel.stop()
            state.active_tunnel = None
            _log("Tunnel stopped by user.")
        state.active_method = ""
        state.socks_port = 0
        state.status = "idle"

    btn_stop_tunnel.on_click(lambda: threading.Thread(target=_stop_tunnel, daemon=True).start())

    def _copy_proxy() -> None:
        if state.socks_port:
            cmd = f"export ALL_PROXY=socks5://127.0.0.1:{state.socks_port}"
            ui.run_javascript(f'navigator.clipboard.writeText({cmd!r})')
            ui.notify("Proxy command copied to clipboard", type="positive")

    btn_copy_proxy.on_click(_copy_proxy)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_dashboard(port: int = 8321) -> None:
    """Launch the web dashboard."""
    create_ui()
    ui.run(
        title="nowifi -- No WiFi? Now WiFi.",
        host="127.0.0.1",  # SECURITY: bind to localhost only -- never expose to network
        port=port,
        reload=False,
        show=True,
    )


if __name__ == "__main__":
    run_dashboard()
