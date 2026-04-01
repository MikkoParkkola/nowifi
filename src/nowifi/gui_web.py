"""NiceGUI web dashboard for nowifi. Cross-platform, runs in browser."""

from __future__ import annotations

import threading
import time

from nicegui import ui

from . import __version__
from .detect import detect_portal, PortalInfo
from .platform_mac import get_gateway, get_wifi_info
from .probe import probe_all, ProbeResults
from .bypass import AuditConfig, run_bypasses, BypassResult


# Shared state between UI and background tasks
class AppState:
    portal: PortalInfo | None = None
    probes: ProbeResults | None = None
    bypasses: list[BypassResult] = []
    status: str = "idle"  # idle, probing, bypassing, active, error
    active_method: str = ""
    log_lines: list[str] = []


state = AppState()


def _log(msg: str):
    state.log_lines.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
    if len(state.log_lines) > 200:
        state.log_lines = state.log_lines[-100:]


def _bool_badge(val: bool) -> str:
    return "OPEN" if val else "CLOSED"


def _bool_color(val: bool) -> str:
    return "positive" if val else "negative"


def create_ui():
    """Build the NiceGUI dashboard."""

    # --- Header ---
    with ui.header().classes("items-center justify-between"):
        ui.label("nowifi").classes("text-2xl font-bold")
        ui.label(f"v{__version__} — No WiFi? Now WiFi.").classes("text-sm opacity-70")

    # --- Main layout ---
    with ui.column().classes("w-full max-w-5xl mx-auto p-4 gap-4"):

        # Status card
        with ui.card().classes("w-full"):
            ui.label("Status").classes("text-lg font-bold")
            status_label = ui.label("Idle — click Run Audit to start").classes("text-md")
            method_label = ui.label("").classes("text-sm text-green-600")

        # Action buttons
        with ui.row().classes("gap-2"):
            ui.button("Run Audit", on_click=lambda: run_audit(status_label, method_label), color="primary").props("icon=shield size=lg")
            ui.button("Probe Only", on_click=lambda: run_probe(status_label), color="secondary").props("icon=search")
            ui.button("Reset Network", on_click=lambda: run_reset(status_label), color="warning").props("icon=refresh")

        # WiFi & Portal info
        with ui.row().classes("w-full gap-4"):
            with ui.card().classes("flex-1"):
                ui.label("WiFi").classes("text-lg font-bold")
                ui.label("Not scanned yet")
            with ui.card().classes("flex-1"):
                ui.label("Portal").classes("text-lg font-bold")
                portal_info = ui.label("Not scanned yet")

        # Probe results table
        with ui.card().classes("w-full"):
            ui.label("Leak Enumeration").classes("text-lg font-bold")
            probe_table = ui.table(
                columns=[
                    {"name": "protocol", "label": "Protocol", "field": "protocol", "align": "left"},
                    {"name": "status", "label": "Status", "field": "status", "align": "center"},
                    {"name": "details", "label": "Details", "field": "details", "align": "left"},
                ],
                rows=[],
            ).classes("w-full")

        # Bypass results table
        with ui.card().classes("w-full"):
            ui.label("Bypass Attempts").classes("text-lg font-bold")
            bypass_table = ui.table(
                columns=[
                    {"name": "technique", "label": "Technique", "field": "technique", "align": "left"},
                    {"name": "result", "label": "Result", "field": "result", "align": "center"},
                    {"name": "severity", "label": "Severity", "field": "severity", "align": "center"},
                    {"name": "impact", "label": "Impact / Details", "field": "impact", "align": "left"},
                ],
                rows=[],
            ).classes("w-full")

        # Live log
        with ui.card().classes("w-full"):
            ui.label("Log").classes("text-lg font-bold")
            log_area = ui.log(max_lines=50).classes("w-full h-48")

    # --- Background update timer ---
    async def update_ui():
        if state.probes:
            rows = []
            p = state.probes
            for name, result, proto in [
                ("DNS (UDP/53)", p.dns, "dns"),
                ("ICMP (ping)", p.icmp, "icmp"),
                ("IPv6", p.ipv6, "ipv6"),
                ("HTTPS (CF)", p.cloudflare, "https"),
                ("QUIC (UDP/443)", p.quic, "quic"),
                ("NTP (UDP/123)", p.ntp, "ntp"),
                ("DoH (HTTPS)", p.doh, "doh"),
            ]:
                rows.append({
                    "protocol": name,
                    "status": _bool_badge(result.is_open),
                    "details": result.details,
                })
            for wl in p.whitelists[:5]:
                rows.append({
                    "protocol": f"  {wl.domain}",
                    "status": _bool_badge(wl.is_open),
                    "details": wl.details,
                })
            open_ports = [port for port in p.open_ports if port.is_open]
            if open_ports:
                rows.append({
                    "protocol": "Open Ports",
                    "status": str(len(open_ports)),
                    "details": ", ".join(f"{port.port}/{port.service}" for port in open_ports),
                })
            probe_table.rows = rows
            probe_table.update()

        if state.bypasses:
            rows = []
            for r in state.bypasses:
                rows.append({
                    "technique": r.method.value,
                    "result": "SUCCESS" if r.success else "failed",
                    "severity": r.severity.value.upper() if r.success else "-",
                    "impact": r.impact if r.success else r.details,
                })
            bypass_table.rows = rows
            bypass_table.update()

        if state.portal:
            p = state.portal
            portal_info.text = f"{'CAPTIVE' if p.is_captive else 'OPEN'} | {p.portal_type.value} | Vendor: {p.vendor or 'Unknown'}"

        if state.active_method:
            method_label.text = f"Active bypass: {state.active_method}"
        else:
            method_label.text = ""

        # Push log lines
        while state.log_lines:
            line = state.log_lines.pop(0)
            log_area.push(line)

    ui.timer(0.5, update_ui)

    # --- Action handlers ---
    async def run_audit(status_lbl, method_lbl):
        if state.status not in ("idle", "error"):
            ui.notify("Already running", type="warning")
            return
        state.status = "probing"
        status_lbl.text = "Probing network..."
        _log("Starting audit...")

        def _background():
            try:
                wifi = get_wifi_info("en0")
                if wifi:
                    _log(f"WiFi: {wifi.ssid} (RSSI: {wifi.rssi})")
                gateway = get_gateway("en0")
                _log(f"Gateway: {gateway}")

                _log("Detecting portal...")
                state.portal = detect_portal("en0")
                if state.portal:
                    state.portal.ssid = wifi.ssid if wifi else ""
                    state.portal.gateway = gateway
                    _log(f"Portal: {'CAPTIVE' if state.portal.is_captive else 'OPEN'} ({state.portal.portal_type.value})")

                _log("Probing leaks (stealth)...")
                state.probes = probe_all(interface="en0", stealth=False)
                _log(f"DNS: {state.probes.dns.is_open} | ICMP: {state.probes.icmp.is_open} | IPv6: {state.probes.ipv6.is_open}")
                _log(f"QUIC: {state.probes.quic.is_open} | NTP: {state.probes.ntp.is_open} | DoH: {state.probes.doh.is_open}")

                if state.portal and state.portal.is_captive:
                    state.status = "bypassing"
                    _log("Attempting bypasses...")
                    config = AuditConfig(interface="en0", stealth=False)
                    state.bypasses = run_bypasses(state.probes, config)
                    wins = [r for r in state.bypasses if r.success]
                    if wins:
                        state.active_method = wins[0].method.value
                        state.status = "active"
                        _log(f"SUCCESS: {wins[0].method.value} — {wins[0].impact}")
                    else:
                        state.status = "idle"
                        _log("No bypass succeeded.")
                else:
                    state.status = "idle"
                    _log("No captive portal detected. Probe complete.")
            except Exception as e:
                state.status = "error"
                _log(f"Error: {e}")

        threading.Thread(target=_background, daemon=True).start()

    async def run_probe(status_lbl):
        if state.status not in ("idle", "error"):
            ui.notify("Already running", type="warning")
            return
        state.status = "probing"
        status_lbl.text = "Probing..."
        _log("Probe-only mode...")

        def _background():
            try:
                state.portal = detect_portal("en0")
                wifi = get_wifi_info("en0")
                if state.portal and wifi:
                    state.portal.ssid = wifi.ssid
                    state.portal.gateway = get_gateway("en0")
                state.probes = probe_all(interface="en0", stealth=False)
                _log("Probe complete.")
                state.status = "idle"
            except Exception as e:
                state.status = "error"
                _log(f"Error: {e}")

        threading.Thread(target=_background, daemon=True).start()

    async def run_reset(status_lbl):
        _log("Resetting network...")
        import subprocess
        subprocess.run(["nowifi", "reset"], capture_output=True)
        _log("Reset complete.")
        state.status = "idle"
        status_lbl.text = "Network reset complete."


def run_dashboard(port: int = 8321):
    """Launch the web dashboard."""
    create_ui()
    ui.run(
        title="nowifi — No WiFi? Now WiFi.",
        host="127.0.0.1",  # SECURITY: bind to localhost only — never expose to network
        port=port,
        reload=False,
        show=True,
    )


if __name__ == "__main__":
    run_dashboard()
