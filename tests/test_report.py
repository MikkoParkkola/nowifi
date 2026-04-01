"""Tests for report generation."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from nowifi.bypass import BypassMethod, BypassResult, Severity
from nowifi.detect import PortalInfo, PortalType
from nowifi.probe import (
    DnsProbeResult,
    HttpsProbeResult,
    IcmpProbeResult,
    Ipv6ProbeResult,
    PortProbeResult,
    ProbeResults,
    WhitelistResult,
)
from nowifi.report import (
    _bool_icon,
    _severity_icon,
    _severity_style,
    generate_json_report,
    generate_markdown_report,
    print_terminal_report,
)
from nowifi.tunnel import TunnelHandle


# ---------------------------------------------------------------------------
# Helper styles / icons
# ---------------------------------------------------------------------------

class TestHelperIcons:

    def test_bool_icon_true(self):
        icon = _bool_icon(True)
        assert "OPEN" in icon
        assert "green" in icon

    def test_bool_icon_false(self):
        icon = _bool_icon(False)
        assert "CLOSED" in icon
        assert "red" in icon

    def test_severity_icon_critical(self):
        icon = _severity_icon(Severity.CRITICAL)
        assert "CRIT" in icon

    def test_severity_icon_high(self):
        icon = _severity_icon(Severity.HIGH)
        assert "HIGH" in icon

    def test_severity_icon_medium(self):
        icon = _severity_icon(Severity.MEDIUM)
        assert "MED" in icon

    def test_severity_style_mapping(self):
        assert "red" in _severity_style(Severity.CRITICAL)
        assert "red" in _severity_style(Severity.HIGH)
        assert "yellow" in _severity_style(Severity.MEDIUM)
        assert "cyan" in _severity_style(Severity.LOW)
        assert "dim" in _severity_style(Severity.INFO)


# ---------------------------------------------------------------------------
# print_terminal_report
# ---------------------------------------------------------------------------

class TestPrintTerminalReport:

    @patch("nowifi.report.Console")
    def test_renders_without_error(
        self, MockConsole, fake_portal_captive, fake_probes_all_open,
    ):
        """Terminal report renders without exception."""
        mock_console = MagicMock()
        MockConsole.return_value = mock_console

        bypass_results = [
            BypassResult(
                method=BypassMethod.IPV6, success=True, severity=Severity.CRITICAL,
                impact="Full IPv6 internet", details="IPv6 unfiltered",
                remediation="Apply IPv6 ACLs",
            ),
        ]
        # Should not raise
        print_terminal_report(fake_portal_captive, fake_probes_all_open, bypass_results)
        assert mock_console.print.call_count > 0

    @patch("nowifi.report.Console")
    def test_renders_with_no_bypasses(
        self, MockConsole, fake_portal_captive, fake_probes_all_closed,
    ):
        """Terminal report works with empty bypass list."""
        mock_console = MagicMock()
        MockConsole.return_value = mock_console
        print_terminal_report(fake_portal_captive, fake_probes_all_closed, [])
        assert mock_console.print.call_count > 0

    @patch("nowifi.report.Console")
    def test_shows_active_tunnel(self, MockConsole, fake_portal_captive, fake_probes_all_open):
        """Terminal report shows active tunnel info when tunnel is active."""
        mock_console = MagicMock()
        MockConsole.return_value = mock_console

        handle = MagicMock()
        handle.active = True
        handle.local_port = 1080

        bypass_results = [
            BypassResult(
                method=BypassMethod.CHISEL_TUNNEL, success=True,
                severity=Severity.CRITICAL, tunnel_handle=handle,
            ),
        ]
        print_terminal_report(fake_portal_captive, fake_probes_all_open, bypass_results)
        # Should print more panels when tunnel is active (header + probes + bypasses + findings + tunnel + spacing)
        # At minimum, more print calls than without a tunnel
        assert mock_console.print.call_count >= 6  # header, probe table, spacing, bypass table, findings, tunnel panel, spacing

    @patch("nowifi.report.Console")
    def test_no_findings_message(
        self, MockConsole, fake_portal_open, fake_probes_all_closed,
    ):
        """No successful bypasses renders 'No Findings' panel."""
        mock_console = MagicMock()
        MockConsole.return_value = mock_console
        bypass_results = [
            BypassResult(method=BypassMethod.IPV6, success=False),
        ]
        print_terminal_report(fake_portal_open, fake_probes_all_closed, bypass_results)
        # Should have printed several panels/tables
        assert mock_console.print.call_count >= 4
        # Verify a Panel was passed (the "No Findings" or findings panel)
        from rich.panel import Panel
        panel_calls = [
            c for c in mock_console.print.call_args_list
            if c.args and isinstance(c.args[0], Panel)
        ]
        assert len(panel_calls) >= 2  # header panel + no-findings panel


# ---------------------------------------------------------------------------
# generate_markdown_report
# ---------------------------------------------------------------------------

class TestGenerateMarkdownReport:

    def test_header_present(self, fake_portal_captive, fake_probes_all_open):
        md = generate_markdown_report(fake_portal_captive, fake_probes_all_open, [])
        assert "# Captive Portal Security Assessment Report" in md

    def test_contains_ssid(self, fake_portal_captive, fake_probes_all_open):
        md = generate_markdown_report(fake_portal_captive, fake_probes_all_open, [])
        assert "Hotel_WiFi" in md

    def test_contains_vendor(self, fake_portal_captive, fake_probes_all_open):
        md = generate_markdown_report(fake_portal_captive, fake_probes_all_open, [])
        assert "unifi" in md

    def test_contains_portal_type(self, fake_portal_captive, fake_probes_all_open):
        md = generate_markdown_report(fake_portal_captive, fake_probes_all_open, [])
        assert "http_redirect" in md

    def test_probe_table_present(self, fake_portal_captive, fake_probes_all_open):
        md = generate_markdown_report(fake_portal_captive, fake_probes_all_open, [])
        assert "Leak Enumeration" in md
        assert "DNS (UDP/53)" in md
        assert "ICMP" in md
        assert "IPv6" in md
        assert "QUIC" in md

    def test_probes_show_open_closed(self, fake_portal_captive, fake_probes_all_open):
        md = generate_markdown_report(fake_portal_captive, fake_probes_all_open, [])
        assert "OPEN" in md

    def test_bypass_table(self, fake_portal_captive, fake_probes_all_open):
        bypass_results = [
            BypassResult(
                method=BypassMethod.IPV6, success=True, severity=Severity.CRITICAL,
                impact="Full IPv6 internet", details="IPv6 unfiltered",
                remediation="Apply IPv6 ACLs",
            ),
            BypassResult(
                method=BypassMethod.CHISEL_TUNNEL, success=False,
                details="No route to tunnel",
            ),
        ]
        md = generate_markdown_report(fake_portal_captive, fake_probes_all_open, bypass_results)
        assert "Bypass Results" in md
        assert "SUCCESS" in md
        assert "failed" in md

    def test_findings_section(self, fake_portal_captive, fake_probes_all_open):
        bypass_results = [
            BypassResult(
                method=BypassMethod.IPV6, success=True, severity=Severity.CRITICAL,
                impact="Full IPv6 internet", details="IPv6 unfiltered",
                remediation="Apply IPv6 ACLs",
            ),
        ]
        md = generate_markdown_report(fake_portal_captive, fake_probes_all_open, bypass_results)
        assert "Findings & Remediation" in md
        assert "CRITICAL" in md
        assert "Apply IPv6 ACLs" in md

    def test_no_findings_no_section(self, fake_portal_captive, fake_probes_all_open):
        bypass_results = [
            BypassResult(method=BypassMethod.IPV6, success=False),
        ]
        md = generate_markdown_report(fake_portal_captive, fake_probes_all_open, bypass_results)
        assert "Findings & Remediation" not in md

    def test_footer(self, fake_portal_captive, fake_probes_all_open):
        md = generate_markdown_report(fake_portal_captive, fake_probes_all_open, [])
        assert "nowifi v0.1.0" in md

    def test_whitelist_entries(self, fake_portal_captive, fake_probes_all_open):
        md = generate_markdown_report(fake_portal_captive, fake_probes_all_open, [])
        assert "captive.apple.com" in md

    def test_date_present(self, fake_portal_captive, fake_probes_all_open):
        md = generate_markdown_report(fake_portal_captive, fake_probes_all_open, [])
        assert "**Date:**" in md
        assert "UTC" in md


# ---------------------------------------------------------------------------
# generate_json_report
# ---------------------------------------------------------------------------

class TestGenerateJsonReport:

    def test_valid_json(self, fake_portal_captive, fake_probes_all_open):
        json_str = generate_json_report(fake_portal_captive, fake_probes_all_open, [])
        data = json.loads(json_str)
        assert isinstance(data, dict)

    def test_portal_section(self, fake_portal_captive, fake_probes_all_open):
        json_str = generate_json_report(fake_portal_captive, fake_probes_all_open, [])
        data = json.loads(json_str)
        assert data["portal"]["is_captive"] is True
        assert data["portal"]["type"] == "http_redirect"
        assert data["portal"]["vendor"] == "unifi"
        assert data["portal"]["ssid"] == "Hotel_WiFi"

    def test_probes_section(self, fake_portal_captive, fake_probes_all_open):
        json_str = generate_json_report(fake_portal_captive, fake_probes_all_open, [])
        data = json.loads(json_str)
        assert data["probes"]["dns"]["open"] is True
        assert data["probes"]["icmp"]["open"] is True
        assert data["probes"]["ipv6"]["open"] is True
        assert data["probes"]["cloudflare"]["open"] is True
        assert data["probes"]["quic"]["open"] is True
        assert data["probes"]["ntp"]["open"] is True
        assert data["probes"]["doh"]["open"] is True

    def test_open_ports_list(self, fake_portal_captive, fake_probes_all_open):
        json_str = generate_json_report(fake_portal_captive, fake_probes_all_open, [])
        data = json.loads(json_str)
        open_ports = data["probes"]["open_ports"]
        assert len(open_ports) == 2
        assert any(p["port"] == 443 for p in open_ports)

    def test_whitelists_section(self, fake_portal_captive, fake_probes_all_open):
        json_str = generate_json_report(fake_portal_captive, fake_probes_all_open, [])
        data = json.loads(json_str)
        wl = data["probes"]["whitelists"]
        assert len(wl) == 1
        assert wl[0]["domain"] == "captive.apple.com"

    def test_bypasses_section(self, fake_portal_captive, fake_probes_all_open):
        bypass_results = [
            BypassResult(
                method=BypassMethod.IPV6, success=True, severity=Severity.CRITICAL,
                impact="Full IPv6 internet", details="IPv6 unfiltered",
                remediation="Apply IPv6 ACLs",
            ),
        ]
        json_str = generate_json_report(fake_portal_captive, fake_probes_all_open, bypass_results)
        data = json.loads(json_str)
        assert len(data["bypasses"]) == 1
        assert data["bypasses"][0]["method"] == "ipv6_bypass"
        assert data["bypasses"][0]["success"] is True
        assert data["bypasses"][0]["severity"] == "critical"

    def test_timestamp_present(self, fake_portal_captive, fake_probes_all_open):
        json_str = generate_json_report(fake_portal_captive, fake_probes_all_open, [])
        data = json.loads(json_str)
        assert "timestamp" in data
        assert "T" in data["timestamp"]  # ISO format

    def test_empty_bypasses(self, fake_portal_open, fake_probes_all_closed):
        json_str = generate_json_report(fake_portal_open, fake_probes_all_closed, [])
        data = json.loads(json_str)
        assert data["bypasses"] == []
        assert data["portal"]["is_captive"] is False

    def test_auth_methods_in_portal(self, fake_portal_captive, fake_probes_all_open):
        json_str = generate_json_report(fake_portal_captive, fake_probes_all_open, [])
        data = json.loads(json_str)
        assert "email" in data["portal"]["auth_methods"]
        assert "password" in data["portal"]["auth_methods"]
