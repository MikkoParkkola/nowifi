"""Tests for diagnosis mode — read-only assessment without exploitation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from nowifi.detect import PortalInfo, PortalType
from nowifi.diagnose import MethodAssessment, assess_methods, _check_tools
from nowifi.probe import (
    DnsProbeResult,
    HttpsProbeResult,
    IcmpProbeResult,
    Ipv6ProbeResult,
    PortProbeResult,
    ProbeResults,
    WhitelistResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def captive_portal():
    return PortalInfo(
        is_captive=True,
        portal_type=PortalType.HTTP_REDIRECT,
        portal_url="http://portal.hotel.com/login",
        redirect_url="http://portal.hotel.com/login",
        vendor="unifi",
        auth_methods=["email"],
        portal_ip="192.168.1.1",
        ssid="Hotel_WiFi",
        gateway="192.168.1.1",
    )


@pytest.fixture
def all_tools_installed():
    """Pretend every tool is installed."""
    return {
        "chisel": True, "iodine": True, "hans": True, "hysteria": True,
        "ntpescape": True, "cloudflared": True, "dnscrypt-proxy": True,
        "hashcat": True, "hcxdumptool": True, "wg-quick": True,
        "aircrack-ng": True, "reaver": True, "wash": True,
        "airodump-ng": True, "aireplay-ng": True,
    }


@pytest.fixture
def no_tools_installed():
    """Pretend no tools are installed."""
    return {
        "chisel": False, "iodine": False, "hans": False, "hysteria": False,
        "ntpescape": False, "cloudflared": False, "dnscrypt-proxy": False,
        "hashcat": False, "hcxdumptool": False, "wg-quick": False,
        "aircrack-ng": False, "reaver": False, "wash": False,
        "airodump-ng": False, "aireplay-ng": False,
    }


def _make_all_open_probes():
    """ProbeResults with everything open."""
    return ProbeResults(
        dns=DnsProbeResult(is_open=True, details="DNS open"),
        icmp=IcmpProbeResult(is_open=True, details="ICMP open"),
        ipv6=Ipv6ProbeResult(is_open=True, address="2001:db8::1", details="IPv6 open"),
        cloudflare=HttpsProbeResult(is_open=True, details="CF open"),
        quic=PortProbeResult(port=443, protocol="udp", is_open=True, service="QUIC", details="QUIC open"),
        ntp=PortProbeResult(port=123, protocol="udp", is_open=True, service="NTP", details="NTP open"),
        doh=PortProbeResult(port=443, protocol="doh", is_open=True, service="DoH", details="DoH open"),
        whitelists=[
            WhitelistResult(domain="captive.apple.com", is_open=True, status_code=200, details="open"),
        ],
        open_ports=[
            PortProbeResult(port=53, protocol="udp", is_open=True, service="DNS"),
            PortProbeResult(port=443, protocol="tcp", is_open=True, service="HTTPS"),
        ],
    )


def _make_all_closed_probes():
    """ProbeResults with everything closed."""
    return ProbeResults()


# ---------------------------------------------------------------------------
# MethodAssessment dataclass
# ---------------------------------------------------------------------------

class TestMethodAssessment:

    def test_dataclass_fields(self):
        m = MethodAssessment(
            name="Test method", number=1, feasible=True,
            confidence="HIGH", reason="it works",
            prerequisites="None", risk="None",
        )
        assert m.name == "Test method"
        assert m.number == 1
        assert m.feasible is True
        assert m.confidence == "HIGH"
        assert m.reason == "it works"
        assert m.prerequisites == "None"
        assert m.risk == "None"


# ---------------------------------------------------------------------------
# assess_methods — all probes open, all tools installed
# ---------------------------------------------------------------------------

class TestAssessMethodsAllOpen:

    @patch("nowifi.platform_mac.get_arp_table")
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_most_methods_feasible(
        self, mock_gw, mock_mac, mock_arp,
        captive_portal, all_tools_installed,
    ):
        """With all probes open and tools installed, most methods are feasible."""
        from nowifi.platform_mac import ArpEntry
        mock_arp.return_value = [
            ArpEntry(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01", interface="en0"),
            ArpEntry(ip="192.168.1.50", mac="11:22:33:44:55:66", interface="en0"),
            ArpEntry(ip="192.168.1.51", mac="22:33:44:55:66:77", interface="en0"),
        ]

        probes = _make_all_open_probes()
        methods = assess_methods(captive_portal, probes, has_tools=all_tools_installed)

        feasible_count = sum(1 for m in methods if m.feasible)
        # With everything open + all tools, the large majority should be feasible
        assert feasible_count >= 15

    @patch("nowifi.platform_mac.get_arp_table")
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_returns_23_methods(
        self, mock_gw, mock_mac, mock_arp,
        captive_portal, all_tools_installed,
    ):
        """assess_methods returns exactly 23 methods (19 bypass + 4 WPA)."""
        from nowifi.platform_mac import ArpEntry
        mock_arp.return_value = [
            ArpEntry(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01", interface="en0"),
            ArpEntry(ip="192.168.1.50", mac="11:22:33:44:55:66", interface="en0"),
        ]

        probes = _make_all_open_probes()
        methods = assess_methods(captive_portal, probes, has_tools=all_tools_installed)
        assert len(methods) == 23


# ---------------------------------------------------------------------------
# assess_methods — all probes closed, no tools
# ---------------------------------------------------------------------------

class TestAssessMethodsAllClosed:

    @patch("nowifi.platform_mac.get_arp_table", return_value=[])
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_few_methods_feasible(
        self, mock_gw, mock_mac, mock_arp,
        captive_portal, no_tools_installed,
    ):
        """With all probes closed and no tools, few methods are feasible."""
        probes = _make_all_closed_probes()
        methods = assess_methods(captive_portal, probes, has_tools=no_tools_installed)

        feasible = [m for m in methods if m.feasible]
        # Some methods are always feasible (CNA spoof, JS bypass, HTTP CONNECT,
        # MAC rotate, DHCP rotate, session replay, default creds)
        # But MAC clone needs ARP candidates, DNS/ICMP/QUIC need open probes + tools
        assert len(feasible) < 15
        # At minimum the "always try" methods should still be feasible
        assert len(feasible) >= 5


# ---------------------------------------------------------------------------
# Individual protocol -> method feasibility
# ---------------------------------------------------------------------------

class TestSpecificProtocols:

    @patch("nowifi.platform_mac.get_arp_table", return_value=[])
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_ipv6_open_method1_feasible(self, mock_gw, mock_mac, mock_arp, captive_portal, no_tools_installed):
        """IPv6 open -> method 1 (IPv6 bypass) is feasible."""
        probes = ProbeResults(
            ipv6=Ipv6ProbeResult(is_open=True, details="IPv6 available"),
        )
        methods = assess_methods(captive_portal, probes, has_tools=no_tools_installed)
        method1 = next(m for m in methods if m.number == 1)
        assert method1.feasible is True
        assert method1.confidence == "HIGH"

    @patch("nowifi.platform_mac.get_arp_table", return_value=[])
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_dns_open_tunnel_feasible(self, mock_gw, mock_mac, mock_arp, captive_portal):
        """DNS open + iodine installed -> DNS tunnel feasible."""
        probes = ProbeResults(
            dns=DnsProbeResult(is_open=True, details="DNS open"),
        )
        has_tools = {"iodine": True, "chisel": False, "hans": False,
                     "hysteria": False, "ntpescape": False, "cloudflared": False,
                     "hashcat": False, "hcxdumptool": False, "wg-quick": False,
                     "reaver": False, "wash": False}
        methods = assess_methods(captive_portal, probes, has_tools=has_tools)
        method8 = next(m for m in methods if m.number == 8)
        assert method8.feasible is True
        assert method8.name == "DNS tunnel (iodine)"

    @patch("nowifi.platform_mac.get_arp_table", return_value=[])
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_quic_open_tunnel_feasible(self, mock_gw, mock_mac, mock_arp, captive_portal):
        """QUIC open + hysteria installed -> QUIC tunnel feasible."""
        probes = ProbeResults(
            quic=PortProbeResult(port=443, protocol="udp", is_open=True, service="QUIC", details="QUIC open"),
        )
        has_tools = {"hysteria": True, "chisel": False, "iodine": False,
                     "hans": False, "ntpescape": False, "cloudflared": False,
                     "hashcat": False, "hcxdumptool": False, "wg-quick": False,
                     "reaver": False, "wash": False}
        methods = assess_methods(captive_portal, probes, has_tools=has_tools)
        method16 = next(m for m in methods if m.number == 16)
        assert method16.feasible is True
        assert method16.name == "QUIC tunnel (Hysteria2)"

    @patch("nowifi.platform_mac.get_arp_table", return_value=[])
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_no_arp_candidates_mac_clone_infeasible(self, mock_gw, mock_mac, mock_arp, captive_portal, all_tools_installed):
        """No ARP candidates -> MAC clone not feasible."""
        probes = _make_all_open_probes()
        methods = assess_methods(captive_portal, probes, has_tools=all_tools_installed)
        method6 = next(m for m in methods if m.number == 6)
        assert method6.feasible is False
        assert "No other devices" in method6.reason


# ---------------------------------------------------------------------------
# WPS method assessment
# ---------------------------------------------------------------------------

class TestWpsMethodAssessment:

    @patch("nowifi.platform_mac.get_arp_table", return_value=[])
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_wps_tools_installed_feasible(self, mock_gw, mock_mac, mock_arp, captive_portal):
        """WPS tools (reaver, hcxdumptool, hashcat) installed -> WPS methods feasible."""
        probes = _make_all_closed_probes()
        has_tools = {
            "chisel": False, "iodine": False, "hans": False, "hysteria": False,
            "ntpescape": False, "cloudflared": False, "wg-quick": False,
            "reaver": True, "wash": True, "hcxdumptool": True,
            "hashcat": True, "aircrack-ng": True,
        }
        methods = assess_methods(captive_portal, probes, has_tools=has_tools)

        # Method 20: PMKID (needs hcxdumptool)
        method20 = next(m for m in methods if m.number == 20)
        assert method20.feasible is True

        # Method 21: WPS Pixie-Dust (needs reaver)
        method21 = next(m for m in methods if m.number == 21)
        assert method21.feasible is True

        # Method 22: WPA handshake + hashcat (needs hcxdumptool + hashcat)
        method22 = next(m for m in methods if m.number == 22)
        assert method22.feasible is True

        # Method 23: WPS PIN brute (needs reaver)
        method23 = next(m for m in methods if m.number == 23)
        assert method23.feasible is True

    @patch("nowifi.platform_mac.get_arp_table", return_value=[])
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_wps_tools_missing_infeasible(self, mock_gw, mock_mac, mock_arp, captive_portal, no_tools_installed):
        """No WPS tools -> WPS methods not feasible."""
        probes = _make_all_closed_probes()
        methods = assess_methods(captive_portal, probes, has_tools=no_tools_installed)

        for num in [20, 21, 22, 23]:
            method = next(m for m in methods if m.number == num)
            assert method.feasible is False


# ---------------------------------------------------------------------------
# _check_tools
# ---------------------------------------------------------------------------

class TestCheckTools:

    @patch("shutil.which")
    @patch("os.path.isfile", return_value=False)
    def test_checks_all_tool_names(self, mock_isfile, mock_which):
        """_check_tools checks all expected tool names."""
        mock_which.return_value = None
        result = _check_tools()

        expected_tools = [
            "chisel", "iodine", "hans", "hysteria", "ntpescape",
            "cloudflared", "dnscrypt-proxy", "hashcat", "hcxdumptool",
            "wg-quick", "aircrack-ng", "reaver", "wash", "airodump-ng",
            "aireplay-ng",
        ]
        for tool in expected_tools:
            assert tool in result

    @patch("os.access", return_value=True)
    @patch("os.path.isfile", return_value=False)
    @patch("shutil.which")
    def test_returns_true_when_found(self, mock_which, mock_isfile, mock_access):
        """Tools found via which() are marked True."""
        mock_which.side_effect = lambda name: f"/usr/bin/{name}" if name == "chisel" else None
        result = _check_tools()
        assert result["chisel"] is True
        assert result["iodine"] is False

    @patch("shutil.which", return_value=None)
    @patch("os.path.isfile")
    @patch("os.access", return_value=True)
    def test_checks_extra_dirs(self, mock_access, mock_isfile, mock_which):
        """_check_tools also checks ~/bin/ and ~/.nowifi/bin/."""
        import os
        home = os.path.expanduser("~")

        def _isfile_side_effect(path):
            if path == f"{home}/bin/chisel":
                return True
            return False
        mock_isfile.side_effect = _isfile_side_effect

        result = _check_tools()
        assert result["chisel"] is True
