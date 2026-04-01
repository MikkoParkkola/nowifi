"""Tests for bypass technique logic."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, call

import pytest

from nowifi.bypass import (
    AuditConfig,
    BypassMethod,
    BypassResult,
    Severity,
    _has_internet,
    _try_cna_spoof,
    _try_chisel,
    _try_default_creds,
    _try_dhcp_rotate,
    _try_dns_tunnel,
    _try_doh_tunnel,
    _try_http_connect,
    _try_icmp_tunnel,
    _try_ipv6,
    _try_js_bypass,
    _try_mac_clone,
    _try_mac_rotate,
    _try_ntp_tunnel,
    _try_quic_tunnel,
    _try_session_replay,
    _try_vpn_port53,
    _try_whitelist,
    _try_cf_workers,
    clear_system_socks_proxy,
    run_bypasses,
)
from nowifi.probe import (
    DnsProbeResult,
    HttpsProbeResult,
    IcmpProbeResult,
    Ipv6ProbeResult,
    PortProbeResult,
    ProbeResults,
    WhitelistResult,
)
from nowifi.tunnel import TunnelHandle, ToolNotFound


# ---------------------------------------------------------------------------
# run_bypasses: orchestration
# ---------------------------------------------------------------------------

class TestRunBypasses:

    @patch("nowifi.bypass._log")
    @patch("nowifi.bypass._try_ipv6")
    def test_stops_on_first_success(self, mock_ipv6, mock_log, fake_config):
        """Stops on first successful bypass."""
        mock_ipv6.return_value = BypassResult(
            method=BypassMethod.IPV6, success=True, severity=Severity.CRITICAL,
        )
        probes = ProbeResults()
        results = run_bypasses(probes, fake_config)
        assert len(results) == 1
        assert results[0].success is True
        assert results[0].method == BypassMethod.IPV6

    @patch("nowifi.bypass._log")
    def test_all_fail_returns_all(self, mock_log, fake_config):
        """All 19 techniques fail -> all 19 results returned, none successful."""
        fail = BypassResult(method=BypassMethod.MAC_ROTATE, success=False, details="failed")

        patches = [
            "nowifi.bypass._try_ipv6",
            "nowifi.bypass._try_chisel",
            "nowifi.bypass._try_cna_spoof",
            "nowifi.bypass._try_js_bypass",
            "nowifi.bypass._try_http_connect",
            "nowifi.bypass._try_mac_clone",
            "nowifi.bypass._try_dns_tunnel",
            "nowifi.bypass._try_icmp_tunnel",
            "nowifi.bypass._try_vpn_port53",
            "nowifi.bypass._try_whitelist",
            "nowifi.bypass._try_session_replay",
            "nowifi.bypass._try_default_creds",
            "nowifi.bypass._try_mac_rotate",
            "nowifi.bypass._try_dhcp_rotate",
            "nowifi.bypass._try_quic_tunnel",
            "nowifi.bypass._try_cf_workers",
            "nowifi.bypass._try_ntp_tunnel",
            "nowifi.bypass._try_doh_tunnel",
        ]
        mock_objects = []
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in patches:
                m = stack.enter_context(patch(p, return_value=fail))
                mock_objects.append(m)

            probes = ProbeResults()
            results = run_bypasses(probes, fake_config)
            assert len(results) == 19
            assert all(not r.success for r in results)

    @patch("nowifi.bypass._log")
    @patch("nowifi.bypass._set_system_socks_proxy")
    @patch("nowifi.bypass._try_ipv6")
    @patch("nowifi.bypass._try_chisel")
    def test_tunnel_sets_system_proxy(self, mock_chisel, mock_ipv6, mock_set_proxy, mock_log, fake_config):
        """Successful tunnel sets system SOCKS proxy."""
        mock_ipv6.return_value = BypassResult(method=BypassMethod.IPV6, success=False)

        handle = MagicMock()
        handle.active = True
        handle.local_port = 1080
        mock_chisel.return_value = BypassResult(
            method=BypassMethod.CHISEL_TUNNEL, success=True,
            severity=Severity.CRITICAL, tunnel_handle=handle,
        )

        probes = ProbeResults()
        results = run_bypasses(probes, fake_config)
        assert results[-1].success is True
        mock_set_proxy.assert_called_once_with(fake_config.interface, 1080)

    @patch("nowifi.bypass._log")
    @patch("nowifi.bypass._try_ipv6")
    def test_exception_in_technique_handled(self, mock_ipv6, mock_log, fake_config):
        """Exception in a technique -> caught, marked as failure, continues."""
        mock_ipv6.side_effect = RuntimeError("Unexpected crash")

        # Need to mock all other techniques too
        with patch("nowifi.bypass._try_chisel") as m2, \
             patch("nowifi.bypass._try_cna_spoof") as m3, \
             patch("nowifi.bypass._try_js_bypass") as m4, \
             patch("nowifi.bypass._try_http_connect") as m5, \
             patch("nowifi.bypass._try_mac_clone") as m6, \
             patch("nowifi.bypass._try_dns_tunnel") as m7, \
             patch("nowifi.bypass._try_icmp_tunnel") as m8, \
             patch("nowifi.bypass._try_vpn_port53") as m9, \
             patch("nowifi.bypass._try_whitelist") as m10, \
             patch("nowifi.bypass._try_session_replay") as m11, \
             patch("nowifi.bypass._try_default_creds") as m12, \
             patch("nowifi.bypass._try_mac_rotate") as m13, \
             patch("nowifi.bypass._try_dhcp_rotate") as m14, \
             patch("nowifi.bypass._try_quic_tunnel") as m15, \
             patch("nowifi.bypass._try_cf_workers") as m16, \
             patch("nowifi.bypass._try_ntp_tunnel") as m17, \
             patch("nowifi.bypass._try_doh_tunnel") as m18:

            fail = BypassResult(method=BypassMethod.MAC_ROTATE, success=False)
            for m in [m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18]:
                m.return_value = fail

            probes = ProbeResults()
            results = run_bypasses(probes, fake_config)
            # First result should be failure from exception
            assert results[0].success is False
            assert "Exception" in results[0].details


# ---------------------------------------------------------------------------
# _try_ipv6
# ---------------------------------------------------------------------------

class TestTryIpv6:

    def test_ipv6_open_succeeds(self, fake_probes_ipv6_only):
        result = _try_ipv6(fake_probes_ipv6_only)
        assert result.success is True
        assert result.method == BypassMethod.IPV6
        assert result.severity == Severity.CRITICAL

    def test_ipv6_closed_fails(self, fake_probes_all_closed):
        result = _try_ipv6(fake_probes_all_closed)
        assert result.success is False
        assert result.method == BypassMethod.IPV6

    def test_ipv6_success_no_further_techniques(self, fake_probes_ipv6_only):
        """IPv6 success -> bypass succeeds immediately."""
        result = _try_ipv6(fake_probes_ipv6_only)
        assert result.success is True
        # Impact should mention unrestricted
        assert "unrestricted" in result.impact.lower() or "bypass" in result.impact.lower()


# ---------------------------------------------------------------------------
# _try_chisel
# ---------------------------------------------------------------------------

class TestTryChisel:

    @patch("nowifi.bypass.tunnel.verify_tunnel_socks", return_value=True)
    @patch("nowifi.bypass.tunnel.start_chisel_tunnel")
    def test_chisel_via_cloudflare(self, mock_start, mock_verify, fake_config):
        """Chisel tunnel via Cloudflare succeeds."""
        handle = TunnelHandle(process=MagicMock(), local_port=1080, method="chisel")
        handle.active = True
        mock_start.return_value = handle

        probes = ProbeResults(cloudflare=HttpsProbeResult(is_open=True))
        result = _try_chisel(fake_config, probes)
        assert result.success is True
        assert result.tunnel_handle is not None
        assert result.tunnel_handle.active is True

    @patch("nowifi.bypass.tunnel.start_chisel_tunnel")
    def test_chisel_tool_not_found(self, mock_start, fake_config):
        """Chisel binary not found -> skipped."""
        mock_start.side_effect = ToolNotFound("chisel", "brew install chisel")
        probes = ProbeResults(cloudflare=HttpsProbeResult(is_open=True))
        result = _try_chisel(fake_config, probes)
        assert result.success is False
        assert "Skipped" in result.details

    def test_chisel_no_route(self, fake_config):
        """No cloudflare/whitelists open, no server ports -> fails."""
        probes = ProbeResults()
        result = _try_chisel(fake_config, probes)
        assert result.success is False


# ---------------------------------------------------------------------------
# _try_mac_clone
# ---------------------------------------------------------------------------

class TestTryMacClone:

    @patch("nowifi.bypass._has_internet", return_value=True)
    @patch("nowifi.bypass.platform_mac.renew_dhcp", return_value=True)
    @patch("nowifi.bypass.platform_mac.set_mac", return_value=True)
    @patch("nowifi.bypass.platform_mac.get_arp_table")
    @patch("nowifi.bypass.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.bypass.platform_mac.get_gateway", return_value="192.168.1.1")
    @patch("nowifi.bypass.time.sleep")
    def test_mac_clone_success(
        self, mock_sleep, mock_gw, mock_mac, mock_arp, mock_set, mock_dhcp, mock_inet,
    ):
        """MAC clone from ARP table succeeds."""
        from nowifi.platform_mac import ArpEntry
        mock_arp.return_value = [
            ArpEntry(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01", interface="en0"),  # gateway
            ArpEntry(ip="192.168.1.50", mac="11:22:33:44:55:66", interface="en0"),
        ]
        result = _try_mac_clone("en0", idle_only=False)
        assert result.success is True
        assert result.severity == Severity.CRITICAL
        mock_set.assert_called_with("en0", "11:22:33:44:55:66")

    @patch("nowifi.bypass.platform_mac.get_arp_table")
    @patch("nowifi.bypass.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.bypass.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_mac_clone_filters_gateway(self, mock_gw, mock_mac, mock_arp):
        """MAC clone filters out gateway from candidates."""
        from nowifi.platform_mac import ArpEntry
        mock_arp.return_value = [
            ArpEntry(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01", interface="en0"),  # gateway only
        ]
        result = _try_mac_clone("en0", idle_only=False)
        assert result.success is False
        assert "No devices" in result.details

    @patch("nowifi.bypass.platform_mac.get_arp_table")
    @patch("nowifi.bypass.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.bypass.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_mac_clone_filters_broadcast(self, mock_gw, mock_mac, mock_arp):
        """MAC clone filters out broadcast MAC."""
        from nowifi.platform_mac import ArpEntry
        mock_arp.return_value = [
            ArpEntry(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01", interface="en0"),
            ArpEntry(ip="192.168.1.255", mac="ff:ff:ff:ff:ff:ff", interface="en0"),
        ]
        result = _try_mac_clone("en0", idle_only=False)
        assert result.success is False

    @patch("nowifi.bypass.platform_mac.get_arp_table")
    @patch("nowifi.bypass.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.bypass.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_mac_clone_filters_own_mac(self, mock_gw, mock_mac, mock_arp):
        """MAC clone filters out own MAC address."""
        from nowifi.platform_mac import ArpEntry
        mock_arp.return_value = [
            ArpEntry(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01", interface="en0"),
            ArpEntry(ip="192.168.1.100", mac="aa:bb:cc:dd:ee:ff", interface="en0"),  # own MAC
        ]
        result = _try_mac_clone("en0", idle_only=False)
        assert result.success is False

    @patch("nowifi.bypass.platform_mac.get_arp_table")
    @patch("nowifi.bypass.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.bypass.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_mac_clone_filters_other_interface(self, mock_gw, mock_mac, mock_arp):
        """MAC clone filters out entries from other interfaces."""
        from nowifi.platform_mac import ArpEntry
        mock_arp.return_value = [
            ArpEntry(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01", interface="en0"),
            ArpEntry(ip="10.0.0.5", mac="11:22:33:44:55:66", interface="en1"),  # wrong interface
        ]
        result = _try_mac_clone("en0", idle_only=False)
        assert result.success is False

    @patch("nowifi.bypass.subprocess.run")
    @patch("nowifi.bypass.platform_mac.get_arp_table")
    @patch("nowifi.bypass.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.bypass.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_mac_clone_idle_prefers_non_responding(self, mock_gw, mock_mac, mock_arp, mock_run):
        """Idle clone prefers devices that don't respond to ping."""
        from nowifi.platform_mac import ArpEntry
        mock_arp.return_value = [
            ArpEntry(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01", interface="en0"),
            ArpEntry(ip="192.168.1.50", mac="11:22:33:44:55:66", interface="en0"),
            ArpEntry(ip="192.168.1.51", mac="22:33:44:55:66:77", interface="en0"),
        ]
        # First device responds (active), second doesn't (idle)
        mock_run.side_effect = [
            MagicMock(returncode=0),  # 192.168.1.50 responds
            MagicMock(returncode=1),  # 192.168.1.51 doesn't respond
        ]

        # Mock the mac set and internet check for the idle candidate
        with patch("nowifi.bypass.platform_mac.set_mac", return_value=True), \
             patch("nowifi.bypass.platform_mac.renew_dhcp", return_value=True), \
             patch("nowifi.bypass._has_internet", return_value=True), \
             patch("nowifi.bypass.time.sleep"):
            result = _try_mac_clone("en0", idle_only=True)
            assert result.success is True
            # Should have used the idle device's MAC
            assert "idle" in result.details.lower() or "22:33:44:55:66:77" in result.impact

    @patch("nowifi.bypass.platform_mac.get_gateway", return_value="")
    def test_mac_clone_no_gateway(self, mock_gw):
        """No gateway -> fails immediately."""
        result = _try_mac_clone("en0", idle_only=False)
        assert result.success is False
        assert "No gateway" in result.details


# ---------------------------------------------------------------------------
# _try_cna_spoof
# ---------------------------------------------------------------------------

class TestTryCnaSpoof:

    @patch("requests.get")
    def test_cna_spoof_success(self, mock_get):
        """Portal auto-approves CNA User-Agent."""
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_get.return_value = mock_resp
        probes = ProbeResults()
        result = _try_cna_spoof(probes)
        assert result.success is True
        assert result.severity == Severity.HIGH

    @patch("requests.get")
    def test_cna_spoof_fails(self, mock_get):
        """Portal doesn't auto-approve any UA."""
        mock_resp = MagicMock()
        mock_resp.status_code = 302  # redirect to portal
        mock_get.return_value = mock_resp
        probes = ProbeResults()
        result = _try_cna_spoof(probes)
        assert result.success is False


# ---------------------------------------------------------------------------
# _try_js_bypass
# ---------------------------------------------------------------------------

class TestTryJsBypass:

    @patch("requests.get")
    def test_js_bypass_success(self, mock_get):
        """Direct HTTP works without JS -> bypass succeeds."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "203.0.113.1"  # real IP, no portal keywords
        mock_get.return_value = mock_resp
        probes = ProbeResults()
        result = _try_js_bypass(probes)
        assert result.success is True
        assert result.severity == Severity.HIGH

    @patch("requests.get")
    def test_js_bypass_portal_detected(self, mock_get):
        """HTTP returns portal page -> bypass fails."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body>Please login to the captive portal</body></html>'
        mock_get.return_value = mock_resp
        probes = ProbeResults()
        result = _try_js_bypass(probes)
        assert result.success is False

    @patch("requests.get")
    def test_js_bypass_all_fail(self, mock_get):
        """All test URLs fail -> bypass fails."""
        mock_get.side_effect = Exception("Connection refused")
        probes = ProbeResults()
        result = _try_js_bypass(probes)
        assert result.success is False


# ---------------------------------------------------------------------------
# _try_http_connect
# ---------------------------------------------------------------------------

class TestTryHttpConnect:

    @patch("socket.socket")
    @patch("nowifi.bypass.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_connect_success(self, mock_gw, mock_socket_cls, fake_config):
        """HTTP CONNECT through gateway succeeds."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recv.return_value = b"HTTP/1.1 200 Connection established\r\n\r\n"
        probes = ProbeResults()
        result = _try_http_connect(probes, fake_config)
        assert result.success is True
        assert result.severity == Severity.HIGH

    @patch("socket.socket")
    @patch("nowifi.bypass.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_connect_refused(self, mock_gw, mock_socket_cls, fake_config):
        """HTTP CONNECT fails on all ports."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recv.return_value = b"HTTP/1.1 403 Forbidden\r\n\r\n"
        probes = ProbeResults()
        result = _try_http_connect(probes, fake_config)
        assert result.success is False

    @patch("nowifi.bypass.platform_mac.get_gateway", return_value="")
    def test_connect_no_gateway(self, mock_gw, fake_config):
        probes = ProbeResults()
        result = _try_http_connect(probes, fake_config)
        assert result.success is False
        assert "No gateway" in result.details


# ---------------------------------------------------------------------------
# _try_dns_tunnel
# ---------------------------------------------------------------------------

class TestTryDnsTunnel:

    def test_dns_closed(self, fake_config_with_dns):
        """DNS not open -> skip."""
        probes = ProbeResults(dns=DnsProbeResult(is_open=False))
        result = _try_dns_tunnel(fake_config_with_dns, probes)
        assert result.success is False
        assert "DNS not open" in result.details

    def test_no_domain_configured(self, fake_config):
        """No DNS tunnel domain -> skip."""
        probes = ProbeResults(dns=DnsProbeResult(is_open=True))
        result = _try_dns_tunnel(fake_config, probes)
        assert result.success is False
        assert "No DNS tunnel domain" in result.details

    @patch("nowifi.bypass.tunnel.verify_tunnel_direct", return_value=True)
    @patch("nowifi.bypass.tunnel.start_dns_tunnel")
    def test_dns_tunnel_success(self, mock_start, mock_verify, fake_config_with_dns):
        """DNS tunnel works."""
        handle = TunnelHandle(process=MagicMock(), local_port=0, method="dns_tunnel")
        handle.active = True
        mock_start.return_value = handle
        probes = ProbeResults(dns=DnsProbeResult(is_open=True))
        result = _try_dns_tunnel(fake_config_with_dns, probes)
        assert result.success is True
        assert result.severity == Severity.HIGH

    @patch("nowifi.bypass.tunnel.start_dns_tunnel")
    def test_dns_tunnel_tool_not_found(self, mock_start, fake_config_with_dns):
        mock_start.side_effect = ToolNotFound("iodine", "brew install iodine")
        probes = ProbeResults(dns=DnsProbeResult(is_open=True))
        result = _try_dns_tunnel(fake_config_with_dns, probes)
        assert result.success is False
        assert "Skipped" in result.details


# ---------------------------------------------------------------------------
# _try_icmp_tunnel
# ---------------------------------------------------------------------------

class TestTryIcmpTunnel:

    def test_icmp_closed(self, fake_config_with_icmp):
        probes = ProbeResults(icmp=IcmpProbeResult(is_open=False))
        result = _try_icmp_tunnel(fake_config_with_icmp, probes)
        assert result.success is False
        assert "ICMP not open" in result.details

    def test_no_server_configured(self, fake_config):
        probes = ProbeResults(icmp=IcmpProbeResult(is_open=True))
        result = _try_icmp_tunnel(fake_config, probes)
        assert result.success is False
        assert "No ICMP server" in result.details


# ---------------------------------------------------------------------------
# _try_vpn_port53
# ---------------------------------------------------------------------------

class TestTryVpnPort53:

    def test_no_vpn_server(self, fake_config):
        probes = ProbeResults()
        result = _try_vpn_port53(fake_config, probes)
        assert result.success is False
        assert "No VPN server" in result.details


# ---------------------------------------------------------------------------
# _try_mac_rotate
# ---------------------------------------------------------------------------

class TestTryMacRotate:

    @patch("nowifi.bypass._has_internet", return_value=True)
    @patch("nowifi.bypass.platform_mac.renew_dhcp", return_value=True)
    @patch("nowifi.bypass.platform_mac.set_mac", return_value=True)
    @patch("nowifi.bypass.platform_mac.generate_random_mac", return_value="02:ab:cd:ef:01:23")
    @patch("nowifi.bypass.time.sleep")
    def test_mac_rotate_success(self, mock_sleep, mock_gen, mock_set, mock_dhcp, mock_inet):
        """Fresh random MAC + portal auto-approves -> success."""
        result = _try_mac_rotate("en0")
        assert result.success is True
        assert result.severity == Severity.HIGH
        mock_set.assert_called_once_with("en0", "02:ab:cd:ef:01:23")

    @patch("nowifi.bypass.platform_mac.set_mac", return_value=False)
    @patch("nowifi.bypass.platform_mac.generate_random_mac", return_value="02:ab:cd:ef:01:23")
    def test_mac_rotate_no_sudo(self, mock_gen, mock_set):
        """No sudo permissions -> fail."""
        result = _try_mac_rotate("en0")
        assert result.success is False
        assert "sudo" in result.details.lower()

    @patch("nowifi.bypass._has_internet", return_value=False)
    @patch("nowifi.bypass.platform_mac.renew_dhcp", return_value=True)
    @patch("nowifi.bypass.platform_mac.set_mac", return_value=True)
    @patch("nowifi.bypass.platform_mac.generate_random_mac", return_value="02:ab:cd:ef:01:23")
    @patch("nowifi.bypass.time.sleep")
    def test_mac_rotate_no_internet(self, mock_sleep, mock_gen, mock_set, mock_dhcp, mock_inet):
        """MAC changed but portal still requires auth."""
        result = _try_mac_rotate("en0")
        assert result.success is False
        assert result.severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# _try_dhcp_rotate
# ---------------------------------------------------------------------------

class TestTryDhcpRotate:

    @patch("nowifi.bypass._has_internet", return_value=True)
    @patch("nowifi.bypass.platform_mac.renew_dhcp", return_value=True)
    @patch("nowifi.bypass.time.sleep")
    def test_dhcp_rotate_success(self, mock_sleep, mock_dhcp, mock_inet):
        result = _try_dhcp_rotate("en0")
        assert result.success is True
        assert result.severity == Severity.MEDIUM

    @patch("nowifi.bypass._has_internet", return_value=False)
    @patch("nowifi.bypass.platform_mac.renew_dhcp", return_value=True)
    @patch("nowifi.bypass.time.sleep")
    def test_dhcp_rotate_fail(self, mock_sleep, mock_dhcp, mock_inet):
        result = _try_dhcp_rotate("en0")
        assert result.success is False


# ---------------------------------------------------------------------------
# _try_quic_tunnel
# ---------------------------------------------------------------------------

class TestTryQuicTunnel:

    def test_quic_blocked(self, fake_config):
        probes = ProbeResults(
            quic=PortProbeResult(port=443, protocol="udp", is_open=False),
        )
        result = _try_quic_tunnel(fake_config, probes)
        assert result.success is False
        assert "QUIC" in result.details

    @patch("nowifi.bypass.tunnel.verify_tunnel_socks", return_value=True)
    @patch("nowifi.bypass.tunnel.start_quic_tunnel")
    def test_quic_tunnel_success(self, mock_start, mock_verify, fake_config):
        handle = TunnelHandle(process=MagicMock(), local_port=1081, method="quic")
        handle.active = True
        mock_start.return_value = handle
        probes = ProbeResults(
            quic=PortProbeResult(port=443, protocol="udp", is_open=True),
        )
        result = _try_quic_tunnel(fake_config, probes)
        assert result.success is True
        assert result.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# _try_cf_workers
# ---------------------------------------------------------------------------

class TestTryCfWorkers:

    def test_no_url_configured(self, fake_config):
        probes = ProbeResults()
        result = _try_cf_workers(fake_config, probes)
        assert result.success is False
        assert "No CF Workers URL" in result.details

    def test_cloudflare_not_reachable(self, fake_config_with_all):
        probes = ProbeResults(
            cloudflare=HttpsProbeResult(is_open=False),
        )
        result = _try_cf_workers(fake_config_with_all, probes)
        assert result.success is False
        assert "not reachable" in result.details

    @patch("nowifi.bypass.tunnel.verify_cf_workers_proxy", return_value=True)
    def test_cf_workers_success(self, mock_verify, fake_config_with_all):
        probes = ProbeResults(
            cloudflare=HttpsProbeResult(is_open=True),
        )
        result = _try_cf_workers(fake_config_with_all, probes)
        assert result.success is True
        assert result.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# _try_ntp_tunnel
# ---------------------------------------------------------------------------

class TestTryNtpTunnel:

    def test_ntp_blocked(self, fake_config_with_all):
        probes = ProbeResults(
            ntp=PortProbeResult(port=123, protocol="udp", is_open=False),
        )
        result = _try_ntp_tunnel(fake_config_with_all, probes)
        assert result.success is False

    def test_no_ntp_server(self, fake_config):
        probes = ProbeResults(
            ntp=PortProbeResult(port=123, protocol="udp", is_open=True),
        )
        result = _try_ntp_tunnel(fake_config, probes)
        assert result.success is False
        assert "No NTP tunnel server" in result.details


# ---------------------------------------------------------------------------
# _try_doh_tunnel
# ---------------------------------------------------------------------------

class TestTryDohTunnel:

    def test_doh_blocked(self, fake_config):
        probes = ProbeResults(
            doh=PortProbeResult(port=443, protocol="doh", is_open=False),
        )
        result = _try_doh_tunnel(fake_config, probes)
        assert result.success is False

    @patch("nowifi.bypass.tunnel.start_doh_tunnel")
    def test_doh_tunnel_success(self, mock_start, fake_config):
        handle = TunnelHandle(process=MagicMock(), local_port=1083, method="doh_tunnel")
        handle.active = True
        mock_start.return_value = handle
        probes = ProbeResults(
            doh=PortProbeResult(port=443, protocol="doh", is_open=True),
        )
        result = _try_doh_tunnel(fake_config, probes)
        assert result.success is True
        assert result.severity == Severity.HIGH

    @patch("nowifi.bypass.tunnel.start_doh_tunnel")
    def test_doh_tool_not_found(self, mock_start, fake_config):
        mock_start.side_effect = ToolNotFound("cloudflared", "brew install cloudflared")
        probes = ProbeResults(
            doh=PortProbeResult(port=443, protocol="doh", is_open=True),
        )
        result = _try_doh_tunnel(fake_config, probes)
        assert result.success is False
        assert "Skipped" in result.details


# ---------------------------------------------------------------------------
# _try_whitelist
# ---------------------------------------------------------------------------

class TestTryWhitelist:

    def test_no_whitelists_open(self, fake_config):
        probes = ProbeResults(whitelists=[])
        result = _try_whitelist(probes, fake_config)
        assert result.success is False

    def test_whitelists_open_reports_domains(self, fake_config):
        probes = ProbeResults(
            whitelists=[
                WhitelistResult(domain="captive.apple.com", is_open=True),
                WhitelistResult(domain="cloudflare.com", is_open=True),
            ],
        )
        result = _try_whitelist(probes, fake_config)
        # Returns False success (finding only, no exploit) but reports domains
        assert result.success is False
        assert "captive.apple.com" in result.details
        assert "cloudflare.com" in result.details


# ---------------------------------------------------------------------------
# _try_session_replay
# ---------------------------------------------------------------------------

class TestTrySessionReplay:

    @patch("requests.get")
    @patch("nowifi.bypass.platform_mac.get_gateway", return_value="192.168.1.1")
    def test_http_cookies_found(self, mock_gw, mock_get):
        """Portal serves cookies over HTTP -> vulnerability reported."""
        mock_resp = MagicMock()
        mock_resp.url = "http://192.168.1.1/login"
        mock_resp.cookies = MagicMock()
        mock_resp.cookies.keys.return_value = ["session_id", "portal_auth"]
        mock_resp.cookies.__bool__ = lambda self: True
        mock_get.return_value = mock_resp

        result = _try_session_replay("en0")
        assert result.success is False  # passive check only
        assert result.severity == Severity.HIGH
        assert "sniffable" in result.details.lower()

    @patch("nowifi.bypass.platform_mac.get_gateway", return_value="")
    def test_no_gateway(self, mock_gw):
        result = _try_session_replay("en0")
        assert result.success is False


# ---------------------------------------------------------------------------
# _has_internet
# ---------------------------------------------------------------------------

class TestHasInternet:

    @patch("requests.get")
    def test_internet_available(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_get.return_value = mock_resp
        assert _has_internet() is True

    @patch("requests.get")
    def test_internet_blocked(self, mock_get):
        mock_get.side_effect = Exception("Connection failed")
        assert _has_internet() is False

    @patch("requests.get")
    def test_internet_portal_redirect(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 302  # redirect to portal
        mock_get.return_value = mock_resp
        assert _has_internet() is False


# ---------------------------------------------------------------------------
# clear_system_socks_proxy
# ---------------------------------------------------------------------------

class TestClearSystemSocksProxy:

    @patch("nowifi.bypass.subprocess.run")
    @patch("nowifi.bypass._get_network_service", return_value="Wi-Fi")
    def test_clears_proxy(self, mock_service, mock_run):
        clear_system_socks_proxy("en0")
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "-setsocksfirewallproxystate" in args
        assert "off" in args

    @patch("nowifi.bypass._get_network_service", return_value="")
    def test_no_service_noop(self, mock_service):
        # Should not raise
        clear_system_socks_proxy("en0")
