"""Tests for leak enumeration (DNS, ICMP, IPv6, QUIC, NTP, DoH, ports)."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, call, patch

import pytest

from nowifi.probe import (
    TUNNEL_CANDIDATE_PORTS,
    DnsProbeResult,
    HttpsProbeResult,
    IcmpProbeResult,
    Ipv6ProbeResult,
    PortProbeResult,
    ProbeResults,
    WhitelistResult,
    _looks_like_portal_redirect,
    _probe_batch_sync,
    _try_dns_beacon,
    probe_all,
    probe_dns,
    probe_doh,
    probe_https,
    probe_icmp,
    probe_ipv6,
    probe_ntp,
    probe_ports,
    probe_quic,
    probe_tunnel_server,
    probe_udp_port,
    probe_whitelists,
)


# ---------------------------------------------------------------------------
# probe_dns
# ---------------------------------------------------------------------------

class TestProbeDns:

    @patch("nowifi.probe.time.sleep")
    @patch("dns.resolver.Resolver")
    def test_dns_open(self, MockResolver, mock_sleep):
        """External DNS resolver responds -> dns.is_open=True."""
        mock_resolver_instance = MagicMock()
        MockResolver.return_value = mock_resolver_instance

        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter([MagicMock(__str__=lambda _: "93.184.216.34")]))
        mock_resolver_instance.resolve.return_value = mock_answer

        result = probe_dns(stealth=False)
        assert result.is_open is True
        assert len(result.resolvers) > 0
        assert "reachable" in result.details.lower()

    @patch("nowifi.probe.time.sleep")
    @patch("dns.resolver.Resolver")
    def test_dns_closed(self, MockResolver, mock_sleep):
        """All DNS resolvers fail -> dns.is_open=False."""
        mock_resolver_instance = MagicMock()
        MockResolver.return_value = mock_resolver_instance
        mock_resolver_instance.resolve.side_effect = Exception("timeout")

        result = probe_dns(stealth=False)
        assert result.is_open is False
        assert result.resolvers == []

    @patch("nowifi.probe.time.sleep")
    @patch("dns.resolver.Resolver")
    def test_dns_stealth_has_delays(self, MockResolver, mock_sleep):
        """Stealth mode adds random delays between resolver checks."""
        mock_resolver_instance = MagicMock()
        MockResolver.return_value = mock_resolver_instance
        mock_resolver_instance.resolve.side_effect = Exception("timeout")

        probe_dns(stealth=True)
        assert mock_sleep.call_count >= 1  # at least some delays


# ---------------------------------------------------------------------------
# probe_icmp
# ---------------------------------------------------------------------------

class TestProbeIcmp:

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe.subprocess.run")
    def test_icmp_open(self, mock_run, mock_sleep):
        """Ping succeeds -> icmp.is_open=True."""
        mock_run.return_value = MagicMock(returncode=0)
        result = probe_icmp(stealth=False)
        assert result.is_open is True
        assert len(result.targets_reached) > 0

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe.subprocess.run")
    def test_icmp_closed(self, mock_run, mock_sleep):
        """Ping fails -> icmp.is_open=False."""
        mock_run.return_value = MagicMock(returncode=1)
        result = probe_icmp(stealth=False)
        assert result.is_open is False
        assert result.targets_reached == []

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe.subprocess.run")
    def test_icmp_timeout_exception(self, mock_run, mock_sleep):
        """Ping subprocess timeout -> treated as failure."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="ping", timeout=5)
        result = probe_icmp(stealth=False)
        assert result.is_open is False

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe.subprocess.run")
    def test_icmp_stealth_timing(self, mock_run, mock_sleep):
        """Stealth mode inserts delays between pings."""
        mock_run.return_value = MagicMock(returncode=1)
        probe_icmp(stealth=True)
        assert mock_sleep.call_count >= 1


# ---------------------------------------------------------------------------
# probe_ipv6
# ---------------------------------------------------------------------------

class TestProbeIpv6:

    @patch("nowifi.probe.socket.socket")
    @patch("nowifi.platform.get_ipv6_address", return_value="2001:db8::1")
    def test_ipv6_connected(self, mock_ipv6, mock_socket_cls):
        """IPv6 socket connects -> ipv6.is_open=True."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect.return_value = None  # success

        result = probe_ipv6(interface="en0")
        assert result.is_open is True
        assert "2001:db8::1" in result.address

    @patch("nowifi.platform.get_ipv6_address", return_value="")
    def test_ipv6_no_address(self, mock_ipv6):
        """No IPv6 address on interface -> not open."""
        result = probe_ipv6(interface="en0")
        assert result.is_open is False
        assert "No global IPv6 address" in result.details

    @patch("requests.get")
    @patch("nowifi.probe.socket.socket")
    @patch("nowifi.platform.get_ipv6_address", return_value="2001:db8::1")
    def test_ipv6_connect_fails_http_fallback(self, mock_ipv6, mock_socket_cls, mock_get):
        """IPv6 socket fails but HTTP fallback works -> open."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect.side_effect = socket.error("Connection refused")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        result = probe_ipv6(interface="en0")
        assert result.is_open is True

    @patch("requests.get")
    @patch("nowifi.probe.socket.socket")
    @patch("nowifi.platform.get_ipv6_address", return_value="2001:db8::1")
    def test_ipv6_all_fail(self, mock_ipv6, mock_socket_cls, mock_get):
        """Both socket and HTTP fallback fail -> not open."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect.side_effect = socket.error("Connection refused")
        mock_get.side_effect = Exception("No IPv6")

        result = probe_ipv6(interface="en0")
        assert result.is_open is False
        assert "no external connectivity" in result.details


# ---------------------------------------------------------------------------
# probe_https
# ---------------------------------------------------------------------------

class TestProbeHttps:

    @patch("requests.get")
    def test_https_open(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp
        result = probe_https("https://1.1.1.1", label="Cloudflare")
        assert result.is_open is True
        assert "Cloudflare" in result.details

    @patch("requests.get")
    def test_https_blocked(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_get.return_value = mock_resp
        result = probe_https("https://1.1.1.1", label="Cloudflare")
        assert result.is_open is False
        assert "blocked" in result.details

    @patch("requests.get")
    def test_https_connection_error(self, mock_get):
        mock_get.side_effect = Exception("Connection failed")
        result = probe_https("https://1.1.1.1")
        assert result.is_open is False
        assert "failed" in result.details


# ---------------------------------------------------------------------------
# probe_ports
# ---------------------------------------------------------------------------

class TestProbePorts:

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe._probe_batch_sync")
    def test_open_ports_returned(self, mock_batch, mock_sleep):
        """Open ports are in results."""
        mock_batch.return_value = [
            PortProbeResult(port=443, protocol="tcp", is_open=True, service="HTTPS"),
            PortProbeResult(port=80, protocol="tcp", is_open=True, service="HTTP"),
            PortProbeResult(port=22, protocol="tcp", is_open=False, service="SSH"),
        ]
        results = probe_ports(stealth=False)
        open_ports = [r for r in results if r.is_open]
        assert len(open_ports) >= 2

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe._probe_batch_sync")
    def test_closed_ports_in_results(self, mock_batch, mock_sleep):
        """Closed ports are also returned (just not marked open)."""
        mock_batch.return_value = [
            PortProbeResult(port=22, protocol="tcp", is_open=False, service="SSH"),
        ]
        results = probe_ports(stealth=False)
        assert any(not r.is_open for r in results)

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe._probe_batch_sync")
    def test_stealth_uses_smaller_batches(self, mock_batch, mock_sleep):
        """Stealth mode uses batch_size=4 (smaller)."""
        mock_batch.return_value = []
        probe_ports(stealth=True)
        # Stealth: batch_size=4, so more batches than fast mode
        stealth_calls = mock_batch.call_count

        mock_batch.reset_mock()
        mock_sleep.reset_mock()
        probe_ports(stealth=False)
        fast_calls = mock_batch.call_count

        assert stealth_calls >= fast_calls

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe._probe_batch_sync")
    def test_results_sorted_by_port(self, mock_batch, mock_sleep):
        """Results are sorted by port number."""
        mock_batch.return_value = [
            PortProbeResult(port=8080, protocol="tcp", is_open=True),
            PortProbeResult(port=80, protocol="tcp", is_open=True),
            PortProbeResult(port=443, protocol="tcp", is_open=True),
        ]
        results = probe_ports(stealth=False)
        ports = [r.port for r in results]
        assert ports == sorted(ports)


# ---------------------------------------------------------------------------
# _probe_batch_sync
# ---------------------------------------------------------------------------

class TestProbeBatchSync:

    @patch("nowifi.probe.socket.socket")
    def test_open_port_detected(self, mock_socket_cls):
        """Connect returns 0 -> port is open."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0

        results = _probe_batch_sync([443], "1.1.1.1", 1.5)
        assert len(results) == 1
        assert results[0].is_open is True
        assert results[0].port == 443

    @patch("nowifi.probe.socket.socket")
    def test_closed_port_detected(self, mock_socket_cls):
        """Connect returns non-zero -> port is closed."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect_ex.return_value = 111  # Connection refused

        results = _probe_batch_sync([22], "1.1.1.1", 1.5)
        assert len(results) == 1
        assert results[0].is_open is False

    @patch("nowifi.probe.socket.socket")
    def test_socket_error(self, mock_socket_cls):
        """Socket error -> port marked closed with error details."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect_ex.side_effect = socket.error("Network unreachable")

        results = _probe_batch_sync([80], "1.1.1.1", 1.5)
        assert len(results) == 1
        assert results[0].is_open is False
        assert "error" in results[0].details.lower()


# ---------------------------------------------------------------------------
# probe_tunnel_server
# ---------------------------------------------------------------------------

class TestProbeTunnelServer:

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe._try_dns_beacon", return_value=[])
    @patch("nowifi.probe._probe_batch_sync")
    def test_early_exit_on_open_port(self, mock_batch, mock_beacon, mock_sleep):
        """Stop scanning once first open port found (plus one more batch)."""
        # First batch: has an open port
        mock_batch.side_effect = [
            [PortProbeResult(port=443, protocol="tcp", is_open=True, service="HTTPS")],
            [PortProbeResult(port=80, protocol="tcp", is_open=False, service="HTTP")],
        ]
        results = probe_tunnel_server("203.0.113.1", stealth=False)
        open_results = [r for r in results if r.is_open]
        assert len(open_results) >= 1
        # Should have called batch at most twice (first found open + one more)
        assert mock_batch.call_count <= 3  # first batch + one more + maybe dns verify

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe._try_dns_beacon", return_value=[])
    @patch("nowifi.probe._probe_batch_sync")
    def test_all_closed(self, mock_batch, mock_beacon, mock_sleep):
        """All ports closed -> returns all results."""
        mock_batch.return_value = [
            PortProbeResult(port=443, protocol="tcp", is_open=False),
        ]
        results = probe_tunnel_server("203.0.113.1", stealth=False)
        assert all(not r.is_open for r in results)

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe._try_dns_beacon")
    @patch("nowifi.probe._probe_batch_sync")
    def test_dns_beacon_verified(self, mock_batch, mock_beacon, mock_sleep):
        """DNS beacon returns ports that are then verified."""
        mock_beacon.return_value = [443, 80]
        mock_batch.return_value = [
            PortProbeResult(port=443, protocol="tcp", is_open=True),
            PortProbeResult(port=80, protocol="tcp", is_open=True),
        ]
        results = probe_tunnel_server("203.0.113.1", stealth=False)
        assert any(r.is_open for r in results)


# ---------------------------------------------------------------------------
# probe_udp_port
# ---------------------------------------------------------------------------

class TestProbeUdpPort:

    @patch("nowifi.probe.socket.socket")
    def test_quic_packet_sent(self, mock_socket_cls):
        """UDP/443 sends QUIC Initial packet header."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (b'\x01\x02\x03', ("1.1.1.1", 443))

        result = probe_udp_port("1.1.1.1", 443, timeout=1.0)
        assert result is True

        # Verify a QUIC-like packet was sent
        send_call = mock_sock.sendto.call_args
        data = send_call[0][0]
        assert data[0] == 0xC0  # Long header, fixed bit

    @patch("nowifi.probe.socket.socket")
    def test_ntp_packet_sent(self, mock_socket_cls):
        """UDP/123 sends NTP client request."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (b'\x24' + b'\x00' * 47, ("pool.ntp.org", 123))

        result = probe_udp_port("pool.ntp.org", 123, timeout=1.0)
        assert result is True

        send_call = mock_sock.sendto.call_args
        data = send_call[0][0]
        assert data[0] == 0x23  # NTP mode 3, version 4
        assert len(data) == 48

    @patch("nowifi.probe.socket.socket")
    def test_udp_timeout(self, mock_socket_cls):
        """No response within timeout -> port closed."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout("timed out")

        result = probe_udp_port("1.1.1.1", 443, timeout=1.0)
        assert result is False

    @patch("nowifi.probe.socket.socket")
    def test_udp_socket_error(self, mock_socket_cls):
        """Socket error -> False."""
        mock_socket_cls.side_effect = socket.error("Network unreachable")
        result = probe_udp_port("1.1.1.1", 443, timeout=1.0)
        assert result is False

    @patch("nowifi.probe.socket.socket")
    def test_generic_udp_probe(self, mock_socket_cls):
        """Non-443/123 port sends generic probe."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (b'\x01', ("1.1.1.1", 5060))

        result = probe_udp_port("1.1.1.1", 5060, timeout=1.0)
        assert result is True
        send_call = mock_sock.sendto.call_args
        assert send_call[0][0] == b'\x00'  # generic 1-byte probe


# ---------------------------------------------------------------------------
# probe_quic
# ---------------------------------------------------------------------------

class TestProbeQuic:

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe.probe_udp_port", return_value=True)
    def test_quic_open(self, mock_udp, mock_sleep):
        result = probe_quic(stealth=False)
        assert result.is_open is True
        assert "QUIC" in result.details

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe.probe_udp_port", return_value=False)
    def test_quic_closed(self, mock_udp, mock_sleep):
        result = probe_quic(stealth=False)
        assert result.is_open is False


# ---------------------------------------------------------------------------
# probe_ntp
# ---------------------------------------------------------------------------

class TestProbeNtp:

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe.probe_udp_port", return_value=True)
    @patch("nowifi.probe.socket.gethostbyname", return_value="216.239.35.0")
    def test_ntp_open(self, mock_resolve, mock_udp, mock_sleep):
        result = probe_ntp(stealth=False)
        assert result.is_open is True
        assert "NTP open" in result.details

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe.probe_udp_port", return_value=False)
    @patch("nowifi.probe.socket.gethostbyname", return_value="216.239.35.0")
    def test_ntp_closed(self, mock_resolve, mock_udp, mock_sleep):
        result = probe_ntp(stealth=False)
        assert result.is_open is False

    @patch("nowifi.probe.time.sleep")
    @patch("nowifi.probe.socket.gethostbyname")
    def test_ntp_dns_fails(self, mock_resolve, mock_sleep):
        """All NTP server DNS lookups fail -> closed."""
        mock_resolve.side_effect = socket.gaierror("DNS failed")
        result = probe_ntp(stealth=False)
        assert result.is_open is False


# ---------------------------------------------------------------------------
# probe_doh
# ---------------------------------------------------------------------------

class TestProbeDoh:

    @patch("nowifi.probe.time.sleep")
    @patch("requests.get")
    def test_doh_open(self, mock_get, mock_sleep):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp
        result = probe_doh(stealth=False)
        assert result.is_open is True
        assert "DoH reachable" in result.details

    @patch("nowifi.probe.time.sleep")
    @patch("requests.get")
    def test_doh_closed(self, mock_get, mock_sleep):
        mock_get.side_effect = Exception("Connection failed")
        result = probe_doh(stealth=False)
        assert result.is_open is False


# ---------------------------------------------------------------------------
# probe_whitelists
# ---------------------------------------------------------------------------

class TestProbeWhitelists:

    @patch("nowifi.probe.time.sleep")
    @patch("requests.get")
    def test_whitelist_accessible(self, mock_get, mock_sleep):
        """Whitelisted domain returns 200 -> is_open=True."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.url = "http://captive.apple.com/hotspot-detect.html"
        mock_get.return_value = mock_resp
        results = probe_whitelists(stealth=False)
        assert any(w.is_open for w in results)

    @patch("nowifi.probe.time.sleep")
    @patch("requests.get")
    def test_whitelist_portal_redirect(self, mock_get, mock_sleep):
        """Whitelisted domain redirects to portal -> redirected=True."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.url = "http://portal.hotel.com/login?redirect=http://captive.apple.com"
        mock_get.return_value = mock_resp
        results = probe_whitelists(stealth=False)
        assert any(w.redirected for w in results)

    @patch("nowifi.probe.time.sleep")
    @patch("requests.get")
    def test_whitelist_connection_error(self, mock_get, mock_sleep):
        """Connection error -> not open, proper details."""
        import requests
        mock_get.side_effect = requests.ConnectionError("refused")
        results = probe_whitelists(stealth=False)
        assert all(not w.is_open for w in results)
        assert all("Connection" in w.details for w in results)


# ---------------------------------------------------------------------------
# _looks_like_portal_redirect
# ---------------------------------------------------------------------------

class TestLooksLikePortalRedirect:

    def test_different_domain_is_portal(self):
        assert _looks_like_portal_redirect(
            "http://portal.hotel.com/login",
            "http://captive.apple.com/hotspot-detect.html",
        ) is True

    def test_same_domain_not_portal(self):
        assert _looks_like_portal_redirect(
            "http://www.apple.com/other",
            "http://www.apple.com/store",
        ) is False

    def test_portal_keyword_in_url(self):
        assert _looks_like_portal_redirect(
            "http://10.0.0.1/login?url=foo",
            "http://10.0.0.1/some_page",
        ) is True

    def test_splash_keyword(self):
        assert _looks_like_portal_redirect(
            "http://10.0.0.1/splash/guest",
            "http://10.0.0.1/generate_204",
        ) is True

    def test_auth_keyword(self):
        assert _looks_like_portal_redirect(
            "http://10.0.0.1/auth/required",
            "http://10.0.0.1/test",
        ) is True

    def test_normal_redirect_no_keywords(self):
        assert _looks_like_portal_redirect(
            "http://10.0.0.1/home",
            "http://10.0.0.1/index",
        ) is False


# ---------------------------------------------------------------------------
# probe_all integration
# ---------------------------------------------------------------------------

class TestProbeAll:

    @patch("nowifi.probe.probe_tunnel_server")
    @patch("nowifi.probe.probe_doh")
    @patch("nowifi.probe.probe_ntp")
    @patch("nowifi.probe.probe_quic")
    @patch("nowifi.probe.probe_ports")
    @patch("nowifi.probe.probe_whitelists")
    @patch("nowifi.probe.probe_https")
    @patch("nowifi.probe.probe_ipv6")
    @patch("nowifi.probe.probe_icmp")
    @patch("nowifi.probe.probe_dns")
    @patch("nowifi.probe.time.sleep")
    def test_probe_all_calls_all_probes(
        self, mock_sleep, mock_dns, mock_icmp, mock_ipv6,
        mock_https, mock_wl, mock_ports, mock_quic, mock_ntp, mock_doh, mock_tunnel,
    ):
        """probe_all calls every probe function."""
        mock_dns.return_value = DnsProbeResult()
        mock_icmp.return_value = IcmpProbeResult()
        mock_ipv6.return_value = Ipv6ProbeResult()
        mock_https.return_value = HttpsProbeResult()
        mock_wl.return_value = []
        mock_ports.return_value = []
        mock_quic.return_value = PortProbeResult(port=443, protocol="udp")
        mock_ntp.return_value = PortProbeResult(port=123, protocol="udp")
        mock_doh.return_value = PortProbeResult(port=443, protocol="doh")

        results = probe_all(stealth=False)
        assert isinstance(results, ProbeResults)
        mock_dns.assert_called_once()
        mock_icmp.assert_called_once()
        mock_ipv6.assert_called_once()
        mock_https.assert_called_once()
        mock_wl.assert_called_once()
        mock_ports.assert_called_once()
        mock_quic.assert_called_once()
        mock_ntp.assert_called_once()
        mock_doh.assert_called_once()
        # No tunnel server IP -> probe_tunnel_server not called
        mock_tunnel.assert_not_called()

    @patch("nowifi.probe.probe_tunnel_server")
    @patch("nowifi.probe.probe_doh")
    @patch("nowifi.probe.probe_ntp")
    @patch("nowifi.probe.probe_quic")
    @patch("nowifi.probe.probe_ports")
    @patch("nowifi.probe.probe_whitelists")
    @patch("nowifi.probe.probe_https")
    @patch("nowifi.probe.probe_ipv6")
    @patch("nowifi.probe.probe_icmp")
    @patch("nowifi.probe.probe_dns")
    @patch("nowifi.probe.time.sleep")
    def test_probe_all_with_tunnel_server(
        self, mock_sleep, mock_dns, mock_icmp, mock_ipv6,
        mock_https, mock_wl, mock_ports, mock_quic, mock_ntp, mock_doh, mock_tunnel,
    ):
        """probe_all calls probe_tunnel_server when tunnel_server_ip is provided."""
        mock_dns.return_value = DnsProbeResult()
        mock_icmp.return_value = IcmpProbeResult()
        mock_ipv6.return_value = Ipv6ProbeResult()
        mock_https.return_value = HttpsProbeResult()
        mock_wl.return_value = []
        mock_ports.return_value = []
        mock_quic.return_value = PortProbeResult(port=443, protocol="udp")
        mock_ntp.return_value = PortProbeResult(port=123, protocol="udp")
        mock_doh.return_value = PortProbeResult(port=443, protocol="doh")
        mock_tunnel.return_value = []

        results = probe_all(stealth=False, tunnel_server_ip="203.0.113.1")
        mock_tunnel.assert_called_once_with("203.0.113.1", stealth=False)

    @patch("nowifi.probe.probe_tunnel_server")
    @patch("nowifi.probe.probe_doh")
    @patch("nowifi.probe.probe_ntp")
    @patch("nowifi.probe.probe_quic")
    @patch("nowifi.probe.probe_ports")
    @patch("nowifi.probe.probe_whitelists")
    @patch("nowifi.probe.probe_https")
    @patch("nowifi.probe.probe_ipv6")
    @patch("nowifi.probe.probe_icmp")
    @patch("nowifi.probe.probe_dns")
    @patch("nowifi.probe.time.sleep")
    def test_stealth_mode_adds_delays(
        self, mock_sleep, mock_dns, mock_icmp, mock_ipv6,
        mock_https, mock_wl, mock_ports, mock_quic, mock_ntp, mock_doh, mock_tunnel,
    ):
        """Stealth mode calls time.sleep between probes."""
        mock_dns.return_value = DnsProbeResult()
        mock_icmp.return_value = IcmpProbeResult()
        mock_ipv6.return_value = Ipv6ProbeResult()
        mock_https.return_value = HttpsProbeResult()
        mock_wl.return_value = []
        mock_ports.return_value = []
        mock_quic.return_value = PortProbeResult(port=443, protocol="udp")
        mock_ntp.return_value = PortProbeResult(port=123, protocol="udp")
        mock_doh.return_value = PortProbeResult(port=443, protocol="doh")

        probe_all(stealth=True)
        # Should have multiple sleep calls for stealth delays
        assert mock_sleep.call_count >= 5  # at least 5 delays between probes

    @patch("nowifi.probe.probe_tunnel_server")
    @patch("nowifi.probe.probe_doh")
    @patch("nowifi.probe.probe_ntp")
    @patch("nowifi.probe.probe_quic")
    @patch("nowifi.probe.probe_ports")
    @patch("nowifi.probe.probe_whitelists")
    @patch("nowifi.probe.probe_https")
    @patch("nowifi.probe.probe_ipv6")
    @patch("nowifi.probe.probe_icmp")
    @patch("nowifi.probe.probe_dns")
    @patch("nowifi.probe.time.sleep")
    def test_fast_mode_no_delays(
        self, mock_sleep, mock_dns, mock_icmp, mock_ipv6,
        mock_https, mock_wl, mock_ports, mock_quic, mock_ntp, mock_doh, mock_tunnel,
    ):
        """Fast mode (stealth=False) has no inter-probe delays."""
        mock_dns.return_value = DnsProbeResult()
        mock_icmp.return_value = IcmpProbeResult()
        mock_ipv6.return_value = Ipv6ProbeResult()
        mock_https.return_value = HttpsProbeResult()
        mock_wl.return_value = []
        mock_ports.return_value = []
        mock_quic.return_value = PortProbeResult(port=443, protocol="udp")
        mock_ntp.return_value = PortProbeResult(port=123, protocol="udp")
        mock_doh.return_value = PortProbeResult(port=443, protocol="doh")

        probe_all(stealth=False)
        mock_sleep.assert_not_called()
