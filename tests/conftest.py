"""Shared fixtures for nowifi test suite."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

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
from nowifi.bypass import AuditConfig, BypassMethod, BypassResult, Severity
from nowifi.tunnel import TunnelHandle


# ---------------------------------------------------------------------------
# Portal fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_portal_captive():
    return PortalInfo(
        is_captive=True,
        portal_type=PortalType.HTTP_REDIRECT,
        portal_url="http://portal.hotel.com/login",
        redirect_url="http://portal.hotel.com/login",
        vendor="unifi",
        vendor_details="Matched with confidence score 3",
        auth_methods=["email", "password"],
        portal_ip="192.168.1.1",
        ssid="Hotel_WiFi",
        gateway="192.168.1.1",
    )


@pytest.fixture
def fake_portal_dns_hijack():
    return PortalInfo(
        is_captive=True,
        portal_type=PortalType.DNS_HIJACK,
        portal_ip="10.0.0.1",
        ssid="Airport_Free",
        gateway="10.0.0.1",
    )


@pytest.fixture
def fake_portal_open():
    return PortalInfo(is_captive=False, portal_type=PortalType.NONE)


# ---------------------------------------------------------------------------
# Probe result fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_probes_all_open():
    return ProbeResults(
        dns=DnsProbeResult(
            is_open=True,
            resolvers=[{"ip": "1.1.1.1", "name": "Cloudflare", "resolved": "93.184.216.34"}],
            details="External DNS reachable: Cloudflare",
        ),
        icmp=IcmpProbeResult(
            is_open=True,
            targets_reached=["Cloudflare (1.1.1.1)"],
            details="ICMP open to: Cloudflare (1.1.1.1)",
        ),
        ipv6=Ipv6ProbeResult(
            is_open=True,
            address="2001:db8::1",
            details="IPv6 unfiltered! Connected to google.com",
        ),
        cloudflare=HttpsProbeResult(is_open=True, url="https://1.1.1.1", details="Cloudflare: HTTP 200"),
        quic=PortProbeResult(port=443, protocol="udp", is_open=True, service="QUIC/HTTP3", details="UDP/443 (QUIC) open"),
        ntp=PortProbeResult(port=123, protocol="udp", is_open=True, service="NTP", details="NTP open"),
        doh=PortProbeResult(port=443, protocol="doh", is_open=True, service="DoH", details="DoH reachable via Cloudflare DoH"),
        whitelists=[
            WhitelistResult(domain="captive.apple.com", is_open=True, status_code=200, details="Accessible (HTTP 200)"),
        ],
        open_ports=[
            PortProbeResult(port=443, protocol="tcp", is_open=True, service="HTTPS", details="TCP/443 (HTTPS) open"),
            PortProbeResult(port=80, protocol="tcp", is_open=True, service="HTTP", details="TCP/80 (HTTP) open"),
        ],
    )


@pytest.fixture
def fake_probes_all_closed():
    return ProbeResults()


@pytest.fixture
def fake_probes_dns_only():
    return ProbeResults(
        dns=DnsProbeResult(
            is_open=True,
            resolvers=[{"ip": "8.8.8.8", "name": "Google", "resolved": "93.184.216.34"}],
            details="External DNS reachable: Google",
        ),
    )


@pytest.fixture
def fake_probes_icmp_only():
    return ProbeResults(
        icmp=IcmpProbeResult(
            is_open=True,
            targets_reached=["Cloudflare (1.1.1.1)"],
            details="ICMP open to: Cloudflare (1.1.1.1)",
        ),
    )


@pytest.fixture
def fake_probes_ipv6_only():
    return ProbeResults(
        ipv6=Ipv6ProbeResult(
            is_open=True,
            address="2001:db8::1",
            details="IPv6 unfiltered! Connected to google.com",
        ),
    )


# ---------------------------------------------------------------------------
# Config fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_config():
    return AuditConfig(
        interface="en0",
        tunnel_server="https://test.example.com",
        stealth=True,
    )


@pytest.fixture
def fake_config_with_dns():
    return AuditConfig(
        interface="en0",
        tunnel_server="https://test.example.com",
        dns_tunnel_domain="t.example.com",
        stealth=True,
    )


@pytest.fixture
def fake_config_with_icmp():
    return AuditConfig(
        interface="en0",
        tunnel_server="https://test.example.com",
        icmp_tunnel_server="203.0.113.1",
        stealth=True,
    )


@pytest.fixture
def fake_config_with_all():
    return AuditConfig(
        interface="en0",
        tunnel_server="https://test.example.com",
        dns_tunnel_domain="t.example.com",
        icmp_tunnel_server="203.0.113.1",
        cf_workers_url="https://my-proxy.workers.dev",
        quic_server="quic.example.com",
        ntp_server="203.0.113.2",
        stealth=True,
    )


# ---------------------------------------------------------------------------
# Tunnel handle fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_tunnel_handle():
    handle = TunnelHandle(process=MagicMock(), local_port=1080, method="chisel")
    handle.active = True
    return handle


# ---------------------------------------------------------------------------
# ARP table fixtures
# ---------------------------------------------------------------------------

ARP_OUTPUT_STANDARD = """\
? (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0 ifscope [ethernet]
? (192.168.1.50) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
? (192.168.1.51) at 22:33:44:55:66:77 on en0 ifscope [ethernet]
? (192.168.1.52) at 33:44:55:66:77:88 on en0 ifscope [ethernet]
? (192.168.1.200) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
"""


@pytest.fixture
def mock_arp_output():
    return ARP_OUTPUT_STANDARD


IFCONFIG_OUTPUT_EN0 = """\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=6467<RXCSUM,TXCSUM,VLAN_MTU,TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
	ether aa:bb:cc:dd:ee:ff
	inet6 fe80::1%en0 prefixlen 64 scopeid 0x6
	inet6 2001:db8::1 prefixlen 64 autoconf
	inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect
	status: active
"""


@pytest.fixture
def mock_ifconfig_output():
    return IFCONFIG_OUTPUT_EN0
