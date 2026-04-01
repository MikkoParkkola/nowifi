"""Tests for macOS platform operations."""

from __future__ import annotations

import atexit
import signal
from unittest.mock import MagicMock, call, patch

import pytest

from nowifi.platform_mac import (
    ArpEntry,
    StateGuard,
    WifiInfo,
    _parse_rssi,
    connect_wifi,
    disconnect_wifi,
    flush_dns,
    generate_random_mac,
    get_arp_table,
    get_current_mac,
    get_gateway,
    get_ipv6_address,
    get_local_ip,
    get_wifi_info,
    rejoin_wifi,
    renew_dhcp,
    set_mac,
)


# ---------------------------------------------------------------------------
# generate_random_mac
# ---------------------------------------------------------------------------

class TestGenerateRandomMac:

    def test_format(self):
        """MAC address is in xx:xx:xx:xx:xx:xx format."""
        mac = generate_random_mac()
        parts = mac.split(":")
        assert len(parts) == 6
        for part in parts:
            assert len(part) == 2
            int(part, 16)  # should not raise

    def test_locally_administered_bit(self):
        """Locally administered bit is set (bit 1 of first octet)."""
        for _ in range(20):
            mac = generate_random_mac()
            first_byte = int(mac.split(":")[0], 16)
            assert first_byte & 0x02 == 0x02  # LA bit set

    def test_unicast_bit(self):
        """Unicast bit is set (bit 0 of first octet = 0)."""
        for _ in range(20):
            mac = generate_random_mac()
            first_byte = int(mac.split(":")[0], 16)
            assert first_byte & 0x01 == 0x00  # unicast (bit 0 = 0)

    def test_randomness(self):
        """Multiple calls produce different MACs."""
        macs = {generate_random_mac() for _ in range(10)}
        assert len(macs) > 1  # at least some variation

    def test_valid_first_bytes(self):
        """First byte is one of [0x02, 0x06, 0x0A, 0x0E]."""
        valid = {0x02, 0x06, 0x0A, 0x0E}
        for _ in range(50):
            mac = generate_random_mac()
            first_byte = int(mac.split(":")[0], 16)
            assert first_byte in valid


# ---------------------------------------------------------------------------
# get_arp_table
# ---------------------------------------------------------------------------

class TestGetArpTable:

    @patch("nowifi.platform_mac.subprocess.run")
    def test_parses_arp_output(self, mock_run, mock_arp_output):
        """Parses real arp -a output format."""
        mock_run.return_value = MagicMock(stdout=mock_arp_output)
        entries = get_arp_table()
        # Should have 3 valid entries (skip incomplete and broadcast ff:ff)
        # Actually ff:ff:ff:ff:ff:ff doesn't match because regex expects
        # 17-char MAC, let's see what the actual filter does
        ips = [e.ip for e in entries]
        macs = [e.mac for e in entries]
        assert "192.168.1.1" in ips
        assert "192.168.1.50" in ips
        assert "192.168.1.51" in ips
        assert "192.168.1.52" in ips
        # Incomplete entry should be skipped
        assert "192.168.1.200" not in ips
        # All entries on en0
        assert all(e.interface == "en0" for e in entries)

    @patch("nowifi.platform_mac.subprocess.run")
    def test_empty_arp_table(self, mock_run):
        mock_run.return_value = MagicMock(stdout="")
        entries = get_arp_table()
        assert entries == []

    @patch("nowifi.platform_mac.subprocess.run")
    def test_timeout_returns_empty(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="arp", timeout=5)
        entries = get_arp_table()
        assert entries == []


# ---------------------------------------------------------------------------
# get_current_mac
# ---------------------------------------------------------------------------

class TestGetCurrentMac:

    @patch("nowifi.platform_mac.subprocess.run")
    def test_parses_mac_from_ifconfig(self, mock_run, mock_ifconfig_output):
        mock_run.return_value = MagicMock(stdout=mock_ifconfig_output)
        mac = get_current_mac("en0")
        assert mac == "aa:bb:cc:dd:ee:ff"

    @patch("nowifi.platform_mac.subprocess.run")
    def test_no_mac_found(self, mock_run):
        mock_run.return_value = MagicMock(stdout="en0: flags=8863\n  status: active\n")
        mac = get_current_mac("en0")
        assert mac == ""

    @patch("nowifi.platform_mac.subprocess.run")
    def test_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="ifconfig", timeout=5)
        mac = get_current_mac("en0")
        assert mac == ""


# ---------------------------------------------------------------------------
# set_mac
# ---------------------------------------------------------------------------

class TestSetMac:

    @patch("nowifi.platform_mac.subprocess.run")
    def test_set_mac_success(self, mock_run):
        mock_run.return_value = MagicMock()
        result = set_mac("en0", "02:ab:cd:ef:01:23")
        assert result is True
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "sudo" in args
        assert "ether" in args
        assert "02:ab:cd:ef:01:23" in args

    @patch("nowifi.platform_mac.subprocess.run")
    def test_set_mac_failure(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.CalledProcessError(1, "ifconfig")
        result = set_mac("en0", "02:ab:cd:ef:01:23")
        assert result is False


# ---------------------------------------------------------------------------
# get_gateway
# ---------------------------------------------------------------------------

class TestGetGateway:

    @patch("nowifi.platform_mac.subprocess.run")
    def test_parses_gateway(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="   route to: default\ndestination: default\n   gateway: 192.168.1.1\n",
        )
        gw = get_gateway("en0")
        assert gw == "192.168.1.1"

    @patch("nowifi.platform_mac.subprocess.run")
    def test_no_gateway(self, mock_run):
        mock_run.return_value = MagicMock(stdout="route: not found\n")
        gw = get_gateway("en0")
        assert gw == ""


# ---------------------------------------------------------------------------
# get_local_ip
# ---------------------------------------------------------------------------

class TestGetLocalIp:

    @patch("nowifi.platform_mac.subprocess.run")
    def test_parses_ip(self, mock_run, mock_ifconfig_output):
        mock_run.return_value = MagicMock(stdout=mock_ifconfig_output)
        ip = get_local_ip("en0")
        assert ip == "192.168.1.100"

    @patch("nowifi.platform_mac.subprocess.run")
    def test_no_ip(self, mock_run):
        mock_run.return_value = MagicMock(stdout="en0: flags=8863\n  status: active\n")
        ip = get_local_ip("en0")
        assert ip == ""


# ---------------------------------------------------------------------------
# get_ipv6_address
# ---------------------------------------------------------------------------

class TestGetIpv6Address:

    @patch("nowifi.platform_mac.subprocess.run")
    def test_returns_global_ipv6(self, mock_run, mock_ifconfig_output):
        mock_run.return_value = MagicMock(stdout=mock_ifconfig_output)
        addr = get_ipv6_address("en0")
        assert addr == "2001:db8::1"

    @patch("nowifi.platform_mac.subprocess.run")
    def test_skips_link_local(self, mock_run):
        """Link-local fe80:: address should be skipped."""
        mock_run.return_value = MagicMock(
            stdout="en0: flags=8863\n  inet6 fe80::1%en0 prefixlen 64\n",
        )
        addr = get_ipv6_address("en0")
        assert addr == ""

    @patch("nowifi.platform_mac.subprocess.run")
    def test_no_ipv6(self, mock_run):
        mock_run.return_value = MagicMock(stdout="en0: flags=8863\n  inet 192.168.1.100\n")
        addr = get_ipv6_address("en0")
        assert addr == ""


# ---------------------------------------------------------------------------
# _parse_rssi
# ---------------------------------------------------------------------------

class TestParseRssi:

    def test_int_input(self):
        assert _parse_rssi(-64) == -64

    def test_string_dbm(self):
        assert _parse_rssi("-64 dBm / -96 dBm") == -64

    def test_plain_string(self):
        assert _parse_rssi("-72") == -72

    def test_invalid_string(self):
        assert _parse_rssi("unknown") == -99

    def test_empty_string(self):
        assert _parse_rssi("") == -99


# ---------------------------------------------------------------------------
# get_wifi_info
# ---------------------------------------------------------------------------

class TestGetWifiInfo:

    @patch("nowifi.platform_mac.subprocess.run")
    def test_system_profiler_success(self, mock_run):
        import json
        profiler_data = {
            "SPAirPortDataType": [{
                "spairport_airport_interfaces": [{
                    "spairport_current_network_information": {
                        "_name": "Hotel_WiFi",
                        "spairport_network_bssid": "aa:bb:cc:dd:ee:01",
                        "spairport_network_channel": "36",
                        "spairport_security_mode": "WPA2 Personal",
                        "spairport_signal_noise": "-64 dBm / -96 dBm",
                    },
                }],
            }],
        }
        mock_run.return_value = MagicMock(stdout=json.dumps(profiler_data))
        info = get_wifi_info("en0")
        assert info is not None
        assert info.ssid == "Hotel_WiFi"
        assert info.bssid == "aa:bb:cc:dd:ee:01"
        assert info.channel == "36"
        assert info.rssi == -64

    @patch("nowifi.platform_mac.subprocess.run")
    def test_all_methods_fail_returns_none(self, mock_run):
        """All fallback methods fail -> None."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="system_profiler", timeout=10)
        info = get_wifi_info("en0")
        assert info is None


# ---------------------------------------------------------------------------
# disconnect_wifi / connect_wifi
# ---------------------------------------------------------------------------

class TestWifiPower:

    @patch("nowifi.platform_mac.subprocess.run")
    def test_disconnect_success(self, mock_run):
        assert disconnect_wifi("en0") is True
        args = mock_run.call_args[0][0]
        assert "off" in args

    @patch("nowifi.platform_mac.subprocess.run")
    def test_disconnect_failure(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.CalledProcessError(1, "networksetup")
        assert disconnect_wifi("en0") is False

    @patch("nowifi.platform_mac.subprocess.run")
    def test_connect_success(self, mock_run):
        assert connect_wifi("en0") is True
        args = mock_run.call_args[0][0]
        assert "on" in args


# ---------------------------------------------------------------------------
# rejoin_wifi
# ---------------------------------------------------------------------------

class TestRejoinWifi:

    @patch("nowifi.platform_mac.subprocess.run")
    def test_rejoin_without_password(self, mock_run):
        assert rejoin_wifi("en0", "Hotel_WiFi") is True
        args = mock_run.call_args[0][0]
        assert "Hotel_WiFi" in args
        assert len(args) == 4  # no password arg

    @patch("nowifi.platform_mac.subprocess.run")
    def test_rejoin_with_password(self, mock_run):
        assert rejoin_wifi("en0", "Hotel_WiFi", password="secret") is True
        args = mock_run.call_args[0][0]
        assert "secret" in args


# ---------------------------------------------------------------------------
# renew_dhcp / flush_dns
# ---------------------------------------------------------------------------

class TestNetworkOps:

    @patch("nowifi.platform_mac.subprocess.run")
    def test_renew_dhcp(self, mock_run):
        assert renew_dhcp("en0") is True

    @patch("nowifi.platform_mac.subprocess.run")
    def test_flush_dns(self, mock_run):
        assert flush_dns() is True
        assert mock_run.call_count == 2  # dscacheutil + killall mDNSResponder


# ---------------------------------------------------------------------------
# StateGuard
# ---------------------------------------------------------------------------

class TestStateGuard:

    @patch("nowifi.platform_mac.flush_dns", return_value=True)
    @patch("nowifi.platform_mac.renew_dhcp", return_value=True)
    @patch("nowifi.platform_mac.set_mac", return_value=True)
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    def test_registers_atexit(self, mock_mac, mock_set, mock_dhcp, mock_flush):
        """StateGuard registers atexit handler on __enter__."""
        with patch("nowifi.platform_mac.atexit.register") as mock_atexit:
            guard = StateGuard("en0")
            with guard:
                mock_atexit.assert_called_once_with(guard.restore)

    @patch("nowifi.platform_mac.flush_dns", return_value=True)
    @patch("nowifi.platform_mac.renew_dhcp", return_value=True)
    @patch("nowifi.platform_mac.set_mac", return_value=True)
    @patch("nowifi.platform_mac.get_current_mac")
    def test_restores_mac_on_exit(self, mock_mac, mock_set, mock_dhcp, mock_flush):
        """StateGuard restores original MAC on __exit__."""
        # First call: save original, second call: check current (different)
        mock_mac.side_effect = ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]

        with patch("nowifi.platform_mac.atexit.register"):
            guard = StateGuard("en0")
            guard.__enter__()
            guard.__exit__(None, None, None)

        mock_set.assert_called_with("en0", "aa:bb:cc:dd:ee:ff")

    @patch("nowifi.platform_mac.flush_dns", return_value=True)
    @patch("nowifi.platform_mac.renew_dhcp", return_value=True)
    @patch("nowifi.platform_mac.set_mac", return_value=True)
    @patch("nowifi.platform_mac.get_current_mac")
    def test_no_restore_if_mac_unchanged(self, mock_mac, mock_set, mock_dhcp, mock_flush):
        """StateGuard doesn't restore MAC if it hasn't changed."""
        mock_mac.return_value = "aa:bb:cc:dd:ee:ff"

        with patch("nowifi.platform_mac.atexit.register"):
            guard = StateGuard("en0")
            guard.__enter__()
            guard.__exit__(None, None, None)

        mock_set.assert_not_called()

    @patch("nowifi.platform_mac.flush_dns", return_value=True)
    @patch("nowifi.platform_mac.renew_dhcp", return_value=True)
    @patch("nowifi.platform_mac.set_mac", return_value=True)
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    def test_signal_handler_registered(self, mock_mac, mock_set, mock_dhcp, mock_flush):
        """StateGuard registers SIGINT and SIGTERM handlers."""
        with patch("nowifi.platform_mac.atexit.register"), \
             patch("nowifi.platform_mac.signal.signal") as mock_signal, \
             patch("nowifi.platform_mac.signal.getsignal", return_value=signal.SIG_DFL):
            guard = StateGuard("en0")
            guard.__enter__()
            # SIGINT and SIGTERM should be registered
            signal_calls = [c[0][0] for c in mock_signal.call_args_list]
            assert signal.SIGINT in signal_calls
            assert signal.SIGTERM in signal_calls
            guard.__exit__(None, None, None)

    @patch("nowifi.platform_mac.flush_dns", return_value=True)
    @patch("nowifi.platform_mac.renew_dhcp", return_value=True)
    @patch("nowifi.platform_mac.set_mac", return_value=True)
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    def test_signal_handler_restores(self, mock_mac, mock_set, mock_dhcp, mock_flush):
        """Signal handler calls restore and raises SystemExit."""
        with patch("nowifi.platform_mac.atexit.register"), \
             patch("nowifi.platform_mac.signal.getsignal", return_value=signal.SIG_DFL):
            guard = StateGuard("en0")
            guard.__enter__()
            with pytest.raises(SystemExit):
                guard._signal_handler(signal.SIGINT, None)

    @patch("nowifi.platform_mac.flush_dns", return_value=True)
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    def test_stops_tunnel_handles(self, mock_mac, mock_flush):
        """StateGuard stops registered tunnel handles on restore."""
        mock_handle = MagicMock()

        with patch("nowifi.platform_mac.atexit.register"), \
             patch("nowifi.platform_mac.signal.getsignal", return_value=signal.SIG_DFL), \
             patch("nowifi.platform_mac.signal.signal"):
            guard = StateGuard("en0")
            guard.__enter__()
            guard.register_tunnel(mock_handle)
            guard.__exit__(None, None, None)

        mock_handle.stop.assert_called_once()

    @patch("nowifi.platform_mac.flush_dns", return_value=True)
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    def test_restore_idempotent(self, mock_mac, mock_flush):
        """restore() is idempotent -- calling twice doesn't double-restore."""
        with patch("nowifi.platform_mac.atexit.register"), \
             patch("nowifi.platform_mac.signal.getsignal", return_value=signal.SIG_DFL), \
             patch("nowifi.platform_mac.signal.signal"):
            guard = StateGuard("en0")
            guard.__enter__()
            guard.restore()
            mock_flush.reset_mock()
            guard.restore()  # second call should be no-op
            mock_flush.assert_not_called()

    @patch("nowifi.platform_mac.flush_dns", return_value=True)
    @patch("nowifi.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    def test_clears_socks_proxy(self, mock_mac, mock_flush):
        """StateGuard clears system SOCKS proxy on restore."""
        with patch("nowifi.platform_mac.atexit.register"), \
             patch("nowifi.platform_mac.signal.getsignal", return_value=signal.SIG_DFL), \
             patch("nowifi.platform_mac.signal.signal"), \
             patch("nowifi.bypass.clear_system_socks_proxy") as mock_clear:
            guard = StateGuard("en0")
            guard.__enter__()
            guard.__exit__(None, None, None)
            mock_clear.assert_called_once_with("en0")
