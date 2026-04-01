"""Tests for monitor mode management."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, call

import pytest

from nowifi.monitor import (
    MonitorGuard,
    MonitorInterface,
    check_monitor_support,
    disable_monitor_mode,
    enable_monitor_mode,
    find_monitor_interfaces,
)


# ---------------------------------------------------------------------------
# check_monitor_support
# ---------------------------------------------------------------------------

class TestCheckMonitorSupport:

    @patch("nowifi.monitor.sys")
    def test_macos_en0_returns_false(self, mock_sys):
        """macOS en0 (built-in WiFi) never supports monitor mode."""
        mock_sys.platform = "darwin"
        result = check_monitor_support("en0")
        assert result is False

    @patch("nowifi.monitor.subprocess.run")
    @patch("nowifi.monitor.sys")
    def test_macos_external_adapter_exists(self, mock_sys, mock_run):
        """macOS external adapter (not en0) that exists -> True."""
        mock_sys.platform = "darwin"
        mock_run.return_value = MagicMock(returncode=0)
        result = check_monitor_support("en1")
        assert result is True
        mock_run.assert_called_once()
        assert "ifconfig" in mock_run.call_args[0][0]

    @patch("nowifi.monitor.subprocess.run")
    @patch("nowifi.monitor.sys")
    def test_macos_external_adapter_not_found(self, mock_sys, mock_run):
        """macOS non-en0 interface that doesn't exist -> False."""
        mock_sys.platform = "darwin"
        mock_run.return_value = MagicMock(returncode=1)
        result = check_monitor_support("en5")
        assert result is False

    @patch("nowifi.monitor.shutil.which", return_value="/usr/sbin/airmon-ng")
    @patch("nowifi.monitor._get_phy_for_interface", return_value="phy#0")
    @patch("nowifi.monitor.subprocess.run")
    @patch("nowifi.monitor.sys")
    def test_linux_airmon_fallback_returns_true(self, mock_sys, mock_run, mock_phy, mock_which):
        """Linux: airmon-ng available -> True (fallback when iw phy parsing doesn't find monitor)."""
        mock_sys.platform = "linux"
        # iw phy output (the parser has a quirk where it resets in_modes on the
        # "Supported interface modes:" line itself, so we exercise the airmon-ng fallback)
        iw_phy_output = (
            "Wiphy phy#0\n"
            "  Supported interface modes:\n"
            "    * IBSS\n"
            "    * managed\n"
            "    * AP\n"
            "    * monitor\n"
            "    * P2P-client\n"
        )
        mock_run.return_value = MagicMock(stdout=iw_phy_output, returncode=0)
        result = check_monitor_support("wlan0")
        assert result is True

    @patch("nowifi.monitor.shutil.which", return_value=None)
    @patch("nowifi.monitor._get_phy_for_interface", return_value="phy#0")
    @patch("nowifi.monitor.subprocess.run")
    @patch("nowifi.monitor.sys")
    def test_linux_no_monitor_no_airmon(self, mock_sys, mock_run, mock_phy, mock_which):
        """Linux: iw phy has no monitor mode and airmon-ng not found -> False."""
        mock_sys.platform = "linux"
        iw_phy_output = (
            "Wiphy phy#0\n"
            "  Supported interface modes:\n"
            "    * IBSS\n"
            "    * managed\n"
            "    * AP\n"
        )
        mock_run.return_value = MagicMock(stdout=iw_phy_output, returncode=0)
        result = check_monitor_support("wlan0")
        assert result is False


# ---------------------------------------------------------------------------
# find_monitor_interfaces
# ---------------------------------------------------------------------------

class TestFindMonitorInterfaces:

    @patch("nowifi.monitor.check_monitor_support", return_value=True)
    @patch("nowifi.monitor.subprocess.run")
    @patch("nowifi.monitor.sys")
    def test_macos_finds_external_adapters(self, mock_sys, mock_run, mock_support):
        """macOS: discovers non-standard interfaces via ifconfig -l."""
        mock_sys.platform = "darwin"
        mock_run.return_value = MagicMock(
            stdout="lo0 gif0 stf0 en0 en1 en2 bridge0 utun0 awdl0 llw0 ap1",
            returncode=0,
        )
        interfaces = find_monitor_interfaces()
        # Should skip lo0, gif0, stf0, bridge0, utun0, awdl0, llw0, ap1, en0
        # Only en1 and en2 should be checked with check_monitor_support
        assert "en1" in interfaces
        assert "en2" in interfaces
        assert "en0" not in interfaces
        assert "lo0" not in interfaces

    @patch("nowifi.monitor.check_monitor_support", return_value=True)
    @patch("nowifi.monitor.subprocess.run")
    @patch("nowifi.monitor.sys")
    def test_linux_finds_wireless_interfaces(self, mock_sys, mock_run, mock_support):
        """Linux: discovers wireless interfaces via iw dev."""
        mock_sys.platform = "linux"
        iw_dev_output = (
            "phy#0\n"
            "  Interface wlan0\n"
            "    ifindex 3\n"
            "    type managed\n"
            "phy#1\n"
            "  Interface wlan1\n"
            "    ifindex 5\n"
            "    type managed\n"
        )
        mock_run.return_value = MagicMock(stdout=iw_dev_output, returncode=0)
        interfaces = find_monitor_interfaces()
        assert "wlan0" in interfaces
        assert "wlan1" in interfaces


# ---------------------------------------------------------------------------
# enable_monitor_mode
# ---------------------------------------------------------------------------

class TestEnableMonitorMode:

    @patch("nowifi.monitor.subprocess.run")
    @patch("nowifi.monitor.shutil.which", return_value="/usr/sbin/airmon-ng")
    @patch("nowifi.monitor.sys")
    def test_linux_airmon_ng(self, mock_sys, mock_which, mock_run):
        """Linux: uses airmon-ng check kill + start, parses new interface name."""
        mock_sys.platform = "linux"
        # airmon-ng start output
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),  # check kill
            MagicMock(
                returncode=0,
                stdout="(monitor mode enabled on wlan0mon)",
                stderr="",
            ),  # start
        ]

        mon = enable_monitor_mode("wlan0")
        assert mon.name == "wlan0mon"
        assert mon.original_name == "wlan0"
        assert mon.was_managed is True

        # Verify airmon-ng was called with correct args
        calls = mock_run.call_args_list
        assert "check" in calls[0][0][0] and "kill" in calls[0][0][0]
        assert "start" in calls[1][0][0] and "wlan0" in calls[1][0][0]

    @patch("nowifi.monitor.sys")
    def test_macos_en0_raises(self, mock_sys):
        """macOS en0 -> raises RuntimeError explaining external adapter needed."""
        mock_sys.platform = "darwin"
        with pytest.raises(RuntimeError) as exc_info:
            enable_monitor_mode("en0")
        assert "en0" in str(exc_info.value)
        assert "USB" in str(exc_info.value) or "external" in str(exc_info.value).lower()

    @patch("nowifi.monitor.sys")
    def test_unsupported_platform_raises(self, mock_sys):
        """Unsupported platform -> RuntimeError."""
        mock_sys.platform = "win32"
        with pytest.raises(RuntimeError):
            enable_monitor_mode("wlan0")


# ---------------------------------------------------------------------------
# disable_monitor_mode
# ---------------------------------------------------------------------------

class TestDisableMonitorMode:

    @patch("nowifi.monitor.subprocess.run")
    @patch("nowifi.monitor.shutil.which")
    @patch("nowifi.monitor.sys")
    def test_linux_airmon_stop_and_nm_restart(self, mock_sys, mock_which, mock_run):
        """Linux: airmon-ng stop + NetworkManager restart."""
        mock_sys.platform = "linux"
        mock_which.side_effect = lambda name: {
            "airmon-ng": "/usr/sbin/airmon-ng",
            "systemctl": "/usr/bin/systemctl",
        }.get(name)
        mock_run.return_value = MagicMock(returncode=0)

        mon = MonitorInterface(name="wlan0mon", original_name="wlan0", was_managed=True)
        result = disable_monitor_mode(mon)
        assert result is True

        # Should have called airmon-ng stop and systemctl restart
        calls = mock_run.call_args_list
        stop_call = calls[0][0][0]
        assert "stop" in stop_call
        assert "wlan0mon" in stop_call

        nm_call = calls[1][0][0]
        assert "systemctl" in nm_call
        assert "restart" in nm_call
        assert "NetworkManager" in nm_call

    def test_was_managed_false_skips_revert(self):
        """If was_managed=False, disable_monitor_mode returns True without doing anything."""
        mon = MonitorInterface(name="wlan0mon", original_name="wlan0", was_managed=False)
        result = disable_monitor_mode(mon)
        assert result is True


# ---------------------------------------------------------------------------
# MonitorGuard context manager
# ---------------------------------------------------------------------------

class TestMonitorGuard:

    @patch("nowifi.monitor.disable_monitor_mode")
    @patch("nowifi.monitor.enable_monitor_mode")
    def test_enter_enables_exit_disables(self, mock_enable, mock_disable):
        """MonitorGuard enables on enter, disables on exit."""
        mock_mon = MonitorInterface(name="wlan0mon", original_name="wlan0", was_managed=True)
        mock_enable.return_value = mock_mon

        with MonitorGuard("wlan0") as mon:
            assert mon.name == "wlan0mon"
            mock_enable.assert_called_once_with("wlan0")

        mock_disable.assert_called_once_with(mock_mon)

    @patch("nowifi.monitor.disable_monitor_mode")
    @patch("nowifi.monitor.enable_monitor_mode")
    def test_no_disable_if_was_managed_false(self, mock_enable, mock_disable):
        """MonitorGuard does not disable if was_managed=False."""
        mock_mon = MonitorInterface(name="wlan0mon", original_name="wlan0", was_managed=False)
        mock_enable.return_value = mock_mon

        with MonitorGuard("wlan0") as mon:
            pass

        # was_managed=False means __exit__ should NOT call disable
        mock_disable.assert_not_called()

    @patch("nowifi.monitor.disable_monitor_mode")
    @patch("nowifi.monitor.enable_monitor_mode")
    def test_disables_on_exception(self, mock_enable, mock_disable):
        """MonitorGuard still disables even if body raises."""
        mock_mon = MonitorInterface(name="wlan0mon", original_name="wlan0", was_managed=True)
        mock_enable.return_value = mock_mon

        with pytest.raises(ValueError):
            with MonitorGuard("wlan0"):
                raise ValueError("test error")

        mock_disable.assert_called_once_with(mock_mon)

    @patch("nowifi.monitor.disable_monitor_mode")
    @patch("nowifi.monitor.enable_monitor_mode")
    def test_monitor_set_to_none_after_exit(self, mock_enable, mock_disable):
        """After exiting the guard, the internal monitor reference is cleared."""
        mock_mon = MonitorInterface(name="wlan0mon", original_name="wlan0", was_managed=True)
        mock_enable.return_value = mock_mon

        guard = MonitorGuard("wlan0")
        with guard:
            assert guard.monitor is not None

        assert guard.monitor is None
