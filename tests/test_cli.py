"""Tests for CLI integration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from nowifi import __version__
from nowifi.cli import main


# ---------------------------------------------------------------------------
# CLI basics
# ---------------------------------------------------------------------------

class TestCliBasics:

    def test_version(self):
        """--version returns version string."""
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_help(self):
        """--help contains key info."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "19 techniques" in result.output
        assert "nowifi" in result.output.lower()
        assert "--probe-only" in result.output
        assert "--stealth" in result.output

    def test_help_contains_subcommands(self):
        """--help shows available subcommands."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert "audit" in result.output
        assert "reset" in result.output
        assert "ui" in result.output
        assert "menubar" in result.output
        assert "setup" in result.output
        assert "doctor" in result.output
        assert "uninstall" in result.output

    def test_audit_help(self):
        """audit --help works."""
        runner = CliRunner()
        result = runner.invoke(main, ["audit", "--help"])
        assert result.exit_code == 0
        assert "--interface" in result.output


# ---------------------------------------------------------------------------
# CLI invocation: default (full audit)
# ---------------------------------------------------------------------------

class TestCliFullAudit:

    @patch("nowifi.cli.print_terminal_report")
    @patch("nowifi.cli.probe_all")
    @patch("nowifi.cli.detect_portal")
    @patch("nowifi.cli.get_gateway", return_value="192.168.1.1")
    @patch("nowifi.cli.get_wifi_info")
    def test_default_invocation(
        self, mock_wifi, mock_gw, mock_detect, mock_probe, mock_report,
    ):
        """Default invocation runs full audit pipeline."""
        from nowifi.platform_mac import WifiInfo
        from nowifi.detect import PortalInfo, PortalType
        from nowifi.probe import ProbeResults

        mock_wifi.return_value = WifiInfo(
            ssid="Hotel_WiFi", bssid="", channel="", security="", rssi=-64,
        )
        mock_detect.return_value = PortalInfo(is_captive=False, portal_type=PortalType.NONE)
        mock_probe.return_value = ProbeResults()

        runner = CliRunner()
        result = runner.invoke(main, [])
        assert result.exit_code == 0
        mock_wifi.assert_called_once()
        mock_detect.assert_called_once()
        mock_probe.assert_called_once()
        mock_report.assert_called_once()

    @patch("nowifi.cli.print_terminal_report")
    @patch("nowifi.cli.probe_all")
    @patch("nowifi.cli.detect_portal")
    @patch("nowifi.cli.get_gateway", return_value="192.168.1.1")
    @patch("nowifi.cli.get_wifi_info", return_value=None)
    def test_no_wifi_exits(self, mock_wifi, mock_gw, mock_detect, mock_probe, mock_report):
        """Not connected to WiFi -> exits with code 1."""
        runner = CliRunner()
        result = runner.invoke(main, [])
        assert result.exit_code == 1
        mock_detect.assert_not_called()


# ---------------------------------------------------------------------------
# CLI: --probe-only
# ---------------------------------------------------------------------------

class TestCliProbeOnly:

    @patch("nowifi.cli.print_terminal_report")
    @patch("nowifi.cli.probe_all")
    @patch("nowifi.cli.detect_portal")
    @patch("nowifi.cli.get_gateway", return_value="192.168.1.1")
    @patch("nowifi.cli.get_wifi_info")
    def test_probe_only_skips_bypass(
        self, mock_wifi, mock_gw, mock_detect, mock_probe, mock_report,
    ):
        """--probe-only skips bypass phase."""
        from nowifi.platform_mac import WifiInfo
        from nowifi.detect import PortalInfo, PortalType
        from nowifi.probe import ProbeResults

        mock_wifi.return_value = WifiInfo(
            ssid="Hotel_WiFi", bssid="", channel="", security="", rssi=-64,
        )
        mock_detect.return_value = PortalInfo(is_captive=True, portal_type=PortalType.HTTP_REDIRECT)
        mock_probe.return_value = ProbeResults()

        runner = CliRunner()
        with patch("nowifi.cli.run_bypasses") as mock_bypass:
            result = runner.invoke(main, ["--probe-only"])
            assert result.exit_code == 0
            mock_bypass.assert_not_called()

    @patch("nowifi.cli.print_terminal_report")
    @patch("nowifi.cli.probe_all")
    @patch("nowifi.cli.detect_portal")
    @patch("nowifi.cli.get_gateway", return_value="192.168.1.1")
    @patch("nowifi.cli.get_wifi_info")
    def test_probe_only_still_reports(
        self, mock_wifi, mock_gw, mock_detect, mock_probe, mock_report,
    ):
        """--probe-only still prints the report."""
        from nowifi.platform_mac import WifiInfo
        from nowifi.detect import PortalInfo, PortalType
        from nowifi.probe import ProbeResults

        mock_wifi.return_value = WifiInfo(
            ssid="Hotel_WiFi", bssid="", channel="", security="", rssi=-64,
        )
        mock_detect.return_value = PortalInfo(is_captive=True, portal_type=PortalType.HTTP_REDIRECT)
        mock_probe.return_value = ProbeResults()

        runner = CliRunner()
        result = runner.invoke(main, ["--probe-only"])
        mock_report.assert_called_once()


# ---------------------------------------------------------------------------
# CLI: --fast mode
# ---------------------------------------------------------------------------

class TestCliFastMode:

    @patch("nowifi.cli.print_terminal_report")
    @patch("nowifi.cli.probe_all")
    @patch("nowifi.cli.detect_portal")
    @patch("nowifi.cli.get_gateway", return_value="192.168.1.1")
    @patch("nowifi.cli.get_wifi_info")
    def test_fast_mode_passes_stealth_false(
        self, mock_wifi, mock_gw, mock_detect, mock_probe, mock_report,
    ):
        """--fast passes stealth=False to probe_all."""
        from nowifi.platform_mac import WifiInfo
        from nowifi.detect import PortalInfo, PortalType
        from nowifi.probe import ProbeResults

        mock_wifi.return_value = WifiInfo(
            ssid="Test", bssid="", channel="", security="", rssi=-64,
        )
        mock_detect.return_value = PortalInfo(is_captive=False, portal_type=PortalType.NONE)
        mock_probe.return_value = ProbeResults()

        runner = CliRunner()
        result = runner.invoke(main, ["--fast"])
        assert result.exit_code == 0
        call_kwargs = mock_probe.call_args
        assert call_kwargs.kwargs.get("stealth") is False or (len(call_kwargs.args) > 1 and call_kwargs.args[1] is False)


# ---------------------------------------------------------------------------
# CLI: interface option
# ---------------------------------------------------------------------------

class TestCliInterface:

    @patch("nowifi.cli.print_terminal_report")
    @patch("nowifi.cli.probe_all")
    @patch("nowifi.cli.detect_portal")
    @patch("nowifi.cli.get_gateway", return_value="192.168.1.1")
    @patch("nowifi.cli.get_wifi_info")
    def test_custom_interface(
        self, mock_wifi, mock_gw, mock_detect, mock_probe, mock_report,
    ):
        """Custom --interface is passed through."""
        from nowifi.platform_mac import WifiInfo
        from nowifi.detect import PortalInfo, PortalType
        from nowifi.probe import ProbeResults

        mock_wifi.return_value = WifiInfo(
            ssid="Test", bssid="", channel="", security="", rssi=-64,
        )
        mock_detect.return_value = PortalInfo(is_captive=False, portal_type=PortalType.NONE)
        mock_probe.return_value = ProbeResults()

        runner = CliRunner()
        result = runner.invoke(main, ["--interface", "en1"])
        assert result.exit_code == 0
        mock_wifi.assert_called_once_with("en1")


# ---------------------------------------------------------------------------
# CLI: captive portal triggers bypass
# ---------------------------------------------------------------------------

class TestCliBypassTriggered:

    @patch("nowifi.cli.print_terminal_report")
    @patch("nowifi.cli.StateGuard")
    @patch("nowifi.cli.run_bypasses")
    @patch("nowifi.cli.probe_all")
    @patch("nowifi.cli.detect_portal")
    @patch("nowifi.cli.get_gateway", return_value="192.168.1.1")
    @patch("nowifi.cli.get_wifi_info")
    def test_captive_portal_runs_bypasses(
        self, mock_wifi, mock_gw, mock_detect, mock_probe, mock_bypass, mock_guard, mock_report,
    ):
        """Captive portal detected + not probe-only -> runs bypasses."""
        from nowifi.platform_mac import WifiInfo
        from nowifi.detect import PortalInfo, PortalType
        from nowifi.probe import ProbeResults
        from nowifi.bypass import BypassResult, BypassMethod

        mock_wifi.return_value = WifiInfo(
            ssid="Hotel_WiFi", bssid="", channel="", security="", rssi=-64,
        )
        mock_detect.return_value = PortalInfo(
            is_captive=True, portal_type=PortalType.HTTP_REDIRECT,
        )
        mock_probe.return_value = ProbeResults()
        mock_bypass.return_value = [
            BypassResult(method=BypassMethod.IPV6, success=False),
        ]

        # Mock StateGuard context manager
        mock_guard_instance = MagicMock()
        mock_guard.return_value = mock_guard_instance
        mock_guard_instance.__enter__ = MagicMock(return_value=mock_guard_instance)
        mock_guard_instance.__exit__ = MagicMock(return_value=False)

        runner = CliRunner()
        result = runner.invoke(main, [])
        mock_bypass.assert_called_once()

    @patch("nowifi.cli.print_terminal_report")
    @patch("nowifi.cli.probe_all")
    @patch("nowifi.cli.detect_portal")
    @patch("nowifi.cli.get_gateway", return_value="192.168.1.1")
    @patch("nowifi.cli.get_wifi_info")
    def test_no_portal_skips_bypasses(
        self, mock_wifi, mock_gw, mock_detect, mock_probe, mock_report,
    ):
        """No captive portal -> bypasses are skipped."""
        from nowifi.platform_mac import WifiInfo
        from nowifi.detect import PortalInfo, PortalType
        from nowifi.probe import ProbeResults

        mock_wifi.return_value = WifiInfo(
            ssid="Home_WiFi", bssid="", channel="", security="", rssi=-64,
        )
        mock_detect.return_value = PortalInfo(is_captive=False, portal_type=PortalType.NONE)
        mock_probe.return_value = ProbeResults()

        runner = CliRunner()
        with patch("nowifi.cli.run_bypasses") as mock_bypass:
            result = runner.invoke(main, [])
            mock_bypass.assert_not_called()


# ---------------------------------------------------------------------------
# CLI: reset subcommand
# ---------------------------------------------------------------------------

class TestCliReset:

    @patch("nowifi.cli._get_hardware_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.cli.platform_mac.renew_dhcp", return_value=True)
    @patch("nowifi.cli.platform_mac.connect_wifi", return_value=True)
    @patch("nowifi.cli.platform_mac.disconnect_wifi", return_value=True)
    @patch("nowifi.cli.platform_mac.flush_dns", return_value=True)
    @patch("nowifi.cli.platform_mac.set_mac", return_value=True)
    @patch("nowifi.cli.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.cli.subprocess.run")
    @patch("time.sleep")
    def test_reset_command(
        self, mock_sleep, mock_run, mock_mac, mock_set, mock_flush,
        mock_disconnect, mock_connect, mock_dhcp, mock_hw_mac,
    ):
        """Reset command completes without error."""
        mock_run.return_value = MagicMock(stdout="")
        with patch("nowifi.bypass.clear_system_socks_proxy"), \
             patch("shutil.which", return_value=None):
            runner = CliRunner()
            result = runner.invoke(main, ["reset"])
            assert result.exit_code == 0
            assert "reset complete" in result.output.lower()


# ---------------------------------------------------------------------------
# CLI: setup subcommand
# ---------------------------------------------------------------------------

class TestCliSetup:

    def test_setup_help(self):
        """setup --help works."""
        runner = CliRunner()
        result = runner.invoke(main, ["setup", "--help"])
        assert result.exit_code == 0
        assert "setup wizard" in result.output.lower()

    @patch("nowifi.cli.detect_portal")
    @patch("nowifi.cli.platform_mac.get_current_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("nowifi.cli.get_wifi_info")
    def test_setup_runs(self, mock_wifi, mock_mac, mock_detect):
        """setup runs through all steps."""
        from nowifi.platform_mac import WifiInfo
        from nowifi.detect import PortalInfo, PortalType

        mock_wifi.return_value = WifiInfo(
            ssid="Test_WiFi", bssid="", channel="", security="", rssi=-64,
        )
        mock_detect.return_value = PortalInfo(is_captive=False, portal_type=PortalType.NONE)

        runner = CliRunner()
        # Answer "no" to tool download prompt
        result = runner.invoke(main, ["setup"], input="n\n")
        assert result.exit_code == 0
        assert "System check" in result.output
        assert "WiFi interface" in result.output
        assert "External tools" in result.output
        assert "Ready" in result.output

    @patch("nowifi.cli.detect_portal")
    @patch("nowifi.cli.get_wifi_info", return_value=None)
    def test_setup_no_wifi(self, mock_wifi, mock_detect):
        """setup handles no WiFi gracefully."""
        from nowifi.detect import PortalInfo, PortalType
        mock_detect.return_value = PortalInfo(is_captive=False, portal_type=PortalType.NONE)

        runner = CliRunner()
        result = runner.invoke(main, ["setup"], input="n\n")
        assert result.exit_code == 0
        assert "Not connected" in result.output


# ---------------------------------------------------------------------------
# CLI: doctor subcommand
# ---------------------------------------------------------------------------

class TestCliDoctor:

    def test_doctor_help(self):
        """doctor --help works."""
        runner = CliRunner()
        result = runner.invoke(main, ["doctor", "--help"])
        assert result.exit_code == 0
        assert "health" in result.output.lower()

    @patch("nowifi.cli.get_wifi_info")
    @patch("nowifi.cli.os.geteuid", return_value=1000)
    @patch("nowifi.cli.socket.gethostbyname", return_value="1.1.1.1")
    def test_doctor_runs(self, mock_dns, mock_euid, mock_wifi):
        """doctor runs and produces output."""
        from nowifi.platform_mac import WifiInfo
        mock_wifi.return_value = WifiInfo(
            ssid="Test", bssid="", channel="", security="", rssi=-64,
        )

        runner = CliRunner()
        with patch("urllib.request.urlopen"):
            result = runner.invoke(main, ["doctor"])
        assert result.exit_code == 0
        assert "Python version" in result.output
        assert "Operating system" in result.output
        assert "WiFi connected" in result.output
        assert "DNS resolution" in result.output


# ---------------------------------------------------------------------------
# CLI: uninstall subcommand
# ---------------------------------------------------------------------------

class TestCliUninstall:

    def test_uninstall_help(self):
        """uninstall --help works."""
        runner = CliRunner()
        result = runner.invoke(main, ["uninstall", "--help"])
        assert result.exit_code == 0
        assert "remove" in result.output.lower()

    def test_uninstall_aborted(self):
        """uninstall without --yes aborts when user declines."""
        runner = CliRunner()
        result = runner.invoke(main, ["uninstall"], input="n\n")
        assert result.exit_code != 0  # Aborted

    @patch("nowifi.cli.shutil.rmtree")
    @patch("nowifi.cli.Path.home")
    def test_uninstall_removes_dir(self, mock_home, mock_rmtree):
        """uninstall --yes removes ~/.nowifi."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            nowifi_dir = Path(tmpdir) / ".nowifi"
            nowifi_dir.mkdir()
            (nowifi_dir / "bin").mkdir()
            (nowifi_dir / "bin" / "chisel").touch()
            mock_home.return_value = Path(tmpdir)

            runner = CliRunner()
            result = runner.invoke(main, ["uninstall", "--yes"])
            assert result.exit_code == 0
            assert "pip uninstall nowifi" in result.output

    @patch("nowifi.cli.Path.home")
    def test_uninstall_no_dir(self, mock_home):
        """uninstall --yes handles missing ~/.nowifi."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            mock_home.return_value = Path(tmpdir)

            runner = CliRunner()
            result = runner.invoke(main, ["uninstall", "--yes"])
            assert result.exit_code == 0
            # Rich may wrap long paths across lines, so normalize whitespace
            output_flat = " ".join(result.output.split())
            assert "does not exist" in output_flat
