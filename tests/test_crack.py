"""Tests for WPA/WPA2 cracking module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from nowifi.crack import (
    CrackMethod,
    CrackResult,
    ToolNotFound,
    WifiTarget,
    _find_tool,
    _parse_reaver_output,
    _parse_wash_output,
    capture_handshake,
    capture_pmkid,
    crack_with_hashcat,
    crack_wps_pin,
    crack_wps_pixie,
    find_aireplay,
    find_aircrack,
    find_hashcat,
    find_hcxdumptool,
    find_hcxpcapngtool,
    find_reaver,
    find_wash,
    find_wordlists,
    run_crack,
    scan_targets,
)


# ---------------------------------------------------------------------------
# CrackMethod enum
# ---------------------------------------------------------------------------

class TestCrackMethod:

    def test_has_seven_values(self):
        """CrackMethod enum has exactly 7 members."""
        assert len(CrackMethod) == 7

    def test_expected_members(self):
        assert CrackMethod.PMKID.value == "pmkid_capture"
        assert CrackMethod.HANDSHAKE.value == "handshake_capture"
        assert CrackMethod.HASHCAT.value == "hashcat_crack"
        assert CrackMethod.DICTIONARY.value == "dictionary_attack"
        assert CrackMethod.ONLINE_BRUTE.value == "online_brute_force"
        assert CrackMethod.WPS_PIXIE.value == "wps_pixie_dust"
        assert CrackMethod.WPS_PIN.value == "wps_pin_brute"


# ---------------------------------------------------------------------------
# WifiTarget dataclass
# ---------------------------------------------------------------------------

class TestWifiTarget:

    def test_fields(self):
        t = WifiTarget(
            ssid="TestNet", bssid="AA:BB:CC:DD:EE:FF",
            channel=6, security="WPA2", signal=-55,
        )
        assert t.ssid == "TestNet"
        assert t.bssid == "AA:BB:CC:DD:EE:FF"
        assert t.channel == 6
        assert t.security == "WPA2"
        assert t.signal == -55
        assert t.clients == []

    def test_wps_defaults(self):
        t = WifiTarget(
            ssid="Net", bssid="11:22:33:44:55:66",
            channel=1, security="WPA2", signal=-70,
        )
        assert t.wps_enabled is False
        assert t.wps_locked is False
        assert t.wps_version == ""

    def test_wps_fields(self):
        t = WifiTarget(
            ssid="WpsNet", bssid="11:22:33:44:55:66",
            channel=11, security="WPA2", signal=-40,
            wps_enabled=True, wps_locked=True, wps_version="2.0",
        )
        assert t.wps_enabled is True
        assert t.wps_locked is True
        assert t.wps_version == "2.0"

    def test_clients_field(self):
        t = WifiTarget(
            ssid="Net", bssid="11:22:33:44:55:66",
            channel=1, security="WPA2", signal=-70,
            clients=["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"],
        )
        assert len(t.clients) == 2


# ---------------------------------------------------------------------------
# scan_targets — mock system_profiler
# ---------------------------------------------------------------------------

SYSTEM_PROFILER_JSON = json.dumps({
    "SPAirPortDataType": [{
        "spairport_airport_interfaces": [{
            "spairport_airport_other_local_wireless_networks": [
                {
                    "_name": "TestNetwork",
                    "spairport_network_bssid": "AA:BB:CC:DD:EE:01",
                    "spairport_network_channel": "6",
                    "spairport_security_mode": "wpa2_personal",
                    "spairport_signal_noise": "-45 -90",
                },
                {
                    "_name": "OpenNetwork",
                    "spairport_network_bssid": "AA:BB:CC:DD:EE:02",
                    "spairport_network_channel": "11, 40MHz",
                    "spairport_security_mode": "open",
                    "spairport_signal_noise": "-65 -90",
                },
            ],
            "spairport_current_network_information": {
                "_name": "ConnectedNet",
                "spairport_network_bssid": "AA:BB:CC:DD:EE:03",
                "spairport_network_channel": "1",
                "spairport_security_mode": "wpa2_personal",
                "spairport_signal_noise": "-30 -88",
            },
        }],
    }],
})


class TestScanTargets:

    @patch("nowifi.crack._is_macos", return_value=True)
    @patch("nowifi.crack.subprocess.run")
    def test_scan_macos_system_profiler(self, mock_run, mock_macos):
        """Parse system_profiler JSON output correctly."""
        mock_run.return_value = MagicMock(
            stdout=SYSTEM_PROFILER_JSON, returncode=0,
        )
        targets = scan_targets("en0")
        assert len(targets) == 3
        # Sorted by signal (strongest first): -30 > -45 > -65
        assert targets[0].ssid == "ConnectedNet"
        assert targets[0].signal == -30
        assert targets[1].ssid == "TestNetwork"
        assert targets[1].channel == 6
        assert targets[2].ssid == "OpenNetwork"
        assert targets[2].channel == 11  # Extracted from "11, 40MHz"

    @patch("nowifi.crack._is_macos", return_value=True)
    @patch("nowifi.crack.subprocess.run")
    def test_scan_macos_no_networks(self, mock_run, mock_macos):
        """Empty scan results -> empty list."""
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"SPAirPortDataType": []}), returncode=0,
        )
        # Also mock the airport fallback to return nothing
        with patch("nowifi.crack._scan_macos_airport", return_value=[]):
            targets = scan_targets("en0")
        assert targets == []


# ---------------------------------------------------------------------------
# find_* tool discovery — ToolNotFound
# ---------------------------------------------------------------------------

class TestFindTools:

    @patch("shutil.which", return_value=None)
    @patch("os.path.isfile", return_value=False)
    def test_find_hcxdumptool_not_found(self, mock_isfile, mock_which):
        with pytest.raises(ToolNotFound) as exc_info:
            find_hcxdumptool()
        assert exc_info.value.tool == "hcxdumptool"
        assert "install" in exc_info.value.install_hint.lower()

    @patch("shutil.which", return_value=None)
    @patch("os.path.isfile", return_value=False)
    def test_find_hcxpcapngtool_not_found(self, mock_isfile, mock_which):
        with pytest.raises(ToolNotFound) as exc_info:
            find_hcxpcapngtool()
        assert exc_info.value.tool == "hcxpcapngtool"

    @patch("shutil.which", return_value=None)
    @patch("os.path.isfile", return_value=False)
    def test_find_hashcat_not_found(self, mock_isfile, mock_which):
        with pytest.raises(ToolNotFound):
            find_hashcat()

    @patch("shutil.which", return_value=None)
    @patch("os.path.isfile", return_value=False)
    def test_find_aircrack_not_found(self, mock_isfile, mock_which):
        with pytest.raises(ToolNotFound):
            find_aircrack()

    @patch("shutil.which", return_value=None)
    @patch("os.path.isfile", return_value=False)
    def test_find_aireplay_not_found(self, mock_isfile, mock_which):
        with pytest.raises(ToolNotFound):
            find_aireplay()

    @patch("shutil.which", return_value="/usr/bin/hcxdumptool")
    @patch("os.path.isfile", return_value=True)
    @patch("os.access", return_value=True)
    def test_find_tool_on_path(self, mock_access, mock_isfile, mock_which):
        path = find_hcxdumptool()
        assert path == "/usr/bin/hcxdumptool"

    @patch("nowifi.toolchain.find_tool", return_value=None)
    def test_find_reaver_not_found(self, mock_find):
        with pytest.raises(ToolNotFound) as exc_info:
            find_reaver()
        assert exc_info.value.tool == "reaver"

    @patch("nowifi.toolchain.find_tool", return_value="/usr/bin/reaver")
    def test_find_reaver_found(self, mock_find):
        path = find_reaver()
        assert path == "/usr/bin/reaver"

    @patch("nowifi.toolchain.find_tool", return_value=None)
    def test_find_wash_not_found(self, mock_find):
        with pytest.raises(ToolNotFound) as exc_info:
            find_wash()
        assert exc_info.value.tool == "wash"


# ---------------------------------------------------------------------------
# capture_pmkid — mock subprocess.Popen
# ---------------------------------------------------------------------------

class TestCapturePmkid:

    def _make_target(self) -> WifiTarget:
        return WifiTarget(
            ssid="TestNet", bssid="AA:BB:CC:DD:EE:FF",
            channel=6, security="WPA2", signal=-50,
        )

    @patch("nowifi.crack._check_monitor_mode", return_value=False)
    @patch("nowifi.crack._is_macos", return_value=True)
    def test_no_monitor_mode_macos(self, mock_macos, mock_mon):
        result = capture_pmkid(self._make_target(), "en0")
        assert result.success is False
        assert "monitor mode" in result.details.lower()
        assert "USB" in result.details

    @patch("nowifi.crack._check_monitor_mode", return_value=True)
    @patch("nowifi.crack.find_hcxdumptool", side_effect=ToolNotFound("hcxdumptool", "install it"))
    def test_hcxdumptool_missing(self, mock_find, mock_mon):
        result = capture_pmkid(self._make_target(), "wlan0mon")
        assert result.success is False
        assert "hcxdumptool" in result.details

    @patch("nowifi.crack._check_monitor_mode", return_value=True)
    @patch("nowifi.crack.find_hcxpcapngtool", side_effect=ToolNotFound("hcxpcapngtool", "install it"))
    @patch("nowifi.crack.find_hcxdumptool", return_value="/usr/bin/hcxdumptool")
    def test_hcxpcapngtool_missing(self, mock_hcx, mock_pcap, mock_mon):
        result = capture_pmkid(self._make_target(), "wlan0mon")
        assert result.success is False
        assert "hcxpcapngtool" in result.details

    @patch("nowifi.crack._check_monitor_mode", return_value=True)
    @patch("nowifi.crack.find_hcxpcapngtool", return_value="/usr/bin/hcxpcapngtool")
    @patch("nowifi.crack.find_hcxdumptool", return_value="/usr/bin/hcxdumptool")
    @patch("nowifi.crack.subprocess.Popen")
    @patch("nowifi.crack.subprocess.run")
    def test_command_constructed_correctly(self, mock_run, mock_popen, mock_hcx, mock_pcap, mock_mon, tmp_path):
        """Verify hcxdumptool command is constructed with correct flags."""
        mock_proc = MagicMock()
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.read.return_value = b""
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        capture_pmkid(self._make_target(), "wlan0mon", output_dir=tmp_path, timeout=30)

        # Verify Popen was called
        assert mock_popen.called
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "/usr/bin/hcxdumptool"
        assert "-i" in cmd
        assert "wlan0mon" in cmd
        assert "--filtermode=2" in cmd
        assert "--enable_status=1" in cmd


# ---------------------------------------------------------------------------
# capture_handshake — mock subprocess, verify deauth + capture
# ---------------------------------------------------------------------------

class TestCaptureHandshake:

    def _make_target(self, clients=None) -> WifiTarget:
        return WifiTarget(
            ssid="TestNet", bssid="AA:BB:CC:DD:EE:FF",
            channel=6, security="WPA2", signal=-50,
            clients=clients or ["11:22:33:44:55:66"],
        )

    @patch("nowifi.crack._check_monitor_mode", return_value=False)
    @patch("nowifi.crack._is_macos", return_value=False)
    def test_no_monitor_mode_linux(self, mock_macos, mock_mon):
        result = capture_handshake(self._make_target(), "wlan0")
        assert result.success is False
        assert "monitor mode" in result.details.lower()
        assert "airmon-ng" in result.details

    @patch("nowifi.crack._check_monitor_mode", return_value=True)
    @patch("nowifi.crack.find_hcxdumptool", side_effect=ToolNotFound("hcxdumptool", "install"))
    @patch("nowifi.crack.find_airodump", side_effect=ToolNotFound("airodump-ng", "install"))
    def test_no_capture_tools(self, mock_airo, mock_hcx, mock_mon):
        result = capture_handshake(self._make_target(), "wlan0mon")
        assert result.success is False
        assert "No capture tools" in result.details


# ---------------------------------------------------------------------------
# crack_with_hashcat
# ---------------------------------------------------------------------------

class TestCrackWithHashcat:

    @patch("nowifi.crack.find_hashcat", return_value="/usr/bin/hashcat")
    @patch("nowifi.crack.find_wordlists", return_value=["/usr/share/wordlists/rockyou.txt"])
    @patch("nowifi.crack._is_macos", return_value=False)
    @patch("nowifi.crack.subprocess.Popen")
    def test_m_22000_flag_used(self, mock_popen, mock_macos, mock_wl, mock_hashcat, tmp_path):
        """Verify hashcat uses -m 22000 for WPA cracking."""
        hash_file = tmp_path / "hash.22000"
        hash_file.write_text("WPA*02*pmkid*aabbccdd*1122334455*testnet\n")

        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.returncode = 1
        mock_popen.return_value = mock_proc

        crack_with_hashcat(str(hash_file))

        cmd = mock_popen.call_args[0][0]
        assert "-m" in cmd
        m_idx = cmd.index("-m")
        assert cmd[m_idx + 1] == "22000"

    @patch("nowifi.crack.find_hashcat", side_effect=ToolNotFound("hashcat", "install"))
    def test_hashcat_missing(self, mock_find, tmp_path):
        hash_file = tmp_path / "hash.22000"
        hash_file.write_text("test\n")
        result = crack_with_hashcat(str(hash_file))
        assert result.success is False
        assert "hashcat" in result.details

    def test_hash_file_not_found(self):
        result = crack_with_hashcat("/nonexistent/hash.22000")
        assert result.success is False
        assert "not found" in result.details


# ---------------------------------------------------------------------------
# crack_wps_pixie — verify reaver -K 1 flag
# ---------------------------------------------------------------------------

class TestCrackWpsPixie:

    def _make_wps_target(self, locked=False) -> WifiTarget:
        return WifiTarget(
            ssid="WpsNet", bssid="AA:BB:CC:DD:EE:FF",
            channel=6, security="WPA2", signal=-45,
            wps_enabled=True, wps_locked=locked,
        )

    @patch("nowifi.crack._check_monitor_mode", return_value=True)
    @patch("nowifi.crack.find_reaver", return_value="/usr/bin/reaver")
    @patch("nowifi.crack.subprocess.Popen")
    def test_pixie_dust_K1_flag(self, mock_popen, mock_reaver, mock_mon, tmp_path):
        """Verify reaver is called with -K 1 for Pixie-Dust."""
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"[+] WPS PIN: '12345670'\n[+] WPA PSK: 'password123'\n", b"")
        mock_proc.stdout = MagicMock()
        mock_popen.return_value = mock_proc

        result = crack_wps_pixie(self._make_wps_target(), "wlan0mon", output_dir=tmp_path)

        cmd = mock_popen.call_args[0][0]
        assert "-K" in cmd
        k_idx = cmd.index("-K")
        assert cmd[k_idx + 1] == "1"
        assert "-b" in cmd
        assert "AA:BB:CC:DD:EE:FF" in cmd

    @patch("nowifi.crack.find_reaver", return_value="/usr/bin/reaver")
    @patch("nowifi.crack._check_monitor_mode", return_value=True)
    def test_wps_locked_skips(self, mock_mon, mock_reaver):
        result = crack_wps_pixie(self._make_wps_target(locked=True), "wlan0mon")
        assert result.success is False
        assert "locked" in result.details.lower()


# ---------------------------------------------------------------------------
# crack_wps_pin — verify reaver without -K flag
# ---------------------------------------------------------------------------

class TestCrackWpsPin:

    def _make_wps_target(self, locked=False) -> WifiTarget:
        return WifiTarget(
            ssid="WpsNet", bssid="AA:BB:CC:DD:EE:FF",
            channel=6, security="WPA2", signal=-45,
            wps_enabled=True, wps_locked=locked,
        )

    @patch("nowifi.crack._check_monitor_mode", return_value=True)
    @patch("nowifi.crack.find_reaver", return_value="/usr/bin/reaver")
    @patch("nowifi.crack.subprocess.Popen")
    def test_pin_brute_no_K_flag(self, mock_popen, mock_reaver, mock_mon, tmp_path):
        """Verify reaver is called WITHOUT -K for PIN brute force."""
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"WPS pin not found\n", b"")
        mock_proc.stdout = MagicMock()
        mock_proc.returncode = 1
        mock_popen.return_value = mock_proc

        crack_wps_pin(self._make_wps_target(), "wlan0mon", output_dir=tmp_path, timeout=60)

        cmd = mock_popen.call_args[0][0]
        assert "-K" not in cmd
        assert "-b" in cmd
        assert "-vv" in cmd

    @patch("nowifi.crack.find_reaver", return_value="/usr/bin/reaver")
    @patch("nowifi.crack._check_monitor_mode", return_value=True)
    def test_wps_locked_skips(self, mock_mon, mock_reaver):
        result = crack_wps_pin(self._make_wps_target(locked=True), "wlan0mon")
        assert result.success is False
        assert "locked" in result.details.lower()


# ---------------------------------------------------------------------------
# find_wordlists
# ---------------------------------------------------------------------------

class TestFindWordlists:

    @patch("nowifi.crack.Path.exists", return_value=True)
    @patch("nowifi.crack.Path.stat")
    @patch("nowifi.crack.Path.is_dir", return_value=False)
    def test_finds_existing_paths(self, mock_is_dir, mock_stat, mock_exists):
        """When paths exist and have content, they are returned."""
        mock_stat.return_value = MagicMock(st_size=100)
        result = find_wordlists()
        assert len(result) > 0

    @patch("nowifi.crack.Path.exists", return_value=False)
    @patch("nowifi.crack.Path.is_dir", return_value=False)
    def test_no_wordlists_found(self, mock_is_dir, mock_exists):
        """When no paths exist, returns empty list."""
        result = find_wordlists()
        assert result == []


# ---------------------------------------------------------------------------
# _parse_reaver_output
# ---------------------------------------------------------------------------

class TestParseReaverOutput:

    def test_parse_pin_and_psk(self):
        output = (
            "[+] WPS PIN: '12345670'\n"
            "[+] AP SSID: TestNet\n"
            "[+] WPA PSK: 'SuperSecret123'\n"
        )
        pin, psk = _parse_reaver_output(output)
        assert pin == "12345670"
        assert psk == "SuperSecret123"

    def test_parse_pin_only(self):
        output = "[+] WPS PIN: '12345670'\n[+] AP SSID: TestNet\n"
        pin, psk = _parse_reaver_output(output)
        assert pin == "12345670"
        assert psk == ""

    def test_parse_nothing(self):
        pin, psk = _parse_reaver_output("some random output\n")
        assert pin == ""
        assert psk == ""


# ---------------------------------------------------------------------------
# _parse_wash_output
# ---------------------------------------------------------------------------

class TestParseWashOutput:

    def test_parse_wash_lines(self):
        output = (
            "BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID\n"
            "-----------------------------------------------------------\n"
            "AA:BB:CC:DD:EE:FF    6  -45  1.0  No   RalinkTe  MyNetwork\n"
            "11:22:33:44:55:66   11  -60  2.0  Yes  Broadcom  LockedNet\n"
        )
        targets = _parse_wash_output(output)
        assert len(targets) == 2
        assert targets[0].bssid == "AA:BB:CC:DD:EE:FF"
        assert targets[0].channel == 6
        assert targets[0].wps_enabled is True
        assert targets[0].wps_locked is False
        assert targets[0].wps_version == "1.0"
        assert targets[1].wps_locked is True


# ---------------------------------------------------------------------------
# run_crack pipeline — mock all sub-functions, verify order
# ---------------------------------------------------------------------------

class TestRunCrack:

    def _make_target(self, wps=False) -> WifiTarget:
        return WifiTarget(
            ssid="TestNet", bssid="AA:BB:CC:DD:EE:FF",
            channel=6, security="WPA2", signal=-45,
            wps_enabled=wps,
        )

    @patch("nowifi.crack.scan_targets", return_value=[])
    def test_no_targets_found(self, mock_scan):
        results = run_crack("en0")
        assert len(results) == 1
        assert results[0].success is False
        assert "No WiFi" in results[0].details

    @patch("nowifi.crack.crack_wps_pin")
    @patch("nowifi.crack.crack_with_aircrack")
    @patch("nowifi.crack.crack_with_hashcat")
    @patch("nowifi.crack.capture_handshake")
    @patch("nowifi.crack.crack_wps_pixie")
    @patch("nowifi.crack.capture_pmkid")
    @patch("nowifi.crack.scan_wps_targets", return_value=[])
    @patch("nowifi.crack.scan_targets")
    def test_pipeline_order_pmkid_first(
        self, mock_scan, mock_wps_scan, mock_pmkid, mock_pixie,
        mock_hs, mock_hashcat, mock_aircrack, mock_wps_pin,
    ):
        """Pipeline: PMKID capture is attempted first."""
        target = self._make_target()
        mock_scan.return_value = [target]
        mock_pmkid.return_value = CrackResult(
            method=CrackMethod.PMKID, success=False, details="No PMKID",
        )
        mock_hs.return_value = CrackResult(
            method=CrackMethod.HANDSHAKE, success=False, details="No handshake",
        )

        results = run_crack("wlan0mon")

        # PMKID was called
        mock_pmkid.assert_called_once()
        # Handshake was called (since PMKID failed)
        mock_hs.assert_called_once()

    @patch("nowifi.crack.crack_wps_pin")
    @patch("nowifi.crack.crack_with_aircrack")
    @patch("nowifi.crack.crack_with_hashcat")
    @patch("nowifi.crack.capture_handshake")
    @patch("nowifi.crack.crack_wps_pixie")
    @patch("nowifi.crack.capture_pmkid")
    @patch("nowifi.crack.scan_wps_targets", return_value=[])
    @patch("nowifi.crack.scan_targets")
    def test_pipeline_wps_pixie_before_hashcat(
        self, mock_scan, mock_wps_scan, mock_pmkid, mock_pixie,
        mock_hs, mock_hashcat, mock_aircrack, mock_wps_pin,
    ):
        """Pipeline: WPS Pixie-Dust is tried after PMKID, before hashcat."""
        target = self._make_target(wps=True)
        mock_scan.return_value = [target]
        mock_pmkid.return_value = CrackResult(
            method=CrackMethod.PMKID, success=True,
            capture_file="/tmp/hash.22000",
        )
        mock_pixie.return_value = CrackResult(
            method=CrackMethod.WPS_PIXIE, success=True,
            password="found_it",
        )

        results = run_crack("wlan0mon")

        # Pipeline should have stopped after pixie success
        mock_pmkid.assert_called_once()
        mock_pixie.assert_called_once()
        # Hashcat should NOT have been called because pixie succeeded
        mock_hashcat.assert_not_called()
        assert any(r.password == "found_it" for r in results)

    @patch("nowifi.crack.crack_wps_pin")
    @patch("nowifi.crack.crack_with_aircrack")
    @patch("nowifi.crack.crack_with_hashcat")
    @patch("nowifi.crack.capture_handshake")
    @patch("nowifi.crack.crack_wps_pixie")
    @patch("nowifi.crack.capture_pmkid")
    @patch("nowifi.crack.scan_wps_targets", return_value=[])
    @patch("nowifi.crack.scan_targets")
    def test_pipeline_wps_pin_last_resort(
        self, mock_scan, mock_wps_scan, mock_pmkid, mock_pixie,
        mock_hs, mock_hashcat, mock_aircrack, mock_wps_pin,
    ):
        """Pipeline: WPS PIN brute force is last resort."""
        target = self._make_target(wps=True)
        mock_scan.return_value = [target]

        # Everything fails
        mock_pmkid.return_value = CrackResult(method=CrackMethod.PMKID, success=False)
        mock_pixie.return_value = CrackResult(method=CrackMethod.WPS_PIXIE, success=False)
        mock_hs.return_value = CrackResult(method=CrackMethod.HANDSHAKE, success=False)
        mock_wps_pin.return_value = CrackResult(method=CrackMethod.WPS_PIN, success=False)

        results = run_crack("wlan0mon")

        # WPS PIN brute force should be the last thing tried
        mock_wps_pin.assert_called_once()
        assert results[-1].method == CrackMethod.WPS_PIN

    @patch("nowifi.crack.scan_targets")
    def test_target_ssid_not_found(self, mock_scan):
        mock_scan.return_value = [self._make_target()]
        results = run_crack("en0", target_ssid="NonExistent")
        assert len(results) == 1
        assert results[0].success is False
        assert "not found" in results[0].details
