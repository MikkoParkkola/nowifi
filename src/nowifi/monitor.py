"""Monitor mode management for WiFi interfaces.

Handles enabling/disabling monitor mode on macOS and Linux.
Reverts to managed mode on exit (via MonitorGuard context manager).

macOS: Built-in card doesn't support monitor mode. Requires external USB adapter.
Linux: airmon-ng (preferred) or iw dev set type monitor.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from dataclasses import dataclass


@dataclass
class MonitorInterface:
    """Represents a WiFi interface in monitor mode."""
    name: str           # Monitor mode interface (e.g., wlan0mon)
    original_name: str  # Original managed mode name (e.g., wlan0)
    was_managed: bool   # True if we switched from managed mode


def check_monitor_support(interface: str) -> bool:
    """Check if an interface supports monitor mode without enabling it."""
    if sys.platform == "darwin":
        # macOS built-in WiFi (en0) doesn't support monitor mode
        # External USB adapters might — check if interface exists and isn't en0
        if interface == "en0":
            return False
        # Check if interface exists
        try:
            result = subprocess.run(
                ["ifconfig", interface], capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    elif sys.platform == "linux":
        # Check iw for monitor mode support
        try:
            result = subprocess.run(
                ["iw", "phy"], capture_output=True, text=True, timeout=5,
            )
            # Find the phy for our interface
            phy = _get_phy_for_interface(interface)
            if not phy:
                return False
            # Check if "monitor" is in supported interface modes
            in_phy = False
            in_modes = False
            for line in result.stdout.splitlines():
                if phy in line:
                    in_phy = True
                if in_phy and "Supported interface modes:" in line:
                    in_modes = True
                if in_modes and "* monitor" in line:
                    return True
                if in_modes and line.strip() and not line.strip().startswith("*"):
                    in_modes = False
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            pass

        # Fallback: check airmon-ng
        airmon = shutil.which("airmon-ng")
        if airmon:
            try:
                result = subprocess.run(
                    [airmon, "--help"], capture_output=True, text=True, timeout=5,
                )
                return True  # airmon-ng exists, assume it can handle the interface
            except (subprocess.TimeoutExpired, OSError):
                pass

    return False


def find_monitor_interfaces() -> list[str]:
    """Find WiFi interfaces that may support monitor mode."""
    interfaces = []

    if sys.platform == "darwin":
        # On macOS, only external USB WiFi adapters support monitor mode
        # Look for non-standard WiFi interfaces
        try:
            result = subprocess.run(
                ["ifconfig", "-l"], capture_output=True, text=True, timeout=5,
            )
            for iface in result.stdout.strip().split():
                # Skip standard interfaces
                if iface.startswith(("lo", "gif", "stf", "bridge", "utun", "awdl", "llw", "ap")):
                    continue
                if iface == "en0":
                    continue  # Built-in, no monitor mode
                # Check if it's a WiFi interface
                if check_monitor_support(iface):
                    interfaces.append(iface)
        except (subprocess.TimeoutExpired, OSError):
            pass

    elif sys.platform == "linux":
        # Check all wireless interfaces
        try:
            result = subprocess.run(
                ["iw", "dev"], capture_output=True, text=True, timeout=5,
            )
            for match in re.finditer(r"Interface\s+(\S+)", result.stdout):
                iface = match.group(1)
                if check_monitor_support(iface):
                    interfaces.append(iface)
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            # Fallback: check /proc/net/wireless
            try:
                with open("/proc/net/wireless") as f:
                    for line in f:
                        m = re.match(r"\s*(\S+):", line)
                        if m:
                            interfaces.append(m.group(1))
            except (FileNotFoundError, PermissionError):
                pass

    return interfaces


def enable_monitor_mode(interface: str) -> MonitorInterface:
    """Enable monitor mode on a WiFi interface.

    Linux: Uses airmon-ng (preferred) or iw.
    macOS: Limited support — only with external USB adapters.

    Returns MonitorInterface with the monitor-mode interface name.
    Raises RuntimeError if monitor mode cannot be enabled.
    """
    if sys.platform == "linux":
        return _enable_monitor_linux(interface)
    elif sys.platform == "darwin":
        return _enable_monitor_macos(interface)
    else:
        raise RuntimeError(f"Monitor mode not supported on {sys.platform}")


def disable_monitor_mode(mon: MonitorInterface) -> bool:
    """Revert interface from monitor mode to managed mode."""
    if not mon.was_managed:
        return True  # Nothing to revert

    if sys.platform == "linux":
        return _disable_monitor_linux(mon)
    elif sys.platform == "darwin":
        return _disable_monitor_macos(mon)
    return False


def _enable_monitor_linux(interface: str) -> MonitorInterface:
    """Enable monitor mode on Linux."""
    # Try airmon-ng first (handles driver quirks, kills interfering processes)
    airmon = shutil.which("airmon-ng")
    if airmon:
        try:
            # Kill interfering processes
            subprocess.run(
                ["sudo", airmon, "check", "kill"],
                capture_output=True, text=True, timeout=10,
            )
            # Start monitor mode
            result = subprocess.run(
                ["sudo", airmon, "start", interface],
                capture_output=True, text=True, timeout=15,
            )
            # Parse output for new interface name (e.g., wlan0mon)
            output = result.stdout + result.stderr
            m = re.search(r"\(monitor mode.*enabled on (\S+)\)", output)
            if m:
                return MonitorInterface(name=m.group(1), original_name=interface, was_managed=True)
            # Some versions just append "mon"
            mon_name = interface + "mon"
            try:
                check = subprocess.run(
                    ["ifconfig", mon_name], capture_output=True, timeout=3,
                )
                if check.returncode == 0:
                    return MonitorInterface(name=mon_name, original_name=interface, was_managed=True)
            except (subprocess.TimeoutExpired, OSError):
                pass
        except (subprocess.TimeoutExpired, OSError):
            pass

    # Fallback: iw
    try:
        subprocess.run(
            ["sudo", "ip", "link", "set", interface, "down"],
            capture_output=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "iw", "dev", interface, "set", "type", "monitor"],
            check=True, capture_output=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "ip", "link", "set", interface, "up"],
            capture_output=True, timeout=5,
        )
        return MonitorInterface(name=interface, original_name=interface, was_managed=True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        raise RuntimeError(f"Failed to enable monitor mode on {interface}: {e}")


def _enable_monitor_macos(interface: str) -> MonitorInterface:
    """Enable monitor mode on macOS (limited — external adapters only)."""
    if interface == "en0":
        raise RuntimeError(
            "macOS built-in WiFi (en0) does not support monitor mode. "
            "Use an external USB WiFi adapter (recommended: Alfa AWUS036ACH with RTL8812AU)."
        )
    # For external adapters, try setting monitor mode via ifconfig
    try:
        subprocess.run(
            ["sudo", "ifconfig", interface, "monitor"],
            check=True, capture_output=True, timeout=10,
        )
        return MonitorInterface(name=interface, original_name=interface, was_managed=True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        raise RuntimeError(f"Failed to enable monitor mode on {interface}: {e}")


def _disable_monitor_linux(mon: MonitorInterface) -> bool:
    """Disable monitor mode on Linux."""
    airmon = shutil.which("airmon-ng")
    if airmon:
        try:
            subprocess.run(
                ["sudo", airmon, "stop", mon.name],
                capture_output=True, text=True, timeout=15,
            )
            # Restart NetworkManager if it was killed
            nm = shutil.which("systemctl")
            if nm:
                subprocess.run(
                    ["sudo", "systemctl", "restart", "NetworkManager"],
                    capture_output=True, timeout=10,
                )
            return True
        except (subprocess.TimeoutExpired, OSError):
            pass

    # Fallback: iw
    try:
        subprocess.run(
            ["sudo", "ip", "link", "set", mon.name, "down"],
            capture_output=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "iw", "dev", mon.name, "set", "type", "managed"],
            capture_output=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "ip", "link", "set", mon.original_name, "up"],
            capture_output=True, timeout=5,
        )
        return True
    except (subprocess.TimeoutExpired, OSError):
        return False


def _disable_monitor_macos(mon: MonitorInterface) -> bool:
    """Disable monitor mode on macOS."""
    try:
        subprocess.run(
            ["sudo", "ifconfig", mon.name, "-monitor"],
            capture_output=True, timeout=10,
        )
        return True
    except (subprocess.TimeoutExpired, OSError):
        return False


def _get_phy_for_interface(interface: str) -> str:
    """Get the phy name for a wireless interface on Linux."""
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "info"],
            capture_output=True, text=True, timeout=5,
        )
        m = re.search(r"wiphy\s+(\d+)", result.stdout)
        if m:
            return f"phy#{m.group(1)}"
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        pass
    return ""


class MonitorGuard:
    """Context manager that enables monitor mode and reverts on exit.

    Usage:
        with MonitorGuard("wlan0") as mon:
            # mon.name is the monitor interface (e.g., wlan0mon)
            run_capture(mon.name)
        # Automatically reverted to managed mode
    """

    def __init__(self, interface: str):
        self.interface = interface
        self.monitor: MonitorInterface | None = None

    def __enter__(self) -> MonitorInterface:
        self.monitor = enable_monitor_mode(self.interface)
        return self.monitor

    def __exit__(self, *args: object) -> None:
        if self.monitor and self.monitor.was_managed:
            disable_monitor_mode(self.monitor)
            self.monitor = None
