"""macOS-specific network operations: MAC spoofing, WiFi info, interface management."""

from __future__ import annotations

import json
import random
import re
import signal
import subprocess
import atexit
from dataclasses import dataclass


@dataclass
class WifiInfo:
    ssid: str
    bssid: str
    channel: str
    security: str
    rssi: int  # signal strength in dBm


@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: str


def _parse_rssi(val: str | int) -> int:
    """Parse RSSI from system_profiler format like '-64 dBm / -96 dBm'."""
    if isinstance(val, int):
        return val
    try:
        return int(str(val).split()[0])
    except (ValueError, IndexError):
        return -99


def get_wifi_info(interface: str = "en0") -> WifiInfo | None:
    """Get current WiFi connection info via system_profiler."""
    try:
        result = subprocess.run(
            ["system_profiler", "SPAirPortDataType", "-json"],
            capture_output=True, text=True, timeout=10,
        )
        data = json.loads(result.stdout)

        # Navigate the nested structure
        for item in data.get("SPAirPortDataType", []):
            interfaces = item.get("spairport_airport_interfaces", [])
            for iface in interfaces:
                current = iface.get("spairport_current_network_information", {})
                if not current:
                    continue
                # current_network_information is a flat dict with _name as SSID
                ssid = current.get("_name", "<redacted>")
                return WifiInfo(
                    ssid=ssid,
                    bssid=current.get("spairport_network_bssid", ""),
                    channel=str(current.get("spairport_network_channel", "")),
                    security=current.get("spairport_security_mode", "unknown"),
                    rssi=_parse_rssi(current.get("spairport_signal_noise", "-99")),
                )
    except (subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, ValueError):
        pass

    # Fallback: use airport command directly (may not exist on newer macOS)
    try:
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        result = subprocess.run(
            [airport_path, "-I"], capture_output=True, text=True, timeout=5,
        )
        info: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if ":" in line:
                key, _, val = line.strip().partition(":")
                info[key.strip()] = val.strip()
        if "SSID" in info:
            return WifiInfo(
                ssid=info.get("SSID", ""),
                bssid=info.get("BSSID", ""),
                channel=info.get("channel", ""),
                security=info.get("link auth", "unknown"),
                rssi=int(info.get("agrCtlRSSI", "-99")),
            )
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError, OSError):
        pass

    # Final fallback: networksetup
    try:
        result = subprocess.run(
            ["networksetup", "-getairportnetwork", interface],
            capture_output=True, text=True, timeout=5,
        )
        m = re.search(r"Current Wi-Fi Network:\s*(.+)", result.stdout)
        if m:
            return WifiInfo(
                ssid=m.group(1).strip(),
                bssid="",
                channel="",
                security="unknown",
                rssi=-99,
            )
    except subprocess.TimeoutExpired:
        pass

    # Last resort: if ifconfig shows en0 is active with an IP, we're connected
    # (macOS redacts SSID from non-privileged processes)
    try:
        result = subprocess.run(
            ["ifconfig", interface], capture_output=True, text=True, timeout=5,
        )
        has_ip = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
        is_active = "status: active" in result.stdout
        if has_ip and is_active:
            return WifiInfo(
                ssid="<redacted>",
                bssid="",
                channel="",
                security="unknown",
                rssi=-99,
            )
    except subprocess.TimeoutExpired:
        pass

    return None


def get_current_mac(interface: str = "en0") -> str:
    """Get current MAC address of an interface."""
    try:
        result = subprocess.run(
            ["ifconfig", interface], capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"ether\s+([0-9a-f:]{17})", result.stdout)
        return match.group(1) if match else ""
    except subprocess.TimeoutExpired:
        return ""


_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_IFACE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9]{0,15}$")


def _validate_mac(mac: str) -> str:
    """Validate MAC address format to prevent command injection."""
    if not _MAC_RE.match(mac):
        raise ValueError(f"Invalid MAC address format: {mac!r}. Expected xx:xx:xx:xx:xx:xx")
    return mac.lower()


def _validate_iface(interface: str) -> str:
    """Validate interface name to prevent command injection."""
    if not _IFACE_RE.match(interface):
        raise ValueError(f"Invalid interface name: {interface!r}")
    return interface


def set_mac(interface: str, mac: str) -> bool:
    """Set MAC address on interface (requires sudo)."""
    try:
        mac = _validate_mac(mac)
        interface = _validate_iface(interface)
        subprocess.run(
            ["sudo", "ifconfig", interface, "ether", mac],
            check=True, capture_output=True, text=True, timeout=10,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
        return False


def get_gateway(interface: str = "en0") -> str:
    """Get the default gateway IP address."""
    try:
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"gateway:\s+(\S+)", result.stdout)
        return match.group(1) if match else ""
    except subprocess.TimeoutExpired:
        return ""


def get_local_ip(interface: str = "en0") -> str:
    """Get the local IP address of the interface."""
    try:
        result = subprocess.run(
            ["ifconfig", interface], capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
        return match.group(1) if match else ""
    except subprocess.TimeoutExpired:
        return ""


def get_ipv6_address(interface: str = "en0") -> str:
    """Get the global IPv6 address of the interface (if any)."""
    try:
        result = subprocess.run(
            ["ifconfig", interface], capture_output=True, text=True, timeout=5,
        )
        # Look for a non-link-local IPv6 address (not fe80::)
        for match in re.finditer(r"inet6\s+([0-9a-f:]+)", result.stdout):
            addr = match.group(1)
            if not addr.startswith("fe80"):
                return addr
        return ""
    except subprocess.TimeoutExpired:
        return ""


def get_arp_table() -> list[ArpEntry]:
    """Get ARP table entries."""
    entries: list[ArpEntry] = []
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            match = re.match(r"\S+\s+\((\S+)\)\s+at\s+([0-9a-f:]+)\s+on\s+(\S+)", line)
            if match:
                mac = match.group(2)
                # Skip incomplete entries
                if mac != "(incomplete)":
                    entries.append(ArpEntry(
                        ip=match.group(1),
                        mac=mac,
                        interface=match.group(3),
                    ))
    except subprocess.TimeoutExpired:
        pass
    return entries


def generate_random_mac() -> str:
    """Generate a random locally-administered unicast MAC address.

    Locally administered: bit 1 of first octet = 1 (second hex char is 2,6,a,e)
    Unicast: bit 0 of first octet = 0
    """
    first_byte = random.choice([0x02, 0x06, 0x0A, 0x0E])
    remaining = [random.randint(0x00, 0xFF) for _ in range(5)]
    octets = [first_byte] + remaining
    return ":".join(f"{b:02x}" for b in octets)


def disconnect_wifi(interface: str = "en0") -> bool:
    """Disconnect from WiFi."""
    try:
        subprocess.run(
            ["networksetup", "-setairportpower", interface, "off"],
            check=True, capture_output=True, text=True, timeout=10,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def connect_wifi(interface: str = "en0") -> bool:
    """Reconnect WiFi power."""
    try:
        subprocess.run(
            ["networksetup", "-setairportpower", interface, "on"],
            check=True, capture_output=True, text=True, timeout=10,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def rejoin_wifi(interface: str, ssid: str, password: str | None = None) -> bool:
    """Rejoin a specific WiFi network."""
    try:
        cmd = ["networksetup", "-setairportnetwork", interface, ssid]
        if password:
            cmd.append(password)
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def renew_dhcp(interface: str = "en0") -> bool:
    """Renew DHCP lease."""
    try:
        subprocess.run(
            ["sudo", "ipconfig", "set", interface, "DHCP"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def flush_dns() -> bool:
    """Flush DNS cache."""
    try:
        subprocess.run(
            ["sudo", "dscacheutil", "-flushcache"],
            capture_output=True, text=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "killall", "-HUP", "mDNSResponder"],
            capture_output=True, text=True, timeout=5,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


class StateGuard:
    """Context manager that restores ALL network state on exit.

    Restores: MAC address, system SOCKS proxy, DNS cache, tunnel processes.
    Handles normal exit, exceptions, SIGINT, SIGTERM, and atexit.
    Guarantees the system returns to pre-nowifi state.
    """

    def __init__(self, interface: str):
        self.interface = interface
        self.original_mac = get_current_mac(interface)
        self.tunnel_handles: list = []  # TunnelHandle objects to stop
        self._registered = False
        self._old_sigint = None
        self._old_sigterm = None

    def __enter__(self) -> "StateGuard":
        atexit.register(self.restore)
        self._old_sigint = signal.getsignal(signal.SIGINT)
        self._old_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        self._registered = True
        return self

    def __exit__(self, *args: object) -> None:
        self.restore()

    def register_tunnel(self, handle: object) -> None:
        """Register a tunnel handle for cleanup on exit."""
        self.tunnel_handles.append(handle)

    def _signal_handler(self, signum: int, frame: object) -> None:
        self.restore()
        raise SystemExit(1)

    def restore(self) -> None:
        if not self._registered:
            return
        self._registered = False

        import sys

        # 1. Stop all tunnel processes
        for handle in self.tunnel_handles:
            try:
                handle.stop()
            except Exception as exc:
                print(f"nowifi: warning: failed to stop tunnel: {exc}", file=sys.stderr)

        # 2. Remove system SOCKS proxy
        try:
            from .bypass import clear_system_socks_proxy
            clear_system_socks_proxy(self.interface)
        except Exception as exc:
            print(f"nowifi: warning: failed to clear SOCKS proxy: {exc}", file=sys.stderr)

        # 3. Restore original MAC
        try:
            current = get_current_mac(self.interface)
            if current and self.original_mac and current != self.original_mac:
                set_mac(self.interface, self.original_mac)
                renew_dhcp(self.interface)
        except Exception as exc:
            print(f"nowifi: warning: failed to restore MAC address: {exc}", file=sys.stderr)

        # 4. Flush DNS cache (remove any tunnel-related DNS state)
        flush_dns()

        # 5. Restore signal handlers
        if self._old_sigint is not None:
            try:
                signal.signal(signal.SIGINT, self._old_sigint)
            except (OSError, ValueError):
                pass
        if self._old_sigterm is not None:
            try:
                signal.signal(signal.SIGTERM, self._old_sigterm)
            except (OSError, ValueError):
                pass
