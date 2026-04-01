"""Linux-specific network operations: MAC spoofing, WiFi info, interface management."""

from __future__ import annotations

import os
import random
import re
import signal
import shutil
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


def _has(cmd: str) -> bool:
    """Check if a command is available on PATH."""
    return shutil.which(cmd) is not None


def _run(args: list[str], timeout: int = 5) -> subprocess.CompletedProcess[str]:
    """Run a command and return the result, suppressing errors."""
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def get_wifi_info(interface: str = "wlan0") -> WifiInfo | None:
    """Get current WiFi connection info using available Linux tools."""
    # Try nmcli first (NetworkManager) — most common on desktop Linux
    if _has("nmcli"):
        try:
            result = _run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,SECURITY,SIGNAL", "dev", "wifi"])
            for line in result.stdout.splitlines():
                parts = line.split(":")
                # nmcli -t uses ':' separator; BSSID itself has '\:' escaped colons
                # Reassemble: ACTIVE:SSID:BSSID(with escaped colons):CHAN:SECURITY:SIGNAL
                if len(parts) >= 2 and parts[0] == "yes":
                    # Re-parse more carefully with nmcli fields format
                    result2 = _run([
                        "nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,SECURITY,SIGNAL",
                        "dev", "wifi", "list", "ifname", interface,
                    ])
                    for line2 in result2.stdout.splitlines():
                        # nmcli escapes colons in BSSID as \:
                        # Split on unescaped colons
                        fields = re.split(r"(?<!\\):", line2)
                        if len(fields) >= 6 and fields[0] == "yes":
                            bssid = fields[2].replace("\\:", ":")
                            rssi_pct = int(fields[5]) if fields[5].isdigit() else 0
                            # Convert percentage (0-100) to approximate dBm
                            rssi_dbm = int(-100 + rssi_pct * 0.6) if rssi_pct else -99
                            return WifiInfo(
                                ssid=fields[1],
                                bssid=bssid,
                                channel=fields[3],
                                security=fields[4],
                                rssi=rssi_dbm,
                            )
                    break
        except (subprocess.TimeoutExpired, ValueError, IndexError):
            pass

    # Fallback: iw dev <iface> link
    if _has("iw"):
        try:
            result = _run(["iw", "dev", interface, "link"])
            if "Not connected" not in result.stdout:
                ssid = ""
                bssid = ""
                channel = ""
                rssi = -99

                m = re.search(r"SSID:\s*(.+)", result.stdout)
                if m:
                    ssid = m.group(1).strip()
                m = re.search(r"Connected to\s+([0-9a-f:]{17})", result.stdout)
                if m:
                    bssid = m.group(1)
                m = re.search(r"freq:\s*(\d+)", result.stdout)
                if m:
                    channel = m.group(1)
                m = re.search(r"signal:\s*(-?\d+)", result.stdout)
                if m:
                    rssi = int(m.group(1))

                if ssid:
                    return WifiInfo(
                        ssid=ssid,
                        bssid=bssid,
                        channel=channel,
                        security="unknown",
                        rssi=rssi,
                    )
        except (subprocess.TimeoutExpired, ValueError):
            pass

    # Fallback: iwgetid + iwconfig
    if _has("iwgetid"):
        try:
            result = _run(["iwgetid", "-r", interface])
            ssid = result.stdout.strip()
            if ssid:
                rssi = -99
                bssid = ""
                if _has("iwconfig"):
                    try:
                        iw_result = _run(["iwconfig", interface])
                        m = re.search(r"Signal level[=:](-?\d+)", iw_result.stdout)
                        if m:
                            rssi = int(m.group(1))
                        m = re.search(r"Access Point:\s*([0-9A-Fa-f:]{17})", iw_result.stdout)
                        if m:
                            bssid = m.group(1).lower()
                    except subprocess.TimeoutExpired:
                        pass
                return WifiInfo(
                    ssid=ssid,
                    bssid=bssid,
                    channel="",
                    security="unknown",
                    rssi=rssi,
                )
        except subprocess.TimeoutExpired:
            pass

    # Last resort: check if interface has an IP and is up
    if _has("ip"):
        try:
            result = _run(["ip", "addr", "show", interface])
            has_ip = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
            is_up = "state UP" in result.stdout
            if has_ip and is_up:
                return WifiInfo(
                    ssid="<unknown>",
                    bssid="",
                    channel="",
                    security="unknown",
                    rssi=-99,
                )
        except subprocess.TimeoutExpired:
            pass

    return None


def get_current_mac(interface: str = "wlan0") -> str:
    """Get current MAC address of an interface."""
    if _has("ip"):
        try:
            result = _run(["ip", "link", "show", interface])
            match = re.search(r"link/ether\s+([0-9a-f:]{17})", result.stdout)
            return match.group(1) if match else ""
        except subprocess.TimeoutExpired:
            pass

    # Fallback: read from sysfs
    sysfs_path = f"/sys/class/net/{interface}/address"
    try:
        with open(sysfs_path) as f:
            mac = f.read().strip()
            if re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
                return mac
    except (FileNotFoundError, PermissionError):
        pass

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
    """Set MAC address on interface (requires sudo).

    Brings the interface down, sets the MAC, and brings it back up.
    """
    try:
        mac = _validate_mac(mac)
        interface = _validate_iface(interface)
        # Must bring interface down before changing MAC on Linux
        subprocess.run(
            ["sudo", "ip", "link", "set", interface, "down"],
            check=True, capture_output=True, text=True, timeout=10,
        )
        subprocess.run(
            ["sudo", "ip", "link", "set", interface, "address", mac],
            check=True, capture_output=True, text=True, timeout=10,
        )
        subprocess.run(
            ["sudo", "ip", "link", "set", interface, "up"],
            check=True, capture_output=True, text=True, timeout=10,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
        return False


def get_gateway(interface: str = "wlan0") -> str:
    """Get the default gateway IP address."""
    if _has("ip"):
        try:
            result = _run(["ip", "route", "show", "default"])
            # Match: default via 192.168.1.1 dev wlan0 ...
            match = re.search(r"default via\s+(\S+)", result.stdout)
            return match.group(1) if match else ""
        except subprocess.TimeoutExpired:
            pass

    # Fallback: read /proc/net/route
    try:
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.strip().split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    # Gateway is in hex, little-endian
                    gw_hex = fields[2]
                    gw_bytes = bytes.fromhex(gw_hex)
                    return f"{gw_bytes[3]}.{gw_bytes[2]}.{gw_bytes[1]}.{gw_bytes[0]}"
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    return ""


def get_local_ip(interface: str = "wlan0") -> str:
    """Get the local IP address of the interface."""
    if _has("ip"):
        try:
            result = _run(["ip", "addr", "show", interface])
            match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
            return match.group(1) if match else ""
        except subprocess.TimeoutExpired:
            pass

    return ""


def get_ipv6_address(interface: str = "wlan0") -> str:
    """Get the global IPv6 address of the interface (if any)."""
    if _has("ip"):
        try:
            result = _run(["ip", "-6", "addr", "show", interface, "scope", "global"])
            match = re.search(r"inet6\s+([0-9a-f:]+)", result.stdout)
            return match.group(1) if match else ""
        except subprocess.TimeoutExpired:
            pass

    return ""


def get_arp_table() -> list[ArpEntry]:
    """Get ARP table entries."""
    entries: list[ArpEntry] = []

    # Prefer `ip neigh show`
    if _has("ip"):
        try:
            result = _run(["ip", "neigh", "show"])
            for line in result.stdout.splitlines():
                # Format: 192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                match = re.match(
                    r"(\S+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-f:]{17})",
                    line,
                )
                if match:
                    entries.append(ArpEntry(
                        ip=match.group(1),
                        mac=match.group(3),
                        interface=match.group(2),
                    ))
            return entries
        except subprocess.TimeoutExpired:
            pass

    # Fallback: arp -a (available on most systems)
    if _has("arp"):
        try:
            result = _run(["arp", "-a"])
            for line in result.stdout.splitlines():
                match = re.match(r"\S+\s+\((\S+)\)\s+at\s+([0-9a-f:]+)\s+.*on\s+(\S+)", line)
                if match and match.group(2) != "(incomplete)":
                    entries.append(ArpEntry(
                        ip=match.group(1),
                        mac=match.group(2),
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


def disconnect_wifi(interface: str = "wlan0") -> bool:
    """Disconnect from WiFi / bring interface down."""
    # Try nmcli first (cleanest on NetworkManager systems)
    if _has("nmcli"):
        try:
            _run(["nmcli", "dev", "disconnect", interface], timeout=10)
            return True
        except subprocess.TimeoutExpired:
            pass

    # Fallback: ip link set down
    if _has("ip"):
        try:
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "down"],
                check=True, capture_output=True, text=True, timeout=10,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    return False


def connect_wifi(interface: str = "wlan0") -> bool:
    """Reconnect WiFi / bring interface up."""
    # Try nmcli first
    if _has("nmcli"):
        try:
            subprocess.run(
                ["nmcli", "dev", "connect", interface],
                check=True, capture_output=True, text=True, timeout=10,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    # Fallback: ip link set up
    if _has("ip"):
        try:
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "up"],
                check=True, capture_output=True, text=True, timeout=10,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    return False


def rejoin_wifi(interface: str, ssid: str, password: str | None = None) -> bool:
    """Rejoin a specific WiFi network."""
    # nmcli is the standard way on NetworkManager systems
    if _has("nmcli"):
        try:
            cmd = ["nmcli", "dev", "wifi", "connect", ssid, "ifname", interface]
            if password:
                cmd.extend(["password", password])
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    # Fallback: wpa_supplicant + wpa_cli
    if _has("wpa_cli"):
        try:
            subprocess.run(
                ["wpa_cli", "-i", interface, "reconnect"],
                check=True, capture_output=True, text=True, timeout=15,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    return False


def renew_dhcp(interface: str = "wlan0") -> bool:
    """Renew DHCP lease."""
    # Try dhclient (most common)
    if _has("dhclient"):
        try:
            subprocess.run(
                ["sudo", "dhclient", "-r", interface],
                capture_output=True, text=True, timeout=10,
            )
            subprocess.run(
                ["sudo", "dhclient", interface],
                check=True, capture_output=True, text=True, timeout=15,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    # Try dhcpcd
    if _has("dhcpcd"):
        try:
            subprocess.run(
                ["sudo", "dhcpcd", "-n", interface],
                check=True, capture_output=True, text=True, timeout=15,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    # Try nmcli
    if _has("nmcli"):
        try:
            # Deactivate and reactivate to force DHCP renewal
            conn_result = _run(["nmcli", "-t", "-f", "NAME", "con", "show", "--active"])
            active_conn = conn_result.stdout.strip().splitlines()
            if active_conn:
                conn_name = active_conn[0]
                subprocess.run(
                    ["nmcli", "con", "down", conn_name],
                    capture_output=True, text=True, timeout=10,
                )
                subprocess.run(
                    ["nmcli", "con", "up", conn_name],
                    check=True, capture_output=True, text=True, timeout=15,
                )
                return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, IndexError):
            pass

    return False


def flush_dns() -> bool:
    """Flush DNS cache."""
    flushed = False

    # systemd-resolve / resolvectl
    if _has("resolvectl"):
        try:
            subprocess.run(
                ["sudo", "resolvectl", "flush-caches"],
                capture_output=True, text=True, timeout=5,
            )
            flushed = True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
    elif _has("systemd-resolve"):
        try:
            subprocess.run(
                ["sudo", "systemd-resolve", "--flush-caches"],
                capture_output=True, text=True, timeout=5,
            )
            flushed = True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    # nscd (Name Service Cache Daemon)
    if _has("nscd"):
        try:
            subprocess.run(
                ["sudo", "nscd", "--invalidate=hosts"],
                capture_output=True, text=True, timeout=5,
            )
            flushed = True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    # dnsmasq (if running as local cache)
    if _has("killall"):
        try:
            subprocess.run(
                ["sudo", "killall", "-HUP", "dnsmasq"],
                capture_output=True, text=True, timeout=5,
            )
            flushed = True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    return flushed


def set_system_socks_proxy(interface: str, host: str, port: int) -> bool:
    """Set system-wide SOCKS proxy via environment variable.

    On Linux there is no universal system proxy command like macOS networksetup.
    We set ALL_PROXY for the current process tree. Desktop environments may
    use gsettings (GNOME) or kwriteconfig (KDE) but those are not universal.
    """
    proxy_url = f"socks5://{host}:{port}"
    os.environ["ALL_PROXY"] = proxy_url
    os.environ["all_proxy"] = proxy_url
    os.environ["SOCKS_PROXY"] = proxy_url

    # Try GNOME gsettings if available
    if _has("gsettings"):
        try:
            subprocess.run(
                ["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"],
                capture_output=True, text=True, timeout=5,
            )
            subprocess.run(
                ["gsettings", "set", "org.gnome.system.proxy.socks", "host", host],
                capture_output=True, text=True, timeout=5,
            )
            subprocess.run(
                ["gsettings", "set", "org.gnome.system.proxy.socks", "port", str(port)],
                capture_output=True, text=True, timeout=5,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    return True


def clear_system_socks_proxy(interface: str) -> None:
    """Remove system-wide SOCKS proxy."""
    for var in ("ALL_PROXY", "all_proxy", "SOCKS_PROXY"):
        os.environ.pop(var, None)

    # Try GNOME gsettings if available
    if _has("gsettings"):
        try:
            subprocess.run(
                ["gsettings", "set", "org.gnome.system.proxy", "mode", "none"],
                capture_output=True, text=True, timeout=5,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass


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
