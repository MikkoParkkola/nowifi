"""Tunnel establishment and management (chisel, DNS, ICMP)."""

from __future__ import annotations

import socket
import subprocess
import time
from dataclasses import dataclass


@dataclass
class TunnelHandle:
    process: subprocess.Popen | None
    local_port: int
    method: str
    active: bool = False

    def stop(self) -> None:
        """Stop the tunnel process."""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.active = False


class ToolNotFound(Exception):
    """External tool not found."""

    def __init__(self, tool: str, install_hint: str):
        self.tool = tool
        self.install_hint = install_hint
        super().__init__(f"{tool} not found. Install: {install_hint}")


def find_chisel() -> str:
    """Find chisel binary (auto-downloads if missing) or raise ToolNotFound."""
    from .toolchain import ensure_tool
    try:
        return ensure_tool("chisel")
    except FileNotFoundError as e:
        raise ToolNotFound("chisel", str(e))


def find_iodine() -> str:
    """Find iodine client binary or raise ToolNotFound."""
    from .toolchain import ensure_tool
    try:
        return ensure_tool("iodine")
    except FileNotFoundError as e:
        raise ToolNotFound("iodine", str(e))


def find_hans() -> str:
    """Find hans (ICMP tunnel) binary or raise ToolNotFound."""
    from .toolchain import ensure_tool
    try:
        return ensure_tool("hans")
    except FileNotFoundError as e:
        raise ToolNotFound("hans", str(e))


def start_chisel_tunnel(
    server_url: str,
    local_port: int = 1080,
    timeout: int = 15,
) -> TunnelHandle:
    """Start chisel client connecting to server, creating a SOCKS5 proxy.

    Args:
        server_url: The chisel server URL (e.g., https://your-server.example.com)
        local_port: Local SOCKS5 proxy port
        timeout: Seconds to wait for tunnel establishment
    """
    chisel_path = find_chisel()

    proc = subprocess.Popen(
        [chisel_path, "client", server_url, f"{local_port}:socks"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    handle = TunnelHandle(process=proc, local_port=local_port, method="chisel")

    # Wait for the SOCKS proxy to start listening
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if proc.poll() is not None:
            # Process died
            stderr = proc.stderr.read().decode() if proc.stderr else ""
            raise RuntimeError(f"Chisel exited early: {stderr[:500]}")

        if _port_listening(local_port):
            handle.active = True
            return handle

        time.sleep(0.5)

    # Timeout -- kill and report
    proc.terminate()
    stderr = proc.stderr.read().decode() if proc.stderr else ""
    raise RuntimeError(f"Chisel tunnel did not start within {timeout}s: {stderr[:500]}")


def start_dns_tunnel(
    domain: str,
    server_ip: str | None = None,
    timeout: int = 30,
) -> TunnelHandle:
    """Start iodine DNS tunnel.

    Args:
        domain: The DNS tunnel domain (e.g., t.example.com)
        server_ip: Optional server IP (otherwise resolved from domain)
        timeout: Seconds to wait for tunnel establishment
    """
    iodine_path = find_iodine()

    cmd = ["sudo", iodine_path, "-f"]
    if server_ip:
        cmd.append(server_ip)
    cmd.append(domain)

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    handle = TunnelHandle(process=proc, local_port=0, method="dns_tunnel")

    # iodine creates a tun interface; wait for it
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode() if proc.stderr else ""
            raise RuntimeError(f"iodine exited early: {stderr[:500]}")

        # Check if tun interface appeared
        try:
            result = subprocess.run(
                ["ifconfig", "dns0"], capture_output=True, text=True, timeout=3,
            )
            if "inet" in result.stdout:
                handle.active = True
                return handle
        except (subprocess.TimeoutExpired, OSError):
            pass

        time.sleep(1)

    proc.terminate()
    raise RuntimeError(f"DNS tunnel did not establish within {timeout}s")


def start_icmp_tunnel(
    server_ip: str,
    timeout: int = 15,
) -> TunnelHandle:
    """Start hans ICMP tunnel.

    Args:
        server_ip: The ICMP tunnel server IP
        timeout: Seconds to wait for tunnel establishment
    """
    hans_path = find_hans()

    proc = subprocess.Popen(
        ["sudo", hans_path, "-c", server_ip, "-f"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    handle = TunnelHandle(process=proc, local_port=0, method="icmp_tunnel")

    # hans creates a tun interface
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode() if proc.stderr else ""
            raise RuntimeError(f"hans exited early: {stderr[:500]}")

        try:
            result = subprocess.run(
                ["ifconfig", "tun0"], capture_output=True, text=True, timeout=3,
            )
            if "inet" in result.stdout:
                handle.active = True
                return handle
        except (subprocess.TimeoutExpired, OSError):
            pass

        time.sleep(1)

    proc.terminate()
    raise RuntimeError(f"ICMP tunnel did not establish within {timeout}s")


def verify_tunnel_socks(local_port: int = 1080) -> bool:
    """Verify a SOCKS tunnel provides internet access."""
    try:
        import requests
        proxies = {
            "http": f"socks5://127.0.0.1:{local_port}",
            "https": f"socks5://127.0.0.1:{local_port}",
        }
        resp = requests.get(
            "http://detectportal.firefox.com/canonical.html",
            proxies=proxies,
            timeout=10,
        )
        return resp.status_code == 200 and "success" in resp.text
    except Exception:
        return False


def verify_tunnel_direct() -> bool:
    """Verify internet access works (for tun-based tunnels like DNS/ICMP)."""
    try:
        import requests
        resp = requests.get(
            "http://detectportal.firefox.com/canonical.html",
            timeout=10,
        )
        return resp.status_code == 200 and "success" in resp.text
    except Exception:
        return False


def find_hysteria() -> str:
    """Find hysteria2 binary (auto-downloads if missing) or raise ToolNotFound."""
    from .toolchain import ensure_tool
    try:
        return ensure_tool("hysteria")
    except FileNotFoundError as e:
        raise ToolNotFound("hysteria", str(e))


def start_quic_tunnel(
    server: str,
    local_port: int = 1081,
    timeout: int = 15,
) -> TunnelHandle:
    """Start Hysteria2 QUIC tunnel (UDP/443 — bypasses TCP-only portals).

    Hysteria2 creates a SOCKS5 proxy over QUIC, which looks like HTTP/3 traffic.
    Most captive portals only inspect TCP, not UDP.
    """
    hysteria_path = find_hysteria()

    # Hysteria2 client config (minimal, inline via args)
    proc = subprocess.Popen(
        [hysteria_path, "client",
         "--server", server,
         "--socks5-listen", f"127.0.0.1:{local_port}",
         "--insecure"],  # Skip cert verify for direct IP connections
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    handle = TunnelHandle(process=proc, local_port=local_port, method="quic_hysteria2")

    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode() if proc.stderr else ""
            raise RuntimeError(f"Hysteria2 exited early: {stderr[:500]}")
        if _port_listening(local_port):
            handle.active = True
            return handle
        time.sleep(0.5)

    proc.terminate()
    stderr = proc.stderr.read().decode() if proc.stderr else ""
    raise RuntimeError(f"QUIC tunnel did not start within {timeout}s: {stderr[:500]}")


def find_ntpescape() -> str:
    """Find ntpescape binary or raise ToolNotFound."""
    from .toolchain import ensure_tool
    try:
        return ensure_tool("ntpescape")
    except FileNotFoundError as e:
        raise ToolNotFound("ntpescape", str(e))


def start_ntp_tunnel(
    server_ip: str,
    local_port: int = 1082,
    timeout: int = 20,
) -> TunnelHandle:
    """Start NTP tunnel (UDP/123 — almost universally allowed).

    Encodes data in NTP extension fields. Very low bandwidth (~1-10 Kbps)
    but NTP is almost never blocked by captive portals.
    """
    ntp_path = find_ntpescape()

    proc = subprocess.Popen(
        [ntp_path, "client",
         "--server", server_ip,
         "--socks", f"127.0.0.1:{local_port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    handle = TunnelHandle(process=proc, local_port=local_port, method="ntp_tunnel")

    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode() if proc.stderr else ""
            raise RuntimeError(f"NTP tunnel exited early: {stderr[:500]}")
        if _port_listening(local_port):
            handle.active = True
            return handle
        time.sleep(0.5)

    proc.terminate()
    raise RuntimeError(f"NTP tunnel did not start within {timeout}s")


def start_doh_tunnel(
    local_port: int = 1083,
    doh_server: str = "https://cloudflare-dns.com/dns-query",
    timeout: int = 15,
) -> TunnelHandle:
    """Start DNS-over-HTTPS tunnel via dnscrypt-proxy or cloudflared.

    Unlike plain DNS tunneling (iodine), DoH goes over HTTPS to trusted
    endpoints (Cloudflare, Google) that are often whitelisted by portals.
    """
    from .toolchain import find_tool

    # Try cloudflared proxy-dns first (single binary, widely available)
    cloudflared = find_tool("cloudflared")
    if cloudflared:
        proc = subprocess.Popen(
            [cloudflared, "proxy-dns",
             "--port", str(local_port),
             "--upstream", doh_server],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        handle = TunnelHandle(process=proc, local_port=local_port, method="doh_tunnel")

        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if proc.poll() is not None:
                break
            if _port_listening(local_port):
                handle.active = True
                return handle
            time.sleep(0.5)
        proc.terminate()

    # Try dnscrypt-proxy
    dnscrypt = find_tool("dnscrypt-proxy")
    if dnscrypt:
        proc = subprocess.Popen(
            [dnscrypt, "--listen_addresses", f"127.0.0.1:{local_port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        handle = TunnelHandle(process=proc, local_port=local_port, method="doh_tunnel")

        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if proc.poll() is not None:
                break
            if _port_listening(local_port):
                handle.active = True
                return handle
            time.sleep(0.5)
        proc.terminate()

    # Last resort: try auto-downloading cloudflared
    from .toolchain import download_tool
    downloaded = download_tool("cloudflared")
    if downloaded:
        proc = subprocess.Popen(
            [downloaded, "proxy-dns",
             "--port", str(local_port),
             "--upstream", doh_server],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        handle = TunnelHandle(process=proc, local_port=local_port, method="doh_tunnel")

        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if proc.poll() is not None:
                break
            if _port_listening(local_port):
                handle.active = True
                return handle
            time.sleep(0.5)
        proc.terminate()

    raise ToolNotFound("cloudflared or dnscrypt-proxy", "brew install cloudflared  OR  brew install dnscrypt-proxy")


def verify_cf_workers_proxy(worker_url: str) -> bool:
    """Verify a Cloudflare Workers proxy provides internet access.

    The Worker acts as an HTTPS proxy — we send requests to it and it
    fetches the real content. No tunnel binary needed.
    """
    import requests
    try:
        # The worker URL should proxy requests: worker_url/https://target
        test_url = f"{worker_url}/https://connectivitycheck.gstatic.com/generate_204"
        resp = requests.get(test_url, timeout=10)
        return resp.status_code == 204
    except Exception:
        return False


def _port_listening(port: int) -> bool:
    """Check if a local port is accepting connections."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex(("127.0.0.1", port))
            return result == 0
        finally:
            sock.close()
    except (socket.error, OSError):
        return False
