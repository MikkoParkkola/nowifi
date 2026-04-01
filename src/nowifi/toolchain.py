"""Auto-download and manage external tool binaries."""

from __future__ import annotations

import gzip
import os
import platform
import stat
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

TOOL_DIR = Path.home() / ".nowifi" / "bin"


@dataclass
class ToolInfo:
    name: str
    description: str
    download_url: str  # GitHub release URL pattern with {version}, {os}, {arch}
    binary_name: str
    version: str
    required_for: list[str] = field(default_factory=list)


# Tool registry -- downloadable binaries for macOS/Linux (ARM64 + AMD64)
TOOLS: dict[str, ToolInfo] = {
    "chisel": ToolInfo(
        name="chisel",
        description="HTTPS/WebSocket tunnel",
        download_url="https://github.com/jpillora/chisel/releases/download/v{version}/chisel_{version}_{os}_{arch}.gz",
        binary_name="chisel",
        version="1.10.1",
        required_for=["chisel_tunnel"],
    ),
    "hysteria": ToolInfo(
        name="hysteria",
        description="QUIC/HTTP3 tunnel (UDP/443)",
        download_url="https://github.com/apernet/hysteria/releases/download/app%2Fv{version}/hysteria-{os}-{arch}",
        binary_name="hysteria",
        version="2.6.1",
        required_for=["quic_tunnel"],
    ),
    "cloudflared": ToolInfo(
        name="cloudflared",
        description="Cloudflare Tunnel / DoH proxy",
        download_url="https://github.com/cloudflare/cloudflared/releases/download/{version}/cloudflared-{os}-{arch}",
        binary_name="cloudflared",
        version="2024.12.2",
        required_for=["doh_tunnel"],
    ),
}

# Tools that need compilation or system packages (not auto-downloadable)
SYSTEM_TOOLS: dict[str, str] = {
    "iodine": "brew install iodine",
    "hans": "brew install hans  OR  build from https://github.com/friedrich/hans",
    "hashcat": "brew install hashcat",
    "hcxdumptool": "brew install hcxdumptool",
    "hcxpcapngtool": "brew install hcxtools",
    "aircrack-ng": "brew install aircrack-ng",
    "ntpescape": "https://github.com/evallen/ntpescape",
    "dnscrypt-proxy": "brew install dnscrypt-proxy",
}


def ensure_tool_dir() -> Path:
    """Create ~/.nowifi/bin/ if it doesn't exist."""
    TOOL_DIR.mkdir(parents=True, exist_ok=True)
    return TOOL_DIR


def find_tool(name: str) -> str | None:
    """Find a tool binary. Checks: PATH, ~/.nowifi/bin/, ~/bin/, /usr/local/bin/."""
    import shutil

    candidates = [
        shutil.which(name),
        str(TOOL_DIR / name),
        str(Path.home() / "bin" / name),
        f"/usr/local/bin/{name}",
    ]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _resolve_platform() -> tuple[str, str] | None:
    """Return (os_name, arch) for download URLs, or None if unsupported."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "darwin":
        os_name = "darwin"
        arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    elif system == "linux":
        os_name = "linux"
        arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    else:
        return None

    return os_name, arch


def download_tool(name: str) -> str | None:
    """Download a tool binary to ~/.nowifi/bin/. Returns path or None."""
    if name not in TOOLS:
        return None

    info = TOOLS[name]
    ensure_tool_dir()

    plat = _resolve_platform()
    if plat is None:
        return None
    os_name, arch = plat

    url = info.download_url.format(version=info.version, os=os_name, arch=arch)
    dest = TOOL_DIR / info.binary_name

    try:
        if url.endswith(".gz"):
            gz_path = str(dest) + ".gz"
            urllib.request.urlretrieve(url, gz_path)
            with gzip.open(gz_path, "rb") as f_in, open(str(dest), "wb") as f_out:
                f_out.write(f_in.read())
            os.unlink(gz_path)
        else:
            urllib.request.urlretrieve(url, str(dest))

        # Make executable
        dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        return str(dest)
    except Exception:
        # Clean up partial download
        if dest.exists():
            dest.unlink()
        return None


def ensure_tool(name: str) -> str:
    """Find tool or download it. Returns path. Raises FileNotFoundError if unavailable."""
    path = find_tool(name)
    if path:
        return path

    # Try auto-download for registered tools
    path = download_tool(name)
    if path:
        return path

    # Fall back to install instructions
    hint = SYSTEM_TOOLS.get(name) or TOOLS.get(name, None)
    if hint and isinstance(hint, str):
        raise FileNotFoundError(f"{name} not found. Install: {hint}")
    raise FileNotFoundError(f"{name} not found and no auto-download available.")


def list_tools() -> dict[str, dict]:
    """List all known tools with their status."""
    result: dict[str, dict] = {}

    # Downloadable tools
    for name, info in TOOLS.items():
        path = find_tool(name)
        result[name] = {
            "installed": path is not None,
            "path": path or "",
            "description": info.description,
            "required_for": info.required_for,
            "downloadable": True,
            "install_hint": "",
        }

    # System-only tools
    for name, hint in SYSTEM_TOOLS.items():
        if name not in result:
            path = find_tool(name)
            result[name] = {
                "installed": path is not None,
                "path": path or "",
                "description": "",
                "required_for": [],
                "downloadable": False,
                "install_hint": hint,
            }

    return result
