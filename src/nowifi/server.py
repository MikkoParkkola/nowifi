"""Server provisioning: spin up your OWN tunnel infrastructure.

Three options:
  A. Cloudflare Workers (FREE, no server needed) — HTTPS proxy on CF edge
  B. Ephemeral VPS (DigitalOcean / Hetzner) — chisel + iodine + hans pre-installed
  C. No server — 10 of 23 techniques need no server at all
"""

from __future__ import annotations

import json
import subprocess
import shutil
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import requests


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ServerInfo:
    provider: str       # "cloudflare_worker", "digitalocean", "hetzner", "custom"
    server_id: str      # Droplet ID, Hetzner server ID, or Worker name
    ip: str             # Public IP (empty for CF Workers)
    url: str            # Chisel/proxy URL
    created_at: str     # ISO timestamp
    ttl_hours: int      # Auto-destroy after this (0 = never)
    status: str         # "active", "creating", "destroyed"


# ---------------------------------------------------------------------------
# Technique classification
# ---------------------------------------------------------------------------

SERVERLESS_TECHNIQUES = [
    "ipv6_bypass",
    "cna_useragent_spoof",
    "js_only_bypass",
    "http_connect_abuse",
    "mac_clone_idle",
    "mac_clone",
    "session_cookie_replay",
    "portal_default_creds",
    "mac_rotate",
    "dhcp_rotate",
]

SERVER_REQUIRED_TECHNIQUES = [
    "chisel_tunnel",       # needs HTTPS tunnel server
    "dns_tunnel",          # needs DNS tunnel server + domain
    "icmp_tunnel",         # needs ICMP tunnel server
    "vpn_port_53",         # needs VPN server on port 53
    "whitelist_domain",    # needs proxy on whitelisted CDN
    "quic_tunnel",         # needs QUIC tunnel server
    "cf_workers_proxy",    # needs CF Worker deployed
    "ntp_tunnel",          # needs NTP tunnel server
    "doh_tunnel",          # needs DoH proxy (cloudflared)
]


# ---------------------------------------------------------------------------
# Config + persistence helpers
# ---------------------------------------------------------------------------

_NOWIFI_DIR = Path.home() / ".nowifi"
_SERVERS_FILE = _NOWIFI_DIR / "servers.json"
_CONFIG_FILE = _NOWIFI_DIR / "config.json"


def _ensure_dir() -> None:
    _NOWIFI_DIR.mkdir(parents=True, exist_ok=True)


def save_server(info: ServerInfo) -> None:
    """Save server info to ~/.nowifi/servers.json."""
    _ensure_dir()
    servers = load_servers()
    # Update existing or append
    updated = False
    for i, s in enumerate(servers):
        if s.server_id == info.server_id and s.provider == info.provider:
            servers[i] = info
            updated = True
            break
    if not updated:
        servers.append(info)
    _SERVERS_FILE.write_text(
        json.dumps([asdict(s) for s in servers], indent=2),
    )


def load_servers() -> list[ServerInfo]:
    """Load all saved servers from ~/.nowifi/servers.json."""
    if not _SERVERS_FILE.exists():
        return []
    try:
        data = json.loads(_SERVERS_FILE.read_text())
        return [ServerInfo(**entry) for entry in data]
    except (json.JSONDecodeError, TypeError, KeyError):
        return []


def load_config() -> dict:
    """Load ~/.nowifi/config.json (tokens, URLs)."""
    if not _CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(_CONFIG_FILE.read_text())
    except json.JSONDecodeError:
        return {}


def save_config(cfg: dict) -> None:
    """Save ~/.nowifi/config.json."""
    _ensure_dir()
    _CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def _get_token(provider: str, explicit_token: str) -> str:
    """Get API token: explicit arg > config file > raise."""
    if explicit_token:
        return explicit_token
    cfg = load_config()
    key = f"{provider}_token"
    token = cfg.get(key, "")
    if not token:
        raise ValueError(
            f"No API token for {provider}. "
            f"Pass --token or set '{key}' in {_CONFIG_FILE}"
        )
    return token


# ---------------------------------------------------------------------------
# Option A: Cloudflare Workers
# ---------------------------------------------------------------------------

CF_WORKER_JS = """\
// Cloudflare Worker -- transparent HTTPS proxy for nowifi
export default {
  async fetch(request) {
    const url = new URL(request.url);
    // Path format: /https://target.com/path
    const targetUrl = url.pathname.slice(1) + url.search;
    if (!targetUrl.startsWith('http')) {
      return new Response('nowifi tunnel proxy active', { status: 200 });
    }
    try {
      const resp = await fetch(targetUrl, {
        method: request.method,
        headers: request.headers,
        body: request.body,
      });
      return new Response(resp.body, {
        status: resp.status,
        headers: resp.headers,
      });
    } catch (e) {
      return new Response(e.message, { status: 502 });
    }
  }
};
"""

CF_WRANGLER_TOML = """\
name = "nowifi-proxy"
main = "worker.js"
compatibility_date = "{date}"
"""


def _find_wrangler() -> str | None:
    """Find the wrangler CLI binary."""
    return shutil.which("wrangler")


def setup_cloudflare_worker() -> str:
    """Guide user through deploying a CF Worker as HTTPS proxy.

    Returns the worker URL on success, or raises RuntimeError on failure.
    Steps:
        1. Check if wrangler is installed (install if missing)
        2. Verify wrangler login
        3. Create temp project with worker code
        4. Deploy via wrangler deploy
        5. Return the worker URL
    """
    import tempfile

    # 1. Find or install wrangler
    wrangler = _find_wrangler()
    if not wrangler:
        # Try installing via npm
        npm = shutil.which("npm")
        if not npm:
            raise RuntimeError(
                "wrangler (Cloudflare CLI) not found and npm is not installed.\n"
                "Install Node.js first: https://nodejs.org\n"
                "Then: npm install -g wrangler"
            )
        result = subprocess.run(
            [npm, "install", "-g", "wrangler"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to install wrangler: {result.stderr[:500]}")
        wrangler = shutil.which("wrangler")
        if not wrangler:
            raise RuntimeError("wrangler installed but not found on PATH. Try: npx wrangler")

    # 2. Check login status (wrangler whoami)
    result = subprocess.run(
        [wrangler, "whoami"], capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0 or "not authenticated" in result.stdout.lower():
        raise RuntimeError(
            "Not logged in to Cloudflare. Run:\n"
            "  wrangler login\n"
            "Then retry: nowifi server create -p cloudflare"
        )

    # 3. Create temp project directory with worker code
    with tempfile.TemporaryDirectory(prefix="nowifi-cf-") as tmpdir:
        worker_path = Path(tmpdir) / "worker.js"
        worker_path.write_text(CF_WORKER_JS)

        toml_path = Path(tmpdir) / "wrangler.toml"
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        toml_path.write_text(CF_WRANGLER_TOML.format(date=today))

        # 4. Deploy
        result = subprocess.run(
            [wrangler, "deploy"],
            capture_output=True, text=True, timeout=60,
            cwd=tmpdir,
        )
        if result.returncode != 0:
            raise RuntimeError(f"wrangler deploy failed:\n{result.stderr[:500]}")

        # 5. Parse the worker URL from output
        # wrangler prints something like: Published nowifi-proxy (https://nowifi-proxy.USER.workers.dev)
        output = result.stdout + result.stderr
        import re
        url_match = re.search(r"(https://[^\s)]+\.workers\.dev)", output)
        if not url_match:
            raise RuntimeError(
                f"Deploy succeeded but could not parse worker URL from output:\n{output[:500]}"
            )
        worker_url = url_match.group(1).rstrip("/")

    # Save server info
    info = ServerInfo(
        provider="cloudflare_worker",
        server_id="nowifi-proxy",
        ip="",
        url=worker_url,
        created_at=datetime.now(timezone.utc).isoformat(),
        ttl_hours=0,
        status="active",
    )
    save_server(info)

    # Update config with worker URL
    cfg = load_config()
    cfg["cf_workers_url"] = worker_url
    save_config(cfg)

    return worker_url


# ---------------------------------------------------------------------------
# Option B: Ephemeral VPS
# ---------------------------------------------------------------------------

CLOUD_INIT_SCRIPT = """\
#!/bin/bash
set -e

# Install chisel
curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz | gunzip > /usr/local/bin/chisel
chmod +x /usr/local/bin/chisel

# Start chisel on multiple ports
chisel server --reverse --port 443 &
chisel server --reverse --port 8080 &
chisel server --reverse --port 80 &

# Install iodine (DNS tunnel)
apt-get update && apt-get install -y iodine

# Install hans (ICMP tunnel)
apt-get install -y hans
"""


def create_vps(
    provider: str = "digitalocean",
    api_token: str = "",
    ttl_hours: int = 24,
) -> ServerInfo:
    """Create an ephemeral VPS with tunnel tools pre-installed.

    Supported providers: digitalocean, hetzner.
    Uses cloud-init to install chisel + iodine + hans on first boot.
    """
    token = _get_token(provider, api_token)

    if provider == "digitalocean":
        return _create_digitalocean(token, ttl_hours)
    elif provider == "hetzner":
        return _create_hetzner(token, ttl_hours)
    else:
        raise ValueError(f"Unknown provider: {provider!r}. Use 'digitalocean' or 'hetzner'.")


def _create_digitalocean(token: str, ttl_hours: int) -> ServerInfo:
    """Create a DigitalOcean droplet ($0.007/hr, smallest instance)."""
    resp = requests.post(
        "https://api.digitalocean.com/v2/droplets",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={
            "name": "nowifi-tunnel",
            "region": "nyc1",
            "size": "s-1vcpu-512mb-10gb",
            "image": "ubuntu-24-04-x64",
            "user_data": CLOUD_INIT_SCRIPT,
            "tags": ["nowifi"],
        },
        timeout=30,
    )
    if resp.status_code not in (201, 202):
        raise RuntimeError(
            f"DigitalOcean API error ({resp.status_code}): {resp.text[:500]}"
        )

    data = resp.json()["droplet"]
    droplet_id = str(data["id"])

    # Poll for public IP (droplet takes ~30-60s to provision)
    ip = _wait_for_droplet_ip(token, droplet_id, timeout=120)

    info = ServerInfo(
        provider="digitalocean",
        server_id=droplet_id,
        ip=ip,
        url=f"https://{ip}:443",
        created_at=datetime.now(timezone.utc).isoformat(),
        ttl_hours=ttl_hours,
        status="active",
    )
    save_server(info)

    # Update config with tunnel server URL
    cfg = load_config()
    cfg["tunnel_server"] = info.url
    save_config(cfg)

    return info


def _wait_for_droplet_ip(token: str, droplet_id: str, timeout: int = 120) -> str:
    """Poll DigitalOcean API until droplet has a public IPv4 address."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        resp = requests.get(
            f"https://api.digitalocean.com/v2/droplets/{droplet_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        if resp.status_code == 200:
            networks = resp.json()["droplet"].get("networks", {})
            for net in networks.get("v4", []):
                if net.get("type") == "public":
                    return net["ip_address"]
        time.sleep(5)
    raise RuntimeError(f"Droplet {droplet_id} did not get a public IP within {timeout}s")


def _create_hetzner(token: str, ttl_hours: int) -> ServerInfo:
    """Create a Hetzner Cloud server ($0.005/hr, smallest instance)."""
    resp = requests.post(
        "https://api.hetzner.cloud/v1/servers",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={
            "name": "nowifi-tunnel",
            "server_type": "cx22",
            "image": "ubuntu-24.04",
            "location": "fsn1",
            "user_data": CLOUD_INIT_SCRIPT,
            "labels": {"project": "nowifi"},
        },
        timeout=30,
    )
    if resp.status_code not in (200, 201):
        raise RuntimeError(
            f"Hetzner API error ({resp.status_code}): {resp.text[:500]}"
        )

    data = resp.json()["server"]
    server_id = str(data["id"])
    ip = data.get("public_net", {}).get("ipv4", {}).get("ip", "")

    if not ip:
        ip = _wait_for_hetzner_ip(token, server_id, timeout=120)

    info = ServerInfo(
        provider="hetzner",
        server_id=server_id,
        ip=ip,
        url=f"https://{ip}:443",
        created_at=datetime.now(timezone.utc).isoformat(),
        ttl_hours=ttl_hours,
        status="active",
    )
    save_server(info)

    cfg = load_config()
    cfg["tunnel_server"] = info.url
    save_config(cfg)

    return info


def _wait_for_hetzner_ip(token: str, server_id: str, timeout: int = 120) -> str:
    """Poll Hetzner API until server has a public IPv4 address."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        resp = requests.get(
            f"https://api.hetzner.cloud/v1/servers/{server_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        if resp.status_code == 200:
            ip = resp.json()["server"].get("public_net", {}).get("ipv4", {}).get("ip", "")
            if ip:
                return ip
        time.sleep(5)
    raise RuntimeError(f"Hetzner server {server_id} did not get a public IP within {timeout}s")


def destroy_vps(provider: str, server_id: str, api_token: str = "") -> bool:
    """Destroy an ephemeral VPS.

    Returns True on success, False on failure.
    """
    token = _get_token(provider, api_token)

    if provider == "digitalocean":
        resp = requests.delete(
            f"https://api.digitalocean.com/v2/droplets/{server_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        ok = resp.status_code == 204
    elif provider == "hetzner":
        resp = requests.delete(
            f"https://api.hetzner.cloud/v1/servers/{server_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        ok = resp.status_code == 200
    elif provider == "cloudflare_worker":
        # CF Workers: use wrangler to delete
        wrangler = _find_wrangler()
        if not wrangler:
            return False
        result = subprocess.run(
            [wrangler, "delete", "--name", server_id, "--force"],
            capture_output=True, text=True, timeout=30,
        )
        ok = result.returncode == 0
    else:
        return False

    if ok:
        _mark_destroyed(provider, server_id)
    return ok


def _mark_destroyed(provider: str, server_id: str) -> None:
    """Mark a server as destroyed in servers.json."""
    servers = load_servers()
    for s in servers:
        if s.server_id == server_id and s.provider == provider:
            s.status = "destroyed"
    _ensure_dir()
    _SERVERS_FILE.write_text(
        json.dumps([asdict(s) for s in servers], indent=2),
    )


def list_servers() -> list[ServerInfo]:
    """List active nowifi VPS instances from ~/.nowifi/servers.json."""
    return [s for s in load_servers() if s.status != "destroyed"]


def check_expired_servers() -> list[ServerInfo]:
    """Find servers that have exceeded their TTL."""
    now = datetime.now(timezone.utc)
    expired = []
    for s in load_servers():
        if s.status == "destroyed" or s.ttl_hours <= 0:
            continue
        try:
            created = datetime.fromisoformat(s.created_at)
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            elapsed_hours = (now - created).total_seconds() / 3600
            if elapsed_hours > s.ttl_hours:
                expired.append(s)
        except (ValueError, TypeError):
            continue
    return expired
