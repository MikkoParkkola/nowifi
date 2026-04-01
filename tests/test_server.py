"""Tests for server provisioning module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from nowifi.cli import main
from nowifi.server import (
    CF_WORKER_JS,
    CLOUD_INIT_SCRIPT,
    SERVER_REQUIRED_TECHNIQUES,
    SERVERLESS_TECHNIQUES,
    ServerInfo,
    check_expired_servers,
    list_servers,
    load_config,
    load_servers,
    save_config,
    save_server,
)


# ---------------------------------------------------------------------------
# ServerInfo
# ---------------------------------------------------------------------------

class TestServerInfo:

    def test_create_dataclass(self):
        info = ServerInfo(
            provider="digitalocean",
            server_id="12345",
            ip="203.0.113.1",
            url="https://203.0.113.1:443",
            created_at="2026-03-29T00:00:00+00:00",
            ttl_hours=24,
            status="active",
        )
        assert info.provider == "digitalocean"
        assert info.ip == "203.0.113.1"
        assert info.status == "active"

    def test_cf_worker_no_ip(self):
        info = ServerInfo(
            provider="cloudflare_worker",
            server_id="nowifi-proxy",
            ip="",
            url="https://nowifi-proxy.user.workers.dev",
            created_at="2026-03-29T00:00:00+00:00",
            ttl_hours=0,
            status="active",
        )
        assert info.ip == ""
        assert info.ttl_hours == 0


# ---------------------------------------------------------------------------
# Technique classification
# ---------------------------------------------------------------------------

class TestTechniqueClassification:

    def test_serverless_count(self):
        assert len(SERVERLESS_TECHNIQUES) == 10

    def test_server_required_count(self):
        assert len(SERVER_REQUIRED_TECHNIQUES) == 9

    def test_no_overlap(self):
        overlap = set(SERVERLESS_TECHNIQUES) & set(SERVER_REQUIRED_TECHNIQUES)
        assert overlap == set(), f"Overlap: {overlap}"

    def test_serverless_includes_ipv6(self):
        assert "ipv6_bypass" in SERVERLESS_TECHNIQUES

    def test_server_required_includes_chisel(self):
        assert "chisel_tunnel" in SERVER_REQUIRED_TECHNIQUES


# ---------------------------------------------------------------------------
# Persistence (servers.json + config.json)
# ---------------------------------------------------------------------------

class TestPersistence:

    def test_save_and_load_servers(self, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._NOWIFI_DIR", tmp_path)
        monkeypatch.setattr("nowifi.server._SERVERS_FILE", tmp_path / "servers.json")

        info = ServerInfo(
            provider="hetzner",
            server_id="999",
            ip="10.0.0.1",
            url="https://10.0.0.1:443",
            created_at="2026-03-29T12:00:00+00:00",
            ttl_hours=6,
            status="active",
        )
        save_server(info)

        loaded = load_servers()
        assert len(loaded) == 1
        assert loaded[0].provider == "hetzner"
        assert loaded[0].server_id == "999"

    def test_save_updates_existing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._NOWIFI_DIR", tmp_path)
        monkeypatch.setattr("nowifi.server._SERVERS_FILE", tmp_path / "servers.json")

        info = ServerInfo(
            provider="digitalocean", server_id="100", ip="1.2.3.4",
            url="https://1.2.3.4:443", created_at="2026-01-01T00:00:00+00:00",
            ttl_hours=24, status="active",
        )
        save_server(info)

        # Update same server
        info.status = "destroyed"
        save_server(info)

        loaded = load_servers()
        assert len(loaded) == 1
        assert loaded[0].status == "destroyed"

    def test_load_servers_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._SERVERS_FILE", tmp_path / "nonexistent.json")
        assert load_servers() == []

    def test_load_servers_bad_json(self, tmp_path, monkeypatch):
        bad_file = tmp_path / "servers.json"
        bad_file.write_text("not json")
        monkeypatch.setattr("nowifi.server._SERVERS_FILE", bad_file)
        assert load_servers() == []

    def test_save_and_load_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._NOWIFI_DIR", tmp_path)
        monkeypatch.setattr("nowifi.server._CONFIG_FILE", tmp_path / "config.json")

        save_config({"tunnel_server": "https://example.com", "digitalocean_token": "tok123"})
        cfg = load_config()
        assert cfg["tunnel_server"] == "https://example.com"
        assert cfg["digitalocean_token"] == "tok123"

    def test_load_config_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._CONFIG_FILE", tmp_path / "nope.json")
        assert load_config() == {}


# ---------------------------------------------------------------------------
# list_servers / check_expired
# ---------------------------------------------------------------------------

class TestListAndExpiry:

    def test_list_excludes_destroyed(self, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._NOWIFI_DIR", tmp_path)
        monkeypatch.setattr("nowifi.server._SERVERS_FILE", tmp_path / "servers.json")

        active = ServerInfo("do", "1", "1.1.1.1", "https://1.1.1.1:443",
                            "2026-03-29T00:00:00+00:00", 24, "active")
        dead = ServerInfo("do", "2", "2.2.2.2", "https://2.2.2.2:443",
                          "2026-03-29T00:00:00+00:00", 24, "destroyed")
        save_server(active)
        save_server(dead)

        result = list_servers()
        assert len(result) == 1
        assert result[0].server_id == "1"

    def test_check_expired(self, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._NOWIFI_DIR", tmp_path)
        monkeypatch.setattr("nowifi.server._SERVERS_FILE", tmp_path / "servers.json")

        # Created 48 hours ago with 24h TTL -> expired
        old = ServerInfo("do", "old", "1.1.1.1", "https://1.1.1.1:443",
                         "2020-01-01T00:00:00+00:00", 24, "active")
        save_server(old)

        expired = check_expired_servers()
        assert len(expired) == 1
        assert expired[0].server_id == "old"

    def test_no_expire_if_ttl_zero(self, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._NOWIFI_DIR", tmp_path)
        monkeypatch.setattr("nowifi.server._SERVERS_FILE", tmp_path / "servers.json")

        cf = ServerInfo("cloudflare_worker", "nowifi-proxy", "", "https://x.workers.dev",
                        "2020-01-01T00:00:00+00:00", 0, "active")
        save_server(cf)

        expired = check_expired_servers()
        assert len(expired) == 0


# ---------------------------------------------------------------------------
# Embedded assets
# ---------------------------------------------------------------------------

class TestEmbeddedAssets:

    def test_cf_worker_js_contains_fetch(self):
        assert "async fetch(request)" in CF_WORKER_JS
        assert "targetUrl" in CF_WORKER_JS

    def test_cloud_init_installs_chisel(self):
        assert "chisel" in CLOUD_INIT_SCRIPT
        assert "iodine" in CLOUD_INIT_SCRIPT
        assert "hans" in CLOUD_INIT_SCRIPT
        assert "#!/bin/bash" in CLOUD_INIT_SCRIPT


# ---------------------------------------------------------------------------
# VPS creation (mocked API)
# ---------------------------------------------------------------------------

class TestCreateVPS:

    @patch("nowifi.server.requests.post")
    @patch("nowifi.server._wait_for_droplet_ip", return_value="203.0.113.10")
    def test_create_digitalocean(self, mock_wait, mock_post, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._NOWIFI_DIR", tmp_path)
        monkeypatch.setattr("nowifi.server._SERVERS_FILE", tmp_path / "servers.json")
        monkeypatch.setattr("nowifi.server._CONFIG_FILE", tmp_path / "config.json")

        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"droplet": {"id": 77777}}
        mock_post.return_value = mock_resp

        from nowifi.server import create_vps
        info = create_vps(provider="digitalocean", api_token="test-token", ttl_hours=12)

        assert info.provider == "digitalocean"
        assert info.server_id == "77777"
        assert info.ip == "203.0.113.10"
        assert info.ttl_hours == 12
        assert info.status == "active"

        # Verify API called correctly
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert "Bearer test-token" in str(call_kwargs)

    @patch("nowifi.server.requests.post")
    def test_create_digitalocean_api_error(self, mock_post, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._NOWIFI_DIR", tmp_path)
        monkeypatch.setattr("nowifi.server._SERVERS_FILE", tmp_path / "servers.json")
        monkeypatch.setattr("nowifi.server._CONFIG_FILE", tmp_path / "config.json")

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_post.return_value = mock_resp

        from nowifi.server import create_vps
        with pytest.raises(RuntimeError, match="DigitalOcean API error"):
            create_vps(provider="digitalocean", api_token="bad-token")

    @patch("nowifi.server.requests.post")
    def test_create_hetzner(self, mock_post, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._NOWIFI_DIR", tmp_path)
        monkeypatch.setattr("nowifi.server._SERVERS_FILE", tmp_path / "servers.json")
        monkeypatch.setattr("nowifi.server._CONFIG_FILE", tmp_path / "config.json")

        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {
            "server": {
                "id": 88888,
                "public_net": {"ipv4": {"ip": "198.51.100.5"}},
            }
        }
        mock_post.return_value = mock_resp

        from nowifi.server import create_vps
        info = create_vps(provider="hetzner", api_token="htz-token", ttl_hours=6)

        assert info.provider == "hetzner"
        assert info.ip == "198.51.100.5"
        assert info.ttl_hours == 6

    def test_create_unknown_provider(self):
        from nowifi.server import create_vps
        with pytest.raises(ValueError, match="Unknown provider"):
            create_vps(provider="aws", api_token="tok")

    def test_create_no_token_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._CONFIG_FILE", tmp_path / "config.json")

        from nowifi.server import create_vps
        with pytest.raises(ValueError, match="No API token"):
            create_vps(provider="digitalocean", api_token="")


# ---------------------------------------------------------------------------
# VPS destroy (mocked API)
# ---------------------------------------------------------------------------

class TestDestroyVPS:

    @patch("nowifi.server.requests.delete")
    def test_destroy_digitalocean(self, mock_delete, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._NOWIFI_DIR", tmp_path)
        monkeypatch.setattr("nowifi.server._SERVERS_FILE", tmp_path / "servers.json")
        monkeypatch.setattr("nowifi.server._CONFIG_FILE", tmp_path / "config.json")

        # Pre-populate a server
        info = ServerInfo("digitalocean", "77777", "203.0.113.10",
                          "https://203.0.113.10:443", "2026-03-29T00:00:00+00:00",
                          24, "active")
        save_server(info)

        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_delete.return_value = mock_resp

        from nowifi.server import destroy_vps
        ok = destroy_vps("digitalocean", "77777", "test-token")
        assert ok is True

        # Verify it's marked destroyed
        all_servers = load_servers()
        assert all_servers[0].status == "destroyed"

    @patch("nowifi.server.requests.delete")
    def test_destroy_hetzner(self, mock_delete, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._NOWIFI_DIR", tmp_path)
        monkeypatch.setattr("nowifi.server._SERVERS_FILE", tmp_path / "servers.json")
        monkeypatch.setattr("nowifi.server._CONFIG_FILE", tmp_path / "config.json")

        info = ServerInfo("hetzner", "88888", "198.51.100.5",
                          "https://198.51.100.5:443", "2026-03-29T00:00:00+00:00",
                          6, "active")
        save_server(info)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_delete.return_value = mock_resp

        from nowifi.server import destroy_vps
        ok = destroy_vps("hetzner", "88888", "htz-token")
        assert ok is True


# ---------------------------------------------------------------------------
# CLI: server subcommands
# ---------------------------------------------------------------------------

class TestServerCLI:

    def test_server_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["server", "--help"])
        assert result.exit_code == 0
        assert "Cloudflare Workers" in result.output
        assert "Ephemeral VPS" in result.output

    def test_server_create_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["server", "create", "--help"])
        assert result.exit_code == 0
        assert "--provider" in result.output
        assert "--token" in result.output
        assert "--ttl" in result.output

    def test_server_list_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr("nowifi.server._SERVERS_FILE", tmp_path / "servers.json")

        runner = CliRunner()
        result = runner.invoke(main, ["server", "list"])
        assert result.exit_code == 0
        assert "No active servers" in result.output

    def test_server_destroy_no_args(self):
        runner = CliRunner()
        result = runner.invoke(main, ["server", "destroy"])
        assert result.exit_code != 0

    def test_server_info(self):
        runner = CliRunner()
        result = runner.invoke(main, ["server", "info"])
        assert result.exit_code == 0
        assert "10 techniques need NO server" in result.output
        assert "9 techniques NEED a server" in result.output
        assert "ipv6_bypass" in result.output
        assert "chisel_tunnel" in result.output

    def test_server_subcommands_in_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert "server" in result.output
