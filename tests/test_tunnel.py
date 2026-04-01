"""Tests for tunnel management."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from nowifi.tunnel import (
    ToolNotFound,
    TunnelHandle,
    _port_listening,
    find_chisel,
    find_hans,
    find_iodine,
    find_hysteria,
    find_ntpescape,
    start_chisel_tunnel,
    start_dns_tunnel,
    start_doh_tunnel,
    start_icmp_tunnel,
    start_ntp_tunnel,
    start_quic_tunnel,
    verify_cf_workers_proxy,
    verify_tunnel_direct,
    verify_tunnel_socks,
)


# ---------------------------------------------------------------------------
# TunnelHandle
# ---------------------------------------------------------------------------

class TestTunnelHandle:

    def test_stop_terminates_process(self):
        """stop() terminates the subprocess."""
        proc = MagicMock()
        proc.poll.return_value = None  # still running
        handle = TunnelHandle(process=proc, local_port=1080, method="chisel")
        handle.active = True

        handle.stop()
        proc.terminate.assert_called_once()
        assert handle.active is False

    def test_stop_kills_on_timeout(self):
        """stop() kills process if terminate times out."""
        proc = MagicMock()
        proc.poll.return_value = None
        proc.wait.side_effect = subprocess.TimeoutExpired(cmd="chisel", timeout=5)
        handle = TunnelHandle(process=proc, local_port=1080, method="chisel")
        handle.active = True

        handle.stop()
        proc.kill.assert_called_once()
        assert handle.active is False

    def test_stop_already_exited(self):
        """stop() handles already-exited process."""
        proc = MagicMock()
        proc.poll.return_value = 0  # already exited
        handle = TunnelHandle(process=proc, local_port=1080, method="chisel")
        handle.active = True

        handle.stop()
        proc.terminate.assert_not_called()
        assert handle.active is False

    def test_stop_no_process(self):
        """stop() handles None process."""
        handle = TunnelHandle(process=None, local_port=1080, method="chisel")
        handle.active = True
        handle.stop()  # should not raise
        assert handle.active is False


# ---------------------------------------------------------------------------
# ToolNotFound
# ---------------------------------------------------------------------------

class TestToolNotFound:

    def test_attributes(self):
        e = ToolNotFound("chisel", "brew install chisel")
        assert e.tool == "chisel"
        assert e.install_hint == "brew install chisel"
        assert "chisel" in str(e)
        assert "brew install" in str(e)


# ---------------------------------------------------------------------------
# find_* functions
# ---------------------------------------------------------------------------

class TestFindTools:

    @patch("nowifi.toolchain.ensure_tool", return_value="/usr/local/bin/chisel")
    def test_find_chisel_success(self, mock_ensure):
        path = find_chisel()
        assert path == "/usr/local/bin/chisel"

    @patch("nowifi.toolchain.ensure_tool", side_effect=FileNotFoundError("chisel not found"))
    def test_find_chisel_not_found(self, mock_ensure):
        with pytest.raises(ToolNotFound) as exc_info:
            find_chisel()
        assert "chisel" in exc_info.value.tool

    @patch("nowifi.toolchain.ensure_tool", return_value="/usr/local/bin/iodine")
    def test_find_iodine_success(self, mock_ensure):
        assert find_iodine() == "/usr/local/bin/iodine"

    @patch("nowifi.toolchain.ensure_tool", side_effect=FileNotFoundError("iodine not found"))
    def test_find_iodine_not_found(self, mock_ensure):
        with pytest.raises(ToolNotFound):
            find_iodine()

    @patch("nowifi.toolchain.ensure_tool", return_value="/usr/local/bin/hans")
    def test_find_hans_success(self, mock_ensure):
        assert find_hans() == "/usr/local/bin/hans"

    @patch("nowifi.toolchain.ensure_tool", side_effect=FileNotFoundError("hans not found"))
    def test_find_hans_not_found(self, mock_ensure):
        with pytest.raises(ToolNotFound):
            find_hans()

    @patch("nowifi.toolchain.ensure_tool", return_value="/usr/local/bin/hysteria")
    def test_find_hysteria_success(self, mock_ensure):
        path = find_hysteria()
        assert "hysteria" in path

    @patch("nowifi.toolchain.ensure_tool", side_effect=FileNotFoundError("hysteria not found"))
    def test_find_hysteria_not_found(self, mock_ensure):
        with pytest.raises(ToolNotFound):
            find_hysteria()


# ---------------------------------------------------------------------------
# start_chisel_tunnel
# ---------------------------------------------------------------------------

class TestStartChiselTunnel:

    @patch("nowifi.tunnel._port_listening", return_value=True)
    @patch("nowifi.tunnel.subprocess.Popen")
    @patch("nowifi.tunnel.find_chisel", return_value="/usr/local/bin/chisel")
    @patch("nowifi.tunnel.time.sleep")
    @patch("nowifi.tunnel.time.monotonic")
    def test_successful_tunnel(self, mock_mono, mock_sleep, mock_find, mock_popen, mock_port):
        """Chisel tunnel starts and port becomes active."""
        mock_mono.side_effect = [0, 1]  # start, first check
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # still running
        mock_popen.return_value = mock_proc

        handle = start_chisel_tunnel("https://test.example.com")
        assert handle.active is True
        assert handle.local_port == 1080
        assert handle.method == "chisel"

    @patch("nowifi.tunnel.subprocess.Popen")
    @patch("nowifi.tunnel.find_chisel", return_value="/usr/local/bin/chisel")
    def test_process_dies_early(self, mock_find, mock_popen):
        """Chisel process exits immediately -> RuntimeError."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1  # exited
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.read.return_value = b"connection refused"
        mock_popen.return_value = mock_proc

        with pytest.raises(RuntimeError, match="Chisel exited early"):
            start_chisel_tunnel("https://test.example.com")

    @patch("nowifi.tunnel._port_listening", return_value=False)
    @patch("nowifi.tunnel.subprocess.Popen")
    @patch("nowifi.tunnel.find_chisel", return_value="/usr/local/bin/chisel")
    @patch("nowifi.tunnel.time.sleep")
    @patch("nowifi.tunnel.time.monotonic")
    def test_timeout(self, mock_mono, mock_sleep, mock_find, mock_popen, mock_port):
        """Chisel doesn't start within timeout -> RuntimeError."""
        mock_mono.side_effect = [0, 5, 10, 16]  # exceeds 15s
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.read.return_value = b""
        mock_popen.return_value = mock_proc

        with pytest.raises(RuntimeError, match="did not start"):
            start_chisel_tunnel("https://test.example.com", timeout=15)
        mock_proc.terminate.assert_called_once()


# ---------------------------------------------------------------------------
# start_dns_tunnel
# ---------------------------------------------------------------------------

class TestStartDnsTunnel:

    @patch("nowifi.tunnel.time.sleep")
    @patch("nowifi.tunnel.time.monotonic")
    @patch("nowifi.tunnel.subprocess.run")
    @patch("nowifi.tunnel.subprocess.Popen")
    @patch("nowifi.tunnel.find_iodine", return_value="/usr/local/bin/iodine")
    def test_dns_tunnel_success(self, mock_find, mock_popen, mock_run, mock_mono, mock_sleep):
        """DNS tunnel creates tun interface."""
        mock_mono.side_effect = [0, 1]
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc
        mock_run.return_value = MagicMock(stdout="dns0: inet 10.0.0.2")

        handle = start_dns_tunnel("t.example.com")
        assert handle.active is True
        assert handle.method == "dns_tunnel"

    @patch("nowifi.tunnel.subprocess.Popen")
    @patch("nowifi.tunnel.find_iodine", return_value="/usr/local/bin/iodine")
    def test_dns_tunnel_process_dies(self, mock_find, mock_popen):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.read.return_value = b"error"
        mock_popen.return_value = mock_proc

        with pytest.raises(RuntimeError, match="iodine exited"):
            start_dns_tunnel("t.example.com")


# ---------------------------------------------------------------------------
# start_icmp_tunnel
# ---------------------------------------------------------------------------

class TestStartIcmpTunnel:

    @patch("nowifi.tunnel.time.sleep")
    @patch("nowifi.tunnel.time.monotonic")
    @patch("nowifi.tunnel.subprocess.run")
    @patch("nowifi.tunnel.subprocess.Popen")
    @patch("nowifi.tunnel.find_hans", return_value="/usr/local/bin/hans")
    def test_icmp_tunnel_success(self, mock_find, mock_popen, mock_run, mock_mono, mock_sleep):
        mock_mono.side_effect = [0, 1]
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc
        mock_run.return_value = MagicMock(stdout="tun0: inet 10.0.0.2")

        handle = start_icmp_tunnel("203.0.113.1")
        assert handle.active is True
        assert handle.method == "icmp_tunnel"


# ---------------------------------------------------------------------------
# start_quic_tunnel
# ---------------------------------------------------------------------------

class TestStartQuicTunnel:

    @patch("nowifi.tunnel._port_listening", return_value=True)
    @patch("nowifi.tunnel.subprocess.Popen")
    @patch("nowifi.tunnel.find_hysteria", return_value="/usr/local/bin/hysteria")
    @patch("nowifi.tunnel.time.sleep")
    @patch("nowifi.tunnel.time.monotonic")
    def test_quic_tunnel_success(self, mock_mono, mock_sleep, mock_find, mock_popen, mock_port):
        mock_mono.side_effect = [0, 1]
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        handle = start_quic_tunnel("quic.example.com")
        assert handle.active is True
        assert handle.method == "quic_hysteria2"
        assert handle.local_port == 1081


# ---------------------------------------------------------------------------
# start_ntp_tunnel
# ---------------------------------------------------------------------------

class TestStartNtpTunnel:

    @patch("nowifi.tunnel._port_listening", return_value=True)
    @patch("nowifi.tunnel.subprocess.Popen")
    @patch("nowifi.tunnel.find_ntpescape", return_value="/usr/local/bin/ntpescape")
    @patch("nowifi.tunnel.time.sleep")
    @patch("nowifi.tunnel.time.monotonic")
    def test_ntp_tunnel_success(self, mock_mono, mock_sleep, mock_find, mock_popen, mock_port):
        mock_mono.side_effect = [0, 1]
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        handle = start_ntp_tunnel("203.0.113.2")
        assert handle.active is True
        assert handle.method == "ntp_tunnel"
        assert handle.local_port == 1082


# ---------------------------------------------------------------------------
# start_doh_tunnel
# ---------------------------------------------------------------------------

class TestStartDohTunnel:

    @patch("nowifi.tunnel._port_listening", return_value=True)
    @patch("nowifi.tunnel.subprocess.Popen")
    @patch("nowifi.toolchain.find_tool", return_value="/usr/local/bin/cloudflared")
    @patch("nowifi.tunnel.time.sleep")
    @patch("nowifi.tunnel.time.monotonic")
    def test_doh_tunnel_cloudflared(self, mock_mono, mock_sleep, mock_find, mock_popen, mock_port):
        mock_mono.side_effect = [0, 1]
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        handle = start_doh_tunnel()
        assert handle.active is True
        assert handle.method == "doh_tunnel"

    @patch("nowifi.toolchain.download_tool", return_value=None)
    @patch("nowifi.toolchain.find_tool", return_value=None)
    def test_doh_tunnel_no_tools(self, mock_find, mock_download):
        with pytest.raises(ToolNotFound):
            start_doh_tunnel()


# ---------------------------------------------------------------------------
# verify_tunnel_socks
# ---------------------------------------------------------------------------

class TestVerifyTunnelSocks:

    @patch("requests.get")
    def test_verify_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "success\n"
        mock_get.return_value = mock_resp

        assert verify_tunnel_socks(1080) is True
        # Verify it used SOCKS proxy
        call_kwargs = mock_get.call_args
        assert "socks5" in str(call_kwargs.kwargs.get("proxies", {}))

    @patch("requests.get")
    def test_verify_failure(self, mock_get):
        mock_get.side_effect = Exception("Connection refused")
        assert verify_tunnel_socks(1080) is False

    @patch("requests.get")
    def test_verify_wrong_content(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "portal login page"
        mock_get.return_value = mock_resp

        assert verify_tunnel_socks(1080) is False


# ---------------------------------------------------------------------------
# verify_tunnel_direct
# ---------------------------------------------------------------------------

class TestVerifyTunnelDirect:

    @patch("requests.get")
    def test_verify_direct_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "success\n"
        mock_get.return_value = mock_resp
        assert verify_tunnel_direct() is True

    @patch("requests.get")
    def test_verify_direct_failure(self, mock_get):
        mock_get.side_effect = Exception("No internet")
        assert verify_tunnel_direct() is False


# ---------------------------------------------------------------------------
# verify_cf_workers_proxy
# ---------------------------------------------------------------------------

class TestVerifyCfWorkersProxy:

    @patch("requests.get")
    def test_workers_proxy_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_get.return_value = mock_resp
        assert verify_cf_workers_proxy("https://my-proxy.workers.dev") is True
        # Verify the proxied URL format
        call_args = mock_get.call_args[0][0]
        assert "workers.dev" in call_args
        assert "gstatic.com" in call_args

    @patch("requests.get")
    def test_workers_proxy_failure(self, mock_get):
        mock_get.side_effect = Exception("Connection refused")
        assert verify_cf_workers_proxy("https://my-proxy.workers.dev") is False


# ---------------------------------------------------------------------------
# _port_listening
# ---------------------------------------------------------------------------

class TestPortListening:

    @patch("nowifi.tunnel.socket.socket")
    def test_port_open(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0
        assert _port_listening(1080) is True

    @patch("nowifi.tunnel.socket.socket")
    def test_port_closed(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect_ex.return_value = 111
        assert _port_listening(1080) is False

    @patch("nowifi.tunnel.socket.socket")
    def test_port_error(self, mock_socket_cls):
        import socket
        mock_socket_cls.side_effect = socket.error("error")
        assert _port_listening(1080) is False
