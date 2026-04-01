"""Tests for toolchain auto-download system."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from nowifi.toolchain import (
    SYSTEM_TOOLS,
    TOOL_DIR,
    TOOLS,
    ToolInfo,
    _resolve_platform,
    download_tool,
    ensure_tool,
    ensure_tool_dir,
    find_tool,
    list_tools,
)


# ---------------------------------------------------------------------------
# ToolInfo
# ---------------------------------------------------------------------------

class TestToolInfo:

    def test_tools_registry_has_expected_entries(self):
        assert "chisel" in TOOLS
        assert "hysteria" in TOOLS
        assert "cloudflared" in TOOLS

    def test_tool_info_fields(self):
        info = TOOLS["chisel"]
        assert info.name == "chisel"
        assert info.binary_name == "chisel"
        assert info.version
        assert "{version}" in info.download_url
        assert isinstance(info.required_for, list)

    def test_system_tools_has_expected_entries(self):
        assert "iodine" in SYSTEM_TOOLS
        assert "hans" in SYSTEM_TOOLS


# ---------------------------------------------------------------------------
# ensure_tool_dir
# ---------------------------------------------------------------------------

class TestEnsureToolDir:

    @patch("nowifi.toolchain.TOOL_DIR")
    def test_creates_directory(self, mock_dir):
        mock_dir.mkdir = MagicMock()
        ensure_tool_dir()
        mock_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# find_tool
# ---------------------------------------------------------------------------

class TestFindTool:

    @patch("shutil.which", return_value="/usr/local/bin/chisel")
    @patch("os.path.isfile", return_value=True)
    @patch("os.access", return_value=True)
    def test_finds_via_which(self, mock_access, mock_isfile, mock_which):
        result = find_tool("chisel")
        assert result == "/usr/local/bin/chisel"

    @patch("shutil.which", return_value=None)
    @patch("os.path.isfile", return_value=False)
    @patch("os.access", return_value=False)
    def test_returns_none_when_not_found(self, mock_access, mock_isfile, mock_which):
        result = find_tool("nonexistent_tool_xyz")
        assert result is None

    @patch("shutil.which", return_value=None)
    @patch("os.path.isfile")
    @patch("os.access")
    def test_finds_in_tool_dir(self, mock_access, mock_isfile, mock_which):
        tool_dir_path = str(TOOL_DIR / "chisel")
        mock_isfile.side_effect = lambda p: p == tool_dir_path
        mock_access.side_effect = lambda p, m: p == tool_dir_path
        result = find_tool("chisel")
        assert result == tool_dir_path

    @patch("shutil.which", return_value="/usr/local/bin/chisel")
    @patch("os.path.isfile", return_value=True)
    @patch("os.access", return_value=False)
    def test_skips_non_executable(self, mock_access, mock_isfile, mock_which):
        """A file that exists but isn't executable should be skipped."""
        result = find_tool("chisel")
        assert result is None


# ---------------------------------------------------------------------------
# _resolve_platform
# ---------------------------------------------------------------------------

class TestResolvePlatform:

    @patch("platform.system", return_value="Darwin")
    @patch("platform.machine", return_value="arm64")
    def test_macos_arm64(self, mock_machine, mock_system):
        result = _resolve_platform()
        assert result == ("darwin", "arm64")

    @patch("platform.system", return_value="Darwin")
    @patch("platform.machine", return_value="x86_64")
    def test_macos_amd64(self, mock_machine, mock_system):
        result = _resolve_platform()
        assert result == ("darwin", "amd64")

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="aarch64")
    def test_linux_arm64(self, mock_machine, mock_system):
        result = _resolve_platform()
        assert result == ("linux", "arm64")

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="x86_64")
    def test_linux_amd64(self, mock_machine, mock_system):
        result = _resolve_platform()
        assert result == ("linux", "amd64")

    @patch("platform.system", return_value="Windows")
    @patch("platform.machine", return_value="AMD64")
    def test_unsupported_os(self, mock_machine, mock_system):
        result = _resolve_platform()
        assert result is None


# ---------------------------------------------------------------------------
# download_tool
# ---------------------------------------------------------------------------

class TestDownloadTool:

    def test_unknown_tool_returns_none(self):
        assert download_tool("nonexistent_tool_xyz") is None

    @patch("nowifi.toolchain._resolve_platform", return_value=None)
    def test_unsupported_platform_returns_none(self, mock_plat):
        assert download_tool("chisel") is None

    @patch("nowifi.toolchain._resolve_platform", return_value=("darwin", "arm64"))
    @patch("nowifi.toolchain.ensure_tool_dir")
    @patch("urllib.request.urlretrieve")
    def test_downloads_gzipped_binary(self, mock_retrieve, mock_dir, mock_plat, tmp_path):
        """Chisel URL ends with .gz -- verify gzip decompression path."""
        import gzip

        with patch("nowifi.toolchain.TOOL_DIR", tmp_path):
            # Create a fake gzipped binary
            fake_binary = b"\x7fELF_fake_binary_content"
            gz_path = str(tmp_path / "chisel.gz")

            def fake_retrieve(url, dest):
                with gzip.open(dest, "wb") as f:
                    f.write(fake_binary)

            mock_retrieve.side_effect = fake_retrieve

            result = download_tool("chisel")
            assert result == str(tmp_path / "chisel")
            assert (tmp_path / "chisel").exists()
            assert (tmp_path / "chisel").read_bytes() == fake_binary
            # Verify it's executable
            mode = (tmp_path / "chisel").stat().st_mode
            assert mode & stat.S_IEXEC

    @patch("nowifi.toolchain._resolve_platform", return_value=("darwin", "arm64"))
    @patch("nowifi.toolchain.ensure_tool_dir")
    @patch("urllib.request.urlretrieve")
    def test_downloads_direct_binary(self, mock_retrieve, mock_dir, mock_plat, tmp_path):
        """Hysteria URL is a direct binary (no .gz)."""
        with patch("nowifi.toolchain.TOOL_DIR", tmp_path):
            fake_binary = b"\x7fELF_hysteria_binary"

            def fake_retrieve(url, dest):
                Path(dest).write_bytes(fake_binary)

            mock_retrieve.side_effect = fake_retrieve

            result = download_tool("hysteria")
            assert result == str(tmp_path / "hysteria")
            assert (tmp_path / "hysteria").exists()

    @patch("nowifi.toolchain._resolve_platform", return_value=("darwin", "arm64"))
    @patch("nowifi.toolchain.ensure_tool_dir")
    @patch("urllib.request.urlretrieve", side_effect=Exception("Network error"))
    def test_download_failure_cleans_up(self, mock_retrieve, mock_dir, mock_plat, tmp_path):
        """Failed download should clean up partial files."""
        with patch("nowifi.toolchain.TOOL_DIR", tmp_path):
            result = download_tool("hysteria")
            assert result is None
            # No leftover files
            assert not (tmp_path / "hysteria").exists()


# ---------------------------------------------------------------------------
# ensure_tool
# ---------------------------------------------------------------------------

class TestEnsureTool:

    @patch("nowifi.toolchain.find_tool", return_value="/usr/local/bin/chisel")
    def test_returns_existing_tool(self, mock_find):
        result = ensure_tool("chisel")
        assert result == "/usr/local/bin/chisel"

    @patch("nowifi.toolchain.download_tool", return_value="/home/user/.nowifi/bin/chisel")
    @patch("nowifi.toolchain.find_tool", return_value=None)
    def test_downloads_missing_tool(self, mock_find, mock_download):
        result = ensure_tool("chisel")
        assert result == "/home/user/.nowifi/bin/chisel"

    @patch("nowifi.toolchain.download_tool", return_value=None)
    @patch("nowifi.toolchain.find_tool", return_value=None)
    def test_raises_for_unavailable_system_tool(self, mock_find, mock_download):
        with pytest.raises(FileNotFoundError, match="iodine"):
            ensure_tool("iodine")

    @patch("nowifi.toolchain.download_tool", return_value=None)
    @patch("nowifi.toolchain.find_tool", return_value=None)
    def test_raises_for_unknown_tool(self, mock_find, mock_download):
        with pytest.raises(FileNotFoundError, match="no auto-download"):
            ensure_tool("totally_unknown_tool_12345")


# ---------------------------------------------------------------------------
# list_tools
# ---------------------------------------------------------------------------

class TestListTools:

    @patch("nowifi.toolchain.find_tool", return_value=None)
    def test_lists_all_tools(self, mock_find):
        result = list_tools()
        # Should include both downloadable and system tools
        assert "chisel" in result
        assert "hysteria" in result
        assert "iodine" in result
        assert "hans" in result

    @patch("nowifi.toolchain.find_tool")
    def test_installed_tool_shows_path(self, mock_find):
        def find_side_effect(name):
            if name == "chisel":
                return "/usr/local/bin/chisel"
            return None
        mock_find.side_effect = find_side_effect

        result = list_tools()
        assert result["chisel"]["installed"] is True
        assert result["chisel"]["path"] == "/usr/local/bin/chisel"
        assert result["iodine"]["installed"] is False
        assert result["iodine"]["downloadable"] is False

    @patch("nowifi.toolchain.find_tool", return_value=None)
    def test_downloadable_flag(self, mock_find):
        result = list_tools()
        assert result["chisel"]["downloadable"] is True
        assert result["hysteria"]["downloadable"] is True
        assert result["iodine"]["downloadable"] is False
        assert result["hans"]["downloadable"] is False
