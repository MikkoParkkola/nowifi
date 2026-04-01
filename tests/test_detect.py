"""Tests for portal detection and vendor fingerprinting."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from nowifi.detect import (
    CANARY_URLS,
    VENDOR_SIGNATURES,
    PortalInfo,
    PortalType,
    _check_canary,
    _check_dns_hijack,
    _detect_auth_methods,
    _fingerprint_portal,
    _resolve_portal_ip,
    detect_portal,
)


# ---------------------------------------------------------------------------
# detect_portal: no captive portal
# ---------------------------------------------------------------------------

class TestDetectPortalOpen:
    """Tests for when no captive portal is present."""

    @patch("nowifi.detect._check_dns_hijack", return_value="")
    @patch("nowifi.detect._check_canary")
    def test_all_canaries_pass(self, mock_canary, mock_dns):
        """All canary URLs return expected content -> not captive."""
        mock_canary.side_effect = [
            (200, CANARY_URLS[0]["expected_body"], CANARY_URLS[0]["url"], {}),
            (204, "", CANARY_URLS[1]["url"], {}),
            (200, "success", CANARY_URLS[2]["url"], {}),
            (200, "Microsoft Connect Test", CANARY_URLS[3]["url"], {}),
        ]
        info = detect_portal()
        assert not info.is_captive
        assert info.portal_type == PortalType.NONE

    @patch("nowifi.detect._check_dns_hijack", return_value="")
    @patch("nowifi.detect._check_canary")
    def test_google_204_pass(self, mock_canary, mock_dns):
        """Google 204 canary returns expected status -> not captive."""
        mock_canary.side_effect = [
            (200, CANARY_URLS[0]["expected_body"], CANARY_URLS[0]["url"], {}),
            (204, "", CANARY_URLS[1]["url"], {}),
            (200, "success", CANARY_URLS[2]["url"], {}),
            (200, "Microsoft Connect Test", CANARY_URLS[3]["url"], {}),
        ]
        info = detect_portal()
        assert not info.is_captive


# ---------------------------------------------------------------------------
# detect_portal: captive portal via redirect
# ---------------------------------------------------------------------------

class TestDetectPortalRedirect:
    """Tests for HTTP redirect detection."""

    @patch("nowifi.detect._resolve_portal_ip", return_value="10.0.0.1")
    @patch("nowifi.detect._check_canary")
    def test_redirect_detected(self, mock_canary, mock_resolve):
        """Canary URL gets redirected -> captive detected, redirect URL captured."""
        portal_url = "http://portal.hotel.com/login"
        mock_canary.return_value = (
            200,
            '<html><body><form>Login</form></body></html>',
            portal_url,  # final URL differs from canary
            {"server": "nginx"},
        )
        info = detect_portal()
        assert info.is_captive
        assert info.portal_type == PortalType.HTTP_REDIRECT
        assert info.portal_url == portal_url
        assert info.redirect_url == portal_url
        assert info.portal_ip == "10.0.0.1"

    @patch("nowifi.detect._resolve_portal_ip", return_value="")
    @patch("nowifi.detect._check_canary")
    def test_redirect_captures_url(self, mock_canary, mock_resolve):
        """Redirect URL is stored in portal_url."""
        mock_canary.return_value = (
            200,
            "<html>Please login</html>",
            "http://10.0.0.1:8080/splash",
            {},
        )
        info = detect_portal()
        assert info.portal_url == "http://10.0.0.1:8080/splash"


# ---------------------------------------------------------------------------
# detect_portal: captive portal via content injection (transparent proxy)
# ---------------------------------------------------------------------------

class TestDetectPortalTransparent:
    """Tests for transparent proxy detection."""

    @patch("nowifi.detect._check_dns_hijack", return_value="")
    @patch("nowifi.detect._check_canary")
    def test_wrong_status_code(self, mock_canary, mock_dns):
        """Canary returns wrong status code -> transparent proxy detected."""
        mock_canary.side_effect = [
            (302, "", CANARY_URLS[0]["url"], {}),  # expected 200, got 302
        ]
        info = detect_portal()
        assert info.is_captive
        assert info.portal_type == PortalType.TRANSPARENT

    @patch("nowifi.detect._check_dns_hijack", return_value="")
    @patch("nowifi.detect._check_canary")
    def test_wrong_body_content(self, mock_canary, mock_dns):
        """Canary returns unexpected body content -> transparent proxy."""
        mock_canary.side_effect = [
            (200, "<html>Login required</html>", CANARY_URLS[0]["url"], {}),
        ]
        info = detect_portal()
        assert info.is_captive
        assert info.portal_type == PortalType.TRANSPARENT


# ---------------------------------------------------------------------------
# detect_portal: firewall block
# ---------------------------------------------------------------------------

class TestDetectPortalFirewall:
    """Tests for firewall block detection."""

    @patch("nowifi.detect._check_dns_hijack", return_value="")
    @patch("nowifi.detect._check_canary")
    def test_all_canaries_fail(self, mock_canary, mock_dns):
        """All canary connections fail -> firewall block."""
        mock_canary.return_value = None  # connection failed
        info = detect_portal()
        assert info.is_captive
        assert info.portal_type == PortalType.FIREWALL_BLOCK


# ---------------------------------------------------------------------------
# detect_portal: DNS hijack
# ---------------------------------------------------------------------------

class TestDetectPortalDnsHijack:
    """Tests for DNS hijack detection."""

    @patch("nowifi.detect._check_dns_hijack", return_value="10.0.0.1")
    @patch("nowifi.detect._check_canary")
    def test_dns_hijack_detected(self, mock_canary, mock_dns):
        """All domains resolve to same IP -> DNS hijack detected."""
        # All canaries pass (expected content), but DNS is hijacked
        mock_canary.side_effect = [
            (200, CANARY_URLS[0]["expected_body"], CANARY_URLS[0]["url"], {}),
            (204, "", CANARY_URLS[1]["url"], {}),
            (200, "success", CANARY_URLS[2]["url"], {}),
            (200, "Microsoft Connect Test", CANARY_URLS[3]["url"], {}),
        ]
        info = detect_portal()
        assert info.is_captive
        assert info.portal_type == PortalType.DNS_HIJACK
        assert info.portal_ip == "10.0.0.1"


# ---------------------------------------------------------------------------
# _check_canary
# ---------------------------------------------------------------------------

class TestCheckCanary:

    @patch("nowifi.detect.requests.get")
    def test_successful_canary(self, mock_get):
        """Successful canary check returns tuple."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Success body"
        mock_resp.url = "http://example.com/test"
        mock_resp.headers = {"Server": "nginx", "Content-Type": "text/html"}
        mock_get.return_value = mock_resp

        result = _check_canary({"url": "http://example.com/test"})
        assert result is not None
        status, body, url, headers = result
        assert status == 200
        assert body == "Success body"
        assert url == "http://example.com/test"
        assert "server" in headers

    @patch("nowifi.detect.requests.get")
    def test_canary_connection_failure(self, mock_get):
        """Connection failure returns None."""
        import requests
        mock_get.side_effect = requests.ConnectionError("Connection refused")
        result = _check_canary({"url": "http://example.com/test"})
        assert result is None

    @patch("nowifi.detect.requests.get")
    def test_canary_timeout(self, mock_get):
        """Timeout returns None."""
        import requests
        mock_get.side_effect = requests.Timeout("Timed out")
        result = _check_canary({"url": "http://example.com/test"})
        assert result is None

    @patch("nowifi.detect.requests.get")
    def test_canary_uses_wispr_ua(self, mock_get):
        """Canary request uses CNA/Wispr User-Agent."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ""
        mock_resp.url = "http://example.com"
        mock_resp.headers = {}
        mock_get.return_value = mock_resp

        _check_canary({"url": "http://example.com"})
        call_kwargs = mock_get.call_args
        assert "CaptiveNetworkSupport" in call_kwargs.kwargs.get("headers", {}).get("User-Agent", "")


# ---------------------------------------------------------------------------
# _check_dns_hijack
# ---------------------------------------------------------------------------

class TestCheckDnsHijack:

    @patch("nowifi.detect.socket.gethostbyname")
    def test_dns_hijacked_all_same(self, mock_resolve):
        """All domains resolve to same IP -> hijack detected."""
        mock_resolve.return_value = "10.0.0.1"
        result = _check_dns_hijack()
        assert result == "10.0.0.1"

    @patch("nowifi.detect.socket.gethostbyname")
    def test_dns_normal_different_ips(self, mock_resolve):
        """Different IPs for different domains -> no hijack."""
        mock_resolve.side_effect = ["172.217.0.1", "104.16.132.229", "13.107.42.14", "54.239.28.85"]
        result = _check_dns_hijack()
        assert result == ""

    @patch("nowifi.detect.socket.gethostbyname")
    def test_dns_all_fail(self, mock_resolve):
        """All DNS lookups fail -> no hijack (empty set)."""
        import socket
        mock_resolve.side_effect = socket.gaierror("DNS failure")
        result = _check_dns_hijack()
        assert result == ""

    @patch("nowifi.detect.socket.gethostbyname")
    def test_dns_partial_failure(self, mock_resolve):
        """Some lookups fail, remaining have different IPs -> no hijack."""
        import socket
        mock_resolve.side_effect = [
            "172.217.0.1",
            socket.gaierror("fail"),
            "104.16.132.229",
            socket.gaierror("fail"),
        ]
        result = _check_dns_hijack()
        assert result == ""  # 2 different IPs


# ---------------------------------------------------------------------------
# _resolve_portal_ip
# ---------------------------------------------------------------------------

class TestResolvePortalIp:

    @patch("nowifi.detect.socket.gethostbyname", return_value="10.0.0.1")
    def test_resolves_hostname(self, mock_resolve):
        result = _resolve_portal_ip("http://portal.hotel.com/login")
        mock_resolve.assert_called_once_with("portal.hotel.com")
        assert result == "10.0.0.1"

    @patch("nowifi.detect.socket.gethostbyname")
    def test_resolve_failure(self, mock_resolve):
        import socket
        mock_resolve.side_effect = socket.gaierror("fail")
        result = _resolve_portal_ip("http://portal.hotel.com/login")
        assert result == ""

    def test_empty_url(self):
        result = _resolve_portal_ip("")
        assert result == ""


# ---------------------------------------------------------------------------
# _fingerprint_portal / vendor detection
# ---------------------------------------------------------------------------

class TestFingerprintPortal:
    """Vendor fingerprinting from HTML body, URL, and headers."""

    def test_meraki_html(self):
        """HTML contains 'meraki' -> vendor=cisco_meraki."""
        info = PortalInfo(is_captive=True, portal_type=PortalType.HTTP_REDIRECT)
        _fingerprint_portal(info, '<div class="meraki-splash">Login</div>', "http://portal.com", {})
        assert info.vendor == "cisco_meraki"

    def test_meraki_url(self):
        """URL contains '/splash/' -> vendor=cisco_meraki (score from url_pattern)."""
        info = PortalInfo(is_captive=True, portal_type=PortalType.HTTP_REDIRECT)
        _fingerprint_portal(info, "<html>Login</html>", "http://portal.com/splash/page", {})
        assert info.vendor == "cisco_meraki"

    def test_meraki_header(self):
        """Headers contain 'meraki' -> vendor=cisco_meraki."""
        info = PortalInfo(is_captive=True, portal_type=PortalType.HTTP_REDIRECT)
        _fingerprint_portal(info, "<html>Login</html>", "http://portal.com", {"x-powered-by": "Meraki"})
        assert info.vendor == "cisco_meraki"

    def test_unifi_html(self):
        info = PortalInfo(is_captive=True, portal_type=PortalType.HTTP_REDIRECT)
        _fingerprint_portal(info, '<div class="unifi-portal">Login</div>', "http://portal.com", {})
        assert info.vendor == "unifi"

    def test_unifi_url_pattern(self):
        info = PortalInfo(is_captive=True, portal_type=PortalType.HTTP_REDIRECT)
        _fingerprint_portal(info, "<html>Login</html>", "http://portal.com/guest/s/default/login", {})
        assert info.vendor == "unifi"

    def test_mikrotik_html(self):
        info = PortalInfo(is_captive=True, portal_type=PortalType.HTTP_REDIRECT)
        _fingerprint_portal(info, '<html><body>RouterOS mikrotik login</body></html>', "http://10.0.0.1/login", {})
        assert info.vendor == "mikrotik"

    def test_fortinet_html(self):
        info = PortalInfo(is_captive=True, portal_type=PortalType.HTTP_REDIRECT)
        _fingerprint_portal(info, '<html><body class="ftnt_login">FortiGate auth</body></html>', "http://10.0.0.1", {})
        assert info.vendor == "fortinet"

    def test_aruba_header(self):
        info = PortalInfo(is_captive=True, portal_type=PortalType.HTTP_REDIRECT)
        _fingerprint_portal(info, '<html>Login</html>', "http://portal.com", {"server": "Aruba ClearPass"})
        assert info.vendor == "aruba"

    def test_unknown_vendor(self):
        """No vendor signatures match -> vendor remains empty."""
        info = PortalInfo(is_captive=True, portal_type=PortalType.HTTP_REDIRECT)
        _fingerprint_portal(info, "<html>Generic Login Page</html>", "http://10.0.0.1/login", {})
        assert info.vendor == ""

    def test_vendor_requires_min_score(self):
        """Single weak match (score=1) below threshold (2) -> no vendor."""
        info = PortalInfo(is_captive=True, portal_type=PortalType.HTTP_REDIRECT)
        # "pfsense" only in html_markers (score 1), not enough
        _fingerprint_portal(info, "<html>pfsense something</html>", "http://10.0.0.1/other", {})
        # pfsense also matches "captiveportal" marker, so let's use truly weak match
        info2 = PortalInfo(is_captive=True, portal_type=PortalType.HTTP_REDIRECT)
        _fingerprint_portal(info2, "<html>nomadix reference</html>", "http://10.0.0.1/unrelated", {})
        assert info2.vendor == ""  # score=1 for "nomadix" in html only, no url/header

    def test_vendor_details_contains_score(self):
        info = PortalInfo(is_captive=True, portal_type=PortalType.HTTP_REDIRECT)
        _fingerprint_portal(info, '<div class="meraki-splash meraki">Login</div>', "http://portal.com/splash/x", {})
        assert info.vendor == "cisco_meraki"
        assert "score" in info.vendor_details


# ---------------------------------------------------------------------------
# _detect_auth_methods
# ---------------------------------------------------------------------------

class TestDetectAuthMethods:

    def test_email_input(self):
        """HTML with email input -> 'email' in auth_methods."""
        html = '<input type="email" name="user_email" />'
        methods = _detect_auth_methods(html)
        assert "email" in methods

    def test_password_input(self):
        html = '<input type="password" name="pwd" />'
        methods = _detect_auth_methods(html)
        assert "password" in methods

    def test_phone_input(self):
        html = '<input type="tel" name="phone_number" />'
        methods = _detect_auth_methods(html)
        assert "phone" in methods

    def test_social_google(self):
        html = '<a href="https://accounts.google.com/o/oauth2/auth">Sign in with Google</a>'
        methods = _detect_auth_methods(html)
        assert "social_google" in methods

    def test_social_facebook(self):
        html = '<a href="https://facebook.com/dialog/oauth">Login with Facebook</a>'
        methods = _detect_auth_methods(html)
        assert "social_facebook" in methods

    def test_room_number(self):
        html = '<input name="room_number" placeholder="Room Number" />'
        methods = _detect_auth_methods(html)
        assert "room_number" in methods

    def test_voucher(self):
        html = '<input name="access_code" placeholder="Enter your voucher code" />'
        methods = _detect_auth_methods(html)
        assert "voucher" in methods

    def test_terms_only(self):
        html = '<button>Accept Terms and Conditions</button>'
        methods = _detect_auth_methods(html)
        assert "terms_only" in methods

    def test_multiple_methods(self):
        html = '''
        <form>
            <input type="email" />
            <input type="password" />
            <a href="#">Sign in with Google</a>
        </form>
        '''
        methods = _detect_auth_methods(html)
        assert "email" in methods
        assert "password" in methods
        assert "social_google" in methods

    def test_no_methods(self):
        html = "<html><body>Welcome</body></html>"
        methods = _detect_auth_methods(html)
        assert methods == []

    def test_case_insensitive(self):
        html = '<INPUT TYPE="EMAIL" NAME="user" />'
        methods = _detect_auth_methods(html)
        assert "email" in methods
