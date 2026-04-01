"""Portal detection and vendor fingerprinting."""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

import requests


class PortalType(Enum):
    HTTP_REDIRECT = "http_redirect"
    DNS_HIJACK = "dns_hijack"
    FIREWALL_BLOCK = "firewall_block"
    TRANSPARENT = "transparent"
    WALLED_GARDEN = "walled_garden"
    NONE = "none"


@dataclass
class PortalInfo:
    is_captive: bool
    portal_type: PortalType
    portal_url: str = ""
    redirect_url: str = ""
    vendor: str = ""
    vendor_details: str = ""
    auth_methods: list[str] = field(default_factory=list)
    portal_ip: str = ""
    ssid: str = ""
    gateway: str = ""


# Canary URLs used by operating systems to detect captive portals
CANARY_URLS = [
    {
        "url": "http://captive.apple.com/hotspot-detect.html",
        "expected_body": "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
        "expected_status": 200,
        "name": "Apple CNA",
    },
    {
        "url": "http://connectivitycheck.gstatic.com/generate_204",
        "expected_body": None,
        "expected_status": 204,
        "name": "Google 204",
    },
    {
        "url": "http://detectportal.firefox.com/canonical.html",
        "expected_body": "success",
        "expected_status": 200,
        "name": "Firefox",
    },
    {
        "url": "http://www.msftconnecttest.com/connecttest.txt",
        "expected_body": "Microsoft Connect Test",
        "expected_status": 200,
        "name": "Microsoft NCSI",
    },
]


# Vendor signature database: patterns matched against portal page content
VENDOR_SIGNATURES: dict[str, dict[str, list[str]]] = {
    "cisco_meraki": {
        "url_patterns": ["/splash/", "meraki"],
        "html_markers": ["meraki-splash", "meraki", "cisco-meraki"],
        "header_patterns": ["meraki"],
    },
    "aruba": {
        "url_patterns": ["/cgi-bin/login", "setafi.com"],
        "html_markers": ["aruba_", "aruba", "clearpass", "hpe"],
        "header_patterns": ["Aruba"],
    },
    "ruckus": {
        "url_patterns": ["/login.html", "ruckus"],
        "html_markers": ["ruckus-", "ruckus", "smartzone"],
        "header_patterns": ["Ruckus"],
    },
    "unifi": {
        "url_patterns": ["/guest/s/", "unifi"],
        "html_markers": ["unifi-portal", "unifi", "ubnt"],
        "header_patterns": ["X-UniFi", "ubnt"],
    },
    "mikrotik": {
        "url_patterns": ["/login", "mikrotik"],
        "html_markers": ["mikrotik", "routeros"],
        "header_patterns": ["Mikrotik"],
    },
    "fortinet": {
        "url_patterns": ["/fgtauth", "fortinet"],
        "html_markers": ["ftnt_", "fortinet", "fortigate"],
        "header_patterns": ["FortiGate", "Fortinet"],
    },
    "pfsense": {
        "url_patterns": ["/index.php?zone=", "pfsense"],
        "html_markers": ["captiveportal", "pfsense"],
        "header_patterns": ["pfSense"],
    },
    "opennds": {
        "url_patterns": ["/opennds_preauth/"],
        "html_markers": ["opennds", "openNDS"],
        "header_patterns": [],
    },
    "coovachilli": {
        "url_patterns": ["/json/status"],
        "html_markers": ["coova", "chilli"],
        "header_patterns": [],
    },
    "nomadix": {
        "url_patterns": ["/nomadix/"],
        "html_markers": ["nomadix", "usg"],
        "header_patterns": ["Nomadix"],
    },
}


def detect_portal(interface: str = "en0") -> PortalInfo:
    """Detect if we're behind a captive portal and identify its type.

    Uses multiple canary URLs for consensus. A single canary failure could be
    a transparent proxy or network quirk — require EITHER a redirect to a
    different domain (definitive) OR majority of canaries failing (consensus).
    """
    info = PortalInfo(is_captive=False, portal_type=PortalType.NONE)

    redirects: list[tuple[str, str, dict[str, str]]] = []  # (url, body, headers)
    failures = 0
    successes = 0

    for canary in CANARY_URLS:
        result = _check_canary(canary)
        if result is None:
            failures += 1
            continue

        status, body, final_url, headers = result

        # Definitive redirect to a DIFFERENT domain = captive portal (instant verdict)
        canary_host = urlparse(canary["url"]).hostname or ""
        final_host = urlparse(final_url).hostname or ""
        if final_host and canary_host and final_host != canary_host:
            info.is_captive = True
            info.portal_type = PortalType.HTTP_REDIRECT
            info.redirect_url = final_url
            info.portal_url = final_url
            info.portal_ip = _resolve_portal_ip(final_url)
            _fingerprint_portal(info, body, final_url, headers)
            return info

        # Check expected content
        expected = canary.get("expected_body")
        expected_status = canary.get("expected_status", 200)

        if status == expected_status and (not expected or expected in body):
            successes += 1
        else:
            failures += 1
            redirects.append((final_url, body, headers))

    # Consensus: majority of canaries fail = likely captive portal
    # (avoids false positive from a single transparent proxy like Mikrotik)
    if failures > successes and failures >= 2:
        info.is_captive = True
        if redirects:
            info.portal_type = PortalType.TRANSPARENT
            info.portal_url = redirects[0][0]
            _fingerprint_portal(info, redirects[0][1], redirects[0][0], redirects[0][2])
        else:
            info.portal_type = PortalType.FIREWALL_BLOCK

    # Also check DNS hijacking
    if not info.is_captive:
        dns_hijack = _check_dns_hijack()
        if dns_hijack:
            info.is_captive = True
            info.portal_type = PortalType.DNS_HIJACK
            info.portal_ip = dns_hijack

    return info


def _check_canary(canary: dict) -> tuple[int, str, str, dict[str, str]] | None:
    """Check a single canary URL. Returns (status, body, final_url, headers) or None."""
    try:
        resp = requests.get(
            canary["url"],
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "CaptiveNetworkSupport/1.0 wispr"},
        )
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status_code, resp.text, resp.url, headers
    except requests.RequestException:
        return None


def _resolve_portal_ip(url: str) -> str:
    """Resolve the portal URL to an IP address."""
    try:
        hostname = urlparse(url).hostname
        if hostname:
            return socket.gethostbyname(hostname)
    except socket.gaierror:
        pass
    return ""


def _check_dns_hijack() -> str:
    """Check if DNS is being hijacked by resolving multiple known domains.

    If they all resolve to the same IP, DNS is being hijacked.
    """
    test_domains = ["google.com", "cloudflare.com", "microsoft.com", "amazon.com"]
    resolved_ips: set[str] = set()

    for domain in test_domains:
        try:
            ip = socket.gethostbyname(domain)
            resolved_ips.add(ip)
        except socket.gaierror:
            continue

    # If all domains resolve to the same single IP, it's likely DNS hijacking
    if len(resolved_ips) == 1:
        return resolved_ips.pop()
    return ""


def _fingerprint_portal(
    info: PortalInfo,
    body: str,
    url: str,
    headers: dict[str, str],
) -> None:
    """Identify the portal vendor from page content, URL, and headers."""
    body_lower = body.lower()
    url_lower = url.lower()
    header_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()

    for vendor, signatures in VENDOR_SIGNATURES.items():
        score = 0

        # Check URL patterns
        for pattern in signatures.get("url_patterns", []):
            if pattern.lower() in url_lower:
                score += 2

        # Check HTML body markers
        for marker in signatures.get("html_markers", []):
            if marker.lower() in body_lower:
                score += 1

        # Check response headers
        for pattern in signatures.get("header_patterns", []):
            if pattern.lower() in header_str:
                score += 2

        if score >= 2:
            info.vendor = vendor
            info.vendor_details = f"Matched with confidence score {score}"
            break

    # Try to detect auth methods from form fields
    info.auth_methods = _detect_auth_methods(body)


def _detect_auth_methods(html: str) -> list[str]:
    """Parse portal HTML to detect available authentication methods."""
    methods: list[str] = []
    html_lower = html.lower()

    patterns = {
        "email": [r'type=["\']email["\']', r'name=["\']email["\']', r"email"],
        "password": [r'type=["\']password["\']', r"password"],
        "phone": [r'type=["\']tel["\']', r"phone", r"mobile"],
        "social_google": [r"google.*sign.?in", r"sign.?in.*google", r"accounts\.google\.com", r"oauth.*google"],
        "social_facebook": [r"facebook.*login", r"facebook\.com/dialog", r"fb-login"],
        "room_number": [r"room.?number", r"room.?no"],
        "voucher": [r"voucher", r"access.?code", r"token"],
        "terms_only": [r"accept.*terms", r"agree.*terms", r"terms.*conditions"],
    }

    for method, regexes in patterns.items():
        for regex in regexes:
            if re.search(regex, html_lower):
                methods.append(method)
                break

    return methods
