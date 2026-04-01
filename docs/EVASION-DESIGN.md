# Evasion Design: Defeating Portal Defense Mechanisms

## Current Defenses vs Our Evasion

| Defense | Implementation | nowifi Status | Gap |
|---|---|---|---|
| MAC-based auth | Portal tracks authenticated MAC | ✅ MAC clone | — |
| Duplicate MAC detection | Switch detects 2 devices, same MAC | ✅ Clone idle devices | — |
| Client isolation | AP blocks client-to-client traffic | ⚠️ Uses ARP table from gateway | Full isolation breaks ARP scan |
| DHCP fingerprinting | Match MAC to DHCP options (OS, hostname) | ❌ Not evaded | DHCP options differ after MAC clone |
| TLS fingerprinting (JA3/JA4) | Unique TLS handshake per OS/browser | ❌ Not evaded | Portal sees different TLS fingerprint |
| Browser fingerprinting | Canvas, fonts, screen, UA | ❌ Not evaded | Rare on captive portals |
| MAC registration rate limit | Limit new MACs per AP per hour | ⚠️ MAC rotate is one-shot | No auto-loop with backoff |
| Session binding (MAC+IP+cookie) | Session tied to multiple identifiers | ⚠️ Clone MAC, get IP via DHCP | Cookie and TLS not spoofed |
| 802.1X/RADIUS | Certificate or credential auth | ❌ Out of scope | Use eaphammer |
| WPS lockout | Lock after N failed PINs | ✅ Rate limiter + backoff | Some APs lock permanently |

## Planned Improvements

### 1. DHCP Fingerprint Spoofing
When cloning MAC, also spoof DHCP options to match target device:
- Hostname: match target (or generic like "iPhone", "DESKTOP-XXXXX")
- Vendor Class Identifier (option 60): match target OS
- Parameter Request List (option 55): match target OS fingerprint
- Implementation: custom DHCP client or dhclient config file

### 2. Automatic MAC Rotation Loop
Current: `mac_rotate` is a single-shot technique.
Needed: auto-loop that detects session expiry and re-rotates:
```
loop:
  1. Check internet (canary URL)
  2. If blocked: generate new MAC → set → DHCP renew → wait 3s
  3. If portal requires login: auto-submit if possible
  4. If working: maintain (check every 60s)
  5. If rate-limited: backoff (wait 5 min between rotations)
```

### 3. IP Address Matching
Some portals bind MAC + IP. After cloning MAC:
1. Release our DHCP lease
2. Check if target's IP is in the DHCP pool
3. Request specific IP via DHCP option 50 (Requested IP Address)
4. If different IP assigned, may need to wait for target's lease to expire

### 4. Session Cookie Replay (Active)
Current: passive detection of HTTP cookies (report only).
Needed: active sniffing with monitor mode:
1. Enable monitor mode on separate interface
2. Capture HTTP traffic from authenticated clients
3. Extract session cookies from unencrypted HTTP
4. Replay cookies in our browser
5. Only works on HTTP portals (decreasing)

### 5. TLS Fingerprint Spoofing
Advanced evasion for portals that check JA3/JA4:
- Use `utls` Go library (uTLS) to mimic Chrome/Safari TLS fingerprint
- Match the fingerprint of the cloned device's OS
- Implementation: replace net/http transport with uTLS transport

## Priority

| Improvement | Impact | Effort | Priority |
|---|---|---|---|
| MAC rotation loop | HIGH — persistent access | LOW | P0 |
| DHCP fingerprint spoof | HIGH — defeats common defense | MEDIUM | P1 |
| IP address matching | MEDIUM — some portals need it | LOW | P2 |
| TLS fingerprint spoof | LOW — rare on portals | MEDIUM | P3 |
| Active cookie replay | LOW — HTTP portals declining | HIGH | P4 |
