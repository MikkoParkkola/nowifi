# Evasion Design: Defeating Every Layer of WiFi Access Control

## Part 1: Defense Mechanisms (Current SOTA)

### Layer 2 Defenses

| Defense | How | Vendors | Prevalence | Bypassable? |
|---|---|---|---|---|
| **MAC-only binding** | Session tracked by MAC | UniFi, pfSense, most hotels | 80% | Trivial — MAC clone |
| **MAC+IP binding** | Session = MAC + DHCP lease | MikroTik, Meraki | 30% | Clone MAC + request same IP (option 50) |
| **MAC+Cookie binding** | Triple: MAC + IP + HTTP cookie | MikroTik (add-mac-cookie), ClearPass | 10% | Need cookie sniff + MAC + IP |
| **Duplicate MAC detection** | Switch detects two MACs on network | MikroTik (deletes session on dupe) | 15% | Target idle devices only |
| **Client isolation (PVLAN)** | Clients can't see each other | Enterprise switches | 20% | Passive broadcast monitoring only |
| **DAI (Dynamic ARP Inspection)** | Validates ARP against DHCP table | Cisco, Aruba, Juniper | 20% | Legitimate DHCP flow bypasses |
| **DHCP Snooping** | Validates DHCP client behavior | All enterprise switches | 30% | Clone uses legitimate DHCP |
| **802.1X** | Per-user EAP credential auth | Enterprise (ISE, ClearPass) | 15% | Cannot MAC-spoof by design |
| **MACsec (802.1AE)** | Layer 2 encryption per frame | Cisco 9K, Aruba CX | <5% | Unbypassable at L2 |

### Layer 3-7 Defenses

| Defense | How | Prevalence | Bypassable? |
|---|---|---|---|
| **DHCP fingerprinting** | Option 55/60/12 identifies OS | 5% (Cisco ISE, Fingerbank) | Spoof DHCP options to match target |
| **TLS fingerprinting (JA3/JA4)** | ClientHello identifies browser | <1% portals (Cloudflare WAF) | uTLS library spoofs any browser |
| **HTTP fingerprinting** | Headers, order, Sec-CH-UA | <1% portals | Match full browser header profile |
| **TCP/IP fingerprinting (p0f)** | TTL, window, MSS, options | 3% enterprise | Tune kernel params or raw sockets |
| **DNS tunnel detection** | High-rate, high-entropy DNS | 10% | Rate limit + low-entropy encoding |
| **Behavioral analysis** | Traffic patterns vs device profile | <2% | Traffic pattern mimicry |

---

## Part 2: Current nowifi Coverage

| Defense | nowifi technique | Status |
|---|---|---|
| MAC-only binding | MAC clone (idle/any) | ✅ Implemented |
| MAC+IP binding | — | ❌ Need DHCP option 50 |
| MAC+Cookie binding | Session cookie replay (passive) | ⚠️ Detect only, no active replay |
| Duplicate MAC | Idle device targeting | ✅ Implemented |
| Client isolation | ARP table from gateway | ⚠️ Fails under full PVLAN |
| DHCP fingerprinting | — | ❌ Not implemented |
| TLS fingerprinting | — | ❌ Not implemented |
| HTTP fingerprinting | CNA UA spoof (partial) | ⚠️ Only User-Agent |
| DNS tunnel detection | — | ❌ No stealth mode for tunnels |
| Rate limiting | Rate limiter for WPS/brute | ✅ Implemented |

---

## Part 3: Planned Techniques

### Technique 24: Full Device Clone

Clone EVERY identifier simultaneously. Undetectable by any defense except 802.1X/MACsec.

**What gets cloned:**
1. MAC address (existing)
2. IP address via DHCP option 50
3. DHCP fingerprint (option 55 sequence, option 60, option 12, option 61)
4. TLS fingerprint (uTLS with matching browser profile)
5. HTTP headers (full browser profile including Sec-CH-UA, Accept-Language, header order)
6. TCP/IP fingerprint (TTL, window size, MSS — via raw socket or sysctl)

**Implementation:**
```go
type DeviceProfile struct {
    MAC              string
    IP               string
    OS               string        // "macos", "ios", "windows", "android", "linux"
    Browser          string        // "chrome", "safari", "firefox", "edge"
    DHCPOptions      DHCPProfile
    TLSProfile       utls.ClientHelloID
    HTTPHeaders      map[string]string
    TCPFingerprint   TCPProfile
}

// Pre-built profiles for common device types
var ProfileiPhone = DeviceProfile{
    OS: "ios",
    Browser: "safari",
    DHCPOptions: DHCPProfile{
        Option55: []byte{1, 121, 3, 6, 15, 119, 252, 67, 52},
        Option12: "iPhone",
    },
    TLSProfile: utls.HelloIOS_Auto,
    HTTPHeaders: map[string]string{
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    },
    TCPFingerprint: TCPProfile{TTL: 64, WindowSize: 65535, MSS: 1460},
}
```

**Defeats:** MAC binding, MAC+IP binding, DHCP fingerprinting, TLS fingerprinting, HTTP fingerprinting, TCP fingerprinting, p0f, DAI, DHCP snooping.

**Does NOT defeat:** 802.1X, MACsec, cookie-based binding (needs cookie), behavioral analysis.

### Technique 25: Behavioral Stealth Mode

All tunnel traffic mimics human browsing patterns to evade behavioral analysis.

**For DNS tunnels:**
- Limit to <10 queries/second (legitimate browsers: 5-20/min)
- Use CNAME/A records instead of TXT (less suspicious)
- Mix tunnel queries with legitimate DNS for popular domains
- Randomize query intervals (not constant rate)
- Use short, dictionary-word-like subdomain labels (low entropy)

**For all tunnels:**
- Burst-pause pattern: 3-15s active, 5-60s idle (mimics page loads + reading)
- Vary packet sizes (don't send uniform 1400-byte frames)
- Inject idle keepalives that look like background app traffic
- Bandwidth cap matching device type (phone: 1-5 Mbps, laptop: 5-20 Mbps)

**For portal interactions:**
- Randomize timing between form submissions (not instant, 2-5s)
- Add mouse-move-like delays before clicks
- Use realistic viewport size in User-Agent

### Technique 26: Anti-Forensic Session Rotation

Automatic identity rotation to avoid long-running sessions in logs.

```
Loop:
  1. Clone idle device (Full Clone technique 24)
  2. Use for 15-25 minutes (randomized)
  3. Clean disconnect: DHCP release → set random transitional MAC → restore
  4. Wait 30-120 seconds (randomized)
  5. Scan for new idle device
  6. Repeat
```

Each session appears as a different device in portal logs. No single MAC has a long session. Pattern is indistinguishable from guests arriving and leaving.

### Technique 27: Passive Device Discovery (PVLAN bypass)

When client isolation prevents ARP scanning, discover devices through passive monitoring:

1. **Broadcast traffic**: DHCP Discover/Request from other clients leaks their MAC, hostname, OS fingerprint
2. **Multicast**: mDNS (.local), SSDP (UPnP), LLMNR — all leak device info
3. **Gateway ARP proxy**: Even with PVLAN, gateway responds to ARP for all clients — enumerate by requesting ARP for sequential IPs
4. **Monitor mode** (if available): Capture all 802.11 frames, see every client's MAC, probe requests, data frame source addresses
5. **DHCP exhaustion probe**: Request IPs sequentially, note which are "already allocated" — reveals active IPs without seeing the clients directly

---

## Part 4: Emerging Attack Vectors

### Innovation 1: "Ghost DHCP" — Predict and Pre-Claim Target's IP

**Concept:** Instead of cloning an existing device, predict what IP a FUTURE authenticated device will get, and pre-claim it.

**How:**
1. Observe DHCP pool pattern (sequential allocation is common)
2. Note last few allocated IPs
3. Predict next IP in sequence
4. Pre-register that IP with your MAC via DHCP
5. When the next user authenticates, the portal authorizes YOUR MAC (which holds the IP)
6. The user gets a different IP and their auth session is on your MAC

**Defeats:** MAC-only binding (portal authorized your MAC), MAC+IP (you have the IP the portal expected)

**Risk:** Fragile — depends on predictable DHCP allocation. Fails with randomized pools.

### Innovation 2: "Portal Reflection" — Hijack the Auth Flow

**Concept:** Intercept another user's portal authentication in transit and redirect it to authorize your MAC instead.

**How:**
1. Perform ARP spoofing between a new (unauthenticated) client and the gateway
2. When the client submits portal login credentials, intercept the POST
3. Replay the credentials from YOUR connection (your MAC/IP)
4. The portal authenticates YOUR session
5. Release ARP spoofing — the original user gets an error, retries, authenticates separately

**Defeats:** Any portal that uses credential-based auth (email, voucher, social login)

**Risk:** HIGH detection risk if DAI is active. Requires client isolation to be disabled.

### Innovation 3: "Time-Shifted Clone" — Clone a Device AFTER It Leaves

**Concept:** Most portals have a session timeout (15 min - 24 hours). After a device disconnects, its session may still be valid. Clone its MAC AFTER it's gone.

**How:**
1. Passively record all device MACs on the network (monitor mode or ARP monitoring)
2. Track when devices disconnect (ARP timeout, no response to ping)
3. After device X leaves: wait 60s (confirm gone), clone X's MAC
4. The portal still has X's session active (hasn't timed out yet)
5. You inherit X's remaining session time

**Defeats:** MAC-only binding, MAC+IP (if you get the same IP via DHCP after original releases)

**Why this is better than current MAC clone:** No collision risk (device is gone). No need to detect "idle" — it's definitively absent. Session is already authenticated.

### Innovation 4: "Layered Tunnel Stack" — Tunnel Inside a Tunnel

**Concept:** If the portal detects and blocks one tunnel type (e.g., DNS), wrap it in another allowed tunnel.

**How:**
1. Detect which protocols are open (existing probe)
2. If DNS is open but detected/throttled: wrap DNS tunnel inside ICMP tunnel
3. If HTTPS is inspected: use QUIC (UDP/443) which can't be deep-inspected without breaking HTTP/3
4. Stack: QUIC → WebSocket → chisel SOCKS → your traffic
5. Each layer adds overhead but defeats a different inspection mechanism

**Defeats:** Single-protocol tunnel detection, DPI that only inspects one layer

### Innovation 5: "Sympathetic Resonance" — Abuse the Portal's Own Infrastructure

**Concept:** The portal itself has whitelisted services (payment processor, social login, update servers). Abuse these whitelisted paths as tunnel endpoints.

**How:**
1. Portal whitelists `accounts.google.com` for OAuth login
2. Use Google Cloud Function (or Firebase) as a relay — traffic goes to Google IP → relayed to your server
3. Portal whitelists Apple update servers → use Apple CDN or iCloud Private Relay as cover
4. Portal whitelists payment processor → if the processor has an open redirect, chain through it

**Defeats:** Walled garden / whitelist-based portals

**Risk:** Depends on specific whitelist configuration. Not universal.

### Innovation 6: "Quantum MAC" — Rapidly Alternate Between Multiple Identities

**Concept:** Instead of cloning ONE device, rapidly alternate between multiple authenticated MACs (10ms per switch). The portal sees multiple "active" devices, but only one is actually you at any given microsecond.

**How:**
1. Discover 5-10 idle authenticated MACs
2. Set MAC to device A → send packets → set to device B → send packets → ...
3. Cycle through all identities at high speed (kernel-level MAC switching)
4. Each identity only appears "active" for a fraction of the time
5. If any one identity gets blocked, seamlessly switch to another

**Defeats:** Session revocation (you have N backup identities), duplicate MAC detection (each MAC is only active briefly)

**Risk:** VERY high implementation complexity. May cause packet loss during switching. Kernel-level MAC changing is slow on some OSes (100ms+ on macOS).

---

## Part 5: Priority Implementation Plan

| # | Technique | Impact | Effort | Priority |
|---|---|---|---|---|
| 24 | Full Device Clone | Defeats everything except 802.1X/MACsec | High | **P0** |
| 25 | Behavioral Stealth | Defeats tunnel detection + analytics | Medium | **P1** |
| 3* | Time-Shifted Clone | Zero collision risk, simpler than idle | Low | **P1** |
| 26 | Anti-Forensic Rotation | No long sessions in logs | Medium | **P2** |
| 27 | Passive PVLAN Discovery | Works under client isolation | Medium | **P2** |
| 1* | Ghost DHCP | Creative but fragile | Low | **P3** |
| 4* | Layered Tunnel Stack | Belt-and-suspenders tunnel evasion | High | **P3** |
| 5* | Sympathetic Resonance | Portal-specific, not universal | Medium | **P3** |
| 2* | Portal Reflection | High risk (ARP spoof needed) | High | **P4** |
| 6* | Quantum MAC | Interesting but impractical on most OSes | Very High | **Defer** |

---

## Part 6: Go Implementation Notes

### Dependencies needed:
- `github.com/insomniacslk/dhcp` — custom DHCP client with full option control
- `github.com/refraction-networking/utls` — TLS fingerprint spoofing
- `github.com/google/gopacket` — passive packet capture for device discovery (optional, for monitor mode)

### New packages:
- `internal/clone/` — Full Device Clone orchestration
- `internal/stealth/` — Behavioral stealth mode for tunnels
- `internal/discover/` — Passive device discovery (broadcast, multicast, monitor mode)

### Existing packages to modify:
- `internal/bypass/bypass.go` — add techniques 24-27
- `internal/tunnel/tunnel.go` — add stealth wrappers for all tunnel types
- `internal/platform/` — add DHCP fingerprint spoofing, sysctl TCP param tuning
