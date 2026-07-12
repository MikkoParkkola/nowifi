# SAS flight offline checklist

Prepared 2026-06-07 for running nowifi during a SAS flight without internet.

## Scope

- Defensive/authorized research on your own device and session.
- Primary in-flight test is `nowifi forensics`: read-only, no elevated
  privileges, local-only, no upload, and no MAC/proxy/DNS changes.
- Full bypass testing is separate and mutates local network state; use the
  existing repo docs for that path only when you intentionally want it.

## Known SAS profile

The code maps SAS to the Thales InFlyt provider profile:

- Provider: `thales_inflyt`
- Typical portal markers: `inflyt`, `flytlive`, `topconnect`, `thales`,
  `aircon`, `afklm`
- SAS allowlist hint in code: `flysas.com`
- Recommended order: `capport_session_extend`, `mac_clone_idle`, `mac_clone`,
  `dns_tunnel`, `doh_tunnel`, `http3_tunnel`, `doq_tunnel`, `ntp_tunnel`,
  `js_only_bypass`, `cna_useragent_spoof`

## Before boarding / while online

From repo root:

```bash
cd ~/github/nowifi

# Use the local checkout, not whichever Homebrew binary happens to be first.
./bin/nowifi --version

# Confirm offline-critical helpers are on disk.
./bin/nowifi tools
test -x /Applications/Tailscale.app/Contents/MacOS/Tailscale && /Applications/Tailscale.app/Contents/MacOS/Tailscale version
test -x ~/go/bin/chisel && ~/go/bin/chisel --version
```

Leave this repo, `bin/nowifi`, and this checklist open before takeoff.

Do not capture the baseline on airport/home internet. The baseline is only
useful after you have joined the SAS onboard Wi-Fi and currently have full
access, for example after portal login or a free tier starts.

## In flight: optional full-access baseline

If the SAS onboard Wi-Fi currently has working internet, capture the baseline
before the portal cuts off or changes policy:

```bash
cd ~/github/nowifi
mkdir -p forensics/sas-flight
./bin/nowifi forensics --baseline --output forensics/sas-flight --timeout 90
```

## In flight: read-only collection

After joining the SAS onboard Wi-Fi, run this even if the captive portal blocks
internet:

```bash
cd ~/github/nowifi
mkdir -p forensics/sas-flight

# If you have a baseline file from before takeoff, include the newest one:
BASELINE="$(ls -t forensics/sas-flight/baseline-*.txt 2>/dev/null | head -1)"

if [ -n "$BASELINE" ]; then
  ./bin/nowifi forensics --baseline-file "$BASELINE" --output forensics/sas-flight --timeout 90
else
  ./bin/nowifi forensics --output forensics/sas-flight --timeout 90
fi
```

Artifacts to keep:

- `forensics/sas-flight/holes-*.txt`
- `forensics/sas-flight/holes-*.json`
- `forensics/sas-flight/baseline-*.txt`, if captured

## In flight: read-only assessment

Use this when you want a quick human-readable assessment without trying to
bypass anything:

```bash
cd ~/github/nowifi
mkdir -p forensics/sas-flight
./bin/nowifi diagnose -r markdown -o forensics/sas-flight/diagnose-sas-$(date -u +%Y%m%dT%H%M%SZ).md
```

## If no Wi-Fi association exists

If the laptop is not associated to the aircraft Wi-Fi at all, live collection
cannot measure captive-portal holes. Save battery and wait until the SAS Wi-Fi
SSID appears, then run the read-only collection command above.
