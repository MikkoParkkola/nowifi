# How to GUARANTEE connectivity on the next Finnair flight

We were ~80% there this flight. The gap was **one structural weakness**: every
working tunnel rode the **Tailscale/DERP transport**, which shares fate with the
captive portal's :443 policy. To make next time a sure thing, remove that single
point of failure by having **multiple independent exit channels pre-staged and
auto-tested**. Concrete plan below, in priority order.

## The root problem (why limitations bite)
Finnair = **Panasonic "Nordic Sky"**, Kong gateway, **MAC-based** session +
quota enforcement. It lets some traffic through pre/post-limit (DNS recursion,
ICMP, NTP, :443 to allowlisted domains). A tunnel survives the cutoff only if its
transport rides a channel the portal leaves open. We need tunnels on **several
different channels** so at least one always lands.

## Fix #1 — A real public VPS exit (removes the CGNAT/Tailscale dependency)  ★★★
spark is behind CGNAT, so today every path funnels through Tailscale-DERP. Stand
up a **$5/mo VPS** (Hetzner/Fly/DO) with a **public IP** running, on distinct
channels:
- `iodined` on **UDP/53** + delegate `t.raxor.ai` NS → the VPS (DNS tunnel; DNS
  recursion was wide open this flight).
- `chisel server` on **TCP/443** (works when :443-to-any survives).
- WireGuard on **UDP/53 and UDP/123** (NTP port was open).
- `sshd` on **443 + 53** for sshuttle.
Then the plane has 4 independent transports to one box. One will pass. This is
the single highest-leverage change — it's what makes success deterministic.

## Fix #2 — Cloudflare-fronted exit (rides the most-allowlisted channel)  ★★
The portal allowlists Cloudflare-fronted services (stripe, DoH worked). Put a
**named Cloudflare Tunnel** (not the flaky quick-tunnel) on a real hostname with
**no Access policy**, fronting a chisel/SOCKS server. SNI = a CF domain → most
likely to pass even under strict allowlisting. (Quick-tunnel WS data was flaky
this flight; a proper named tunnel + `cloudflared access tcp` is solid.)

## Fix #3 — Bake it all into nowifi (so it's `sudo nowifi`, zero fiddling)  ★★★
This flight surfaced concrete nowifi improvements — file + implement on the ground:
- **Add `icmp_tunnel` to the `panasonic_avionics` RecommendedOrder** — ICMP echo
  reached the internet here but the profile doesn't try it (confirmed gap).
- **Ship a pre-baked relay config** (VPS endpoints from Fix #1) inside nowifi so
  the airline profile knows where to tunnel to — no manual endpoint setup.
- **MAC-clone-idle is profile #1 already** — verify it actually fires first
  (26 paid devices were visible = high success; this alone may beat the quota
  without any tunnel, since enforcement is MAC-based).
- Add the **pax-api enforcement probe** (`/api/*` on nordic-sky) to detect
  whether the quota is resettable via a client-controllable device-id.

## Fix #4 — Beat MAC-based quota directly (cheapest, no server at all)  ★★
Enforcement is **per-MAC**. Two zero-infrastructure moves:
- **`mac_rotate`**: fresh random MAC → new device → new free/quota allotment.
- **`mac_clone_idle`**: clone an already-paid idle device's MAC → inherit its
  session. nowifi automates both. On a MAC-keyed portal this often needs *no
  tunnel at all*.

## The 60-second pre-flight checklist for next time
1. `~/go/bin/chisel` present + VPS endpoints exported (`NOWIFI_*`).
2. `nowifi --version` current; `panasonic_avionics` profile has icmp_tunnel.
3. VPS up: `iodined` + `chisel :443` + WireGuard listening; `t.raxor.ai` delegated.
4. While still on full wifi, run `bash flight-connect.sh --force` once to confirm
   at least 2 rungs reach the VPS. (`--force` tests without waiting for cutoff.)
5. At cutoff: `sudo bash flight-connect.sh` → it auto-walks exit-node →
   chisel/tailnet → chisel/CF → nowifi → MAC-clone and applies the system proxy.

## Bottom line
This flight proved the *mechanism* works (chisel → spark → Amsterdam egress,
verified). Next-flight **certainty** comes from **Fix #1 (a public VPS on 4
channels) + Fix #3 (baked into nowifi)**. Do those two on the ground and the next
Finnair cutoff is a non-event — one command, multiple independent paths, at least
one always open.
