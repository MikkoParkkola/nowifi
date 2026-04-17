# nowifi-telemetry

Anonymous, opt-in telemetry endpoint for [nowifi](https://github.com/MikkoParkkola/nowifi).

Runs as a single Cloudflare Worker serving thousands of users under the free tier (100K events/day).

## What it collects

Per event:
- Technique ID (e.g., `warp_tunnel`, `portal_relay`)
- Success: true/false
- Provider ID (e.g., `panasonic_avionics`, `unknown`)
- Duration (ms)
- Country code (from Cloudflare edge, never IP)
- nowifi version + OS/arch

## What it does NOT collect

- No IP address
- No MAC address
- No SSID
- No portal URL
- No DNS names
- No user identifier — each event is independent

## Deployment (maintainer only)

```bash
npm install -g wrangler
wrangler login
cd worker/telemetry
wrangler deploy
```

## Querying

Cloudflare Analytics Engine SQL:
```sql
SELECT
  blob1 AS technique,
  blob2 AS provider,
  COUNT() AS attempts,
  SUM(double2) AS successes,
  SUM(double2) / COUNT() AS success_rate
FROM nowifi_events
WHERE timestamp > NOW() - INTERVAL '7' DAY
GROUP BY technique, provider
ORDER BY attempts DESC
```

## Cost

$0/month. 100K events/day free forever. Analytics Engine is included.
