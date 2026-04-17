// nowifi telemetry worker — free, zero-config, anonymous
//
// Deployed once by the maintainer; shared across all opt-in nowifi users.
// Uses Cloudflare Analytics Engine (AE) for aggregation. AE free tier:
//   - 100,000 writes/day forever
//   - SQL-queryable via Workers Analytics Engine API
//
// PRIVACY MODEL:
//   - No IP stored (CF-IPCountry kept for geographic aggregation only)
//   - No MAC, no SSID, no portal URL, no DNS names ever collected
//   - Each request is independent — no session/user tracking
//   - Opt-in only (clients default to disabled)
//
// PURPOSE:
//   Track which bypass techniques actually succeed against which inflight
//   providers, across the user base. Aggregate data informs:
//     1. Security research (which portals are weakest)
//     2. Client updates (better RecommendedOrder rankings)
//
// Maintainer deploys via wrangler:
//   npx wrangler deploy
//
// Client posts to:  https://nowifi-telemetry.<account>.workers.dev/event
// Client polls:     https://nowifi-telemetry.<account>.workers.dev/rankings

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS preflight — let any origin query rankings.
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: corsHeaders(),
      });
    }

    if (url.pathname === "/event" && request.method === "POST") {
      return handleEvent(request, env);
    }

    if (url.pathname === "/rankings" && request.method === "GET") {
      return handleRankings(request, env);
    }

    if (url.pathname === "/" || url.pathname === "/about") {
      return new Response(
        `nowifi telemetry endpoint\n\n` +
          `Purpose: track which captive-portal bypass techniques succeed\n` +
          `against which inflight WiFi providers. Anonymous, opt-in.\n\n` +
          `Endpoints:\n` +
          `  POST /event      Submit an anonymous event\n` +
          `  GET  /rankings   Fetch community rankings\n\n` +
          `Source: https://github.com/MikkoParkkola/nowifi\n`,
        { status: 200, headers: { "Content-Type": "text/plain", ...corsHeaders() } }
      );
    }

    return new Response("Not Found", { status: 404, headers: corsHeaders() });
  },
};

async function handleEvent(request, env) {
  let event;
  try {
    event = await request.json();
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }

  // Validate: only accept known fields. Drop anything else silently.
  const technique = safeString(event.technique, 64);
  const success = !!event.success;
  const provider = safeString(event.provider || "unknown", 64);
  const durationMs = clampInt(event.duration_ms, 0, 300000);
  const version = safeString(event.version, 16);
  const osArch = safeString(event.os_arch, 32); // e.g., "darwin/arm64"

  if (!technique || !version) {
    return json({ error: "missing required fields" }, 400);
  }

  // Country from CF-IPCountry header (set by Cloudflare edge). Never log IP.
  const country = request.headers.get("CF-IPCountry") || "XX";

  // Write to Analytics Engine if bound.
  if (env.TELEMETRY) {
    env.TELEMETRY.writeDataPoint({
      blobs: [technique, provider, country, version, osArch],
      doubles: [durationMs, success ? 1 : 0],
      indexes: [technique], // AE supports one index — query by technique
    });
  }

  return json({ ok: true });
}

async function handleRankings(request, env) {
  // Returns community-aggregated technique ranking per provider.
  // Served from a KV or D1 cache that a cron job populates from AE.
  //
  // For the initial launch we return a static baseline; cron job can
  // update the KV entry once enough telemetry accumulates.
  if (env.RANKINGS) {
    const cached = await env.RANKINGS.get("rankings.json");
    if (cached) {
      return new Response(cached, {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }
  }

  // Baseline: no crowdsourced data yet.
  return json(
    {
      version: 0,
      generated_at: new Date().toISOString(),
      providers: {},
      note: "No aggregate data yet. Client should keep using built-in profiles.",
    },
    200
  );
}

// --- helpers ---

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function safeString(v, maxLen) {
  if (typeof v !== "string") return "";
  // Only allow printable ASCII + "_" + "-" + "/" + ".".
  const cleaned = v.replace(/[^A-Za-z0-9_\-\/\.]/g, "");
  return cleaned.slice(0, maxLen);
}

function clampInt(v, min, max) {
  const n = Number(v) | 0;
  if (n < min) return min;
  if (n > max) return max;
  return n;
}
