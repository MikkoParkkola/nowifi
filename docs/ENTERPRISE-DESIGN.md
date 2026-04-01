# nowifi Enterprise -- Product Design Document

**Status:** Draft
**Date:** 2026-03-29
**Author:** Mikko Parkkola
**Version:** 0.1.0
**Audience:** Investors, engineering team, enterprise customers

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Market Analysis](#2-market-analysis)
3. [Product Tiers](#3-product-tiers)
4. [Technical Architecture](#4-technical-architecture)
5. [PDF Report Generator](#5-pdf-report-generator)
6. [Compliance Templates](#6-compliance-templates)
7. [Monetization Strategy](#7-monetization-strategy)
8. [Go-to-Market](#8-go-to-market)
9. [Implementation Roadmap](#9-implementation-roadmap)
10. [Competitive Moat](#10-competitive-moat)

---

## 1. Executive Summary

**nowifi** is a WiFi security assessment tool that automates 27 bypass and attack techniques against captive portals and WPA networks. It detects portal type and vendor, enumerates every protocol leak, attempts bypass techniques in order of effectiveness, and produces security reports with findings and remediation advice.

**The opportunity:** Every organization with guest WiFi needs quarterly security assessments (PCI-DSS 11.1 mandates it). Pentest firms run these assessments manually, spending 4-8 hours per site with fragmented tools (Wireshark, aircrack-ng, manual MAC spoofing, custom scripts). nowifi reduces this to 30 seconds of automated assessment with a single command.

**Business model:** Open-core. The CLI tool remains free and open source (MIT license), driving adoption among individual pentesters. Revenue comes from an enterprise management layer: professional PDF reports, centralized dashboards, team management, compliance templates, and API integrations.

**Target revenue:** $2.4M ARR by end of Year 2, scaling to $8M+ ARR by Year 3.

---

## 2. Market Analysis

### 2.1 Market Size

**WiFi Security Assessment Market**

The global wireless security market was valued at approximately $12.3B in 2025 and is projected to reach $25B+ by 2030 (CAGR ~15%). The penetration testing services subset is approximately $3.2B, with wireless assessments comprising roughly 15-20% of pentest engagements ($480-640M annually).

| Segment | Size (2025) | Growth |
|---------|-------------|--------|
| Wireless security (total) | $12.3B | 15% CAGR |
| Penetration testing services | $3.2B | 18% CAGR |
| WiFi-specific pentest tools | ~$500M | 20% CAGR |
| Automated pentest platforms | ~$1.2B | 25% CAGR |

**TAM (Total Addressable Market):** $500M -- all organizations purchasing WiFi security assessment tools and services globally.

**SAM (Serviceable Addressable Market):** $120M -- pentest firms, MSSPs, and enterprise security teams in English-speaking markets that use automated tools (vs. fully manual testing).

**SOM (Serviceable Obtainable Market):** $8M by Year 3 -- realistic capture of ~6.7% of SAM through open-source-driven adoption, targeting the underserved "automated WiFi pentest tool" niche where no clear market leader exists.

### 2.2 Customer Segments

| Segment | Size | Budget | Pain Point | Buying Behavior |
|---------|------|--------|------------|-----------------|
| **Independent pentesters** | ~50,000 globally | $50-200/mo for tools | Need professional reports for clients, spend hours formatting findings manually | Self-serve, credit card, monthly |
| **Pentest firms** (5-50 consultants) | ~5,000 firms | $2,000-10,000/mo | Need consistent methodology across team, shared credential vaults, centralized audit history | Sales-assisted, annual contracts |
| **Enterprise security teams** | ~20,000 teams | $5,000-50,000/mo | Compliance requirements (PCI-DSS, SOC2), need scheduled quarterly scans, SIEM integration | Enterprise sales, procurement, POC |
| **MSSPs** (Managed Security Service Providers) | ~3,000 providers | $10,000-100,000/mo | Multi-tenant, white-label reports for their clients, API-driven automation | Channel partnerships, volume licensing |

### 2.3 Competitor Analysis

#### Direct Competitors (WiFi Security Assessment)

| Tool | Pricing | Strengths | Weaknesses |
|------|---------|-----------|------------|
| **WiFi Pineapple (Hak5)** | $120-400 hardware + $0/mo software | Physical device, community, established brand | Hardware-dependent, limited automation, no enterprise management, no reporting |
| **Pwnie Express (Outpost)** | $5,000-15,000/yr per sensor | Continuous wireless monitoring, enterprise dashboard | Discontinued/acquired 2020, sensor-dependent, monitoring-only (not active testing) |
| **Kismet** | Free (open source) | Passive recon, multi-protocol (WiFi/BT/Zigbee) | Passive only, no active bypass testing, no reports |
| **Aircrack-ng suite** | Free (open source) | WPA cracking standard, mature | Fragmented tools, no automation, no portal bypass, no reporting |
| **Acrylic WiFi** | $20-100/license | Windows WiFi analysis, decent UI | Windows-only, analysis-only, no active testing |

#### Adjacent Competitors (General Pentest Platforms)

| Tool | Pricing | Model | Relevance |
|------|---------|-------|-----------|
| **Metasploit Pro (Rapid7)** | $15,000/yr per user | Open core (Metasploit Framework = free, Pro = paid) | Gold standard for open-core security. WiFi modules exist but are minimal. Revenue: Rapid7 $780M ARR (2025) |
| **Burp Suite (PortSwigger)** | $449/yr Pro, $8,395/yr Enterprise | Freemium (Community free, Pro/Enterprise paid) | Web-focused, not WiFi. Revenue: estimated $100M+ ARR. Acquired by Insight for $700M+ (2024) |
| **Pentera** | $50,000-200,000/yr | SaaS automated pentesting | Network-focused, includes some wireless. Revenue: ~$100M ARR (2025). Raised $315M Series C |
| **Snyk** | Free tier, $25/mo Pro, custom Enterprise | Open core (developer security) | Different domain (code security), but excellent open-core model to study. Revenue: $300M+ ARR |
| **Nessus (Tenable)** | $4,090/yr per scanner | Commercial | Vulnerability scanning, limited WiFi. Revenue: Tenable $830M ARR |
| **Cobalt Strike** | $5,900/yr per user | Commercial (red team) | Red team C2, no WiFi focus. Acquired by Fortra |

#### Key Competitive Insight

**There is no market leader for automated WiFi security assessment tools.** The space is fragmented between:
- Free CLI tools (aircrack-ng, wifite, Kismet) with no enterprise features
- Expensive hardware sensors (Hak5, Pwnie Express) with limited automation
- General pentest platforms (Metasploit, Pentera) with minimal WiFi coverage

nowifi occupies a unique position: the most comprehensive automated WiFi assessment tool (27 techniques), delivered as a single binary, with an enterprise layer for professional use.

### 2.4 Open-Core Precedent Analysis

The most successful open-core security companies follow a consistent pattern:

| Company | Free Tier | Paid Tier | Conversion Rate | Revenue |
|---------|-----------|-----------|-----------------|---------|
| Rapid7 (Metasploit) | Framework: CLI, modules, exploits | Pro: GUI, automation, reporting, collaboration | ~2-3% of users | $780M ARR |
| PortSwigger (Burp Suite) | Community: basic scanning | Pro: advanced scanning, $449/yr. Enterprise: CI/CD, $8,395/yr | ~5-8% of users | $100M+ ARR |
| Snyk | Free: 200 tests/mo | Pro: unlimited, $25/user/mo. Enterprise: SSO, RBAC, custom | ~3-5% of users | $300M+ ARR |
| HashiCorp | Terraform/Vault OSS | Cloud/Enterprise: governance, SSO, audit logs | ~2-4% of users | $580M ARR |
| GitLab | Free tier | Premium: $29/user/mo. Ultimate: $99/user/mo | ~3% of users | $560M ARR |

**Pattern:** Free tool captures 95-98% of users (marketing + community), paid tier captures 2-5% who need reporting, team management, compliance, and support. The conversion percentage is small, but the funnel is massive.

---

## 3. Product Tiers

### 3.1 nowifi Community (Free, Open Source, MIT)

Everything in the current tool and Go rewrite. This is the adoption engine.

| Feature | Details |
|---------|---------|
| All 27 techniques | Portal bypass (19) + WPA cracking (4) + advanced evasion (4) |
| Full audit pipeline | Detect, probe, bypass, report |
| Diagnosis mode | Read-only security assessment |
| Terminal reports | Colored terminal output with findings and remediation |
| Markdown reports | Pentest report in markdown format |
| JSON reports | Machine-readable output for scripting |
| Web dashboard | Local htmx dashboard on localhost |
| System tray app | macOS/Linux system tray integration |
| Single binary | Zero dependencies, cross-platform |
| CLI only | Single user, local execution |

**Limitations (driving Pro upgrade):**
- No PDF reports (the #1 pentest deliverable)
- No audit history (results lost after terminal closes)
- No scheduled scans
- No team features
- Community support only (GitHub Issues)

### 3.2 nowifi Pro ($29/month per user, $290/year)

For individual pentesters who need professional deliverables.

| Feature | Details |
|---------|---------|
| **PDF report generator** | Professional, client-ready PDF reports with executive summary, findings, risk ratings, remediation, compliance mapping, and appendices |
| **Report templates** | 3 built-in templates: Executive Brief (2-page), Technical Assessment (10-20 pages), Full Audit (comprehensive with appendices) |
| **Custom branding** | Add your company logo, colors, and contact info to reports |
| **Audit history** | Local SQLite database of all past audits with full-text search |
| **Audit comparison** | Diff two audits of the same network to show remediation progress |
| **Credential manager** | Encrypted local vault for tunnel server credentials, WiFi passwords, portal creds |
| **Auto-portal-login** | Credential manager auto-fills portal login for known networks |
| **Priority updates** | Early access to new techniques and features (1 week before Community) |
| **Email support** | 48-hour response SLA |
| **License** | Proprietary. Single-user, tied to machine fingerprint |

**Pricing rationale:** $29/mo is below the threshold requiring procurement approval at most companies ($50-100/mo). Comparable to Burp Suite Pro at $449/yr ($37/mo). Individual pentesters bill $150-300/hr; the tool pays for itself with one 15-minute engagement per month.

### 3.3 nowifi Enterprise ($149/month per seat, minimum 5 seats)

For pentest firms, security teams, and MSSPs. Requires the nowifi server.

| Feature | Details |
|---------|---------|
| **Everything in Pro** | All Pro features included |
| **Centralized dashboard** | Web-based dashboard for the entire team, hosted or self-hosted |
| **Team management (RBAC)** | Roles: Owner, Admin, Pentester, Viewer. Granular permissions per project |
| **Shared credential vault** | Team-wide encrypted credential store (AES-256-GCM, zero-knowledge) |
| **Projects & scopes** | Organize audits by client/project with defined scope boundaries |
| **Scheduled scans** | Cron-based recurring assessments (quarterly for PCI-DSS compliance) |
| **API + webhooks** | RESTful API for automation, webhooks for SIEM/SOAR integration |
| **Compliance templates** | PCI-DSS 11.1, SOC2 CC6.1, ISO 27001 A.13.1, NIST 800-53 AC-18 |
| **Compliance evidence packs** | Auto-generated evidence documents for auditors |
| **White-label reports** | Full custom branding (logo, colors, fonts, cover page, headers/footers) |
| **SSO (SAML 2.0 / OIDC)** | Okta, Azure AD, Google Workspace, OneLogin, JumpCloud |
| **Audit log** | Immutable log of every action (who ran what, when, from where) |
| **Multi-agent deployment** | Deploy nowifi agents on multiple sites, results centralized |
| **SLA support** | 4-hour response, dedicated Slack channel, quarterly business review |
| **Self-hosted option** | Docker Compose or Kubernetes Helm chart for air-gapped environments |
| **License** | Proprietary. Per-seat, annual contract, volume discounts |

**Pricing rationale:** $149/seat/mo ($745/mo minimum for 5 seats = $8,940/yr) is competitive with Metasploit Pro ($15,000/yr single user) and significantly below Pentera ($50,000-200,000/yr). A 10-person pentest firm pays $17,880/yr -- roughly 1-2 client engagements.

### 3.4 Volume & Custom Pricing

| Seats | Monthly per Seat | Annual per Seat | Discount |
|-------|-----------------|-----------------|----------|
| 5-10 | $149 | $1,490 | -- |
| 11-25 | $129 | $1,290 | 13% |
| 26-50 | $109 | $1,090 | 27% |
| 51-100 | $89 | $890 | 40% |
| 100+ | Custom | Custom | Contact sales |

**MSSP/White-label license:** Custom pricing based on number of managed clients. Includes multi-tenant dashboard, per-client branding, and API access for automation. Starting at $2,500/mo.

---

## 4. Technical Architecture

### 4.1 System Overview

```
                              nowifi Enterprise Architecture

  +------------------+     +------------------+     +------------------+
  | nowifi agent     |     | nowifi agent     |     | nowifi agent     |
  | (Site A)         |     | (Site B)         |     | (Site C)         |
  | - runs locally   |     | - runs locally   |     | - runs locally   |
  | - WiFi access    |     | - WiFi access    |     | - WiFi access    |
  +--------+---------+     +--------+---------+     +--------+---------+
           |                         |                         |
           | HTTPS (mTLS)            | HTTPS (mTLS)            | HTTPS (mTLS)
           |                         |                         |
  +--------v---------+---------------v-------------------------v---------+
  |                                                                      |
  |                        nowifi Server                                 |
  |                                                                      |
  |  +-------------+  +-------------+  +-------------+  +-------------+ |
  |  | API Gateway |  | Auth (OIDC) |  | Job Queue   |  | Report Gen  | |
  |  | (Go net/http|  | + RBAC      |  | (Redis)     |  | (PDF engine)| |
  |  +------+------+  +------+------+  +------+------+  +------+------+ |
  |         |                |                |                |         |
  |  +------v----------------v----------------v----------------v------+ |
  |  |                     PostgreSQL                                 | |
  |  |  audits | findings | users | teams | projects | schedules     | |
  |  +-----------------------------------------------------------+---+ |
  |                                                               |     |
  |  +------------------------------------------------------------v--+ |
  |  |                    S3 / MinIO                                  | |
  |  |  PDF reports | raw scan data | evidence packs                 | |
  |  +---------------------------------------------------------------+ |
  |                                                                      |
  +----------------------------------------------------------------------+
           |                    |                    |
           v                    v                    v
  +--------+--------+  +-------+--------+  +--------+--------+
  | Web Dashboard   |  | SIEM/SOAR      |  | Compliance      |
  | (htmx + Go)     |  | (webhooks)     |  | Auditor Portal  |
  +-----------------+  +----------------+  +-----------------+
```

### 4.2 Agent Mode

The nowifi binary operates in two modes:

**Standalone mode** (Community/Pro): Runs locally, stores results locally. This is the current behavior.

**Agent mode** (Enterprise): The same binary connects to a central server, receives scan jobs, and reports results back.

```bash
# Register agent with server
nowifi agent register --server https://app.nowifi.dev --token eyJhbG...

# Agent runs in background, polls for jobs
nowifi agent start

# Or run a single audit in agent mode (results sent to server)
nowifi agent audit --project "Acme Hotels Q1"

# Check agent status
nowifi agent status
```

**Agent protocol:**
- Agent authenticates with server via API token (JWT, 1-hour expiry, auto-refresh)
- Communication over HTTPS with mutual TLS (agent has client certificate)
- Agent polls server every 30s for pending jobs (long-poll with 30s timeout)
- Audit results submitted as structured JSON via `POST /api/v1/audits`
- Heartbeat every 60s reports agent status (online, running, idle)
- Offline resilience: results queued locally in SQLite if server unreachable, synced on reconnect

**Agent security:**
- Agent token is scoped to a project (cannot access other projects)
- Agent binary does not contain server credentials or other clients' data
- All communication encrypted (TLS 1.3)
- Agent can be remotely deactivated by admin

### 4.3 Server Stack

All components written in Go (same language as the tool) for operational simplicity.

| Component | Technology | Purpose |
|-----------|-----------|---------|
| API server | Go `net/http` + `chi` router | REST API, WebSocket for live updates |
| Authentication | Go `coreos/go-oidc` + `golang-jwt/jwt` | OIDC/SAML SSO, JWT sessions, API tokens |
| Authorization | Custom RBAC middleware | Role-based access control (Owner/Admin/Pentester/Viewer) |
| Database | PostgreSQL 16 | Audit storage, user management, team/project structure |
| Migrations | `golang-migrate/migrate` | Schema versioning |
| Job queue | Redis 7 + `hibiken/asynq` | Scheduled scans, report generation, agent job dispatch |
| Object storage | S3-compatible (AWS S3 / MinIO) | PDF reports, raw scan data, evidence packs |
| PDF engine | `go-wkhtmltopdf` or `chromedp` (headless Chrome) | HTML-to-PDF rendering for reports |
| Frontend | Go `html/template` + htmx + Alpine.js | Server-rendered dashboard with dynamic updates |
| Real-time | Server-Sent Events (SSE) | Live audit progress, agent status |
| Metrics | Prometheus + Grafana | Server health, audit throughput, agent fleet status |

**Deployment options:**

```yaml
# Docker Compose (self-hosted, recommended for Enterprise)
services:
  nowifi-server:
    image: ghcr.io/mikkoparkkola/nowifi-server:latest
    ports: ["443:443"]
    environment:
      DATABASE_URL: postgres://nowifi:secret@db:5432/nowifi
      REDIS_URL: redis://redis:6379
      S3_ENDPOINT: http://minio:9000
      S3_BUCKET: nowifi-reports
      OIDC_ISSUER: https://accounts.google.com
      OIDC_CLIENT_ID: ...
      OIDC_CLIENT_SECRET: ...
    depends_on: [db, redis, minio]

  db:
    image: postgres:16-alpine
    volumes: ["pgdata:/var/lib/postgresql/data"]

  redis:
    image: redis:7-alpine

  minio:
    image: minio/minio:latest
    command: server /data
    volumes: ["s3data:/data"]
```

```yaml
# Kubernetes Helm chart (large-scale Enterprise)
helm install nowifi-enterprise ./charts/nowifi-enterprise \
  --set server.replicas=3 \
  --set postgres.storageClass=gp3 \
  --set ingress.host=nowifi.internal.corp.com
```

### 4.4 API Design

All endpoints are versioned under `/api/v1/`. Authentication via Bearer token (JWT) or API key.

#### Audits

```
POST   /api/v1/audits                    Submit audit results (from agent)
GET    /api/v1/audits                    List audits (filtered by project, date, network)
GET    /api/v1/audits/{id}               Get audit detail (findings, probes, bypasses)
GET    /api/v1/audits/{id}/findings      Get findings for an audit
DELETE /api/v1/audits/{id}               Delete audit (admin only)
GET    /api/v1/audits/{id}/diff/{id2}    Compare two audits (remediation tracking)
```

#### Reports

```
POST   /api/v1/reports/generate          Generate PDF report for an audit
GET    /api/v1/reports/{id}              Get report metadata (status, format, size)
GET    /api/v1/reports/{id}/download     Download PDF report
GET    /api/v1/reports/templates         List available report templates
POST   /api/v1/reports/templates         Upload custom report template (Enterprise)
```

#### Scans (Scheduled)

```
POST   /api/v1/scans/schedule            Create scheduled scan
GET    /api/v1/scans/schedules           List all schedules
PUT    /api/v1/scans/schedules/{id}      Update schedule
DELETE /api/v1/scans/schedules/{id}      Delete schedule
GET    /api/v1/scans/schedules/{id}/runs List past runs for a schedule
```

#### Team Management

```
GET    /api/v1/team                      Get team info
GET    /api/v1/team/members              List team members
POST   /api/v1/team/members/invite       Invite member (email)
PUT    /api/v1/team/members/{id}/role    Update member role
DELETE /api/v1/team/members/{id}         Remove member
```

#### Projects

```
POST   /api/v1/projects                  Create project
GET    /api/v1/projects                  List projects
GET    /api/v1/projects/{id}             Get project detail
PUT    /api/v1/projects/{id}             Update project
GET    /api/v1/projects/{id}/audits      List audits in project
```

#### Agents

```
POST   /api/v1/agents/register           Register new agent
GET    /api/v1/agents                    List agents (status, last seen)
GET    /api/v1/agents/{id}               Get agent detail
DELETE /api/v1/agents/{id}               Deactivate agent
GET    /api/v1/agents/{id}/jobs          Get pending jobs for agent (long-poll)
POST   /api/v1/agents/{id}/heartbeat     Agent heartbeat
```

#### Webhooks

```
POST   /api/v1/webhooks                  Create webhook
GET    /api/v1/webhooks                  List webhooks
PUT    /api/v1/webhooks/{id}             Update webhook
DELETE /api/v1/webhooks/{id}             Delete webhook
POST   /api/v1/webhooks/{id}/test        Send test event
```

**Webhook events:**
- `audit.completed` -- new audit results available
- `finding.critical` -- critical severity finding discovered
- `scan.scheduled.started` -- scheduled scan began
- `scan.scheduled.completed` -- scheduled scan finished
- `agent.offline` -- agent went offline (missed 3 heartbeats)
- `report.ready` -- PDF report generation completed

**Webhook payload example:**

```json
{
  "event": "audit.completed",
  "timestamp": "2026-04-15T14:30:00Z",
  "data": {
    "audit_id": "aud_7kQ2xR9pLm",
    "project": "Acme Hotels Q1",
    "network_ssid": "Acme-Guest",
    "findings_count": 4,
    "critical_count": 2,
    "high_count": 1,
    "medium_count": 1,
    "agent": "agent-lobby-01"
  }
}
```

### 4.5 Database Schema (Core Tables)

```sql
-- Teams
CREATE TABLE teams (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    plan        TEXT NOT NULL DEFAULT 'enterprise',  -- 'pro', 'enterprise'
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    settings    JSONB NOT NULL DEFAULT '{}'
);

-- Users
CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    team_id     UUID REFERENCES teams(id),
    role        TEXT NOT NULL DEFAULT 'pentester',  -- 'owner', 'admin', 'pentester', 'viewer'
    sso_sub     TEXT,  -- OIDC subject identifier
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login  TIMESTAMPTZ
);

-- Projects
CREATE TABLE projects (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id     UUID NOT NULL REFERENCES teams(id),
    name        TEXT NOT NULL,
    description TEXT,
    scope       JSONB,  -- { "networks": ["Acme-Guest", "Acme-Corp"], "sites": ["NYC", "LAX"] }
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived    BOOLEAN NOT NULL DEFAULT false
);

-- Audits
CREATE TABLE audits (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID REFERENCES projects(id),
    user_id     UUID REFERENCES users(id),
    agent_id    UUID REFERENCES agents(id),
    ssid        TEXT,
    bssid       TEXT,
    gateway     TEXT,
    portal_type TEXT,
    portal_vendor TEXT,
    auth_methods TEXT[],
    started_at  TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    status      TEXT NOT NULL DEFAULT 'running',  -- 'running', 'completed', 'failed'
    probe_data  JSONB NOT NULL DEFAULT '{}',
    bypass_data JSONB NOT NULL DEFAULT '[]',
    raw_output  TEXT,
    metadata    JSONB NOT NULL DEFAULT '{}'
);

-- Findings (denormalized from audit for fast querying)
CREATE TABLE findings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id    UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    technique   TEXT NOT NULL,
    severity    TEXT NOT NULL,  -- 'critical', 'high', 'medium', 'low', 'info'
    impact      TEXT NOT NULL,
    details     TEXT,
    remediation TEXT,
    compliance  JSONB,  -- [{"framework": "PCI-DSS", "control": "11.1", "status": "fail"}]
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_audit ON findings(audit_id);

-- Agents
CREATE TABLE agents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id     UUID NOT NULL REFERENCES teams(id),
    name        TEXT NOT NULL,
    token_hash  BYTEA NOT NULL,  -- bcrypt hash of agent token
    last_seen   TIMESTAMPTZ,
    status      TEXT NOT NULL DEFAULT 'offline',  -- 'online', 'running', 'idle', 'offline'
    metadata    JSONB NOT NULL DEFAULT '{}',  -- { "os": "darwin", "arch": "arm64", "version": "1.2.0" }
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Scheduled Scans
CREATE TABLE scan_schedules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id),
    agent_id    UUID NOT NULL REFERENCES agents(id),
    cron_expr   TEXT NOT NULL,  -- "0 2 1 */3 *" = quarterly at 2am on the 1st
    config      JSONB NOT NULL DEFAULT '{}',  -- audit options (interface, stealth, etc.)
    enabled     BOOLEAN NOT NULL DEFAULT true,
    last_run    TIMESTAMPTZ,
    next_run    TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Reports
CREATE TABLE reports (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id    UUID NOT NULL REFERENCES audits(id),
    template    TEXT NOT NULL DEFAULT 'technical',
    format      TEXT NOT NULL DEFAULT 'pdf',
    status      TEXT NOT NULL DEFAULT 'pending',  -- 'pending', 'generating', 'ready', 'failed'
    s3_key      TEXT,  -- S3 object key for the generated PDF
    size_bytes  BIGINT,
    branding    JSONB,  -- custom logo URL, colors, company name
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ready_at    TIMESTAMPTZ
);

-- Audit Log (immutable)
CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    team_id     UUID NOT NULL REFERENCES teams(id),
    user_id     UUID REFERENCES users(id),
    action      TEXT NOT NULL,  -- 'audit.run', 'report.generate', 'member.invite', etc.
    resource    TEXT,
    resource_id UUID,
    ip_address  INET,
    user_agent  TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_log_team ON audit_log(team_id, created_at DESC);

-- Webhooks
CREATE TABLE webhooks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id     UUID NOT NULL REFERENCES teams(id),
    url         TEXT NOT NULL,
    secret      TEXT NOT NULL,  -- HMAC signing secret
    events      TEXT[] NOT NULL,  -- ['audit.completed', 'finding.critical']
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 4.6 Security Architecture

| Concern | Implementation |
|---------|---------------|
| **Transport** | TLS 1.3 everywhere. Agent-server uses mTLS (client certificates) |
| **Authentication** | OIDC/SAML for SSO. JWT access tokens (1-hour expiry). Refresh tokens (30-day, single-use rotation) |
| **Authorization** | RBAC with 4 roles. Permission checks in middleware. Row-level security in PostgreSQL for multi-tenant isolation |
| **Secrets** | Credential vault uses AES-256-GCM with per-user encryption keys derived from OIDC token. Server never sees plaintext credentials |
| **Agent tokens** | Stored as bcrypt hashes. Tokens are 256-bit random, base64url-encoded. Rotatable without agent restart |
| **Audit log** | Append-only table. No UPDATE/DELETE permissions for application user. Separate read-only role for compliance queries |
| **Report storage** | S3 objects encrypted with SSE-S3 (or SSE-KMS for FIPS). Pre-signed URLs with 15-minute expiry for downloads |
| **Data residency** | Self-hosted option for organizations that cannot use SaaS. All data stays on-premises |

---

## 5. PDF Report Generator

This is the #1 enterprise feature. Pentesters need client-facing reports; this is what they charge for.

### 5.1 Report Structure

#### Executive Brief (2 pages)

For C-level executives and non-technical stakeholders.

```
Page 1:
  +------------------------------------------------------+
  |  [Company Logo]           WiFi Security Assessment    |
  |                           [Client Name]               |
  |                           [Date]                      |
  |                                                       |
  |  OVERALL RISK SCORE:  [  CRITICAL  ]                  |
  |                       (gauge graphic, red)            |
  |                                                       |
  |  Key Findings:                                        |
  |  - 4 critical vulnerabilities found                   |
  |  - Guest WiFi can be bypassed in under 30 seconds     |
  |  - Any device on the network can be impersonated      |
  |  - Captive portal has default admin credentials       |
  |                                                       |
  |  Recommendation: Immediate remediation required.      |
  |  Guest WiFi currently provides no meaningful          |
  |  access control.                                      |
  +------------------------------------------------------+

Page 2:
  +------------------------------------------------------+
  |  Findings Summary                                     |
  |                                                       |
  |  # | Finding           | Severity | Status            |
  |  1 | IPv6 bypass       | CRITICAL | Exploitable       |
  |  2 | MAC clone         | CRITICAL | Exploitable       |
  |  3 | Default creds     | CRITICAL | Exploitable       |
  |  4 | DNS tunnel        | HIGH     | Exploitable       |
  |                                                       |
  |  Scope: SSID "Acme-Guest", 192.168.1.0/24            |
  |  Methodology: nowifi v1.0 automated assessment        |
  |  Assessor: [Pentester Name]                           |
  |  Contact: [Pentest Firm Contact Info]                 |
  +------------------------------------------------------+
```

#### Technical Assessment (10-20 pages)

For security teams and IT administrators. The standard deliverable.

**Section 1: Cover Page**
- Client logo (if provided) and assessor company branding
- Report title, date, classification (Confidential)
- Version, assessor name, reviewer name

**Section 2: Executive Summary** (1 page)
- 3-5 sentences summarizing the overall security posture
- Risk rating (Critical / High / Medium / Low / Informational)
- Number of findings by severity
- Top recommendation

**Section 3: Scope & Methodology** (1 page)
- Target network(s): SSID, BSSID, IP range
- Assessment type: automated, using nowifi v1.x
- Date/time window of the assessment
- Techniques attempted (all 27, or a subset if scoped)
- Limitations and exclusions
- Standards referenced (PCI-DSS 11.1, NIST 800-53 AC-18, etc.)

**Section 4: Network Reconnaissance** (2-3 pages)
- Portal detection results (type, vendor, authentication methods)
- Protocol leak enumeration table (DNS, ICMP, IPv6, HTTPS, QUIC, NTP, DoH)
- Open ports table
- Whitelisted domains discovered
- Network topology diagram (auto-generated from probe results):

```
  Internet
      |
  [Firewall/Portal: Cisco Meraki MR46]
      |
  [Gateway: 192.168.1.1]
      |
  +---------+---------+---------+
  |         |         |         |
 Client A  Client B  Client C  nowifi Agent
 (iPhone)  (MacBook) (Windows) (assessor)
```

**Section 5: Findings** (1-2 pages per finding)

Each finding follows a consistent structure:

```
+------------------------------------------------------------------+
| Finding #1: IPv6 Bypass                                          |
+------------------------------------------------------------------+
| Severity: CRITICAL    | CVSS: 9.1    | Status: Exploitable       |
+------------------------------------------------------------------+
|                                                                  |
| Description:                                                     |
| The captive portal only applies access control rules to IPv4     |
| traffic. IPv6 traffic passes through the portal's firewall       |
| unfiltered, allowing any pre-authenticated client to access      |
| the internet via IPv6 without completing portal authentication.  |
|                                                                  |
| Impact:                                                          |
| An attacker can bypass the captive portal entirely using IPv6,   |
| gaining unrestricted internet access without authentication.     |
| This renders the captive portal ineffective for any device       |
| with IPv6 connectivity.                                          |
|                                                                  |
| Evidence:                                                        |
| - IPv6 probe to 2606:4700:4700::1111 succeeded (Cloudflare)     |
| - IPv6 probe to 2001:4860:4860::8888 succeeded (Google)         |
| - HTTP GET via IPv6 returned 200 OK with valid content           |
| - Timestamp: 2026-04-15T14:32:17Z                               |
|                                                                  |
| Affected Systems:                                                |
| - SSID: Acme-Guest                                               |
| - Portal: Cisco Meraki (firmware MR 30.x)                       |
| - Gateway: 192.168.1.1                                          |
|                                                                  |
| Remediation:                                                     |
| 1. Apply captive portal ACLs to both IPv4 AND IPv6 traffic      |
| 2. If IPv6 is not required for guest network, disable it on     |
|    the guest VLAN                                                |
| 3. Configure the Meraki dashboard: Wireless > Firewall &        |
|    traffic shaping > Layer 3 firewall rules > Add IPv6 rule     |
|                                                                  |
| Compliance:                                                      |
| - PCI-DSS 11.1: FAIL (unauthorized access without credential)   |
| - NIST 800-53 AC-18: FAIL (wireless access not controlled)      |
| - ISO 27001 A.13.1.1: FAIL (network controls bypassed)          |
+------------------------------------------------------------------+
```

**Section 6: Compliance Mapping** (1-2 pages)
- Table mapping each finding to compliance framework controls
- Pass/fail status for each control
- Remediation priority based on compliance impact

**Section 7: Risk Summary Matrix** (1 page)
- Findings plotted on Likelihood vs. Impact matrix
- Overall risk rating with justification

**Section 8: Remediation Roadmap** (1 page)
- Prioritized list of remediations (critical first)
- Estimated effort for each (Low / Medium / High)
- Suggested timeline

**Section 9: Appendix**
- A: Raw probe data (JSON)
- B: Tool versions and configuration
- C: Full technique list with pass/fail status
- D: Glossary of terms

#### Full Audit Report (Comprehensive)

Everything in Technical Assessment, plus:
- Detailed packet captures (relevant excerpts)
- Step-by-step reproduction instructions for each finding
- Network diagrams with all discovered devices
- Historical comparison (if previous audits exist)
- Risk trend analysis over time

### 5.2 Implementation

**PDF generation pipeline:**

```
Audit JSON data
      |
      v
Go HTML template engine (html/template)
      |
      v
Rendered HTML + CSS (print-optimized)
      |
      v
Headless Chrome (via chromedp) or wkhtmltopdf
      |
      v
PDF file -> S3 storage
      |
      v
Pre-signed download URL (15-min expiry)
```

**Why HTML-to-PDF (not a Go PDF library):**
- HTML/CSS is the most flexible layout engine available
- Print-optimized CSS (`@media print`, `@page`) handles pagination, headers, footers
- Charts and diagrams render correctly (SVG, Canvas)
- Templates are easy to customize (HTML + CSS, not Go code)
- wkhtmltopdf is battle-tested; chromedp gives pixel-perfect rendering

**Template customization (Enterprise):**
- Upload custom HTML/CSS template
- Variables injected via Go template engine: `{{.Portal.SSID}}`, `{{range .Findings}}`, etc.
- Custom logo: uploaded as PNG/SVG, stored in S3, injected into template
- Color scheme: CSS variables for primary/secondary/accent colors
- Sandboxed: templates cannot execute arbitrary code (Go's `html/template` auto-escapes)

### 5.3 Network Topology Diagram

Auto-generated from probe and bypass results using Go's `image` package or SVG generation.

**Data sources:**
- Gateway IP and MAC (from detect phase)
- Portal vendor and type (from fingerprinting)
- ARP table entries (from MAC clone probe)
- Agent's own position in the network

**Output:** SVG diagram embedded in the PDF report, showing the network topology with the portal, gateway, discovered clients, and the assessor's position.

---

## 6. Compliance Templates

### 6.1 PCI-DSS 4.0 -- Requirement 11.1

> "Implement processes to test for the presence of wireless access points (802.11), and detect and identify all authorized and unauthorized wireless access points on a quarterly basis."

**Sub-requirements mapped to nowifi:**

| PCI-DSS Control | Requirement | nowifi Coverage | Auto-Evidence |
|-----------------|-------------|-----------------|---------------|
| 11.1.1 | Processes for detecting unauthorized wireless APs | `nowifi crack --scan-only` scans all nearby APs, identifies authorized vs unknown | Scan results JSON with SSID/BSSID/channel/security for all detected APs |
| 11.1.2 | Maintain inventory of authorized wireless APs | Enterprise dashboard tracks known networks per project scope | Project scope definition + audit history |
| 11.2.1 | Quarterly internal vulnerability scans | Scheduled quarterly `nowifi diagnose` on all guest networks | Scheduled scan results with findings and remediation |
| 11.3.1 | External penetration testing annually | Full `nowifi` audit with bypass attempts | Full audit report with all 27 techniques attempted |
| 1.2.3 | Network segmentation controls | nowifi probes test whether pre-auth clients can reach internal resources | Probe results showing which protocols/ports pass through portal |

**Compliance evidence pack (auto-generated):**
```
PCI-DSS-11.1-Evidence-Pack-Q1-2026/
  01-scan-results.json          # All detected APs with metadata
  02-authorized-ap-inventory.csv # Known APs from project scope
  03-unauthorized-ap-report.pdf  # Any APs not in inventory
  04-vulnerability-findings.pdf  # Full assessment report
  05-remediation-tracking.pdf    # Comparison with previous quarter
  06-assessor-attestation.pdf    # Signed by pentester
```

### 6.2 SOC 2 -- CC6.1 (Logical and Physical Access Controls)

> "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events."

| SOC 2 Control | Requirement | nowifi Coverage |
|---------------|-------------|-----------------|
| CC6.1 | Logical access controls over network | Portal detection + bypass testing validates access controls work |
| CC6.2 | Prior to credential issuance, registered and authorized | MAC clone and credential replay tests show if unauthorized access is possible |
| CC6.3 | Prior to system access, identity is validated | Portal auth method detection and bypass testing |
| CC6.6 | Boundaries to protect against threats | Probe results show which protocols pass through portal firewall |

### 6.3 ISO 27001:2022 -- Annex A

| ISO 27001 Control | Requirement | nowifi Coverage |
|-------------------|-------------|-----------------|
| A.8.20 | Network security | Full portal security assessment |
| A.8.21 | Security of network services | Portal vendor identification, auth method validation |
| A.8.22 | Segregation of networks | Probe testing validates pre-auth isolation |
| A.8.23 | Web filtering | Portal whitelist domain discovery |
| A.5.15 | Access control | Portal bypass testing validates access controls |

### 6.4 NIST 800-53 Rev. 5

| NIST Control | Requirement | nowifi Coverage |
|-------------|-------------|-----------------|
| AC-18 | Wireless access | Full wireless security assessment |
| AC-18(1) | Authentication and encryption | Portal auth validation, WPA security assessment |
| AC-18(3) | Disable wireless when not needed | AP inventory vs. authorized list |
| AC-18(4) | Restrict configurations | Portal default credential testing |
| AC-18(5) | Antennas and transmission power | Not covered (physical assessment) |
| IA-11 | Re-authentication | Session persistence and timeout testing |
| SC-7 | Boundary protection | Protocol leak enumeration |
| SC-40 | Wireless link protection | WPA encryption assessment (crack module) |
| SI-4 | System monitoring | Portal IDS/behavioral detection assessment (stealth probes) |

### 6.5 Compliance Mapping Matrix

Each nowifi technique maps to one or more compliance controls. The report engine auto-populates this:

| Technique | PCI-DSS | SOC 2 | ISO 27001 | NIST 800-53 |
|-----------|---------|-------|-----------|-------------|
| IPv6 bypass | 1.2.3, 11.3.1 | CC6.6 | A.8.20 | SC-7, AC-18 |
| HTTPS tunnel | 1.2.3, 11.3.1 | CC6.6 | A.8.20 | SC-7 |
| CNA spoof | 11.3.1 | CC6.3 | A.5.15 | AC-18, IA-11 |
| MAC clone | 11.3.1 | CC6.1, CC6.2 | A.5.15 | AC-18(1) |
| DNS tunnel | 1.2.3 | CC6.6 | A.8.20, A.8.22 | SC-7 |
| Default creds | 2.1 | CC6.1 | A.8.5 | AC-18(4) |
| Session replay | 11.3.1 | CC6.3 | A.5.15 | IA-11 |
| PMKID crack | 11.3.1, 4.2.1 | CC6.1 | A.8.24 | SC-40 |
| WPS attack | 11.3.1, 2.1 | CC6.1 | A.8.24 | SC-40, AC-18(1) |

---

## 7. Monetization Strategy

### 7.1 Pricing Summary

| Tier | Monthly | Annual | Target Segment |
|------|---------|--------|----------------|
| **Community** | Free | Free | Individual hackers, students, CTF players |
| **Pro** | $29/user | $290/user | Freelance pentesters, consultants |
| **Enterprise** | $149/seat (min 5) | $1,490/seat | Pentest firms, corporate security teams |
| **MSSP** | Custom (from $2,500/mo) | Custom | Managed security providers |

### 7.2 Revenue Model

**Assumptions (conservative):**

| Metric | Year 1 | Year 2 | Year 3 |
|--------|--------|--------|--------|
| GitHub stars | 5,000 | 15,000 | 35,000 |
| Monthly active users (Community) | 2,000 | 8,000 | 25,000 |
| Pro subscribers | 100 | 400 | 1,200 |
| Enterprise teams | 5 | 25 | 80 |
| Avg Enterprise seats | 8 | 10 | 12 |
| MSSP customers | 0 | 3 | 10 |

**Revenue projection:**

| Revenue Stream | Year 1 | Year 2 | Year 3 |
|----------------|--------|--------|--------|
| Pro ($290/yr) | $29,000 | $116,000 | $348,000 |
| Enterprise ($1,490/seat/yr) | $59,600 | $372,500 | $1,430,400 |
| MSSP ($30,000/yr avg) | $0 | $90,000 | $300,000 |
| Support & services | $0 | $50,000 | $150,000 |
| **Total ARR** | **$88,600** | **$628,500** | **$2,228,400** |

**Key conversion metrics:**

| Metric | Target | Benchmark |
|--------|--------|-----------|
| Community -> Pro conversion | 5% | Burp Suite: ~5-8% |
| Pro -> Enterprise upgrade | 10% | Industry: 8-15% |
| Annual churn (Pro) | 25% | SaaS average: 20-30% |
| Annual churn (Enterprise) | 10% | SaaS average: 5-15% |
| Net Revenue Retention (Enterprise) | 120% | Seat expansion drives NRR > 100% |

### 7.3 Free Trial Strategy

| Tier | Trial | Conversion Tactics |
|------|-------|-------------------|
| **Pro** | 14-day free trial, no credit card | After trial: "Your 3 audit reports will expire in 7 days. Subscribe to keep them." |
| **Enterprise** | 30-day POC, full features, 10 seats | Dedicated onboarding call. Custom demo with their network data. |

**Pro trial -> paid conversion flow:**

```
Day 0:  User runs `nowifi` for the first time
        -> Post-audit prompt: "Generate a professional PDF report? Start free Pro trial"
        -> `nowifi report --pdf` triggers trial signup (email only, no CC)

Day 1:  Trial activated. PDF reports, audit history, credential manager unlocked
Day 7:  Email: "You've generated 3 reports this week. Here's what's in your audit history."
Day 12: Email: "Your trial expires in 2 days. Reports generated during trial stay available."
Day 14: Trial expires. PDF generation disabled. Existing PDFs downloadable for 7 more days.
Day 21: Final email: "Your reports expire tomorrow. Subscribe to keep them: $29/mo or $290/yr."
```

### 7.4 Sales Channels

| Channel | Tier | Motion | CAC Target |
|---------|------|--------|------------|
| Self-serve (website) | Pro | Credit card checkout | <$50 |
| Product-led growth | Pro -> Enterprise | In-app upgrade prompts | <$200 |
| Inside sales | Enterprise | Demo call -> POC -> contract | <$2,000 |
| Channel partners | Enterprise / MSSP | Reseller agreements with pentest training companies | 30% rev share |
| Conferences | All | Booth + talk -> leads -> pipeline | <$5,000/deal |

---

## 8. Go-to-Market

### 8.1 Phase 0: Pre-Launch (Month -2 to 0)

**Build in public. Create anticipation.**

- [ ] Open-source the Go rewrite on GitHub with clean README + demo GIF
- [ ] Write announcement blog post: "nowifi: 27 WiFi bypass techniques in a single binary"
- [ ] Record 60-second demo video: hotel WiFi bypass from stuck to browsing
- [ ] Prepare Hacker News Show HN post
- [ ] Prepare Reddit posts: r/netsec, r/hacking, r/pentesting, r/golang
- [ ] Create Twitter/X thread with GIF demos of each technique category
- [ ] Set up landing page: nowifi.dev (features, pricing, waitlist for Enterprise)

### 8.2 Phase 1: Open Source Launch (Month 1-2)

**Goal: 5,000 GitHub stars, 2,000 MAU**

**Launch day (coordinated across channels):**

| Channel | Content | Target |
|---------|---------|--------|
| Hacker News | "Show HN: nowifi -- 27 automated WiFi bypass techniques in a single binary" | Top 10 front page |
| Reddit r/netsec | Technical deep-dive on portal bypass techniques | Top post of the week |
| Reddit r/golang | "We rewrote our Python security tool in Go -- here's what changed" | Community engagement |
| Twitter/X | Thread: "Your hotel WiFi captive portal has at least 5 bypasses. Here's how I test all 27 automatically" with GIFs | Viral security community |
| LinkedIn | Professional angle: "How to audit your guest WiFi in 30 seconds (and why your captive portal is probably insecure)" | Enterprise audience |

**Ongoing content (month 1-6):**

| Content Type | Frequency | Examples |
|--------------|-----------|---------|
| Blog posts | 2/month | "How to audit hotel WiFi in 30 seconds", "Why captive portals are security theater", "The 5 most common captive portal vulnerabilities" |
| YouTube demos | 1/month | "Bypassing airport WiFi with nowifi", "WPA cracking: PMKID vs handshake" |
| Technical writeups | 1/month | "Building a DNS tunnel detector that can't be evaded", "MAC cloning in 2026: what works and what doesn't" |

### 8.3 Phase 2: Pro Launch (Month 3-4)

**Goal: 100 Pro subscribers**

- [ ] Launch nowifi Pro with PDF report generator
- [ ] Blog post: "Professional WiFi pentest reports in one command"
- [ ] Add `nowifi report --pdf` command with trial prompt in Community edition
- [ ] Partner with pentest training YouTubers for reviews
- [ ] Submit to pentest tool lists and directories

### 8.4 Phase 3: Enterprise Launch (Month 5-8)

**Goal: 5 Enterprise customers**

- [ ] Launch nowifi Enterprise with server + dashboard
- [ ] Case study with first beta customer
- [ ] Launch compliance templates (PCI-DSS 11.1)
- [ ] Attend BSides/regional security conferences (booth + lightning talk)
- [ ] Build outbound sales pipeline targeting pentest firms

### 8.5 Phase 4: Scale (Month 9-18)

**Goal: 25 Enterprise customers, 3 MSSPs**

- [ ] DEF CON / Black Hat talk submission (demo village or main track)
- [ ] Partnership with SANS for tool inclusion in SEC560 (WiFi pentesting course)
- [ ] Partnership with Offensive Security for inclusion in OSCP/OWSE lab environments
- [ ] Partnership with Hack The Box for WiFi pentest lab integration
- [ ] MSSP program launch with multi-tenant dashboard
- [ ] SOC 2 Type II certification for nowifi SaaS platform
- [ ] FedRAMP pursuit for US government sales (if traction warrants)

### 8.6 Community Building

| Initiative | Purpose |
|------------|---------|
| GitHub Discussions | Support, feature requests, technique ideas |
| Discord server | Real-time community, technique sharing, beta testing |
| Technique bounty program | $50-500 for community-contributed bypass techniques merged into nowifi |
| "WiFi Hall of Shame" blog series | Document the worst captive portals found (anonymized), drives virality |
| Annual "State of WiFi Security" report | Data-driven report from anonymized Community scan data (opt-in), establishes authority |

---

## 9. Implementation Roadmap

### Phase 1: Pro Foundation (Month 1-2)

**Deliverables:** PDF reports, audit history, Pro licensing

| Week | Deliverable | Details |
|------|-------------|---------|
| 1-2 | PDF report engine | HTML template + chromedp/wkhtmltopdf pipeline. Three templates: Executive Brief, Technical Assessment, Full Audit |
| 3 | Report branding | Custom logo, company name, colors in PDF |
| 4 | Local audit history | SQLite database at `~/.nowifi/audits.db`. Full-text search. `nowifi history`, `nowifi history search "hotel"` |
| 5 | Audit comparison | `nowifi diff <audit-id-1> <audit-id-2>` shows remediation progress |
| 6 | Credential manager | Encrypted vault at `~/.nowifi/vault.enc`. AES-256-GCM with passphrase-derived key. `nowifi vault add`, `nowifi vault list` |
| 7 | Licensing system | Machine-fingerprint license key validation. Offline-capable (license checked once per 30 days) |
| 8 | Pro launch | Website, Stripe integration, trial flow, documentation |

**Engineering effort:** 1 engineer, 8 weeks. All Go, no new dependencies beyond PDF renderer.

### Phase 2: Enterprise Server (Month 3-4)

**Deliverables:** Server, dashboard, agent mode, team management

| Week | Deliverable | Details |
|------|-------------|---------|
| 9-10 | Server skeleton | Go HTTP server, PostgreSQL schema, Redis job queue, Docker Compose |
| 11-12 | Agent mode | `nowifi agent` subcommand. Registration, heartbeat, job polling, result submission |
| 13-14 | Web dashboard | htmx + Alpine.js. Audit list, audit detail, agent status, real-time SSE updates |
| 15 | Team management | User invite, RBAC (Owner/Admin/Pentester/Viewer), team settings |
| 16 | Projects | Create projects, assign scopes, organize audits by project |

**Engineering effort:** 2 engineers, 8 weeks.

### Phase 3: Compliance & Automation (Month 5-6)

**Deliverables:** Compliance templates, scheduled scans, webhooks

| Week | Deliverable | Details |
|------|-------------|---------|
| 17-18 | Compliance templates | PCI-DSS 11.1, SOC 2 CC6.1, ISO 27001 A.13.1. Auto-map findings to controls |
| 19-20 | Evidence packs | Auto-generated compliance evidence ZIP for auditors |
| 21-22 | Scheduled scans | Cron-based recurring assessments. Agent polls for scheduled jobs |
| 23-24 | Webhooks | Webhook configuration, delivery, retry logic. SIEM integration docs |

**Engineering effort:** 2 engineers, 8 weeks.

### Phase 4: Scale Features (Month 7-12)

**Deliverables:** SSO, API, MSSP features, advanced reporting

| Month | Deliverable | Details |
|-------|-------------|---------|
| 7 | SSO (SAML/OIDC) | Okta, Azure AD, Google Workspace integration |
| 8 | Public API + API keys | Documented REST API. API key management in dashboard |
| 9 | Advanced reporting | Risk trend charts over time, network topology auto-diagram |
| 10 | MSSP multi-tenancy | Tenant isolation, per-client branding, MSSP admin dashboard |
| 11 | Kubernetes Helm chart | Production-grade Helm chart for large Enterprise deployments |
| 12 | Audit analytics | Aggregate statistics across all audits. "What % of guest WiFi networks are vulnerable to IPv6 bypass?" |

**Engineering effort:** 3 engineers, 6 months.

### Milestone Summary

```
Month:  1   2   3   4   5   6   7   8   9  10  11  12
        |---|---|---|---|---|---|---|---|---|---|---|---|
Phase 1: [PDF reports + Pro launch    ]
Phase 2:         [Server + dashboard + Enterprise  ]
Phase 3:                     [Compliance + automation  ]
Phase 4:                                 [SSO, API, MSSP, analytics ]
Revenue: |---Pro revenue starts--------|---Enterprise revenue-------->
Stars:   5K     10K     15K     20K     25K     30K     35K
```

---

## 10. Competitive Moat

### 10.1 Why Enterprises Choose nowifi Over Alternatives

**1. Technique breadth -- no other tool covers 27 automated techniques**

The closest competitor (wifite2) automates 4 WPA cracking methods. aircrack-ng requires manual orchestration. WiFi Pineapple requires hardware. No tool automates captive portal bypass at all -- pentesters do this manually or skip it entirely. nowifi is the only tool that treats captive portal security as a first-class assessment category.

**2. Single binary with zero dependencies**

Pentest tools are notorious for dependency hell (Metasploit requires Ruby + PostgreSQL + Redis + multiple gems). nowifi is a single static Go binary. Download, run, done. This matters for:
- Field deployment (hotel WiFi with no internet for `pip install`)
- Air-gapped environments (government, defense)
- Ephemeral environments (live USBs, Kali containers)
- Large fleet deployment (100 agents across 100 sites)

**3. Open-source core = trust + auditability**

Security teams will not run closed-source tools that modify network settings, spoof MAC addresses, and create tunnels. Open source is not optional in offensive security -- it is a requirement. The free tier is not a marketing gimmick; it is the product's trust layer.

**4. Active bypass, not passive detection**

Most WiFi security tools detect problems. nowifi exploits them. This is the difference between "we found a potential IPv6 leak" and "we bypassed your captive portal in 2 seconds via IPv6 and accessed the internet without authentication." Enterprise customers need proof of exploitability for their compliance evidence.

**5. Report quality directly translates to revenue for pentest firms**

A pentest firm billing $200/hr that saves 4 hours per engagement on report writing saves $800 per engagement. At 10 engagements/month, that is $96,000/yr in recovered billable time. The $8,940/yr Enterprise license pays for itself in the first month.

### 10.2 Defensibility Over Time

| Moat Layer | Description | Time to Replicate |
|------------|-------------|-------------------|
| **Technique library** | 27 techniques with real-world testing across hundreds of portal types | 12-18 months |
| **Vendor fingerprint DB** | Signatures for 10+ portal vendors, growing with community contributions | 6-12 months |
| **Community** | Open-source contributors, technique researchers, beta testers | 18-24 months |
| **Compliance templates** | Pre-built mappings to PCI-DSS, SOC 2, ISO 27001, NIST validated by real auditors | 6-12 months |
| **Enterprise integrations** | SIEM webhooks, SSO, API, agent fleet management | 12+ months |
| **Data network effect** | Aggregated anonymized scan data improves technique effectiveness and detection rates | 24+ months |
| **Brand** | "nowifi" becomes synonymous with WiFi security assessment (like "Burp" = web pentest) | 36+ months |

### 10.3 Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Large competitor adds WiFi module (Rapid7, Pentera) | Medium | High | Move fast, establish brand, community lock-in. Their WiFi module will always be secondary to their core product |
| Captive portals become unbypassable | Low | High | Techniques 24-27 (evasion design) stay ahead. MACsec/802.1X adoption is <5% and growing slowly |
| Open-source fork competition | Medium | Medium | Enterprise features are proprietary. Community goodwill through responsive maintenance. Fork without enterprise layer has no business model |
| Regulatory risk (tool misuse) | Medium | Medium | Clear ToS, responsible disclosure guidance, enterprise audit logging, "diagnosis mode" for non-destructive assessment |
| Low conversion rate (<1%) | Medium | High | A/B test trial flow, add more Pro-only features (e.g., technique auto-selection based on ML), reduce friction |

---

## Appendix A: Comparable Pricing Data Points

| Tool | Price Point | Model | Notes |
|------|------------|-------|-------|
| Burp Suite Pro | $449/yr/user | Annual license | Web pentest. Individual pentester standard |
| Burp Suite Enterprise | $8,395/yr/5 agents | Annual license | CI/CD integration. Enterprise standard |
| Metasploit Pro | $15,000/yr/user | Annual license | Network pentest. Full-featured. Rapid7 |
| Nessus Professional | $4,090/yr/scanner | Annual license | Vulnerability scanning. Tenable |
| Cobalt Strike | $5,900/yr/user | Annual license | Red team C2. Fortra |
| Pentera | $50,000-200,000/yr | Annual contract | Automated pentesting. Enterprise only |
| Acunetix | $4,495/yr | Annual license | Web vulnerability scanner |
| Nmap (Zenmap) | Free | Open source | Network scanning. No enterprise tier |
| Wireshark | Free | Open source | Packet capture. No enterprise tier |
| WiFi Pineapple Mark VII | $120 (hardware) | One-time purchase | WiFi auditing hardware. Hak5 |
| Aircrack-ng | Free | Open source | WPA cracking. No enterprise tier |

**nowifi pricing rationale:** Pro at $29/mo ($348/yr) is intentionally below Burp Suite Pro ($449/yr) to reduce friction. Enterprise at $149/seat/mo ($1,788/yr) is significantly below Metasploit Pro ($15,000/yr) and an order of magnitude below Pentera, making it an easy budget approval.

---

## Appendix B: Technical Dependencies (Enterprise Server)

| Dependency | Purpose | License |
|------------|---------|---------|
| Go 1.26+ | Server + agent runtime | BSD-3 |
| PostgreSQL 16 | Primary datastore | PostgreSQL License |
| Redis 7 | Job queue, caching | BSD-3 |
| MinIO / S3 | Object storage (reports) | AGPL-3 / Commercial |
| `chi` router | HTTP routing | MIT |
| `golang-jwt/jwt` | JWT token handling | MIT |
| `coreos/go-oidc` | OIDC authentication | Apache-2.0 |
| `hibiken/asynq` | Async job processing | MIT |
| `golang-migrate/migrate` | Database migrations | MIT |
| `chromedp` | Headless Chrome for PDF | MIT |
| htmx | Frontend dynamic updates | BSD-2 |
| Alpine.js | Frontend reactivity | MIT |

---

## Appendix C: Success Criteria by Phase

| Phase | Timeframe | Success Metric | Target |
|-------|-----------|---------------|--------|
| OS Launch | Month 1-2 | GitHub stars | 5,000 |
| OS Launch | Month 1-2 | Monthly active users | 2,000 |
| Pro Launch | Month 3-4 | Pro subscribers | 100 |
| Pro Launch | Month 3-4 | Trial-to-paid conversion | >5% |
| Enterprise | Month 5-8 | Enterprise customers | 5 |
| Enterprise | Month 5-8 | ARR | $100,000 |
| Scale | Month 9-12 | Enterprise customers | 25 |
| Scale | Month 9-12 | ARR | $600,000 |
| Growth | Year 2 | Enterprise customers | 80 |
| Growth | Year 2 | Total ARR | $2,200,000 |

---

*This document is a living artifact. Updated as market conditions, customer feedback, and technical feasibility evolve.*

*Generated for nowifi v0.1.0 -- the 27-technique WiFi security assessment tool.*
