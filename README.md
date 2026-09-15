# PhishGuard Enterprise Browser Security Hub & Chrome Extension

An enterprise-grade browser security monitoring and threat interception system connecting multiple Chrome Extension installations to a central security server, real-time deterministic decision engine, and administrative SOC console.

---

## 1. System Architecture

```
┌────────────────────────────────────────────────────────┐
│               Chrome Extension Fleet                   │
│   (Workstations, Laptops, Remote Endpoints)            │
│                                                        │
│  • Service Worker (background.js, Manifest V3)         │
│  • Real URL Interception (chrome.webNavigation)        │
│  • Content In-Page Scanner (content.js)                │
│  • Quishing / QR Detector (qr_scanner.js)              │
│  • Email Deceptive Link Shield (gmail_content.js)      │
│  • Threat Interception Screen (warning.html)           │
└───────────────────────────┬────────────────────────────┘
                            │ REST / SSE Heartbeats & Events
                            ▼
┌────────────────────────────────────────────────────────┐
│             Central Enterprise Server                  │
│                    (Node.js / Express)                 │
│                                                        │
│  • Client Enrollment & Registration (/api/clients)     │
│  • Central Security Decision Engine (/api/security)    │
│  • Deterministic Rules CRUD Engine (/api/rules)        │
│  • Real-Time Alert & Incident Generator (/api/alerts)  │
│  • Real-time SSE Broadcast Hub (/api/dashboard)        │
│  • Admin Auth & Audit Trails (/api/auth, /audit-logs)  │
└───────────────────────────┬────────────────────────────┘
                            │ Direct SQL Transactions
                            ▼
┌────────────────────────────────────────────────────────┐
│   Persistent Database - PostgreSQL in production       │
│   (Neon / Supabase / Netlify DB); local SQLite file     │
│   only for standalone/offline development               │
│                                                        │
│  • clients          • rules         • url_events       │
│  • alerts           • incidents     • audit_logs       │
│  • users            • system_config                    │
└────────────────────────────────────────────────────────┘
```

---

## 2. Chrome Extension Installation Guide

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** in the top right corner.
3. Click **Load unpacked** in the top left corner.
4. Select the PhishGuard project root directory.
5. Click the PhishGuard puzzle/shield icon in the browser toolbar.
6. Verify your generated **Client ID** (e.g., `CLIENT-7KX8A2`) and confirm connection to the Central Server URL.

---

## 3. Core Enterprise Features

### A. Centralized Client Fleet Management
- **Automatic Enrollment**: Extension instances generate a unique persistent client identifier on first run and enroll with the central database.
- **Real-Time Heartbeats**: Periodic background signals report online/offline status. Systems idle longer than the configured timeout automatically transition to `OFFLINE`.
- **System Telemetry**: Tracks hostname, OS, browser version, extension build, IP address, and total inspected navigations.

### B. Real-Time URL Monitoring & Interception
- Top-level frame navigations trigger an evaluation against the central policy rules and threat heuristics.
- If a site is determined to be a **BLOCK** target, the extension halts navigation and redirects the active tab to `warning.html`.
- If a site is flagged with a **WARNING**, warnings are logged, badges update, and alerts are dispatched to the SOC console.

### C. Deterministic Administrative Rules Engine
- Rules support `ALLOW`, `WARNING`, and `BLOCK` outcomes.
- Match types include exact domain, full URL, or glob/wildcard patterns (`*.xyz`).
- Strict priority evaluation ensures explicit organizational whitelists or high-priority blocks supersede lower-ranked heuristics.

### D. Incident Management & Security Alerts
- Threat navigations generate actionable alerts (`NEW`, `ACKNOWLEDGED`, `RESOLVED`).
- Correlated events group under active client incidents for security review.

### E. Real-Time Security Operations Dashboard
- Live Server-Sent Events (SSE) feed streams real navigation events across the entire fleet.
- Searchable URL history with multi-parameter filtering and CSV data export.
- Full administrative audit trail tracking rule modifications, client changes, and logins.

---

## 4. Configuration & Environment Variables

Copy `.env.example` to `.env` for local development. See that file for full
documentation of every variable. The short version:

```env
# Local dev only - omit DATABASE_URL and the server auto-creates a local
# phishguard.db SQLite file. This SQLite fallback is NEVER used in production.
DATABASE_URL=
JWT_SECRET=change-me-to-a-long-random-string
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-me-before-deploying
SERVER_PORT=3000
```

**Default admin login (local dev only, change immediately in production):**
`admin` / `PhishGuardAdmin2026!`

---

## 5. Deploying to Netlify (production)

FortiNex ships with Netlify Functions (`netlify/functions/api.js`) that wrap the
same Express app used locally, plus a `netlify.toml` that wires up redirects so
`/api/*` on your site routes to that function.

1. **Provision a real Postgres database.** Netlify Functions run on an ephemeral
   filesystem, so SQLite cannot persist data between requests - a real Postgres
   connection is required in production and the server will refuse to boot
   without one. Easiest options (all have a free tier):
   - Netlify DB (Neon), enabled directly from your Netlify site dashboard, or
   - [neon.tech](https://neon.tech), or
   - [supabase.com](https://supabase.com)

   Copy the resulting `postgresql://...` connection string.

2. **Push this project to a Git repo** (GitHub/GitLab/Bitbucket) and create a
   new Netlify site from it, or run `netlify deploy` from the CLI.

3. **Set environment variables** in Netlify: *Site configuration → Environment
   variables*:
   - `DATABASE_URL` - the Postgres connection string from step 1
   - `JWT_SECRET` - a long random string
   - `ADMIN_USERNAME` / `ADMIN_PASSWORD` - your real admin credentials
   - (optional) `PRODUCTION_API_URL` - only needed if you're using a custom
     domain and want to pin it explicitly; otherwise the build auto-detects
     your Netlify URL.

4. **Deploy.** Netlify runs `npm run build` (see `build.js`), which builds the
   static dashboard into `dist/`, and bundles `netlify/functions/api.js` as
   your serverless API. The build also bakes your live site URL into the
   Chrome extension's `config.js`/`background.js`, so extensions work with
   zero manual configuration.

5. **Verify:** open `https://your-site.netlify.app`, log in with your admin
   credentials, and check `GET /api/health` - it reports `database.type` as
   `PostgreSQL` when correctly configured (and a clear error if not).

### Installing the extension on any computer

From the dashboard's **Install Extension** tab, click **Download Extension**.
The server generates a ZIP on the fly, pre-configured with your deployed
HTTPS server URL and the active enrollment token — install it unpacked via
`chrome://extensions` → Developer mode → Load unpacked, on any machine, and it
will connect automatically. No source-code editing required. The server URL
can also be changed at any time from the extension's Options page.

---

## 6. Verifying the System

- **Dashboard**: Visit your deployed URL (or `http://localhost:3000` locally).
- **API Health**: `GET /api/health` returns operational status, uptime, and
  which database backend is active.
- **End-to-end test**: install the extension from the dashboard's Install tab,
  browse to any site, and confirm the visit appears under URL History within
  a few seconds, with fleet status/online counts updating on Overview.
