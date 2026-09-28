# blind-xss-collector

A **self-hosted, interactive blind-XSS collector** built on **Cloudflare Workers + D1**.
It does the same job as XSS Hunter / ezXSS — you plant a probe in a stored-input field,
and when a staff member / admin later views it in their browser the probe fires and calls
home with everything about their authenticated session — except the callback data (client
DOM, cookies, storage, screenshots) stays on **your own Cloudflare account**. No
third-party SaaS ever sees your engagement data.

It is also **interactive**: as long as the victim's tab stays open, you drive their browser
live from the dashboard (re-dump DOM, read same-origin admin pages with their cookies, log
keystrokes, run arbitrary JS).

> ### ⚠️ Authorized testing only
> Blind XSS fires in **someone else's** browser session — usually a support agent or
> admin. Only inject probes into targets you are **authorized in writing** to test.
> Keep proofs minimal, do **not** read real user data beyond what proves impact, and
> **purge** all callback data at engagement close (see [Purge](#purge-engagement-close)).
> This is a *defensive* tool: the goal is to locate the stored-XSS sink so the client can
> fix it. Every injection point is a logged active request — record the `token → surface`
> mapping in your engagement/session file.

---

## Table of contents
- [How it works](#how-it-works)
- [What it captures](#what-it-captures)
- [HTTP endpoints](#http-endpoints)
- [Prerequisites](#prerequisites)
- [Deploy to Cloudflare (step by step)](#deploy-to-cloudflare-step-by-step)
- [Point a custom domain at the worker](#point-a-custom-domain-at-the-worker)
- [Local development](#local-development)
- [Using the dashboard](#using-the-dashboard)
- [Full engagement workflow](#full-engagement-workflow)
- [Interactive command reference](#interactive-command-reference)
- [CSP-aware exfiltration](#csp-aware-exfiltration)
- [Purge (engagement close)](#purge-engagement-close)
- [Tests](#tests)
- [Troubleshooting](#troubleshooting)
- [File layout](#file-layout)

---

## How it works

```
   YOU (operator)                    VICTIM (admin/support browser)         COLLECTOR (your Worker + D1)
 ┌───────────────┐                 ┌──────────────────────────────┐      ┌───────────────────────────┐
 │ 1. mint token  │                │                              │      │                           │
 │    + payload   │─inject into───▶│  stored field renders later  │      │                           │
 │  (dashboard    │  target's      │  in admin panel → probe runs │      │                           │
 │   Generator)   │  stored input  │                              │      │                           │
 │               │                │  2. GET /c/<token>  ─────────┼─────▶│ serves probe JS           │
 │               │                │  3. POST /r/<token> (capture)┼─────▶│ storeReport() → D1        │
 │ 5. watch the   │◀──dashboard────│  4. GET /q/<sid> (poll 5s)  ◀┼──────┤ hands out queued commands │
 │    Sessions tab│   reads D1     │     POST /qr/<id> (result)  ─┼─────▶│ writes result → D1        │
 └───────────────┘                └──────────────────────────────┘      └───────────────────────────┘
```

1. **You** mint a unique token per injection point in the dashboard's *Payload Generator*,
   then inject the generated payload into a stored input on the authorized target.
2. Later, a **victim** (admin/staff) opens the page that renders your stored payload. The
   browser loads `GET /c/<token>` — the **probe** — from your collector.
3. The probe immediately collects the session (DOM, cookies, storage, forms, meta) and
   **POSTs a full report** to `/r/<token>`. The Worker writes it to **D1** (SQLite) and
   upserts a *session* row keyed by a random `sid`.
4. The probe then **long-polls** `GET /q/<sid>` every 5s for commands you queue, runs each
   one in the victim's context, and returns the result to `/qr/<id>`.
5. **You** open the auth-gated dashboard, watch sessions arrive live, inspect each capture,
   and issue interactive commands — all reading/writing the same D1 database.

Everything is a single Worker (`src/worker.js`) plus one D1 database. There is no build
step — Wrangler ships the source directly.

---

## What it captures

**Automatically, the instant the probe fires:**
- fire **URL + page title + origin** → tells you *which* injection point executed, and in
  whose panel
- **victim IP** (recorded server-side from `CF-Connecting-IP`), **User-Agent**, browser/device fingerprint
- `document.cookie` (all non-`HttpOnly` cookies), `localStorage`, `sessionStorage`
- full **DOM snapshot** of the victim's authenticated page
- every **form / hidden input** (pre-filled admin values, CSRF tokens) and `<meta>` tags

**Interactively, while the victim tab stays open** (probe long-polls every 5s):
- `dom` / `cookies` / `storage` / `forms` — re-dump fresh
- `fetch:<url>` — request a **same-origin** URL *with the victim's cookies* and return the
  response body (read `/admin`, internal APIs, other users' records — an in-browser
  authenticated read that bypasses CSRF because it runs from the victim's own origin)
- `keylog:<selector>` — stream keystrokes from matching fields (blank = whole document)
- `screenshot` — best-effort page image via html2canvas (needs `script-src` to allow the CDN)
- `eval:<js>` — run arbitrary JavaScript in the victim's context and return the result

**CSP-aware exfil:** the probe tries `fetch`(CORS) → `navigator.sendBeacon` → a chunked
`Image()` GET (reassembled server-side), so data still escapes even a strict `connect-src`
as long as `img-src` allows the collector host. See [CSP-aware exfiltration](#csp-aware-exfiltration).

---

## HTTP endpoints

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/c/:token[.js]` | GET | public | Serve the probe JS (victims load this). `token`/base are substituted in. |
| `/r/:token` | POST | public (CORS `*`) | Full capture report via `fetch`/`sendBeacon`. |
| `/p/:token` | GET | public | Chunked **image-beacon** report (CSP `img-src` fallback), reassembled server-side. |
| `/q/:sid` | GET | public (CORS `*`) | Probe long-polls for queued commands; also refreshes `last_seen`. |
| `/qr/:id` | POST | public (CORS `*`) | Probe returns a command result. |
| `/` | GET | **`?key=AUTH_KEY`** | Operator dashboard (HTML). |
| `/api/sessions` | GET | **key** | List sessions (newest first). |
| `/api/reports?sid=` | GET | **key** | Reports for one session. |
| `/api/cmdresults?sid=` | GET | **key** | Command history + results for one session. |
| `/api/cmd` | POST | **key** | Queue an interactive command `{sid, cmd}`. |

The public collector routes are intentionally unauthenticated (the victim's browser has no
key); only the dashboard and its `/api/*` data routes require the `AUTH_KEY`, compared in
constant time.

---

## Prerequisites

- A **Cloudflare account** (the free plan is enough for typical engagement volumes).
- **Node.js 18+** and **npm** locally.
- **Wrangler** (Cloudflare's CLI) — installed globally or run via `npx`.
- (Optional, recommended) a **domain on Cloudflare** so you can give the collector an
  innocuous custom hostname instead of the default `*.workers.dev` name.
- (Optional, for `npm run test:e2e`) **Google Chrome** installed locally.

---

## Deploy to Cloudflare (step by step)

All commands run from this directory (`tools/blind-xss-collector`).

### 1. Install Wrangler and log in
```sh
cd tools/blind-xss-collector
npm i -g wrangler          # or prefix every command below with: npx
wrangler login             # opens a browser to authorize your Cloudflare account
```
`wrangler login` needs an interactive browser. In this Claude Code session you can run it
yourself by typing `! wrangler login` at the prompt so its output lands in the chat.

### 2. Create the D1 database
```sh
wrangler d1 create bxss
```
This prints a block like:
```
[[d1_databases]]
binding = "DB"
database_name = "bxss"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```
Copy the **`database_id`** value and paste it into `wrangler.toml`, replacing
`REPLACE_WITH_D1_ID`:
```toml
[[d1_databases]]
binding = "DB"
database_name = "bxss"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # ← your real id
```
The `binding = "DB"` name must stay `DB` — the Worker reads the database as `env.DB`.

### 3. Create the tables
```sh
wrangler d1 execute bxss --remote --file=schema.sql
```
`--remote` runs against the real (deployed) D1 instance. This creates the `sessions`,
`reports`, `commands`, and `chunks` tables plus their indexes.

### 4. Set the dashboard password
```sh
wrangler secret put AUTH_KEY
```
Paste a **long random string** when prompted (e.g. `openssl rand -hex 32`). This is the
`key` you append to the dashboard URL. It is stored as an encrypted Worker secret — never
commit a real one to the repo.

### 5. Deploy
```sh
wrangler deploy
```
Wrangler prints your Worker URL, e.g. `https://blind-xss-collector.<subdomain>.workers.dev`.

### 6. Verify
```sh
# probe should return JavaScript with your token substituted in:
curl -s https://<your-worker-host>/c/smoketest | head -c 120

# dashboard should refuse without the key (HTTP 401):
curl -s -o /dev/null -w '%{http_code}\n' https://<your-worker-host>/

# and load with it (HTTP 200):
curl -s -o /dev/null -w '%{http_code}\n' 'https://<your-worker-host>/?key=YOUR_AUTH_KEY'
```

Open the dashboard in a browser: **`https://<your-worker-host>/?key=YOUR_AUTH_KEY`**

---

## Point a custom domain at the worker

The default `*.workers.dev` host is an obvious callback. For real engagements, give the
Worker an innocuous custom hostname on a domain you control in Cloudflare:

1. Cloudflare dashboard → **Workers & Pages** → your worker → **Settings → Triggers →
   Custom Domains → Add Custom Domain**.
2. Enter something benign, e.g. `cdn-metrics.example.net` or `assets.example.net`.
   Cloudflare provisions the route and TLS automatically (the domain's DNS must already be
   on Cloudflare).
3. From then on, use that host everywhere: probes become
   `https://cdn-metrics.example.net/c/<token>` and the dashboard is
   `https://cdn-metrics.example.net/?key=YOUR_AUTH_KEY`.

A plausible host also helps against CSP: if the target's `script-src` allows a CDN-looking
domain or a wildcard, matching the collector host to it lets the external-script payloads load.

---

## Local development

Run the whole thing locally without deploying:

```sh
# one-time: create a LOCAL D1 and load the schema into it
wrangler d1 execute bxss --local --file=schema.sql

# add a throwaway dev key so the dashboard is reachable locally
#   in wrangler.toml, under [vars]:  AUTH_KEY = "devkey"
#   (do NOT commit a real key; [vars] is plaintext)

wrangler dev              # serves on http://127.0.0.1:8787
```
Dashboard: `http://127.0.0.1:8787/?key=devkey`. Local `--local` D1 is a separate SQLite
file from `--remote`, so local test data never touches production.

For a fast sanity check with **no Cloudflare at all**, the test suite runs the real
`worker.js` against a `node:sqlite` D1 shim — see [Tests](#tests).

---

## Using the dashboard

Open `https://<host>/?key=YOUR_AUTH_KEY`. The header shows a live session count and a
heartbeat dot, and there are two tabs.

### Sessions tab
- **Live feed** of every session, newest first. A **pulsing green dot** means that victim's
  tab is still open and long-polling (`last_seen` within 30s) — i.e. interactive commands
  will land. A grey dot means the tab has closed; automatic captures are still there but
  live commands won't run.
- **Filter box** — type to filter by token, URL, or IP.
- Click a session to open its **detail** on the right:
  - `fired at` — URL / title / origin / referrer / timestamp (which surface fired).
  - `victim` — IP + User-Agent.
  - `cookies`, `storage`, `forms / hidden inputs`, `meta / csrf` — each with a **copy
    button**.
  - `interactive` — quick-action buttons (dom, cookies, storage, screenshot,
    fetch-as-victim, keylog) plus a free-form command box.
  - `command results` — status + output of everything you've queued for this session.
  - `DOM snapshot` — the captured HTML, with the **screenshot** rendered inline if one was
    captured.
- The view auto-refreshes every 4s.

### Payload Generator tab
Mints unique probe URLs and ready-to-inject payloads so you never hand-write them:

1. Type an **injection-point label** (e.g. `support-form`, `ua-header`, `crm-bio`).
2. Confirm the **collector host** (pre-filled from the current URL).
3. Click **Generate**. You get:
   - a **unique token** (`t-support-form-a1b2c3`) and its probe URL, with a copy button;
   - ready-to-inject payloads for **every context** — external `<script>`, event-handler
     breakout, markup-injection / no-JS-context sink, and a strict-CSP image-beacon — each
     with its own copy button, host and token already substituted.
4. Every generated token is saved to a **token registry** in this browser's `localStorage`
   (token → label → host → time), with a delete control. This is your canary map: keep it
   in sync with the engagement/session file so every callback self-identifies.

Because the token is echoed back on every callback, a distinct token per injection point
tells you exactly which surface fired and in whose panel — critical when you seed dozens of
fields across a target.

---

## Full engagement workflow

1. **Deploy** the collector and give it a custom domain (above). Confirm the dashboard loads.
2. In the **Payload Generator**, mint one token per injection point you intend to seed.
   Record each `token → surface` in your session file.
3. **Inject** the generated payload into each authorized stored-input surface. Classic
   blind-XSS surfaces (the payload is stored, an admin views it later):
   - support tickets / contact forms / "report a problem" / abuse reports
   - `User-Agent`, `Referer`, `X-Forwarded-For` headers (logged & rendered in admin log viewers)
   - name / company / address / bio / avatar-filename fields shown in a CRM
   - order notes, delivery instructions, cancellation reasons
   - review/comment bodies moderated in a back-office queue
   - filenames of uploaded files (rendered in an admin file browser)
   - referral codes, coupon names, saved-search names, calendar-event titles
   - SSO/SAML display-name / `givenName` rendered in an IdP admin console

   See `payloads.md` for the full payload catalogue and per-context notes.
4. **Wait.** When a probe fires, a session row appears in the dashboard.
5. **Triage** the automatic capture: which token, whose session, what cookies/CSRF/DOM.
6. If the tab is still live (green dot), **drive it interactively** — read `/admin` with
   `fetch:`, dump fresh state, capture a screenshot as proof.
7. **Validate** the finding (reproduce, save request/response, write impact), file it, and
   **purge** the callback data at engagement close.

---

## Interactive command reference

Queue these from a live session's detail view (free-form box or quick buttons). Results
appear under *command results* within a few seconds. Commands only run while the victim's
tab is open and polling.

| Command | Effect |
|---|---|
| `dom` | Re-dump the current DOM. |
| `cookies` | Re-dump `document.cookie`. |
| `storage` | Re-dump `localStorage` + `sessionStorage`. |
| `forms` | Re-dump all form / hidden-input values. |
| `screenshot` | Best-effort page screenshot via html2canvas (needs `script-src` to allow the CDN). |
| `fetch:<url>` | Fetch a **same-origin** URL with the victim's cookies and return the body (e.g. `fetch:/admin`, `fetch:/api/users/1`). |
| `keylog:<selector>` | Stream keystrokes from matching inputs; blank selector = whole document (e.g. `keylog:#password`). |
| `eval:<js>` | Run arbitrary JS in the victim context and return the result (e.g. `eval:document.domain`). |

---

## CSP-aware exfiltration

The probe adapts to the victim page's Content-Security-Policy by trying channels in order,
so data escapes even hardened pages:

1. **`fetch()` (CORS)** — POST the report to `/r/<token>`. Works when `connect-src` allows
   the collector host (the routes send `Access-Control-Allow-Origin: *`).
2. **`navigator.sendBeacon`** — fallback POST that survives page unload.
3. **Chunked `Image()` GET** — when `connect-src` is locked down but `img-src` allows the
   collector host, the probe base64-encodes the payload, splits it across many
   `GET /p/<token>?s=<sid>&f=<field>&i=<idx>&n=<total>&d=<chunk>` image requests, and the
   Worker **reassembles** them in the `chunks` table, decodes, and stores the full report
   once all `n` chunks arrive (partial buffers older than 10 min are purged).

If both `connect-src` and `img-src` are locked to `self`, use the degraded inline beacon in
`payloads.md` §5 (confirms fire + leaks the cookie) or a CSP-report / prefetch channel.

---

## Purge (engagement close)

Delete all callback data from D1 when the engagement ends:
```sh
wrangler d1 execute bxss --remote --command \
  "DELETE FROM reports; DELETE FROM sessions; DELETE FROM commands; DELETE FROM chunks;"
```
Also clear the browser's **token registry** (Payload Generator tab) and, if you no longer
need the collector, remove the custom-domain route and `wrangler delete` the Worker.

---

## Tests

Execution-verified with **no cloud deploy** — a D1-compatible `node:sqlite` adapter runs the
real `worker.js`:

- **`npm test`** — 24 server-side assertions against the real worker: report store,
  dashboard auth gate, interactive command lifecycle, and chunked image-beacon reassembly.
- **`npm run test:e2e`** — 13 assertions driving **real headless Chrome** as the victim
  against a mock admin-log-viewer app: the probe fires from a stored payload, collects real
  DOM / cookies / localStorage / CSRF-token, exfils cross-origin, `fetch`-as-victim reads a
  protected same-origin page with the victim's cookie, and — under a strict CSP
  (`connect-src 'self'`) — falls back to the `img-src` image-beacon. **Requires Google
  Chrome.**

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `wrangler deploy` fails on D1 | `database_id` in `wrangler.toml` is still `REPLACE_WITH_D1_ID`, or you didn't run `d1 create bxss`. |
| Dashboard returns `401 unauthorized` | Missing/wrong `?key=`. It must exactly match the `AUTH_KEY` secret. Re-set with `wrangler secret put AUTH_KEY`. |
| Probe loads (`/c/<token>` returns JS) but no session appears | The victim page's CSP blocks the exfil channels — check for a strict `connect-src` **and** `img-src`; fall back to the §5 inline beacon in `payloads.md`. |
| Session shows but interactive commands never complete | The victim tab closed (grey dot). Live commands only run while the tab polls; the automatic capture is still valid. |
| `no such table` errors | Schema not loaded on that D1 instance — run `d1 execute bxss --remote --file=schema.sql` (or `--local` for dev). |
| External-`<script>` payload doesn't run | Target's `script-src` doesn't allow your host — match the collector's custom domain to an allowed CDN/wildcard, or use an event-handler / `import()` payload from `payloads.md`. |

---

## File layout
- `src/worker.js` — router (public collector endpoints + auth-gated dashboard API)
- `src/probe.js` — the injectable probe (served with token/base substituted)
- `src/dashboard.js` — operator UI (Sessions feed + Payload Generator)
- `schema.sql` — D1 tables (`sessions`, `reports`, `commands`, `chunks`)
- `wrangler.toml` — Worker + D1 binding config
- `payloads.md` — delivery payloads per injection context + CSP channel notes
- `test/unit.mjs`, `test/e2e.mjs`, `test/env.mjs` — the test suites and D1 shim
