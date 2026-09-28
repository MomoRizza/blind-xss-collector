# Manual test app

A mock vulnerable "support desk" for testing your collector **by hand** in a real browser.
It has a stored-XSS sink so a payload you submit as a customer renders unescaped in a
fake staff panel — exactly the blind-XSS shape the collector is built for.

## 1. Start the collector (locally)
```sh
cd tools/blind-xss-collector
# one-time local D1:
npx wrangler d1 execute bxss --local --file=schema.sql
# add a dev key in wrangler.toml under [vars]:  AUTH_KEY = "devkey"
npx wrangler dev            # → http://127.0.0.1:8787
```
Open the dashboard: `http://127.0.0.1:8787/?key=devkey`
(You can also point the test at your **deployed** worker host instead of `wrangler dev`.)

## 2. Start this test app
```sh
npm run demo               # → http://127.0.0.1:8080   (PORT=9000 npm run demo to change)
```

## 3. Drive it
1. In the dashboard **Payload Generator** tab, set the host to `127.0.0.1:8787` (or your
   deployed host) and **Generate**. Copy the **External script** payload.
2. Open the attacker side `http://127.0.0.1:8080/`, paste the payload into **message**, submit.
3. Open the staff panel `http://127.0.0.1:8080/admin` in another tab — you are now "the admin".
   The stored payload executes in that authenticated page and your probe fires.
4. Watch the dashboard **Sessions** tab: a session appears with the token, the `/admin` URL,
   the fake `adminsess` cookie, `localStorage` jwt, `sessionStorage` role, and the CSRF token/meta.
5. While the `/admin` tab stays open (green pulse dot), test interactive commands:
   - `fetch:/admin/secret` → reads the protected customer-export page **as the victim** (proves impact)
   - `dom` / `cookies` / `storage` → fresh re-dump
   - `screenshot`, `keylog:` etc.

## 4. Test the CSP fallback
Open `http://127.0.0.1:8080/admin?csp=1` instead. It serves a strict CSP
(`connect-src 'self'`, `img-src *`) that blocks `fetch`/`sendBeacon`, so the probe must fall
back to the chunked **image-beacon** channel — the session should still arrive. (The CSP
auto-allows whatever collector host it finds in a stored payload.)

## Notes
- All state is in-memory; **Reset** clears tickets, or just restart the server.
- This is a local testbed only — loopback hosts, no real data. Purge collector data after:
  see the main README's *Purge* section.
