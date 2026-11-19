// Fixed, repository-owned assets; untrusted data is rendered only as text.
export const workspacePage='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Verivaro | Evidence workspace</title><link rel="stylesheet" href="/assets/workspace.css"><script defer src="/assets/workspace.js"></script></head><body><header><div><span class="brand">VERIVARO</span><span class="sub">Evidence workspace</span></div><div class="actions"><form action="/auth/login" method="post"><button>Sign in</button></form><form action="/auth/logout" method="post"><button>Sign out</button></form><form action="/auth/logout-all" method="post"><button>Sign out everywhere</button></form></div></header><main><h1>Verification workspace</h1><p id="notice" role="status" aria-live="polite">Checking session…</p><section id="workspace" hidden><div class="panel controls"><label>Workspace<select id="tenant"></select></label><label>Project<select id="project"></select></label><button id="refresh">Refresh</button><p id="roles"></p></div><section class="panel"><h2>Project details</h2><form id="rename"><label>Project name<input id="name" maxlength="128" required></label><button>Save name</button></form></section><section class="panel"><h2>Evidence</h2><p>Uploads: UTF-8 text, restricted PNG and canonical text PDF; maximum 256 KiB. Downloads are attachments only.</p><form id="upload"><label>Select evidence<input type="file" id="file" accept=".txt,.png,.pdf" required></label><button>Upload</button></form><div id="evidence"></div></section><section class="panel"><h2>Review &amp; release</h2><p>A contributor submits, an independent reviewer decides, and a separate owner publishes. Permissions are rechecked by the server.</p><div id="requests"></div></section></section></main></body></html>';
export const workspaceCss=':root{color-scheme:light;font-family:system-ui,sans-serif;color:#172b3b;background:#f4f6f8}*{box-sizing:border-box}body{margin:0}header{background:#163047;color:white;padding:18px 5%;display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}.brand{font-weight:800;letter-spacing:2px}.sub{display:block;font-size:13px;margin-top:4px;color:#cbdde8}.actions{display:flex;gap:8px;flex-wrap:wrap}main{max-width:1050px;margin:auto;padding:24px 16px 56px}h1{font-size:clamp(24px,4vw,36px);margin:0 0 12px}h2{margin:0 0 12px;font-size:20px}.panel{background:white;border:1px solid #dbe2e7;border-radius:12px;margin:14px 0;padding:18px}.controls,form:not(header form){display:flex;align-items:end;gap:12px;flex-wrap:wrap}label{display:grid;gap:5px;min-width:0;font-size:14px;font-weight:600}select,input,button,a.download{font:inherit;border-radius:6px;padding:10px;border:1px solid #b8c6cf;max-width:100%}button,a.download{background:#234b65;color:white;border:none;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}header button{background:#30536b}button:disabled,input:disabled,select:disabled{opacity:.55;cursor:default}button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #bd7e18;outline-offset:2px}.item{padding:14px 0;border-top:1px solid #e7ecef}.item p{margin:6px 0;overflow-wrap:anywhere}.item .meta{font-size:12px;color:#516575}.item .actions{margin-top:8px}.state{font-weight:700;text-transform:capitalize}#notice{min-height:24px;color:#30536b}#roles{font-size:13px;margin:0}#name{min-width:min(300px,72vw)}[hidden]{display:none!important}@media(max-width:600px){.controls,form:not(header form){align-items:stretch;flex-direction:column}.controls label{width:100%}header{padding:14px 16px}.actions{gap:6px}}';
export const workspaceScript=String.raw`
'use strict';
const el=id=>document.getElementById(id),tenant=el('tenant'),project=el('project'),notice=el('notice');
let current=null,busy=false,projects=[];
const attempts=new Map();
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const messages={400:'Invalid request.',401:'Sign in again.',403:'Request denied.',404:'Not available or permission denied.',409:'Conflict: refresh and check current state.',422:'Evidence rejected by validation or scanning.',429:'Request limit reached. Try again shortly.',503:'Service unavailable. Retry the same action.',507:'Storage quota reached.'};
function say(text){notice.textContent=text;}
async function api(path,options={}){
 const r=await fetch(path,{credentials:'same-origin',cache:'no-store',redirect:'error',...options});
 if(!r.ok){const e=new Error(messages[r.status]||'Request failed.');e.status=r.status;throw e;}
 return r.json();
}
function path(){if(!uuid.test(tenant.value)||!uuid.test(project.value))throw Error('Select a project.');return '/api/v1/tenants/'+tenant.value+'/projects/'+project.value;}
function node(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;}
function option(select,value,text){const o=node('option',text);o.value=value;select.append(o);}
function button(text,fn){const b=node('button',text);b.type='button';b.addEventListener('click',()=>perform(fn));return b;}
function link(label,url){const a=node('a',label,'download');a.href=url;a.download='';return a;}
function setDisabled(disabled){for(const n of el('workspace').querySelectorAll('button,input,select'))n.disabled=disabled||n.dataset.unavailable==='yes';}
function clear(){current=null;el('evidence').replaceChildren();el('requests').replaceChildren();el('roles').textContent='';el('name').value='';el('rename').hidden=true;el('upload').hidden=true;}
function retryId(key){if(!attempts.has(key)){if(attempts.size>=128)throw Error('Too many pending actions. Refresh this page after checking outcomes.');attempts.set(key,crypto.randomUUID());}return attempts.get(key);}
async function perform(fn){if(busy)return;busy=true;setDisabled(true);try{await fn();}catch(e){say(e.message||'Request failed.');if(e.status===401){clear();el('workspace').hidden=true;} }finally{busy=false;setDisabled(false);}}
async function loadProjects(){
 clear();project.replaceChildren();projects=[];
 if(!uuid.test(tenant.value))return;
 projects=(await api('/api/v1/tenants/'+tenant.value+'/projects')).items;
 for(const p of projects)if(uuid.test(p.id))option(project,p.id,p.name);
 if(project.options.length)await loadProject();else say('No accessible projects.');
}
async function loadProject(){
 clear();if(!uuid.test(project.value))return;
 const base=path(),data=await api(base+'/releases'),detail=await api(base);
 current={base,data,project:detail.project};
 el('roles').textContent='Workspace role: '+data.tenantRole+' · Project role: '+data.projectRole;
 el('name').value=detail.project.name;
 el('rename').hidden=!(data.tenantRole==='owner'&&data.projectRole==='owner');
 el('upload').hidden=!data.uploadsEnabled||!['owner','reviewer','contributor'].includes(data.tenantRole)||!['owner','reviewer','contributor'].includes(data.projectRole);
 render();say('Workspace ready.');
}
async function mutate(action,body){
 await api(current.base+'/releases/'+action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 await loadProject();
}
function render(){
 const {base,data}=current,evidence=el('evidence'),requests=el('requests');evidence.replaceChildren();requests.replaceChildren();
 for(const e of data.evidence){
  const row=node('div',undefined,'item'),a=node('div',undefined,'actions');
  row.append(node('p','Evidence '+e.id),node('p',e.mediaType+' · '+e.bytes+' bytes','meta'),node('p','SHA-256: '+e.sha256,'meta'));
  a.append(link('Download',base+'/evidence/'+e.id+'/download'));
  if(e.canSubmit&&data.publishEnabled)a.append(button('Submit for review',async()=>{
   const key=base+':submit:'+e.id,requestId=retryId(key);
   await mutate('submit',{requestId,evidenceId:e.id,sha256:e.sha256});attempts.delete(key);
  }));
  row.append(a);evidence.append(row);
 }
 if(!data.evidence.length)evidence.append(node('p','No encrypted evidence.'));
 for(const r of data.requests){
  const row=node('div',undefined,'item'),a=node('div',undefined,'actions');
  row.append(node('p',r.state,'state'),node('p','Evidence '+r.evidenceId),node('p','Request '+r.id+' · '+r.createdAt,'meta'),node('p','SHA-256: '+r.sha256,'meta'));
  if(r.reason)row.append(node('p','Decision reason: '+r.reason));
  if(r.exportId)row.append(node('p','Export reference: '+r.exportId,'meta'));
  a.append(link('Download evidence',base+'/evidence/'+r.evidenceId+'/download'));
  if(r.canReview&&data.publishEnabled){
   const select=node('select');select.setAttribute('aria-label','Review decision');
   for(const [v,label] of [['verified','Approve — verified'],['integrity_concern','Reject — integrity concern'],['insufficient_evidence','Reject — insufficient evidence'],['policy_denied','Reject — policy denied']])option(select,v,label);
   a.append(select,button('Record decision',async()=>{
    const reason=select.value;if(!confirm('Record this final review decision?'))return;
    await mutate('review',{requestId:r.id,sha256:r.sha256,decision:reason==='verified'?'approved':'rejected',reason});
   }));
  }
  if(r.canPublish&&data.publishEnabled)a.append(button('Authorize release',async()=>{
   if(!confirm('Authorize this evidence for recipient-bound release?'))return;
   await mutate('publish',{requestId:r.id,evidenceId:r.evidenceId,sha256:r.sha256});
  }));
  row.append(a);requests.append(row);
 }
 if(!data.requests.length)requests.append(node('p','No visible review requests.'));
}
tenant.addEventListener('change',()=>perform(loadProjects));project.addEventListener('change',()=>perform(loadProject));el('refresh').addEventListener('click',()=>perform(loadProject));
el('rename').addEventListener('submit',event=>{event.preventDefault();perform(async()=>{
 if(!current)return;const name=el('name').value.trim(),revision=current.project.revision,base=current.base,key=base+':rename:'+revision+':'+name;
 await api(base,{method:'PATCH',headers:{'Content-Type':'application/json','Idempotency-Key':retryId(key)},body:JSON.stringify({name,revision})});
 attempts.delete(key);await loadProject();say('Project name saved.');
});});
el('upload').addEventListener('submit',event=>{event.preventDefault();perform(async()=>{
 if(!current)return;const file=el('file').files[0];if(!file||file.size<1||file.size>262144)throw Error('Choose a file of 1–262144 bytes.');
 const mediaType=file.type==='image/png'?'image/png':file.type==='application/pdf'?'application/pdf':file.type==='text/plain'||file.name.toLowerCase().endsWith('.txt')?'text/plain; charset=utf-8':null;
 if(!mediaType)throw Error('Unsupported evidence format.');
 const data=await file.arrayBuffer(),digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',data)),b=>b.toString(16).padStart(2,'0')).join(''),base=current.base,key=base+':upload:'+mediaType+':'+digest;
 await api(base+'/evidence',{method:'POST',headers:{'Content-Type':mediaType,'Idempotency-Key':retryId(key),'X-Evidence-SHA256':digest},body:data});
 attempts.delete(key);el('file').value='';await loadProject();say('Evidence uploaded.');
});});
perform(async()=>{
 const data=await api('/api/v1/workspaces');tenant.replaceChildren();
 for(const t of data.items)if(uuid.test(t.id))option(tenant,t.id,t.name);
 el('workspace').hidden=false;if(tenant.options.length)await loadProjects();else say('No accessible workspaces.');
});
`;
