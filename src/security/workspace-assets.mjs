// Fixed, repository-owned assets; untrusted data is rendered only as text.
export const workspacePage='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Verivaro | Evidence workspace</title><link rel="stylesheet" href="/assets/workspace.css"><script defer src="/assets/workspace.js"></script></head><body><header><div><span class="brand">VERIVARO</span><span class="sub">Evidence workspace</span></div><div class="actions"><form action="/auth/login" method="post"><button>Sign in</button></form><form action="/auth/logout" method="post"><button>Sign out</button></form><form action="/auth/logout-all" method="post"><button>Sign out everywhere</button></form></div></header><main><h1>Verification workspace</h1><p id="notice" role="status" aria-live="polite">Checking session…</p><section id="recipientPanel" class="panel" hidden><h2>Receive shared evidence</h2><form id="redeem"><label>Recipient code<input id="receiveCode" type="password" autocomplete="off" maxlength="43" required></label><button>Download shared evidence</button></form></section><section id="workspace" hidden><div class="panel controls"><label>Workspace<select id="tenant"></select></label><label>Project<select id="project"></select></label><button id="refresh">Refresh</button><p id="roles"></p></div><section class="panel" id="creation" hidden><h2>Create project</h2><form id="createProject"><label>Project name<input id="newName" maxlength="128" required></label><button>Create</button></form></section><section class="panel"><h2>Project details</h2><p id="lifecycle"></p><button id="archive" hidden>Archive project permanently</button><form id="rename"><label>Project name<input id="name" maxlength="128" required></label><button>Save name</button></form></section><section class="panel" id="reportPanel" hidden><h2>Verification report</h2><div id="metrics"></div><div class="actions"><a id="reportPdf" class="download">PDF report</a><a id="reportPackage" class="download">Verification package (ZIP)</a><a id="reportDownload" class="download">JSON snapshot</a></div><p>Unsigned snapshot, not an independently signed custody checkpoint.</p></section><section class="panel"><h2>Evidence</h2><p>Uploads: UTF-8 text, restricted PNG and canonical text PDF; maximum 256 KiB. Downloads are attachments only.</p><form id="upload"><label>Select evidence<input type="file" id="file" accept=".txt,.png,.pdf" required></label><button>Upload</button></form><div id="evidence"></div></section><section class="panel"><h2>Review &amp; release</h2><p>A contributor submits, an independent reviewer decides, and a separate owner publishes. Permissions are rechecked by the server.</p><div id="requests"></div></section><section class="panel" id="permissions" hidden><h2>Project access</h2><p>Existing tenant members only. Non-owner assignments expire after 30 days.</p><div id="directory"></div></section><section class="panel" id="sharing" hidden><h2>Recipient sharing</h2><p>Recipient codes expire after 15 minutes and require the designated signed-in recipient. Deliver the code securely outside this workspace.</p><form id="share"><label>Released evidence<select id="shareExport"></select></label><label>Recipient actor ID<input id="recipient" maxlength="36" autocomplete="off" required></label><button>Issue code</button></form><label id="issued" hidden>Copy this private code<input id="issuedCode" readonly autocomplete="off"></label><div id="shares"></div></section></section></main></body></html>';
export const workspaceCss=':root{color-scheme:light;font-family:system-ui,sans-serif;color:#172b3b;background:#f4f6f8}*{box-sizing:border-box}body{margin:0}header{background:#163047;color:white;padding:18px 5%;display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}.brand{font-weight:800;letter-spacing:2px}.sub{display:block;font-size:13px;margin-top:4px;color:#cbdde8}.actions{display:flex;gap:8px;flex-wrap:wrap}main{max-width:1050px;margin:auto;padding:24px 16px 56px}h1{font-size:clamp(24px,4vw,36px);margin:0 0 12px}h2{margin:0 0 12px;font-size:20px}.panel{background:white;border:1px solid #dbe2e7;border-radius:12px;margin:14px 0;padding:18px}.controls,form:not(header form){display:flex;align-items:end;gap:12px;flex-wrap:wrap}label{display:grid;gap:5px;min-width:0;font-size:14px;font-weight:600}select,input,button,a.download{font:inherit;border-radius:6px;padding:10px;border:1px solid #b8c6cf;max-width:100%}button,a.download{background:#234b65;color:white;border:none;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}header button{background:#30536b}button:disabled,input:disabled,select:disabled{opacity:.55;cursor:default}button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #bd7e18;outline-offset:2px}.item{padding:14px 0;border-top:1px solid #e7ecef}.item p{margin:6px 0;overflow-wrap:anywhere}.item .meta{font-size:12px;color:#516575}.item .actions{margin-top:8px}.state{font-weight:700;text-transform:capitalize}#metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(122px,1fr));gap:10px;margin:12px 0}.metric{border:1px solid #dbe2e7;border-radius:8px;padding:12px;display:grid;gap:5px}.metric strong{font-size:23px}.metric span{font-size:12px;text-transform:capitalize;color:#516575}#notice{min-height:24px;color:#30536b}#roles{font-size:13px;margin:0}#name{min-width:min(300px,72vw)}[hidden]{display:none!important}@media(max-width:600px){.controls,form:not(header form){align-items:stretch;flex-direction:column}.controls label{width:100%}header{padding:14px 16px}.actions{gap:6px}}';
export const workspaceScript=String.raw`
'use strict';
const el=id=>document.getElementById(id),tenant=el('tenant'),project=el('project'),notice=el('notice');
let current=null,busy=false,projects=[],tenantRows=[],pendingShare=null;
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
function setDisabled(disabled){for(const n of document.querySelectorAll('#workspace button,#workspace input,#workspace select,#recipientPanel button,#recipientPanel input'))n.disabled=disabled||n.dataset.unavailable==='yes';}
function clear(){current=null;el('evidence').replaceChildren();el('requests').replaceChildren();el('roles').textContent='';el('name').value='';el('rename').hidden=true;el('upload').hidden=true;el('archive').hidden=true;el('reportPanel').hidden=true;el('metrics').replaceChildren();el('lifecycle').textContent='';el('permissions').hidden=true;el('sharing').hidden=true;el('directory').replaceChildren();el('shares').replaceChildren();el('issued').hidden=true;el('issuedCode').value='';}
function retryId(key){if(!attempts.has(key)){if(attempts.size>=128)throw Error('Too many pending actions. Refresh this page after checking outcomes.');attempts.set(key,crypto.randomUUID());}return attempts.get(key);}
async function perform(fn){if(busy)return;busy=true;setDisabled(true);try{await fn();}catch(e){say(e.message||'Request failed.');if(e.status===401){clear();el('workspace').hidden=true;el('recipientPanel').hidden=true;pendingShare=null;el('receiveCode').value='';} }finally{busy=false;setDisabled(false);}}
async function loadProjects(){
 clear();project.replaceChildren();projects=[];el('creation').hidden=tenantRows.find(t=>t.id===tenant.value)?.role!=='owner';
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
 const closed=!!detail.project.archivedAt,owner=data.tenantRole==='owner'&&data.projectRole==='owner',reviewer=data.tenantRole==='reviewer'&&data.projectRole==='reviewer';
 el('lifecycle').textContent=closed?'Archived '+detail.project.archivedAt:'Active project';el('archive').hidden=closed||!owner;
 el('rename').hidden=closed||!owner;
 el('upload').hidden=closed||!data.uploadsEnabled||!['owner','reviewer','contributor'].includes(data.tenantRole)||!['owner','reviewer','contributor'].includes(data.projectRole);
 render();await loadAdministration();
 if(owner||reviewer){const report=await api(base+'/report');el('reportPanel').hidden=false;el('reportDownload').href=base+'/report-download';el('reportDownload').download='';el('reportPdf').href=base+'/report-pdf';el('reportPdf').download='';el('reportPackage').href=base+'/report-package';el('reportPackage').download='';const s=report.summary;for(const [label,value] of [['Evidence',s.evidence],['Encrypted evidence',s.encrypted],['Evidence bytes',s.bytes],['Review requests',s.requests],...Object.entries(s.states)])(()=>{const tile=node('div',undefined,'metric');tile.append(node('strong',String(value)),node('span',label));el('metrics').append(tile);})();}
 say('Workspace ready.');
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
  if(!current.project.archivedAt&&e.canSubmit&&data.publishEnabled)a.append(button('Submit for review',async()=>{
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
  if(!current.project.archivedAt&&r.canReview&&data.publishEnabled){
   const select=node('select');select.setAttribute('aria-label','Review decision');
   for(const [v,label] of [['verified','Approve — verified'],['integrity_concern','Reject — integrity concern'],['insufficient_evidence','Reject — insufficient evidence'],['policy_denied','Reject — policy denied']])option(select,v,label);
   a.append(select,button('Record decision',async()=>{
    const reason=select.value;if(!confirm('Record this final review decision?'))return;
    await mutate('review',{requestId:r.id,sha256:r.sha256,decision:reason==='verified'?'approved':'rejected',reason});
   }));
  }
  if(!current.project.archivedAt&&r.canPublish&&data.publishEnabled)a.append(button('Authorize release',async()=>{
   if(!confirm('Authorize this evidence for recipient-bound release?'))return;
   await mutate('publish',{requestId:r.id,evidenceId:r.evidenceId,sha256:r.sha256});
  }));
  row.append(a);requests.append(row);
 }
 if(!data.requests.length)requests.append(node('p','No visible review requests.'));
}

async function loadAdministration(){
 const {base,data}=current,owner=data.tenantRole==='owner'&&data.projectRole==='owner';
 el('permissions').hidden=!owner;el('sharing').hidden=!owner||!data.publishEnabled;
 if(!owner)return;
 if(current.project.archivedAt){el('sharing').hidden=true;}
 const directory=(await api(base+'/directory')).items;
 for(const member of directory){
  const row=node('div',undefined,'item'),select=node('select');select.setAttribute('aria-label','New project role');
  if(!current.project.archivedAt){option(select,'viewer','Viewer');if(['reviewer','contributor'].includes(member.tenantRole))option(select,member.tenantRole,member.tenantRole);}
  if(member.active)option(select,'revoke','Revoke access');if(!select.options.length)continue;
  row.append(node('p',member.actorId),node('p','Tenant: '+member.tenantRole+' · Project: '+(member.active?member.projectRole:'Not active'),'meta'),select,button('Apply access',async()=>{
   const role=select.value;if(!confirm('Apply '+role+' for '+member.actorId+'?'))return;
   const key=base+':access:'+member.actorId+':'+role+':'+member.generation;
   await api(base+'/access',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({requestId:retryId(key),targetId:member.actorId,role,generation:member.generation})});attempts.delete(key);await loadProject();
  }));el('directory').append(row);
 }
 if(!directory.length)el('directory').append(node('p','No eligible members.'));
 if(!data.publishEnabled||current.project.archivedAt)return;
 const exports=el('shareExport');exports.replaceChildren();
 for(const r of data.requests)if(r.state==='released'&&uuid.test(r.exportId))option(exports,r.exportId,r.evidenceId);
 for(const s of (await api(base+'/shares')).items){
  const row=node('div',undefined,'item');row.append(node('p',s.state,'state'),node('p','Recipient: '+s.recipientId),node('p','Expires: '+s.expiresAt,'meta'));
  if(s.state==='active')row.append(button('Revoke share',async()=>{if(!confirm('Revoke this recipient code?'))return;await api(base+'/share-revoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({shareId:s.id})});await loadProject();}));
  el('shares').append(row);
 }
}
el('createProject').addEventListener('submit',event=>{event.preventDefault();perform(async()=>{
 const name=el('newName').value.trim(),base='/api/v1/tenants/'+tenant.value+'/projects',key=base+':create:'+name;
 const r=await api(base+'/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,requestId:retryId(key)})});
 attempts.delete(key);el('newName').value='';await loadProjects();project.value=r.id;await loadProject();say('Project created.');
});});
el('share').addEventListener('submit',event=>{event.preventDefault();perform(async()=>{
 const exportId=el('shareExport').value,recipientId=el('recipient').value.trim(),base=current.base;
 if(!uuid.test(exportId)||!uuid.test(recipientId))throw Error('Select a release and valid recipient ID.');
 if(!confirm('Issue a 15-minute code for this recipient?'))return;
 const key=base+':'+exportId+':'+recipientId;
 if(pendingShare&&pendingShare.key!==key)throw Error('Resolve the previous share attempt before issuing another.');
 if(!pendingShare){const bytes=crypto.getRandomValues(new Uint8Array(32)),code=btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');pendingShare={key,code,shareId:crypto.randomUUID()};}
 const r=await api(base+'/share-issue',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({exportId,recipientId,shareId:pendingShare.shareId,code:pendingShare.code})});
 const code=pendingShare.code;pendingShare=null;
 await loadProject();el('issuedCode').value=code;el('issued').hidden=false;el('issuedCode').select();say('Code issued. Expires '+r.expiresAt+'. Copy privately now.');
});});
el('redeem').addEventListener('submit',event=>{event.preventDefault();perform(async()=>{
 const input=el('receiveCode'),code=input.value.trim();
 if(!/^[A-Za-z0-9_-]{43}$/.test(code))throw Error('Invalid recipient code.');
 const r=await fetch('/api/v1/recipient-download',{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',headers:{'X-Verivaro-Share':code}});
 if(!r.ok)throw Error(messages[r.status]||'Share unavailable.');
 const blob=await r.blob();if(blob.size<1||blob.size>262144)throw Error('Invalid download.');
 const url=URL.createObjectURL(blob),a=node('a');a.href=url;a.download='verivaro-export.bin';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);input.value='';say('Shared evidence downloaded.');
});});

el('archive').addEventListener('click',()=>perform(async()=>{
 if(!current||!confirm('Permanently archive this project and revoke all active exports? Evidence is retained.'))return;
 const {base,project}=current,key=base+':archive:'+project.revision;
 await api(base+'/archive',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({requestId:retryId(key),revision:project.revision})});
 attempts.delete(key);await loadProject();say('Project archived.');
}));
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
 const data=await api('/api/v1/workspaces');tenantRows=data.items;tenant.replaceChildren();el('recipientPanel').hidden=false;
 for(const t of data.items)if(uuid.test(t.id))option(tenant,t.id,t.name);
 el('workspace').hidden=false;if(tenant.options.length)await loadProjects();else say('No accessible workspaces.');
});
`;
