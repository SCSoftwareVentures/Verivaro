// Fixed, repository-owned assets; untrusted data is rendered only as text.
export const workspacePage='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Verivaro | Evidence workspace</title><link rel="stylesheet" href="/assets/workspace.css"><script defer src="/assets/workspace.js"></script></head><body><header><div><span class="brand">VERIVARO</span><span class="sub">Evidence workspace</span></div><div class="actions"><form action="/auth/login" method="post"><button>Sign in</button></form><form action="/auth/logout" method="post"><button>Sign out</button></form><form action="/auth/logout-all" method="post"><button>Sign out everywhere</button></form></div></header><main><h1>Verification workspace</h1><p id="notice" role="status" aria-live="polite">Checking session…</p><section id="invitationPanel" class="panel" hidden><h2>Accept workspace invitation</h2><form id="acceptInvite"><label>Workspace ID<input id="inviteTenant" maxlength="36" required></label><label>Request ID<input id="inviteRequest" maxlength="36" required></label><label>Private invitation code<input id="inviteCode" type="password" autocomplete="off" maxlength="43" required></label><button>Accept invitation</button></form></section><section id="recipientPanel" class="panel" hidden><h2>Receive shared evidence</h2><form id="redeem"><label>Recipient code<input id="receiveCode" type="password" autocomplete="off" maxlength="43" required></label><button>Download shared evidence</button></form></section><section id="workspace" hidden><div class="panel controls"><label>Workspace<select id="tenant" aria-describedby="selectedTenantName"></select><span class="selection-name" id="selectedTenantName"></span></label><label>Project<select id="project" aria-describedby="selectedProjectName"></select><span class="selection-name" id="selectedProjectName"></span></label><button id="refresh">Refresh</button><p id="roles"></p></div><section class="panel" id="tenantAdmin" hidden><h2>Workspace administration</h2><div id="tenantOwnerControls" hidden><p>Enrollment requires a provider subject hash from an independent identity operator. Requests expire in 15 minutes.</p><form id="enrollTenant"><label>Verified subject SHA-256<input id="enrollDigest" maxlength="64" autocomplete="off" required></label><label>Tenant role<select id="enrollRole"><option value="viewer">Viewer</option><option value="contributor">Contributor</option><option value="reviewer">Reviewer</option></select></label><button>Request enrollment</button></form><div id="enrollments"></div><div id="tenantDirectory"></div></div><h3>Ownership succession</h3><p>Requires recipient acceptance and separate operator approval. Archived evidence remains read-only; custody transfers are audited.</p><div id="transfers"></div></section><section class="panel" id="creation" hidden><h2>Create project</h2><form id="createProject"><label>Project name<input id="newName" maxlength="128" required></label><button>Create</button></form></section><div id="projectContent" hidden><section class="panel"><h2>Project details</h2><p id="lifecycle"></p><button id="archive" hidden>Archive project permanently</button><form id="rename"><label>Project name<input id="name" maxlength="128" required></label><button>Save name</button></form></section><section class="panel" id="graphPanel" hidden><h2>Requirements &amp; completion</h2><p id="graphStatus" role="status"></p><p>Reviewed criteria subset only. Satisfaction is not certification or release authorization.</p><div id="graphMetrics"></div><section id="preflight"><h3>Submission preflight</h3><p id="preflightSummary"></p><div id="preflightActions"></div><p id="preflightLimits" class="meta"></p></section><section id="contractIQ" hidden><h3>ContractIQ — source candidates</h3><p>Find possible obligations in supported text documents. Review the full original; this is not exhaustive contract analysis.</p><form id="extractForm"><label>Source document<select id="extractEvidence"></select></label><button>Find candidate requirements</button></form><p id="extractNotice" role="status"></p><div id="extractCandidates"></div></section><form id="requirementForm" hidden><label>Requirement title<input id="ruleTitle" maxlength="128" required></label><label>Verification criterion<textarea id="ruleCriterion" maxlength="1024" rows="3" required></textarea></label><label>Applicability<select id="ruleApplicability"><option value="unknown">Unknown</option><option value="required">Required</option><option value="optional">Optional</option><option value="not_applicable">Not applicable</option></select></label><button>Create requirement</button></form><div id="graphItems"></div><section id="submissionPanel"><h3>Controlled submission packages</h3><p>All criteria must be satisfied or independently confirmed not applicable, including optional criteria. A separate preparer, reviewer and owner must approve the exact snapshot. Download is not external submission.</p><button id="prepareSubmission" hidden>Prepare submission snapshot</button><div id="submissionItems"></div></section></section><section class="panel" id="proofLockPanel" hidden><h2>ProofLock — capture planning</h2><p>Confirmed schedule and independently reviewed capture rules. Planned dates do not establish work completion, timely capture or release authority.</p><p id="proofLockSummary" role="status"></p><div id="proofLockTasks"></div><div id="proofLockSchedule"></div><div id="proofLockRules"></div><p id="proofLockLimits" class="meta"></p></section><section class="panel" id="reportPanel" hidden><h2>Verification report</h2><div id="metrics"></div><div class="actions"><a id="reportPdf" class="download">PDF report</a><a id="reportPackage" class="download">Verification package (ZIP)</a><a id="reportDownload" class="download">JSON snapshot</a></div><p>Unsigned snapshot, not an independently signed custody checkpoint.</p></section><section class="panel"><h2>Evidence</h2><p>Uploads: UTF-8 text, restricted PNG and canonical text PDF; maximum 256 KiB. Downloads are attachments only.</p><form id="upload"><label>Select evidence<input type="file" id="file" accept=".txt,.png,.pdf" required></label><button>Upload</button></form><div id="evidence"></div></section><section class="panel"><h2>Review &amp; release</h2><p>A contributor submits, an independent reviewer decides, and a separate owner publishes. Permissions are rechecked by the server.</p><div id="requests"></div></section><section class="panel" id="permissions" hidden><h2>Project access</h2><p>Existing tenant members only. Non-owner assignments expire after 30 days.</p><div id="directory"></div></section><section class="panel" id="sharing" hidden><h2>Recipient sharing</h2><p>Recipient codes expire after 15 minutes and require the designated signed-in recipient. Deliver the code securely outside this workspace.</p><form id="share"><label>Released evidence<select id="shareExport"></select></label><label>Recipient actor ID<input id="recipient" maxlength="36" autocomplete="off" required></label><button>Issue code</button></form><label id="issued" hidden>Copy this private code<input id="issuedCode" readonly autocomplete="off"></label><div id="shares"></div></section></div></section></main></body></html>';
export const workspaceCss=':root{color-scheme:light;font-family:system-ui,sans-serif;color:#172b3b;background:#f4f6f8}*{box-sizing:border-box}body{margin:0}header{background:#163047;color:white;padding:18px 5%;display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}.brand{font-weight:800;letter-spacing:2px}.sub{display:block;font-size:13px;margin-top:4px;color:#cbdde8}.actions{display:flex;gap:8px;flex-wrap:wrap}main{width:100%;min-width:0;max-width:1050px;margin:auto;padding:24px 16px 56px}h1{font-size:clamp(24px,4vw,36px);margin:0 0 12px}h2{margin:0 0 12px;font-size:20px}.panel{min-width:0;max-width:100%;overflow-wrap:anywhere;background:white;border:1px solid #dbe2e7;border-radius:12px;margin:14px 0;padding:18px}.controls,form:not(header form){display:flex;align-items:end;gap:12px;flex-wrap:wrap}label{display:grid;grid-template-columns:minmax(0,1fr);gap:5px;min-width:0;max-width:100%;font-size:14px;font-weight:600}select,input,textarea,button,a.download{font:inherit;border-radius:6px;padding:10px;border:1px solid #b8c6cf;max-width:100%}button,a.download{background:#234b65;color:white;border:none;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}header button{background:#30536b}button:disabled,input:disabled,select:disabled{opacity:.55;cursor:default}button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #bd7e18;outline-offset:2px}.item{padding:14px 0;border-top:1px solid #e7ecef}.item p{margin:6px 0;overflow-wrap:anywhere}.item .meta{font-size:12px;color:#516575}.item .actions{margin-top:8px}.state{font-weight:700;text-transform:capitalize}#metrics,#graphMetrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(122px,1fr));gap:10px;margin:12px 0}.metric{border:1px solid #dbe2e7;border-radius:8px;padding:12px;display:grid;gap:5px}.metric strong{font-size:23px}.metric span{font-size:12px;text-transform:capitalize;color:#516575}textarea{min-width:0;max-width:100%;width:100%;resize:vertical}.graph-controls,details{display:grid;gap:10px;margin:12px 0;min-width:0}.manifest-text{white-space:pre-wrap;overflow-wrap:anywhere;max-width:100%;max-height:320px;overflow:auto;font-size:12px}.preflight-item{border-left:3px solid #8f9ca7;padding:8px 12px;margin:10px 0;overflow-wrap:anywhere}.preflight-item p{margin:6px 0}.preflight-item a{color:#234b65}.graph-link{border-left:3px solid #b8c6cf;padding:8px 12px;margin:12px 0;min-width:0}.graph-controls button,details button{justify-self:start}#notice{min-height:24px;color:#30536b}#roles{font-size:13px;margin:0}#name{width:min(300px,100%);min-width:0}select,input{min-width:0;max-width:100%;width:100%}select{width:100%;text-overflow:ellipsis;overflow:hidden}.selection-name{display:block;font-size:12px;font-weight:400;overflow-wrap:anywhere;min-width:0;max-width:100%;color:#516575}label>select,label>input,label>textarea{min-inline-size:0;max-inline-size:100%;inline-size:100%}button,a.download{min-height:44px}#notice{overflow-wrap:anywhere}[hidden]{display:none!important}@media(max-width:600px){.controls,form:not(header form){align-items:stretch;flex-direction:column}.controls label,form:not(header form)>label{width:100%;min-width:0;max-width:100%;flex:0 1 auto}.controls select,.controls input{width:100%;max-width:100%;min-width:0;contain:inline-size}.panel button,.panel a.download{max-width:100%;white-space:normal;text-align:center}.panel{padding:14px}select,input{width:100%}#name{contain:inline-size;overflow:hidden}header .actions{max-width:100%;min-width:0}header .actions form{min-width:0;max-width:100%}header{padding:14px 16px}.actions{gap:6px}}';
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
// Native WebKit select popups may retain the intrinsic width of very long
// option text. Keep option labels short and show the exact selected name
// separately as wrapping text. UUID remains the actual selection value.
function namedOption(select,value,text){const chars=Array.from(String(text)),short=chars.length>15?chars.slice(0,10).join('')+'… '+value.slice(-6):String(text);const o=node('option',short);o.value=value;o.setAttribute('aria-label',String(text));select.append(o);}
function selectionNames(){el('selectedTenantName').textContent=tenantRows.find(t=>t.id===tenant.value)?.name??'';el('selectedProjectName').textContent=projects.find(p=>p.id===project.value)?.name??'';}
function button(text,fn){const b=node('button',text);b.type='button';b.addEventListener('click',()=>perform(fn));return b;}
function link(label,url){const a=node('a',label,'download');a.href=url;a.download='';return a;}
function setDisabled(disabled){for(const n of document.querySelectorAll('#workspace button,#workspace input,#workspace select,#workspace textarea,#recipientPanel button,#recipientPanel input,#invitationPanel button,#invitationPanel input'))n.disabled=disabled||n.dataset.unavailable==='yes';}
function clear(){current=null;el('projectContent').hidden=true;el('evidence').replaceChildren();el('requests').replaceChildren();el('roles').textContent='';el('name').value='';el('rename').hidden=true;el('upload').hidden=true;el('archive').hidden=true;el('contractIQ').hidden=true;el('extractCandidates').replaceChildren();el('extractNotice').textContent='';el('extractEvidence').replaceChildren();el('graphPanel').hidden=true;el('graphMetrics').replaceChildren();el('preflightSummary').textContent='';el('preflightActions').replaceChildren();el('preflightLimits').textContent='';el('graphItems').replaceChildren();el('proofLockPanel').hidden=true;el('proofLockSummary').textContent='';el('proofLockTasks').replaceChildren();el('proofLockSchedule').replaceChildren();el('proofLockRules').replaceChildren();el('proofLockLimits').textContent='';el('submissionItems').replaceChildren();el('prepareSubmission').hidden=true;el('ruleTitle').value='';el('ruleCriterion').value='';el('ruleApplicability').value='unknown';el('reportPanel').hidden=true;el('metrics').replaceChildren();el('lifecycle').textContent='';el('permissions').hidden=true;el('sharing').hidden=true;el('directory').replaceChildren();el('shares').replaceChildren();el('issued').hidden=true;el('issuedCode').value='';}
function retryId(key){if(!attempts.has(key)){if(attempts.size>=128)throw Error('Too many pending actions. Refresh this page after checking outcomes.');attempts.set(key,crypto.randomUUID());}return attempts.get(key);}
async function perform(fn){if(busy)return;busy=true;setDisabled(true);try{await fn();}catch(e){say(e.message||'Request failed.');if(e.status===401){clear();el('workspace').hidden=true;el('recipientPanel').hidden=true;el('invitationPanel').hidden=true;el('inviteCode').value='';pendingShare=null;el('receiveCode').value='';} }finally{busy=false;setDisabled(false);}}
async function loadTenantAdmin(){
 const root=el('tenantAdmin');root.hidden=true;el('tenantDirectory').replaceChildren();el('enrollments').replaceChildren();el('transfers').replaceChildren();
 if(!uuid.test(tenant.value))return;
 const base='/api/v1/tenants/'+tenant.value+'/administration',owner=tenantRows.find(t=>t.id===tenant.value)?.role==='owner';
 el('tenantOwnerControls').hidden=!owner;
 const transfers=(await api(base+'/transfers')).items;
 for(const r of transfers){const row=node('div',undefined,'item');row.append(node('p','Transfer '+r.id),node('p',r.completedAt?'Completed':r.acceptedAt?'Accepted; awaiting operator':'Awaiting successor acceptance','state'),node('p','From '+r.fromActor+' to '+r.toActor,'meta'));
  if(r.canAccept)row.append(button('Accept ownership',async()=>{if(!confirm('Accept responsibility for this workspace?'))return;await api(base+'/transfer-accept',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({requestId:r.id})});await loadTenantAdmin();}));el('transfers').append(row);}
 if(owner){
  for(const r of (await api(base+'/enrollments')).items){const row=node('div',undefined,'item');row.append(node('p',r.role+' | '+r.state+' | '+r.id,'meta'));if(r.state==='invited')row.append(button('Cancel invitation',async()=>{if(!confirm('Cancel this invitation?'))return;await api(base+'/invite-cancel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({requestId:r.id})});await loadTenantAdmin();}));el('enrollments').append(row);}
  for(const m of (await api(base+'/directory')).items){const row=node('div',undefined,'item');row.append(node('p',m.actorId),node('p',m.role+' | '+(m.active?'Active':'Inactive'),'meta'));
   if(m.active&&m.role!=='owner'){const select=node('select');select.setAttribute('aria-label','Workspace role');for(const role of ['viewer','contributor','reviewer','revoke'])option(select,role,role);select.value=m.role;
    row.append(select,button('Change tenant access',async()=>{const role=select.value;if(!confirm('This withdraws all existing project permissions. Continue?'))return;const key=base+':access:'+m.actorId+':'+role+':'+m.generation;await api(base+'/access',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({requestId:retryId(key),targetId:m.actorId,role,generation:m.generation})});attempts.delete(key);await loadProjects();}));
    if(m.bound)row.append(button('Nominate successor',async()=>{if(!confirm('Nominate this member? Final transfer removes your workspace access.'))return;const key=base+':transfer:'+m.actorId+':'+m.generation;await api(base+'/transfer-request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({requestId:retryId(key),targetId:m.actorId,generation:m.generation})});attempts.delete(key);await loadTenantAdmin();}));
   }el('tenantDirectory').append(row);
  }
 }
 root.hidden=false;
}
el('enrollTenant').addEventListener('submit',event=>{event.preventDefault();perform(async()=>{const subjectDigest=el('enrollDigest').value.trim(),role=el('enrollRole').value,base='/api/v1/tenants/'+tenant.value+'/administration';if(!/^[a-f0-9]{64}$/.test(subjectDigest))throw Error('Provide the verified lowercase SHA-256 digest.');const key=base+':enroll:'+subjectDigest+':'+role;await api(base+'/enroll',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({requestId:retryId(key),subjectDigest,role})});attempts.delete(key);el('enrollDigest').value='';await loadTenantAdmin();say('Enrollment requested; independent operator approval required.');});});
async function loadProjects(preferred){
 clear();el('tenantAdmin').hidden=true;project.replaceChildren();projects=[];selectionNames();el('creation').hidden=tenantRows.find(t=>t.id===tenant.value)?.role!=='owner';
 if(!uuid.test(tenant.value))return;
 await loadTenantAdmin();
 projects=(await api('/api/v1/tenants/'+tenant.value+'/projects')).items;
 for(const p of projects)if(uuid.test(p.id))namedOption(project,p.id,p.name);
 if(preferred&&projects.some(p=>p.id===preferred))project.value=preferred;
 selectionNames();if(project.options.length)await loadProject();else say('No accessible projects.');
}
async function loadProject(){
 selectionNames();clear();if(!uuid.test(project.value))return;
 const base=path(),data=await api(base+'/releases'),detail=await api(base);
 current={base,data,project:detail.project};el('selectedProjectName').textContent=detail.project.name;el('projectContent').hidden=false;
 el('roles').textContent='Workspace role: '+data.tenantRole+' · Project role: '+data.projectRole;
 el('name').value=detail.project.name;
 const closed=!!detail.project.archivedAt,owner=data.tenantRole==='owner'&&data.projectRole==='owner',reviewer=data.tenantRole==='reviewer'&&data.projectRole==='reviewer';
 el('lifecycle').textContent=closed?'Archived '+detail.project.archivedAt:'Active project';el('archive').hidden=closed||!owner;
 el('rename').hidden=closed||!owner;
 el('upload').hidden=closed||!data.uploadsEnabled||!['owner','reviewer','contributor'].includes(data.tenantRole)||!['owner','reviewer','contributor'].includes(data.projectRole);
 render();await loadGraph();await loadAdministration();
 if(owner||reviewer){const report=await api(base+'/report');el('reportPanel').hidden=false;el('reportDownload').href=base+'/report-download';el('reportDownload').download='';el('reportPdf').href=base+'/report-pdf';el('reportPdf').download='';el('reportPackage').href=base+'/report-package';el('reportPackage').download='';const s=report.summary;for(const [label,value] of [['Evidence',s.evidence],['Encrypted evidence',s.encrypted],['Evidence bytes',s.bytes],['Review requests',s.requests],...Object.entries(s.states)])(()=>{const tile=node('div',undefined,'metric');tile.append(node('strong',String(value)),node('span',label));el('metrics').append(tile);})();}
 say('Workspace ready.');
}
async function graphPost(action,body){
 await api(current.base+'/verification/'+action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
}
function graphField(label,control){const l=node('label',label);control.setAttribute('aria-label',label);l.append(control);return l;}
function graphChoice(options,selected){const s=node('select');for(const [v,t] of options)option(s,v,t);if(selected)s.value=selected;return s;}
const graphApplicability=[['unknown','Unknown'],['required','Required'],['optional','Optional'],['not_applicable','Not applicable']];
function graphReview(row,action,idKey,idValue,choices){
 const s=graphChoice(choices),reason=node('textarea'),a=node('div',undefined,'graph-controls');reason.rows=2;reason.maxLength=512;
 a.append(graphField('Decision',s),graphField('Review reason',reason),button('Record '+(action==='rule-review'?'rule review':action==='dependency-review'?'dependency review':action==='dependency-removal-review'?'dependency removal review':action==='window-review'?'capture rule review':'evidence assessment'),async()=>{
  const why=reason.value.trim();if(!why)throw Error('Provide a review reason.');if(!confirm('Record this immutable review decision?'))return;
  await graphPost(action,{[idKey]:idValue,decision:s.value,reason:why});await loadProject();
 }));row.append(a);
}
function milestoneEditor(root,prior){
 const box=node('details'),title=node('input'),mode=graphChoice([['unknown','Date unknown'],['confirmed','Confirmed date']],prior?.confirmed?'confirmed':'unknown'),local=node('input'),zone=node('input'),offset=node('input');
 title.maxLength=128;title.value=prior?.title??'';local.placeholder='YYYY-MM-DDTHH:MM';local.maxLength=16;local.value=prior?.localTime??'';zone.maxLength=80;zone.value=prior?.timezone??'UTC';offset.type='number';offset.min='-840';offset.max='840';offset.step='1';offset.value=prior?.offsetMinutes??'';
 box.append(node('summary',prior?'Revise milestone schedule':'Create milestone'),graphField('Milestone title',title),graphField('Schedule status',mode),graphField('Local date and time',local),graphField('IANA timezone',zone),graphField('UTC offset minutes',offset),node('p','For a confirmed date, use an explicit offset (Melbourne daylight time: 660, standard time: 600). Unknown schedules must have no date or offset.','meta'),button('Save milestone',async()=>{
  const n=title.value.trim(),tz=zone.value.trim(),confirmed=mode.value==='confirmed',localTime=confirmed?local.value.trim():null,offsetMinutes=confirmed?Number(offset.value):null;
  if(!n||!tz||confirmed&&(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(localTime)||offset.value.trim()===''||!Number.isInteger(offsetMinutes)||offsetMinutes< -840||offsetMinutes>840))throw Error('Enter title, timezone and confirmed local time with explicit UTC offset.');
  if(!confirmed&&(local.value.trim()||offset.value.trim()))throw Error('Clear the local date and offset for an unknown schedule.');
  if(!confirm('Record this schedule revision? Past schedule revisions remain in history.'))return;
  const expectedRevision=prior?.revision??0,key=current.base+':milestone:'+JSON.stringify([prior?.milestoneId??null,expectedRevision,n,confirmed,localTime,tz,offsetMinutes]);
  await graphPost('milestone-write',{milestoneId:prior?.milestoneId??retryId(key+':id'),revisionId:retryId(key+':revision'),expectedRevision,title:n,confirmed,localTime,timezone:tz,offsetMinutes});attempts.delete(key+':id');attempts.delete(key+':revision');await loadProject();say('Milestone schedule saved.');
 }));root.append(box);
}
async function loadProofLock(){
 const {base,data}=current,p=await api(base+'/verification/prooflock'),g=p.assessment,plan=p.plan;
 const tasks=el('proofLockTasks'),schedule=el('proofLockSchedule'),rules=el('proofLockRules');
 tasks.replaceChildren(node('h3','Prioritised evidence tasks'));schedule.replaceChildren(node('h3','Milestone schedules'));rules.replaceChildren(node('h3','Capture rules'));
 const writable=g.canWrite&&!g.archived&&!current.project.archivedAt,reviewer=!g.archived&&!current.project.archivedAt&&data.tenantRole==='reviewer'&&data.projectRole==='reviewer';
 const latest=new Map();for(const m of p.milestones){if(!latest.has(m.milestoneId)||latest.get(m.milestoneId).revision<m.revision)latest.set(m.milestoneId,m);}
 const byReq=new Map(g.requirements.map(q=>[q.requirementId,q]));
 el('proofLockPanel').hidden=false;
 el('proofLockSummary').textContent=plan.summary.total+' evidence tasks · '+plan.summary.critical+' critical · '+plan.summary.overdue+' overdue · '+plan.summary.clarification+' need clarification';
 el('proofLockLimits').textContent=plan.limitations.join(' ');
 if(!plan.tasks.length)tasks.append(node('p','No capture rules defined. Add a milestone and propose a capture rule against an approved criterion.'));
 for(const t of plan.tasks){
  const q=byReq.get(t.requirementId),stage=latest.get(t.milestoneId),row=node('article',undefined,'item'),a=node('a',q?.title??'Requirement');
  a.href='#requirement-'+t.requirementId;
  row.append(a,node('p',(stage?.title??'Unknown milestone')+' | '+t.status.replaceAll('_',' ')+' | '+t.urgency+' priority','state'),node('p','Risk: '+t.risk+' · '+(t.mandatory?'Mandatory':'Non-mandatory'),'meta'),node('p','Capture deadline (UTC): '+(t.deadline??'Not established')),node('p','Planned stage (UTC): '+(t.stage??'Not established')),node('p',t.action));
  if(stage?.confirmed)row.append(node('p','Local planned stage: '+stage.localTime+' '+stage.timezone+' (UTC offset '+stage.offsetMinutes+' min)','meta'));
  if(t.history.length){const history=node('details');history.append(node('summary','Calculated deadline history'));for(const h of t.history)history.append(node('p','Revision '+h.revision+' · '+(h.deadline??'Unknown deadline')+(h.superseded?' · Superseded':' · Current')+(h.deadlineElapsedBeforeSupersessionOrAsOf?' · Deadline elapsed':'')+(h.ruleApprovedDuringOrBeforeRevisionEnd===false?' · Rule was not yet approved':''),'meta'));row.append(history);}
  const win=p.windows.find(w=>w.windowId===t.windowId);
  if(writable&&data.uploadsEnabled&&q?.canLink&&q.versionId===t.versionId&&win?.ruleDecision==='approved'&&stage?.revisionId){
   const box=node('details'),file=node('input');file.type='file';file.accept='.txt,.png,.pdf';
   box.append(node('summary','Capture evidence'),node('p','Upload a supported file directly to this exact capture rule. The server records receipt time, not the original capture time. Independent evidence review is still required.','meta'),graphField('Capture evidence file',file),button('Submit captured evidence',async()=>{
    const f=file.files[0];if(!f||f.size<1||f.size>262144)throw Error('Choose a supported file of 1–262144 bytes.');
    const media=f.type==='image/png'?'image/png':f.type==='application/pdf'?'application/pdf':f.type==='text/plain'||f.name.toLowerCase().endsWith('.txt')?'text/plain; charset=utf-8':null;
    if(!media)throw Error('Unsupported evidence format. Use a supported PNG, text or canonical PDF file.');
    if(!confirm('Upload and link this file for independent review?'))return;
    const bytes=await f.arrayBuffer();try{
     const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join(''),endpoint=base+'/evidence/capture/'+t.windowId+'/'+t.versionId+'/'+stage.revisionId,key=endpoint+':'+media+':'+digest;
     await api(endpoint,{method:'POST',headers:{'Content-Type':media,'Idempotency-Key':retryId(key),'X-Evidence-SHA256':digest},body:bytes});attempts.delete(key);file.value='';await loadProject();say('Captured evidence submitted for independent review.');
    }finally{new Uint8Array(bytes).fill(0);}
   }));row.append(box);
  }
  tasks.append(row);
 }
 if(writable&&latest.size<128)milestoneEditor(schedule);
 if(!latest.size)schedule.append(node('p','No milestone schedules recorded.'));
 for(const m of latest.values()){
  const row=node('article',undefined,'item');row.append(node('h3',m.title),node('p','Revision '+m.revision+' · '+(m.confirmed?'Confirmed planned stage':'Date unknown'),'state'),node('p',m.confirmed?m.localTime+' '+m.timezone+' (UTC offset '+m.offsetMinutes+' min)':'Clarify planned date and time.','meta'));
  const history=node('details');history.append(node('summary','Schedule revisions'));for(const h of p.milestones.filter(x=>x.milestoneId===m.milestoneId))history.append(node('p','Revision '+h.revision+' · '+h.recordedAt+' · '+(h.confirmed?h.localTime+' '+h.timezone+' (UTC offset '+h.offsetMinutes+' min)':'Unknown date'),'meta'));row.append(history);
  if(writable&&m.revision<16)milestoneEditor(row,m);schedule.append(row);
 }
 if(!p.windows.length)rules.append(node('p','No capture rules proposed.'));
 for(const w of p.windows){
  const q=byReq.get(w.requirementId),row=node('article',undefined,'item'),fresh=q?.versionId===w.versionId;
  row.append(node('h3',q?.title??'Requirement'),node('p',(latest.get(w.milestoneId)?.title??'Milestone')+' · '+w.leadMinutes+' min lead · '+w.irreversibility,'meta'),node('p','Rule decision: '+w.ruleDecision+(fresh?'':' · Superseded criterion'),'state'),node('p',w.proposalReason));
  if(w.reviewReason)row.append(node('p',w.reviewReason));
  if(reviewer&&fresh&&w.ruleDecision==='pending')graphReview(row,'window-review','windowId',w.windowId,[['rejected','Reject'],['approved','Approve']]);rules.append(row);
 }
 if(writable&&p.windows.length<256&&latest.size){
  const eligible=g.requirements.filter(q=>q.ruleDecision==='approved'&&['required','optional'].includes(q.applicability)&&[...latest.keys()].some(m=>!p.windows.some(w=>w.versionId===q.versionId&&w.milestoneId===m)));
  if(eligible.length){const box=node('details'),req=node('select'),milestone=node('select'),lead=node('input'),risk=graphChoice([['reversible','Reversible'],['costly','Costly to recreate'],['irreversible','Potentially irreversible']]),why=node('textarea');
   for(const q of eligible)namedOption(req,q.versionId,q.title);
   const refill=()=>{milestone.replaceChildren();for(const m of latest.values())if(!p.windows.some(w=>w.versionId===req.value&&w.milestoneId===m.milestoneId))namedOption(milestone,m.milestoneId,m.title);};
   req.addEventListener('change',refill);refill();lead.type='number';lead.min='0';lead.max='525600';lead.step='1';lead.value='60';why.rows=2;why.maxLength=512;
   box.append(node('summary','Propose capture rule'),graphField('Approved criterion',req),graphField('Planned milestone',milestone),graphField('Evidence review lead minutes',lead),graphField('Evidence irreversibility',risk),graphField('Capture rule justification',why),button('Submit capture rule',async()=>{
    const n=Number(lead.value),reason=why.value.trim();if(!uuid.test(req.value)||!uuid.test(milestone.value)||!lead.value.trim()||!Number.isInteger(n)||n<0||n>525600||!reason)throw Error('Select criterion and milestone, enter whole lead minutes and justification.');
    if(!confirm('Submit this immutable rule for independent review?'))return;
    const key=base+':window:'+JSON.stringify([req.value,milestone.value,n,risk.value,reason]);
    await graphPost('window-propose',{versionId:req.value,milestoneId:milestone.value,windowId:retryId(key),leadMinutes:n,irreversibility:risk.value,reason});attempts.delete(key);await loadProject();say('Capture rule proposed.');
   }));rules.append(box);
  }
 }
}
function renderPreflight(g){
 const pf=g.preflight,items=el('preflightActions');items.replaceChildren();
 if(!pf){el('preflightSummary').textContent='Preflight unavailable.';return;}
 const coverage=pf.mandatoryCoveragePercent===null?'Not assessed':pf.mandatoryCoveragePercent+'% of reviewed mandatory criteria satisfied';
 el('preflightSummary').textContent=coverage+' · '+pf.blockers+' blockers · '+pf.advisories+' advisories'+(pf.archived?' · Archived (read-only)':'');
 el('preflightLimits').textContent=pf.limitations.join(' ');
 if(!pf.issues.length&&!pf.warnings.length)items.append(node('p',pf.status==='not_assessed'?'Define and independently review mandatory criteria before assessment.':'No issues detected in the reviewed subset.'));
 for(const issue of [...pf.issues,...pf.warnings]){
  const rule=g.requirements.find(q=>q.requirementId===issue.requirementId),row=node('div',undefined,'preflight-item'),a=node('a','View requirement');
  row.append(node('p',(issue.level==='blocker'?'Blocker: ':'Advisory: ')+issue.code.replaceAll('_',' '),'state'),node('p',rule?.title??'Requirement'),node('p',issue.action));
  if(issue.responsible)row.append(node('p','Suggested responsible role: '+issue.responsible,'meta'));
  a.href='#requirement-'+issue.requirementId;row.append(a);items.append(row);
 }
}
async function loadSubmissions(g){
 const {base}=current,root=el('submissionItems'),listing=await api(base+'/verification/submission-list');
 root.replaceChildren();el('prepareSubmission').hidden=!(g.canWrite&&g.summary.status==='criteria_satisfied'&&g.requirements.every(x=>['satisfied','not_applicable'].includes(x.state)));
 for(const s of listing.items){
  const row=node('article',undefined,'item'),panel=node('div');row.append(node('p','Submission '+s.id,'meta'),node('p',s.authorizedAt?'Authorized (freshness checked on download)':s.decision??'Awaiting independent review','state'),node('p','Snapshot SHA-256: '+s.sha256,'meta'));
  if(s.reason)row.append(node('p',s.reason));
  row.append(button('Inspect exact snapshot',async()=>{
   const snapshot=await api(base+'/verification/submission-inspect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({submissionId:s.id})});
   if(snapshot.sha256!==s.sha256)throw Error('Snapshot mismatch.');
   const details=node('pre',JSON.stringify(JSON.parse(snapshot.manifest),null,2),'manifest-text');panel.replaceChildren(details);
   const args={submissionId:s.id,sha256:s.sha256};
   if(s.canReview){const choice=graphChoice([['rejected','Reject'],['approved','Approve']]),reason=node('textarea');reason.maxLength=512;reason.rows=2;panel.append(graphField('Decision',choice),graphField('Reason',reason),button('Record submission review',async()=>{
    if(!reason.value.trim()||!confirm('Record an immutable decision on this exact snapshot?'))return;
    await graphPost('submission-review',{...args,decision:choice.value,reason:reason.value.trim()});await loadProject();
   }));}
   if(s.canAuthorize)panel.append(button('Authorize package download',async()=>{if(!confirm('Authorize this exact reviewed package for internal download?'))return;await graphPost('submission-authorize',args);await loadProject();}));
  }));
  row.append(button('Compare current requirements',async()=>{
   const diff=await api(base+'/verification/submission-impact',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({submissionId:s.id})});
   if(diff.baselineSha256!==s.sha256)throw Error('Snapshot mismatch.');
   panel.replaceChildren(node('p',diff.changedCount+' changed · '+diff.unchangedCount+' unchanged · '+diff.currentBlockers+' current blockers'));
   for(const change of diff.changes){const a=node('a',change.requirementId);a.href='#requirement-'+change.requirementId;panel.append(a,node('p',change.reasons.map(x=>x.replaceAll('_',' ')).join(' · ')));}
   panel.append(node('p',diff.scope,'meta'));
  }));
  if(s.canDownload&&listing.downloadEnabled)row.append(button('Download authorized package',async()=>{
   const response=await fetch(base+'/verification/submission-download',{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',headers:{'Content-Type':'application/json'},body:JSON.stringify({submissionId:s.id,sha256:s.sha256})});
   if(!response.ok)throw Error(messages[response.status]||'Package unavailable.');
   const blob=await response.blob();if(blob.size<1||blob.size>20*1024*1024||blob.type!=='application/zip')throw Error('Invalid package.');
   const url=URL.createObjectURL(blob),a=node('a');a.href=url;a.download='submission-'+s.id+'.zip';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);say('Authorized package downloaded.');
  }));
  row.append(panel);root.append(row);
 }
 if(!listing.items.length)root.append(node('p','No submission snapshots.'));
}
el('prepareSubmission').addEventListener('click',()=>perform(async()=>{
 if(!current||!confirm('Freeze the current reviewed criteria and evidence inventory as a submission draft?'))return;
 const key=current.base+':submission';await graphPost('submission-prepare',{submissionId:retryId(key)});attempts.delete(key);await loadProject();say('Submission snapshot prepared.');
}));
async function loadGraph(){
 const {base,data}=current,g=await api(base+'/verification'),items=el('graphItems'),metrics=el('graphMetrics');
 el('graphPanel').hidden=false;el('requirementForm').hidden=!g.canWrite;items.replaceChildren();metrics.replaceChildren();
 const sources=data.evidence.filter(e=>['text/plain; charset=utf-8','application/pdf'].includes(e.mediaType));el('contractIQ').hidden=!(g.canWrite&&g.extractionEnabled&&sources.length);el('extractEvidence').replaceChildren();for(const e of sources)option(el('extractEvidence'),e.id,'Document '+e.id.slice(-8));
 const status={blocked:'Blocked — unresolved requirements',not_assessed:'Not assessed — no mandatory criteria',criteria_satisfied:'Reviewed mandatory criteria satisfied'};
 el('graphStatus').textContent=status[g.summary.status]||'Assessment unavailable';
 renderPreflight(g);
 for(const [label,value] of [['Requirements',g.summary.requirements],['Mandatory criteria',g.summary.required],['Satisfied mandatory',g.summary.verifiedRequired],['Blockers',g.summary.blockers]]){const tile=node('div',undefined,'metric');tile.append(node('strong',String(value)),node('span',label));metrics.append(tile);}
 for(const q of g.requirements){
  const row=node('article',undefined,'item');row.id='requirement-'+q.requirementId;row.append(node('h3',q.title),node('p',q.criterion),node('p','Revision '+q.revision+' | '+q.applicability+' | Rule '+q.ruleDecision,'meta'),node('p',q.state.replaceAll('_',' '),'state'));
  if(q.source){row.append(node('p','Source: '+q.source.evidenceId+' | '+(q.source.page?'Page '+q.source.page+' | ':'')+'Line '+q.source.line,'meta'),node('p','Source SHA-256: '+q.source.sha256,'meta'),node('p','Quote SHA-256: '+q.source.quoteSha256,'meta'),link('Download source document',base+'/evidence/'+q.source.evidenceId+'/download'));}
  if(q.ruleReason)row.append(node('p','Rule review: '+q.ruleReason));
  const pins=q.dependencyPins??[];
  for(const pin of pins){
   const parent=g.requirements.find(x=>x.requirementId===pin.prerequisiteId),box=node('div',undefined,'graph-link');
   const label=node('a',parent?.title??'Prerequisite');label.href='#requirement-'+pin.prerequisiteId;
   box.append(node('strong','Prerequisite: '),label,node('p','Decision: '+pin.decision+' | Current state: '+pin.prerequisiteState.replaceAll('_',' '),'meta'),node('p',pin.pinnedFingerprint===pin.currentFingerprint?'Exact prerequisite pin matches.':'Prerequisite changed — fresh review required.','state'));
   if(pin.reason)box.append(node('p',pin.reason));
   if(g.dependencyManagementEnabled&&!g.archived&&data.tenantRole==='reviewer'&&data.projectRole==='reviewer'&&pin.decision==='pending')graphReview(box,'dependency-review','edgeId',pin.edgeId,[['rejected','Reject'],['approved','Approve']]);
   row.append(box);
  }
  const removals=q.dependencyRemovals??[];
  for(const rm of removals){
   const parent=g.requirements.find(x=>x.requirementId===rm.prerequisiteId),box=node('div',undefined,'graph-link');
   box.append(node('strong','Dependency removal: '+(parent?.title??rm.prerequisiteId)),node('p',rm.proposalReason),node('p','Decision: '+rm.decision,'state'));
   if(rm.reviewReason)box.append(node('p',rm.reviewReason));
   if(g.dependencyRemovalEnabled&&!g.archived&&data.tenantRole==='reviewer'&&data.projectRole==='reviewer'&&rm.decision==='pending')graphReview(box,'dependency-removal-review','removalId',rm.removalId,[['rejected','Reject'],['approved','Approve']]);
   row.append(box);
  }
  const removable=(g.removalCandidates??[]).filter(x=>x.versionId===q.versionId);
  if(g.dependencyRemovalEnabled&&g.canWrite&&q.ruleDecision==='pending'&&removable.length){
   const select=graphChoice(removable.map(x=>[x.prerequisiteId,(g.requirements.find(y=>y.requirementId===x.prerequisiteId)?.title??'Prior dependency')+' · '+x.prerequisiteId.slice(-8)])),reason=node('textarea'),box=node('div',undefined,'graph-controls');reason.rows=2;reason.maxLength=512;
   box.append(graphField('Historical prerequisite to remove',select),graphField('Justification for removal',reason),button('Propose dependency removal',async()=>{
    const why=reason.value.trim();if(!why)throw Error('Provide a removal justification.');
    if(!confirm('Request removal for this exact revision? Independent review is required and historical decisions will remain.'))return;
    const key=base+':remove:'+q.versionId+':'+select.value+':'+why;
    await graphPost('dependency-removal-propose',{versionId:q.versionId,removalId:retryId(key),prerequisiteId:select.value,reason:why});attempts.delete(key);await loadProject();say('Dependency removal proposed.');
   }));row.append(box);
  }
  const prerequisites=g.requirements.filter(x=>x.requirementId!==q.requirementId&&x.state==='satisfied'&&!pins.some(p=>p.prerequisiteId===x.requirementId)&&!removals.some(r=>r.prerequisiteId===x.requirementId));
  if(g.dependencyManagementEnabled&&g.canWrite&&q.ruleDecision==='pending'&&['required','optional'].includes(q.applicability)&&pins.length<8&&prerequisites.length){
   const choice=graphChoice(prerequisites.map(x=>[x.requirementId,x.title+' · '+x.requirementId.slice(-8)])),box=node('div',undefined,'graph-controls');
   box.append(graphField('Satisfied prerequisite',choice),button('Propose dependency',async()=>{
    if(!prerequisites.some(x=>x.requirementId===choice.value)||!confirm('Pin this exact prerequisite assessment? An independent reviewer must approve the dependency.'))return;
    const key=base+':dependency:'+q.versionId+':'+choice.value;
    await graphPost('dependency-propose',{versionId:q.versionId,edgeId:retryId(key),prerequisiteId:choice.value});attempts.delete(key);await loadProject();say('Dependency proposed.');
   }));row.append(box);
  }
  if(q.canReview)graphReview(row,'rule-review','versionId',q.versionId,[['rejected','Reject'],['approved','Approve']]);
  if(q.canRevise){const box=node('details'),title=node('input'),criterion=node('textarea'),app=graphChoice(graphApplicability,q.applicability);title.value=q.title;title.maxLength=128;criterion.value=q.criterion;criterion.maxLength=1024;criterion.rows=3;
   box.append(node('summary','Draft new revision'),graphField('Requirement title',title),graphField('Verification criterion',criterion),graphField('Applicability',app),button('Save new revision',async()=>{
    const t=title.value.trim(),c=criterion.value.trim(),ap=app.value;if(!t||!c)throw Error('Enter a title and criterion.');if(!confirm('New revision requires independent review and does not inherit assessments. Continue?'))return;
    const key=base+':revise:'+q.versionId+':'+JSON.stringify([t,c,ap]);await graphPost('requirement',{requirementId:q.requirementId,versionId:retryId(key),expectedRevision:q.revision,title:t,criterion:c,applicability:ap});attempts.delete(key);await loadProject();
   }));row.append(box);
  }
  for(const l of q.links){const linked=node('div',undefined,'graph-link');linked.append(node('p','Evidence '+l.evidenceId),node('p','SHA-256: '+l.sha256,'meta'),node('p','Assessment: '+l.decision));if(l.reason)linked.append(node('p',l.reason));linked.append(link('Download evidence',base+'/evidence/'+l.evidenceId+'/download'));if(l.canReview)graphReview(linked,'link-review','linkId',l.linkId,[['unknown','Unknown'],['fail','Fail'],['pass','Pass']]);row.append(linked);}
  const candidates=data.evidence.filter(e=>!q.links.some(l=>l.evidenceId===e.id));
  if(q.canLink&&candidates.length){const s=graphChoice(candidates.map(e=>[e.id,'Evidence '+e.id.slice(-8)])),a=node('div',undefined,'graph-controls');
   a.append(graphField('Evidence to link',s),button('Link evidence',async()=>{const e=candidates.find(e=>e.id===s.value);if(!e)throw Error('Select evidence.');const key=base+':link:'+q.versionId+':'+e.id;await graphPost('link',{versionId:q.versionId,linkId:retryId(key),evidenceId:e.id,sha256:e.sha256});attempts.delete(key);await loadProject();}));row.append(a);
  }
  items.append(row);
 }
 if(!g.requirements.length)items.append(node('p','No requirements recorded.'));
 await loadSubmissions(g);
 if(g.proofLockEnabled)await loadProofLock();
}
el('extractForm').addEventListener('submit',event=>{event.preventDefault();perform(async()=>{
 if(!current)return;const {base,data}=current,selected=data.evidence.find(e=>e.id===el('extractEvidence').value);
 if(!selected)throw Error('Select a supported source document.');
 const source={evidenceId:selected.id,sha256:selected.sha256},out=el('extractCandidates'),notice=el('extractNotice');
 out.replaceChildren();notice.textContent='';
 const result=await api(base+'/verification/extract',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(source)});
 notice.textContent=result.candidates.length+' candidates; '+result.skipped+' skipped'+(result.truncated?' (additional candidates not shown)':'')+'. '+result.warning;
 out.append(link('Download original document',base+'/evidence/'+selected.id+'/download'));
 for(const c of result.candidates){const row=node('article',undefined,'item'),app=graphChoice(graphApplicability,'unknown');
  row.append(node('p',(c.page?'Page '+c.page+' · ':'')+'Line '+c.line,'meta'),node('p',c.quote),graphField('Applicability',app),button('Draft from source',async()=>{
   if(!confirm('Create this source-linked draft? An independent reviewer must assess it.'))return;
   const key=base+':source:'+selected.id+':'+c.line+':'+app.value;
   await graphPost('import-source',{...source,line:c.line,quoteSha256:c.quoteSha256,requirementId:retryId(key+':id'),versionId:retryId(key+':version'),applicability:app.value});
   attempts.delete(key+':id');attempts.delete(key+':version');await loadProject();say('Source-linked requirement drafted.');
  }));out.append(row);
 }
});});
el('extractEvidence').addEventListener('change',()=>{el('extractCandidates').replaceChildren();el('extractNotice').textContent='';});
el('requirementForm').addEventListener('submit',event=>{event.preventDefault();perform(async()=>{
 if(!current)return;const title=el('ruleTitle').value.trim(),criterion=el('ruleCriterion').value.trim(),applicability=el('ruleApplicability').value,base=current.base;
 if(!title||!criterion)throw Error('Enter a title and criterion.');
 const key=base+':requirement:'+JSON.stringify([title,criterion,applicability]);
 await graphPost('requirement',{requirementId:retryId(key+':id'),versionId:retryId(key+':version'),expectedRevision:0,title,criterion,applicability});attempts.delete(key+':id');attempts.delete(key+':version');await loadProject();say('Requirement drafted.');
});});
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
tenant.addEventListener('change',()=>perform(loadProjects));project.addEventListener('change',()=>perform(loadProject));el('refresh').addEventListener('click',()=>perform(()=>reloadWorkspaces(tenant.value,project.value)));
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
el('acceptInvite').addEventListener('submit',event=>{event.preventDefault();perform(async()=>{
 const tenantId=el('inviteTenant').value.trim(),requestId=el('inviteRequest').value.trim(),input=el('inviteCode'),code=input.value.trim();
 if(!uuid.test(tenantId)||!uuid.test(requestId)||!/^[A-Za-z0-9_-]{43}$/.test(code))throw Error('Enter the supplied invitation details.');
 await api('/api/v1/tenants/'+tenantId+'/administration/invite-redeem',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({requestId,code})});
 input.value='';await reloadWorkspaces(tenantId);say('Invitation accepted.');
});});
async function reloadWorkspaces(preferredTenant,preferredProject){
 const data=await api('/api/v1/workspaces');tenantRows=data.items;tenant.replaceChildren();el('recipientPanel').hidden=false;el('invitationPanel').hidden=false;
 for(const t of data.items)if(uuid.test(t.id))namedOption(tenant,t.id,t.name);
 if(preferredTenant&&tenantRows.some(t=>t.id===preferredTenant))tenant.value=preferredTenant;
 el('workspace').hidden=false;
 selectionNames();if(tenant.options.length)await loadProjects(tenant.value===preferredTenant?preferredProject:undefined);
 else{clear();project.replaceChildren();el('tenantAdmin').hidden=true;el('creation').hidden=true;say('No accessible workspaces.');}
}
perform(()=>reloadWorkspaces());
`;
