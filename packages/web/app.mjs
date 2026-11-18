import {createUploadQueue} from '/app/upload-queue.mjs';
const $=id=>document.getElementById(id),root=$('content');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
let session=null,model=null,tab='overview',epoch=0,busy=false;
const id=()=>crypto.randomUUID();
let captures=createUploadQueue();
const online=()=>navigator.onLine!==false;
function valid(s){if(!UUID.test(s))throw Error('Invalid identifier.');return s;}
function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=String(text);if(cls)e.className=cls;return e;}
function add(e,...c){e.append(...c);return e;}
function panel(title){return add(el('section',undefined,'panel'),el('h2',title));}
function note(s){$('notice').textContent=s;}
async function run(fn){if(busy)return;busy=true;const g=epoch;note('Working…');try{await fn();if(g===epoch&&$('notice').textContent==='Working…')note('Done.');}catch(e){if(g===epoch)note(e.message||'Request failed.');}finally{busy=false;}}
function button(text,fn){const b=el('button',text);b.type='button';b.addEventListener('click',()=>run(fn));return b;}
function field(n,label,type='text',v=''){const l=el('label',label),i=el('input');i.name=n;i.type=type;if(type!=='file')i.value=v;l.append(i);return l;}
function choice(n,label,items){const l=el('label',label),s=el('select');s.name=n;for(const [v,t] of items){const o=el('option',t);o.value=v;s.append(o);}l.append(s);return l;}
function form(fields,text,fn){const f=el('form');f.append(...fields,el('button',text));f.addEventListener('submit',e=>{e.preventDefault();const data=new FormData(f);run(()=>fn(data));});return f;}
const v=(f,n)=>String(f.get(n)??'');
async function req(path,{method='GET',body,raw,share,download=false}={}){
 const g=epoch,authorization=share??session?.auth;
 if(!authorization)throw Error('Connect first.');
 const url=share?path:session.base+path;if(!url.startsWith('/v1/'))throw Error('Invalid scope.');
 const headers={authorization};let data;if(raw!==undefined){headers['content-type']='application/octet-stream';data=raw;}else if(body!==undefined){headers['content-type']='application/json';data=JSON.stringify(body);}
 const r=await fetch(url,{method,headers,body:data,cache:'no-store',redirect:'error',credentials:'omit',signal:AbortSignal.timeout(40000)});
 if(g!==epoch)throw Error('Session changed.');
 if(!r.ok)throw Error(({401:'Invalid or expired access token.',404:'Resource unavailable or permission denied.',409:'Revision conflict. Refresh and retry.',422:'Upload integrity check failed.',503:'Service unavailable.'})[r.status]??'Request rejected ('+r.status+').');
 const result=download?await r.blob():await r.json();if(g!==epoch)throw Error('Session changed.');return result;
}
const post=(p,b)=>req(p,{method:'POST',body:b});
async function refresh(){const g=epoch;const [project,r,c,f]=await Promise.all([req(''),req('/readiness'),req('/catalog'),req('/finance')]);if(g!==epoch)return;model={project,r,c,f};$('project-name').textContent=project.name;render();}
function reset(){epoch++;captures.close();captures=createUploadQueue();session=null;model=null;tab='overview';root.replaceChildren();$('project-name').textContent='';$('portal-results').replaceChildren();$('login').reset();$('portal-form').reset();$('workspace').hidden=true;$('portal').hidden=true;$('connect').hidden=false;$('disconnect').hidden=true;note('Disconnected.');}
$('login').addEventListener('submit',e=>{e.preventDefault();const f=new FormData($('login'));run(async()=>{const t=valid(v(f,'tenant')),p=valid(v(f,'project')),token=v(f,'token').trim();if(!/^[A-Za-z0-9_.-]+$/.test(token))throw Error('Invalid token.');session={base:'/v1/tenants/'+t+'/projects/'+p,auth:'Bearer '+token};$('login').elements.token.value='';try{await refresh();$('connect').hidden=true;$('workspace').hidden=false;$('disconnect').hidden=false;note('Connected.');}catch(e){reset();note(e.message);}});});
$('disconnect').addEventListener('click',reset);$('refresh').addEventListener('click',()=>run(refresh));
$('nav').addEventListener('click',e=>{const b=e.target.closest('[data-tab]');if(b&&model&&!busy){tab=b.dataset.tab;render();}});
function render(){root.replaceChildren();for(const b of $('nav').querySelectorAll('button')){if(b.dataset.tab===tab)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');}({overview,documents,prooflock,resolve,handover}[tab])();}
function item(...c){return add(el('article',undefined,'item'),...c);}
function state(s){return el('span',s,'state');}
function metric(t,n){return add(el('div',undefined,'metric'),el('small',t),el('strong',n));}
const options=()=>model.c.requirements.map(r=>[r.versionId,r.kind+' · '+r.expected]);
function overview(){const r=model.r,p=panel('Project readiness');p.append(state(r.ready?'Configured checks ready':'Review required'),el('p',r.label,'muted'),add(el('div',undefined,'grid'),metric('Verified',r.verified+'/'+r.confirmed),metric('Blockers',r.blockers),metric('Workflow blockers',r.operationalBlockers),metric('Coverage',r.coverage===null?'—':Math.round(r.coverage*100)+'%')),el('p',r.scopeConfirmed?'Scope confirmed':'Scope unconfirmed'),button('Confirm configured scope',async()=>{if(confirm('Confirm only the configured documentary scope?')){await post('/scope/confirm',{generation:r.generation});await refresh();}}));root.append(p);
 const f=panel('Financial intelligence');f.append(el('p',model.f.label,'muted'));for(const x of model.f.totals)f.append(item(el('h3',x.category+' · '+x.taxBasis),el('p','AUD '+x.recorded+' recorded'),el('small','AUD '+x.configuredConditionsMet+' documentary conditions met')));for(const x of model.f.items)f.append(item(el('h3',x.title),el('p','AUD '+x.amount),state(x.status),el('p',x.retentionStatus??'')));root.append(f);}
async function digest(b){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',b))].map(x=>x.toString(16).padStart(2,'0')).join('');}
function captureList(p){
 const list=el('div',undefined,'capture-list');
 const jobs=captures.list();list.append(el('p',(online()?'Connection available.':'Offline.')+' '+jobs.length+' session capture(s). Keep this tab open; unsent files are discarded on disconnect or reload.','muted'));
 for(const j of jobs)list.append(item(el('h3',j.title||'Existing document revision'),state(j.stage),el('p',j.bytes+' bytes'),button('Retry capture',async()=>{await syncCapture(j.intentId);}),button('Discard local capture',()=>{if(confirm('Discard the local file? Server-side records already created will remain.')){captures.discard(j.intentId);render();}})));
 p.append(list);
}
async function syncCapture(k){
 if(!online()){note('Offline. Capture retained in this tab.');return;}
 try{await captures.flush(k,(path,body,raw)=>raw===undefined?post(path,body):req(path,{method:'PUT',raw}));}
 catch(e){render();throw Error(e.message+' Capture retained; retry uses the same identifiers.');}
 render();await refresh();note('Quarantined. Refresh after worker processing.');
}
function documents(){const p=panel('Upload a document');p.append(el('p','Capture now, synchronise when connected. Files enter quarantine before extraction. Local queue is memory-only and limited to five files / 50 MiB total.','muted'),form([field('title','New title'),choice('document','Existing document or new',[['','New'],...model.c.documents.map(d=>[d.id,d.title])]),field('file','PDF, image or text','file')],'Capture file',async f=>{
 const file=f.get('file');if(!(file instanceof File)||file.size<1||file.size>52428800)throw Error('Select a file up to 50 MiB.');
 const mime=file.type||({pdf:'application/pdf',jpg:'image/jpeg',jpeg:'image/jpeg',png:'image/png',txt:'text/plain'}[file.name.split('.').pop().toLowerCase()]);if(!['application/pdf','image/jpeg','image/png','text/plain'].includes(mime))throw Error('Unsupported format.');
 const title=v(f,'title').trim(),existing=v(f,'document');if(!existing&&(!title||title.length>250))throw Error('Enter a valid title.');
 const g=epoch,d=existing||id(),u=id(),sha256=await digest(await file.arrayBuffer());if(g!==epoch)throw Error('Session changed.');
 captures.enqueue({documentId:d,intentId:u,title,newDocument:!existing,sha256,mediaType:mime,file});render();if(online())await syncCapture(u);else note('Captured offline. Retry when connected.');
 }));captureList(p);root.append(p);
 const list=panel('Document inventory');for(const d of model.c.documents){const card=item(el('h3',d.title),el('p','Revision '+d.revision));for(const u of d.uploads){const row=item(state(u.state),el('small',u.mediaType+' · '+u.bytes+' bytes'));if(['reviewed','extraction-complete'].includes(u.state))row.append(button('Review extracted source',()=>review(row,d,u)));card.append(row);}list.append(card);}root.append(list);}
async function review(row,d,u){const a=await req('/uploads/'+u.id+'/review');const b=await post('/uploads/'+u.id+'/intelligence',{useProvider:false});row.querySelector('.detail')?.remove();const box=el('div',undefined,'detail');for(const p of a.pages)box.append(el('h3','Page '+p.page+' · '+p.method),el('pre',p.text_value));box.append(el('p','Compare the original independently. OCR may be inaccurate.','muted'));
 if(u.state!=='reviewed')box.append(button('Approve extracted revision',async()=>{if(confirm('Have you compared this extraction with the original?')){await post('/uploads/'+u.id+'/promote',{id:id(),priorRevision:d.revision,sourceSha256:u.sha256,textDigest:a.textDigest});await refresh();}}));
 if(u.state==='reviewed')for(const c of b.candidates){box.append(item(el('p',c.quote),state(c.tags.join(', ')),form([field('kind','Criterion type'),field('expected','Exact expected text'),choice('mandatory','Mandatory',[['true','Yes'],['false','No']]),choice('old','Requirement',[['','New'],...model.c.requirements.map(r=>[r.id,r.kind+' · '+r.expected])])],'Approve requirement',async f=>{if(!v(f,'expected')||!c.quote.includes(v(f,'expected')))throw Error('Expected text must occur in quote.');if(!confirm('Approve this exact source requirement?'))return;
 const decision=id(),old=model.c.requirements.find(r=>r.id===v(f,'old'));await post('/uploads/'+u.id+'/review',{id:decision,page:c.page,start:c.start,end:c.end,quote:c.quote,textSha256:c.textSha256,decision:'approved',kind:v(f,'kind'),expected:v(f,'expected'),mandatory:v(f,'mandatory')==='true'});await post('/decisions/'+decision+'/promote',{requirementId:old?.id??id(),versionId:id(),priorRevision:old?.revision??0,spanId:id()});await refresh();})));}row.append(box);}
function editMilestone(m){const opts=model.c.requirements.filter(r=>r.id===m.requirementId).map(r=>[r.versionId,r.kind+' · '+r.expected]);if(!opts.length)return el('p','Replacement requirement unavailable.');return form([choice('req','Current requirement',opts),field('date','UTC ISO milestone (blank unknown)','text',m.milestone??''),field('lead','Lead minutes','number',m.leadMinutes)],'Revise schedule',async f=>{const x=v(f,'date').trim();if(x&&!/Z$/.test(x))throw Error('Use UTC ending in Z.');await post('/prooflock',{id:m.id,priorRevision:m.revision,requirementVersionId:v(f,'req'),title:m.title,milestone:x?new Date(x).toISOString():null,confirmed:!!x,leadMinutes:Number(v(f,'lead')),irreversibility:m.irreversibility});await refresh();});}
function prooflock(){const p=panel('ProofLock · evidence deadlines');for(const m of model.r.milestones)p.append(item(el('h3',m.title),state(m.status),el('p','Deadline: '+(m.due??'Unconfirmed')),editMilestone(m)));if(options().length)p.append(form([field('title','Milestone'),choice('req','Requirement',options()),field('date','UTC ISO milestone (blank unknown)'),field('lead','Lead minutes','number','120'),choice('risk','Risk',[['irreversible','Irreversible'],['costly','Costly'],['reversible','Reversible']])],'Add milestone',async f=>{const x=v(f,'date').trim();if(x&&!/Z$/.test(x))throw Error('Use a UTC timestamp ending in Z.');await post('/prooflock',{id:id(),priorRevision:0,requirementVersionId:v(f,'req'),title:v(f,'title'),milestone:x?new Date(x).toISOString():null,confirmed:!!x,leadMinutes:Number(v(f,'lead')),irreversibility:v(f,'risk')});await refresh();}));root.append(p);}
function resolve(){const p=panel('Resolve documentary gaps');for(const f of model.r.findings){const r=model.c.requirements.find(r=>r.id===f.requirementId),card=item(el('h3',r?r.kind+' · '+r.expected:f.requirementId),state(f.status),el('p',f.reason));if(r)card.append(button('Find candidate evidence',async()=>{const a=await req('/requirements/'+r.id+'/suggestions');card.querySelector('.matches')?.remove();const box=el('div',undefined,'matches');for(const x of a.candidates)box.append(item(el('p',x.quote),el('small','Page '+x.page+' · '+x.documentVersionId),button('Approve evidence',async()=>{if(confirm('Confirm you reviewed this independent source?')){await post('/evidence',{id:id(),requirementVersionId:r.versionId,spanId:id(),documentVersionId:x.documentVersionId,page:x.page,start:x.start,end:x.end,quote:x.quote,textSha256:x.textSha256,decision:'approved'});await refresh();}})));if(!a.candidates.length)box.append(el('p','No current literal matches.'));card.append(box);}));p.append(card);}root.append(p);
 const cases=panel('Rejection cases');for(const c of model.r.cases)cases.append(item(state(c.state),el('p',c.note),form([field('note','Review note')],c.state==='open'?'Record resolution':'Reopen',async f=>{await post('/rejections',{id:c.id,priorRevision:c.revision,requirementVersionId:c.requirementVersionId,state:c.state==='open'?'resolution-recorded':'open',note:v(f,'note')});await refresh();})));if(options().length)cases.append(form([choice('req','Requirement',options()),field('note','Rejection details')],'Open case',async f=>{await post('/rejections',{id:id(),priorRevision:0,requirementVersionId:v(f,'req'),state:'open',note:v(f,'note')});await refresh();}));root.append(cases);
 const rel=panel('Contract relationships');for(const x of model.r.contractRelations??[])rel.append(item(state(x.relation+' · '+x.state),el('p',x.quote),el('p',x.note)));root.append(rel);}
function download(blob,name){const url=URL.createObjectURL(blob),a=el('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function selections(list,label){const box=el('fieldset');box.append(el('legend',label));for(const d of list){const l=el('label',d.title),c=el('input');c.type='checkbox';c.name='selected';c.value=d.id;l.prepend(c);box.append(l);}return box;}
const selected=f=>f.getAll('selected').map(String);
function releaseManager(p){
 if(model.c.role!=='owner')return;
 const section=panel('Owner release management');section.append(el('p','Metadata and original-file access are separate. Never send access secrets through an untrusted channel.','muted'));
 for(const r of model.c.releases??[]){
 const card=item(el('h3','Selected document release'),state(r.current?'Current':'Stale — access denied'),el('small',r.id));
 if(r.current){
 if(!r.originalDocumentVersionIds.length){const docs=r.documentVersionIds.map(x=>({id:x,title:model.c.documents.find(d=>d.currentVersionId===x)?.title??x}));
 card.append(form([selections(docs,'Approve originals separately')],'Freeze original selection',async f=>{const ids=selected(f);if(!ids.length)throw Error('Choose at least one original.');if(!confirm('Explicitly allow original bytes for this selection? This selection is frozen after approval.'))return;await post('/index-releases/'+r.id+'/approve-originals',{documentVersionIds:ids});await refresh();}));
 }
 const grantForm=original=>form([field('ttl','Lifetime in minutes (1–10080)','number','60')],original?'Create original-file grant':'Create metadata grant',async f=>{
 const ttl=Number(v(f,'ttl'));if(!Number.isSafeInteger(ttl)||ttl<1||ttl>10080)throw Error('Invalid lifetime.');if(!confirm('Create a transferable, time-limited access token?'))return;
 const gid=id(),result=await post('/index-releases/'+r.id+(original?'/original-grants':'/grants'),{id:gid,ttlSeconds:ttl*60});await refresh();const secretBox=panel('Copy access credentials now');secretBox.append(el('p','This secret is not retrievable again. Closing this view clears it.','muted'),el('pre','Release ID: '+r.id+'\nGrant ID: '+gid+'\nToken: '+result.token));root.prepend(secretBox);
 });
 card.append(grantForm(false));if(r.originalDocumentVersionIds.length)card.append(grantForm(true));
 }
 for(const g of r.grants)card.append(item(el('p',(g.originalAccess?'Original file':'Metadata')+' access'),state(g.revoked?'Revoked':g.expired?'Expired':r.current?'Active':'Stale'),el('small',g.id),el('p','Expiry '+g.expiresAt),...(!g.revoked?[button('Revoke grant',async()=>{if(confirm('Revoke future access? Previously downloaded copies cannot be recalled.')){await post('/index-grants/'+g.id+'/revoke',{});await refresh();}})]:[])));
 section.append(card);
 }p.append(section);
}
function handover(){const p=panel('Handover · immutable drafts');p.append(button('Create draft',async()=>{await post('/handover',{id:id(),generation:model.r.generation});await refresh();}));
 for(const d of model.c.drafts){const card=item(state(d.stale?'Stale historical draft':'Current draft'),el('p','Generation '+d.generation));for(const k of ['pdf','xlsx','zip'])card.append(button(k.toUpperCase(),async()=>download(await req('/handover/'+d.id+'/export/'+k,{download:true}),'handover-draft.'+k)));
 if(model.c.role==='owner'&&!d.stale&&model.r.scopeConfirmed){const docs=model.c.documents.filter(x=>x.currentVersionId).map(x=>({id:x.currentVersionId,title:x.title}));if(docs.length)card.append(form([selections(docs,'Select document metadata only')],'Approve selected index',async f=>{const ids=selected(f);if(!ids.length)throw Error('Choose documents.');if(!confirm('Approve only this document metadata index, not full handover?'))return;await post('/handover/'+d.id+'/approve-index',{id:id(),generation:d.generation,documentVersionIds:ids});await refresh();}));}
 p.append(card);}releaseManager(p);root.append(p);}
window.addEventListener('online',()=>{if(tab==='documents'&&model&&!busy)render();});
window.addEventListener('offline',()=>{if(tab==='documents'&&model&&!busy)render();});
$('portal-open').addEventListener('click',()=>{$('connect').hidden=true;$('portal').hidden=false;});
$('portal-back').addEventListener('click',reset);
$('portal-form').addEventListener('submit',e=>{e.preventDefault();const f=new FormData($('portal-form'));run(async()=>{const release=valid(v(f,'release')),token=v(f,'secret').trim();if(!/^[A-Za-z0-9_-]{43}$/.test(token))throw Error('Invalid share token.');$('portal-form').elements.secret.value='';const share='Share '+token,path='/v1/shared-index/'+release;const result=await req(path,{share});if(await digest(new TextEncoder().encode(result.json))!==result.sha256)throw Error('Index hash mismatch.');const box=$('portal-results');box.replaceChildren(el('h2','Selected documents'),el('p','Hash checked; signature trust requires independently provisioned public key.','muted'));for(const d of JSON.parse(result.json).documents)box.append(item(el('h3','Revision '+d.revision),el('small',d.documentVersionId),el('p',d.originalSha256)));box.append(button('Check approved originals',async()=>{const r=await req(path+'/bundle',{share});if(await digest(new TextEncoder().encode(r.json))!==r.sha256)throw Error('Bundle hash mismatch.');for(const x of JSON.parse(r.json).originalDocumentVersionIds){valid(x);box.append(button('Download '+x,async()=>download(await req(path+'/originals/'+x,{share,download:true}),x)));}}));note('Index opened.');});});
