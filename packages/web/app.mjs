import {labelFor,parseLabel,qrMatrix} from '/app/qr-label.mjs';
import {textareaSpan,selectedAmount,currentSources} from '/app/source-selection.mjs';
import {unlockVault,deleteVault} from '/app/capture-vault.mjs';
import {createUploadQueue} from '/app/upload-queue.mjs';
const $=id=>document.getElementById(id),root=$('content');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
let session=null,model=null,tab='overview',epoch=0,busy=false,captureLabel='';
const id=()=>crypto.randomUUID();
let captures=createUploadQueue(),vault=null;
function scopeParts(){return [...session.base.matchAll(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g)].map(m=>m[0]).concat(valid(model.c.actorId));}
function lockLocal(){vault?.close();vault=null;captures.close();captures=createUploadQueue();}
async function persist(){if(vault)await vault.save(captures.snapshot());}
const online=()=>navigator.onLine!==false;
function valid(s){if(!UUID.test(s))throw Error('Invalid identifier.');return s;}
function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=String(text);if(cls)e.className=cls;return e;}
function add(e,...c){e.append(...c);return e;}
function panel(title){return add(el('section',undefined,'panel'),el('h2',title));}
function note(s,error=false){$('notice').textContent=s;$('notice').dataset.error=String(error);}
async function run(fn){if(busy)return;busy=true;root.setAttribute('aria-busy','true');const g=epoch;note('Working…');try{await fn();if(g===epoch&&$('notice').textContent==='Working…')note('Done.');}catch(e){if(g===epoch)note(e.message||'Request failed.',true);}finally{busy=false;root.setAttribute('aria-busy','false');}}
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
async function refresh(){const g=epoch;const [project,r,c,f,corrections]=await Promise.all([req(''),req('/readiness'),req('/catalog'),req('/finance'),req('/correction-plans')]);if(g!==epoch)return;if(model?.c.actorId&&model.c.actorId!==c.actorId){reset();throw Error('Authenticated actor changed. Reconnect.');}model={project,r,c,f,corrections};$('project-name').textContent=project.name;render();}
function reset(){epoch++;captureLabel='';lockLocal();session=null;model=null;tab='overview';root.replaceChildren();$('project-name').textContent='';$('portal-results').replaceChildren();$('login').reset();$('portal-form').reset();$('workspace').hidden=true;$('portal').hidden=true;$('connect').hidden=false;$('disconnect').hidden=true;note('Disconnected.');$('login').elements.tenant.focus();}
$('login').addEventListener('submit',e=>{e.preventDefault();const f=new FormData($('login'));run(async()=>{const t=valid(v(f,'tenant')),p=valid(v(f,'project')),token=v(f,'token').trim();if(!/^[A-Za-z0-9_.-]+$/.test(token))throw Error('Invalid token.');session={base:'/v1/tenants/'+t+'/projects/'+p,auth:'Bearer '+token};$('login').elements.token.value='';try{await refresh();$('connect').hidden=true;$('workspace').hidden=false;$('disconnect').hidden=false;note('Connected.');}catch(e){reset();note(e.message,true);}});});
$('disconnect').addEventListener('click',reset);$('refresh').addEventListener('click',()=>run(refresh));
$('nav').addEventListener('click',e=>{const b=e.target.closest('[data-tab]');if(b&&model&&!busy){tab=b.dataset.tab;render();const heading=root.querySelector('h2');if(heading){heading.tabIndex=-1;heading.focus();}}});
function render(){root.replaceChildren();for(const b of $('nav').querySelectorAll('button')){if(b.dataset.tab===tab)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');}({overview,documents,prooflock,resolve,handover}[tab])();}
function item(...c){return add(el('article',undefined,'item'),...c);}
function state(s){return el('span',s,'state');}
function metric(t,n){return add(el('div',undefined,'metric'),el('small',t),el('strong',n));}
const options=()=>model.c.requirements.map(r=>[r.versionId,r.kind+' · '+r.expected]);
function labelledCheck(name,value,label,checked=false){const l=el('label'),c=el('input');c.type='checkbox';c.name=name;c.value=value;c.checked=checked;l.append(c,document.createTextNode(label));return l;}
function selectDefault(n,label,items,def){const q=choice(n,label,items);if(def!==undefined&&items.some(([k])=>k===def))q.querySelector('select').value=def;return q;}
function pickSource(host,callback,initial){
 const sources=currentSources(model.c);if(!sources.length){host.append(el('p','No current reviewed sources. Approve an extracted revision first.'));return;}
 const wrapper=el('div',undefined,'source-picker');
 const selector=selectDefault('source-version','Current reviewed source',sources.map(x=>[x.versionId,x.title]),initial);
 const area=el('div');wrapper.append(selector,button('Load source pages',async()=>{
 const source=sources.find(x=>x.versionId===selector.querySelector('select').value);if(!source)throw Error('Select source.');
 const draft=await req('/uploads/'+source.uploadId+'/review');area.replaceChildren();
 for(const page of draft.pages){
 const text=el('textarea');text.readOnly=true;text.rows=6;text.value=page.text_value;text.setAttribute('aria-label','Exact text, page '+page.page);
 const card=item(el('h3','Page '+page.page+' · '+page.method),el('p','Select the exact excerpt in the text field, then use the selection.','muted'),text,button('Use selected text',()=>{const span=textareaSpan(page,text.value,text.selectionStart,text.selectionEnd);callback(source,span);}));
 area.append(card);
 }
 }),area);selector.querySelector('select').addEventListener('change',()=>area.replaceChildren());host.append(wrapper);
}
function financeEditor(host,existing){
 const editor=panel(existing?'Revise financial record':'Create financial record');
 editor.append(el('p','Select an exact reviewed amount in AUD. Tax basis and retention date are reviewer-entered assertions, not automatically interpreted legal terms.','muted'));
 const details=el('div');pickSource(editor,(source,span)=>{
 const amount=selectedAmount(span);details.replaceChildren(el('p','Selected: '+span.quote+' · '+source.title+' · page '+span.page));
 const conditions=el('fieldset');conditions.append(el('legend','Current documentary conditions (optional)'));
 for(const r of model.c.requirements)conditions.append(labelledCheck('condition',r.versionId,r.kind+' · '+r.expected,!!existing?.conditions?.some(c=>c.id===r.id&&c.revision===r.revision)));
 const fields=[field('title','Record title','text',existing?.title??''),selectDefault('category','Category',existing?[[existing.category,existing.category]]:[['milestone','Milestone'],['retention','Retention']],existing?.category),selectDefault('tax','Tax basis',[['inclusive','Inclusive'],['exclusive','Exclusive']],existing?.taxBasis),field('release','Recorded retention date (optional)','date',existing?.releaseOn??''),conditions];
 const recordId=existing?.id??id(),spanId=id();
 details.append(form(fields,'Save financial revision',async f=>{
 const category=v(f,'category'),releaseOn=v(f,'release')||null;
 if(releaseOn&&category!=='retention')throw Error('Retention date only applies to retention.');
 if(!v(f,'title').trim())throw Error('Enter a title.');
 if(!confirm('Save this source-linked financial record? This does not establish a payment entitlement.'))return;
 await post('/finance',{id:recordId,priorRevision:existing?.revision??0,category,title:v(f,'title').trim(),amount,taxBasis:v(f,'tax'),spanId,documentVersionId:source.versionId,...span,releaseOn,conditionVersionIds:f.getAll('condition').map(String)});await refresh();
 }));
 },existing?.sourceId);
 editor.append(details);host.append(editor);
}
function disputeEditor(host,x){
 const events=(model.f.events??[]).filter(e=>e.financeId===x.id);
 const history=(model.f.history??[]).filter(e=>e.id===x.id);
 const box=item(el('h3','Dispute chronology'),el('p','Events are member assertions, not independent evidence of delivery or payment.','muted'));
 for(const e of events)box.append(item(state(e.type),el('p',e.note),el('small','Occurred: '+(e.occurredAt??'unknown')+' · Recorded: '+e.recordedAt)));
 for(const r of history)box.append(el('small','Revision '+r.revision+' · AUD '+r.amount+' · '+r.recordedAt));
 const eventId=id();
 box.append(form([choice('type','Event type',['submission-asserted','delivery-asserted','receipt-asserted','acceptance-asserted','rejection-asserted','disputed','correction','payment-asserted','note'].map(x=>[x,x])),field('occurred','Occurred UTC ISO (blank unknown)'),field('note','Event details'),choice('document','Related current document',[['','None'],...currentSources(model.c).map(s=>[s.versionId,s.title])]),choice('handover','Related handover draft',[['','None'],...model.c.drafts.map(d=>[d.id,'Generation '+d.generation])])],'Record dispute event',async f=>{
 const instant=v(f,'occurred').trim();if(instant&&!/Z$/.test(instant))throw Error('Use UTC timestamp ending in Z.');
 if(!v(f,'note').trim())throw Error('Enter an event note.');
 if(!confirm('Record this event as a member assertion?'))return;
 await post('/finance/events',{id:eventId,financeId:x.id,financeRevision:x.revision,type:v(f,'type'),occurredAt:instant?new Date(instant).toISOString():null,note:v(f,'note').trim(),documentVersionId:v(f,'document')||null,handoverId:v(f,'handover')||null});await refresh();
 }),button('Export dispute draft',async()=>{const r=await req('/finance/'+x.id+'/dispute-pack');if(await digest(new TextEncoder().encode(r.json))!==r.sha256)throw Error('Dispute draft hash mismatch.');download(new Blob([r.json],{type:'application/json'}),'dispute-draft.json');}));
 host.append(box);
}
function relationEditor(host,existing){
 const editor=panel(existing?'Revise contract relationship':'Record contract relationship');
 editor.append(el('p','Choose an exact clause from the current amendment. The relationship records reviewer judgment, not automatic legal precedence.','muted'));
 const details=el('div');pickSource(editor,(source,span)=>{
 const bases=currentSources(model.c).filter(x=>x.documentId!==source.documentId);
 details.replaceChildren(el('p',span.quote));if(!bases.length){details.append(el('p','A separate reviewed base document is required.'));return;}
 const recordId=existing?.id??id(),spanId=id();
 details.append(form([selectDefault('base','Base document',bases.map(x=>[x.versionId,x.title]),existing?.baseVersionId),selectDefault('relation','Relationship',['amends','supersedes','qualifies','conflicts'].map(x=>[x,x]),existing?.relation),selectDefault('state','Review state',(existing?['unresolved','reviewed','withdrawn']:['unresolved','reviewed']).map(x=>[x,x]),existing?.state),field('note','Review explanation','text',existing?.note??'')],'Save contract relationship',async f=>{
 if(!v(f,'note').trim())throw Error('A review explanation is required.');
 if(!confirm('Record this relationship and exact source excerpt? Original documents will remain unchanged.'))return;
 await post('/contract-relations',{id:recordId,priorRevision:existing?.revision??0,amendmentVersionId:source.versionId,baseVersionId:v(f,'base'),spanId,...span,relation:v(f,'relation'),state:v(f,'state'),note:v(f,'note').trim()});await refresh();
 }));
 },existing?.amendmentVersionId);editor.append(details);host.append(editor);
}
function overview(){const r=model.r,p=panel('Project readiness');p.append(state(r.ready?'Configured checks ready':'Review required'),el('p',r.label,'muted'),add(el('div',undefined,'grid'),metric('Verified',r.verified+'/'+r.confirmed),metric('Blockers',r.blockers),metric('Workflow blockers',r.operationalBlockers),metric('Coverage',r.coverage===null?'—':Math.round(r.coverage*100)+'%')),el('p',r.scopeConfirmed?'Scope confirmed':'Scope unconfirmed'),button('Confirm configured scope',async()=>{if(confirm('Confirm only the configured documentary scope?')){await post('/scope/confirm',{generation:r.generation});await refresh();}}));root.append(p);
 const f=panel('Financial intelligence');f.append(el('p',model.f.label,'muted'));for(const x of model.f.totals)f.append(item(el('h3',x.category+' · '+x.taxBasis),el('p','AUD '+x.recorded+' recorded'),el('small','AUD '+x.configuredConditionsMet+' documentary conditions met')));for(const x of model.f.items){const card=item(el('h3',x.title),el('p','AUD '+x.amount),state(x.status),el('p',x.retentionStatus??''));card.append(button('Revise financial record',()=>{card.querySelector('.record-editor')?.remove();const area=el('div',undefined,'record-editor');financeEditor(area,x);card.append(area);}),button('Dispute records',()=>{card.querySelector('.dispute-editor')?.remove();const area=el('div',undefined,'dispute-editor');disputeEditor(area,x);card.append(area);}));f.append(card);}f.append(button('New financial record',()=>{f.querySelector('.new-finance')?.remove();const area=el('div',undefined,'new-finance');financeEditor(area,null);f.append(area);}));root.append(f);}
async function digest(b){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',b))].map(x=>x.toString(16).padStart(2,'0')).join('');}
function captureList(p){
 const list=el('div',undefined,'capture-list');
 const jobs=captures.list();list.append(el('p',(online()?'Connection available.':'Offline.')+' '+jobs.length+' capture(s). '+(vault?'Encrypted device vault unlocked.':'Session-only; unsent files are lost on reload.'),'muted'));
 if(vault)list.append(button('Lock device vault',async()=>{await persist();lockLocal();render();note('Vault locked. Reconnect and unlock to resume.');}));
 else if(model.c.actorId){const pass=field('passphrase','Unique device vault passphrase (16+ characters)','password');pass.querySelector('input').autocomplete='new-password';
 const f=form([pass],'Unlock / create encrypted vault',async(data)=>{const g=epoch;if(captures.list().length)throw Error('Synchronise or discard existing session captures before unlocking.');if(!confirm('Store encrypted files on this device? Browser storage can be erased; keep originals and remember your unique passphrase.'))return;
 const opened=await unlockVault(scopeParts(),v(data,'passphrase'));if(g!==epoch){opened.close();throw Error('Session changed.');}vault=opened;for(const j of opened.jobs)captures.enqueue(j);opened.jobs.length=0;render();note('Encrypted vault unlocked.');});
 f.addEventListener('submit',()=>{pass.querySelector('input').value='';});list.append(f,button('Delete local encrypted vault',async()=>{if(!confirm('Permanently delete this project and actor’s local encrypted captures, including unsent files?'))return;await deleteVault(scopeParts());note('Local vault deleted.');}));}
 for(const j of jobs)list.append(item(el('h3',j.title||'Existing document revision'),state(j.stage),el('p',j.bytes+' bytes'),button('Retry capture',async()=>{await syncCapture(j.intentId);}),button('Discard local capture',async()=>{if(confirm('Discard the local file? Server-side records already created will remain.')){if(vault)await vault.save(captures.snapshot().filter(x=>x.intentId!==j.intentId));captures.discard(j.intentId);render();}})));
 p.append(list);
}
async function syncCapture(k){
 if(!online()){note('Offline. Capture retained '+(vault?'in encrypted device storage.':'in this tab.'));return;}
 const g=epoch;await persist();if(g!==epoch)throw Error('Session changed.');
 try{await captures.flush(k,(path,body,raw)=>raw===undefined?post(path,body):req(path,{method:'PUT',raw}));}
 catch(e){render();throw Error(e.message+' Capture retained; retry uses the same identifiers.');}
 if(g!==epoch)return;
 try{await persist();}catch{render();throw Error('Server acknowledged quarantine; encrypted vault cleanup failed. Reopen vault and replay safely.');}
 render();await refresh();note('Quarantined. Refresh after worker processing.');
}
function documents(){const p=panel('Upload a document');p.append(el('p','Capture now, synchronise when connected. Files enter quarantine before extraction. Optional encrypted device storage; five files / 50 MiB total. Unlock after connecting. Keep original copies.','muted'),form([field('title','New title'),choice('document','Existing document or new',[['','New'],...model.c.documents.map(d=>[d.id,d.title])]),field('file','PDF, image or text','file'),field('marker','ProofLock label (optional)','text',captureLabel)],'Capture file',async f=>{
 const file=f.get('file');if(!(file instanceof File)||file.size<1||file.size>52428800)throw Error('Select a file up to 50 MiB.');
 const mime=file.type||({pdf:'application/pdf',jpg:'image/jpeg',jpeg:'image/jpeg',png:'image/png',txt:'text/plain'}[file.name.split('.').pop().toLowerCase()]);if(!['application/pdf','image/jpeg','image/png','text/plain'].includes(mime))throw Error('Unsupported format.');
 const title=v(f,'title').trim(),existing=v(f,'document');if(!existing&&(!title||title.length>250))throw Error('Enter a valid title.');
 const g=epoch,d=existing||id(),u=id(),sha256=await digest(await file.arrayBuffer());if(g!==epoch)throw Error('Session changed.');
 const marker=v(f,'marker').trim(),link=marker?parseLabel(marker):{};if(marker&&!model.r.milestones.some(m=>m.id===link.milestoneId&&m.revision===link.milestoneRevision))throw Error('Label is not a current milestone in this project. Refresh.');captures.enqueue({documentId:d,intentId:u,title,newDocument:!existing,sha256,mediaType:mime,file,...link});captureLabel='';try{await persist();}catch(e){render();throw Error('Encrypted save failed; file remains in this tab. '+e.message);}if(g!==epoch)throw Error('Session changed.');render();if(online())await syncCapture(u);else note('Captured offline. Retry when connected.');
 }));captureList(p);root.append(p);
 const list=panel('Document inventory');for(const d of model.c.documents){const card=item(el('h3',d.title),el('p','Revision '+d.revision));for(const u of d.uploads){const row=item(state(u.state),el('small',u.mediaType+' · '+u.bytes+' bytes'),...(u.milestoneId?[el('p','ProofLock '+u.milestoneId+' · revision '+u.milestoneRevision,'muted')]:[]));if(['reviewed','extraction-complete'].includes(u.state))row.append(button('Review extracted source',()=>review(row,d,u)));card.append(row);}list.append(card);}root.append(list);}
function originalReview(box,u){
 box.append(button('Open verified original',async()=>{
 const blob=await req('/uploads/'+u.id+'/original',{download:true});if(await digest(await blob.arrayBuffer())!==u.sha256)throw Error('Original hash mismatch.');
 const area=el('div',undefined,'original-preview');box.querySelector('.original-preview')?.remove();
 area.append(el('p','Original hash checked. Fresh scanner approval required for this retrieval.','muted'));
 if(u.mediaType==='text/plain'&&blob.size<=1048576)area.append(el('pre',new TextDecoder('utf-8',{fatal:true}).decode(await blob.arrayBuffer())));
 else area.append(el('p','For safety, PDFs and images are provided as attachments rather than embedded active content.'));
 area.append(button('Save original attachment',()=>download(blob,u.id+({'application/pdf':'.pdf','image/png':'.png','image/jpeg':'.jpg','text/plain':'.txt'}[u.mediaType]??'.bin'))));box.append(area);
 }));
}
async function review(row,d,u){const a=await req('/uploads/'+u.id+'/review');const b=await post('/uploads/'+u.id+'/intelligence',{useProvider:false});row.querySelector('.detail')?.remove();const box=el('div',undefined,'detail');for(const p of a.pages)box.append(el('h3','Page '+p.page+' · '+p.method),el('pre',p.text_value));box.append(el('p','Compare the original independently. OCR may be inaccurate.','muted'));originalReview(box,u);
 if(u.state!=='reviewed')box.append(button('Approve extracted revision',async()=>{if(confirm('Have you compared this extraction with the original?')){await post('/uploads/'+u.id+'/promote',{id:id(),priorRevision:d.revision,sourceSha256:u.sha256,textDigest:a.textDigest});await refresh();}}));
 if(u.state==='reviewed')for(const c of b.candidates){box.append(item(el('p',c.quote),state(c.tags.join(', ')),form([field('kind','Criterion type'),field('expected','Exact expected text'),choice('mandatory','Mandatory',[['true','Yes'],['false','No']]),choice('old','Requirement',[['','New'],...model.c.requirements.map(r=>[r.id,r.kind+' · '+r.expected])])],'Approve requirement',async f=>{if(!v(f,'expected')||!c.quote.includes(v(f,'expected')))throw Error('Expected text must occur in quote.');if(!confirm('Approve this exact source requirement?'))return;
 const decision=id(),old=model.c.requirements.find(r=>r.id===v(f,'old'));await post('/uploads/'+u.id+'/review',{id:decision,page:c.page,start:c.start,end:c.end,quote:c.quote,textSha256:c.textSha256,decision:'approved',kind:v(f,'kind'),expected:v(f,'expected'),mandatory:v(f,'mandatory')==='true'});await post('/decisions/'+decision+'/promote',{requirementId:old?.id??id(),versionId:id(),priorRevision:old?.revision??0,spanId:id()});await refresh();})));}row.append(box);}
function editMilestone(m){const opts=model.c.requirements.filter(r=>r.id===m.requirementId).map(r=>[r.versionId,r.kind+' · '+r.expected]);if(!opts.length)return el('p','Replacement requirement unavailable.');return form([choice('req','Current requirement',opts),field('date','UTC ISO milestone (blank unknown)','text',m.milestone??''),field('lead','Lead minutes','number',m.leadMinutes)],'Revise schedule',async f=>{const x=v(f,'date').trim();if(x&&!/Z$/.test(x))throw Error('Use UTC ending in Z.');await post('/prooflock',{id:m.id,priorRevision:m.revision,requirementVersionId:v(f,'req'),title:m.title,milestone:x?new Date(x).toISOString():null,confirmed:!!x,leadMinutes:Number(v(f,'lead')),irreversibility:m.irreversibility});await refresh();});}
function qrLabel(m){
 const text=labelFor(m.id,m.revision),matrix=qrMatrix(text),canvas=el('canvas');canvas.width=canvas.height=296;canvas.setAttribute('aria-label','QR pointer for '+m.title);const c=canvas.getContext('2d');c.fillStyle='white';c.fillRect(0,0,296,296);c.fillStyle='black';for(let y=0;y<29;y++)for(let x=0;x<29;x++)if(matrix[y][x])c.fillRect((x+4)*8,(y+4)*8,8,8);
 return item(el('h3','Capture label'),canvas,el('pre',text),el('p','Pointer only; no access credentials. Scan into a QR reader or paste the label.','muted'),button('Save QR label',async()=>{const b=await new Promise(r=>canvas.toBlob(r,'image/png'));if(!b)throw Error('QR image unavailable.');download(b,'prooflock-label.png');}),button('Capture for this milestone',()=>{captureLabel=text;tab='documents';render();}));
}
function scanLabelControl(p){
 const f=form([field('label','Paste scanned ProofLock label')],'Use capture label',d=>{const s=v(d,'label').trim(),l=parseLabel(s);if(!model.r.milestones.some(m=>m.id===l.milestoneId&&m.revision===l.milestoneRevision))throw Error('Unknown or stale milestone.');captureLabel=s;tab='documents';render();});p.append(f);
 if('BarcodeDetector' in globalThis)p.append(form([field('image','QR photo','file')],'Read QR photo',async f=>{const file=f.get('image');if(!(file instanceof File)||!file.size||file.size>10485760)throw Error('Select a QR image up to 10 MiB.');const bitmap=await createImageBitmap(file);try{const result=await new BarcodeDetector({formats:['qr_code']}).detect(bitmap);if(result.length!==1)throw Error('Exactly one QR code required.');const s=result[0].rawValue,l=parseLabel(s);if(!model.r.milestones.some(m=>m.id===l.milestoneId&&m.revision===l.milestoneRevision))throw Error('Unknown or stale milestone.');captureLabel=s;tab='documents';render();}finally{bitmap.close();}}));
}
function prooflock(){const p=panel('ProofLock · evidence deadlines');for(const m of model.r.milestones)p.append(item(el('h3',m.title),state(m.status),el('p','Deadline: '+(m.due??'Unconfirmed')),editMilestone(m),button('Show capture QR',()=>{p.querySelector('.active-label')?.remove();const box=el('div',undefined,'active-label');box.append(qrLabel(m));p.append(box);})));scanLabelControl(p);if(options().length)p.append(form([field('title','Milestone'),choice('req','Requirement',options()),field('date','UTC ISO milestone (blank unknown)'),field('lead','Lead minutes','number','120'),choice('risk','Risk',[['irreversible','Irreversible'],['costly','Costly'],['reversible','Reversible']])],'Add milestone',async f=>{const x=v(f,'date').trim();if(x&&!/Z$/.test(x))throw Error('Use a UTC timestamp ending in Z.');await post('/prooflock',{id:id(),priorRevision:0,requirementVersionId:v(f,'req'),title:v(f,'title'),milestone:x?new Date(x).toISOString():null,confirmed:!!x,leadMinutes:Number(v(f,'lead')),irreversibility:v(f,'risk')});await refresh();}));root.append(p);}
function correctionEditor(host,n){
 const existing=model.corrections.plans.find(x=>x.noticeId===n.id),c=model.r.cases.find(x=>x.id===n.id);
 if(existing){host.append(item(state(existing.state+(existing.current?'':' · stale')),el('p','Assigned reviewer: '+existing.assignee),el('p','Proposed filename: '+existing.filename),el('p',existing.coverNote),el('small','Original SHA256 '+existing.originalSha256)));
 if(existing.current&&existing.state==='draft')host.append(button('Approve exact correction draft',async()=>{if(!confirm('Approve metadata and cover sheet only? No original changes or release.'))return;await post('/correction-plans',{noticeId:n.id,priorRevision:existing.revision,caseRevision:existing.caseRevision,assignee:existing.assignee,documentVersionId:existing.documentVersionId,filename:existing.filename,coverNote:existing.coverNote,state:'approved'});await refresh();}));
 if(existing.current&&existing.state==='approved')host.append(button('Download approved correction cover',async()=>download(await req('/correction-plans/'+n.id+'/cover',{download:true}),'correction-cover.pdf')));
 }
 const sources=currentSources(model.c);
 if(c?.state==='open'&&sources.length&&model.corrections.reviewers.length){
 host.append(form([selectDefault('assignee','Assign reviewer',model.corrections.reviewers.map(a=>[a,a===model.c.actorId?'Me · '+a:a]),existing?.assignee??model.c.actorId),selectDefault('source','Correction target',sources.map(x=>[x.versionId,x.title]),existing?.documentVersionId),field('filename','Proposed filename (include original file extension)','text',existing?.filename??''),field('cover','Cover sheet note','text',existing?.coverNote??'')],'Save correction draft',async f=>{await post('/correction-plans',{noticeId:n.id,priorRevision:existing?.revision??0,caseRevision:c.revision,assignee:v(f,'assignee'),documentVersionId:v(f,'source'),filename:v(f,'filename'),coverNote:v(f,'cover'),state:'draft'});await refresh();}));
 }
}
function resolve(){const p=panel('Resolve documentary gaps');for(const f of model.r.findings){const r=model.c.requirements.find(r=>r.id===f.requirementId),card=item(el('h3',r?r.kind+' · '+r.expected:f.requirementId),state(f.status),el('p',f.reason));if(r)card.append(button('Find candidate evidence',async()=>{const a=await req('/requirements/'+r.id+'/suggestions');card.querySelector('.matches')?.remove();const box=el('div',undefined,'matches');for(const x of a.candidates)box.append(item(el('p',x.quote),el('small','Page '+x.page+' · '+x.documentVersionId),button('Approve evidence',async()=>{if(confirm('Confirm you reviewed this independent source?')){await post('/evidence',{id:id(),requirementVersionId:r.versionId,spanId:id(),documentVersionId:x.documentVersionId,page:x.page,start:x.start,end:x.end,quote:x.quote,textSha256:x.textSha256,decision:'approved'});await refresh();}})));if(!a.candidates.length)box.append(el('p','No current bounded literal matches.'));for(const x of (a.contextual??[]))box.append(item(el('h4',x.classification==='potential-mismatch'?'Potential discrepancy':'Formatting variation'),el('p',x.quote),el('small','Page '+x.page+' · '+x.documentVersionId),el('p','Expected: '+x.expected+' · Observed: '+x.observed),el('p',x.recommendation,'muted')));if(a.truncated)box.append(el('p','Search limits reached. Results are incomplete.','muted'));card.append(box);}));p.append(card);}root.append(p);
 const notices=panel('RejectionDNA · correction drafts');
 notices.append(el('p','Import the exact objection from a reviewed notice. Unknown objections remain blockers until mapped and resolved. Drafts never edit originals.','muted'));
 const assigned=model.corrections.plans.filter(x=>x.assignedToMe&&x.current);notices.append(el('p',assigned.length+' current correction assignment(s) for you. Refresh for updates.','muted'));
 for(const n of model.r.rejectionNotices??[]){
 const card=item(state(n.status),el('p',n.quote),el('small','Notice '+n.documentVersionId+' · page '+n.page),el('p',n.current?'Current source':'Historical notice source'));
 for(const task of n.draft.tasks)card.append(item(el('h4',task.category),el('p',task.recommendation)));
 for(const event of n.history)card.append(item(el('small','Revision '+event.revision+' · '+event.state+' · '+event.recordedAt),el('p',event.note)));
 if(!n.caseId&&options().length)card.append(form([choice('req','Approved requirement',options()),field('note','Mapping rationale')],'Open linked correction case',async f=>{if(!v(f,'note').trim())throw Error('Explain the mapping.');if(!confirm('Link this exact objection to the selected requirement?'))return;await post('/rejections',{id:n.id,priorRevision:0,requirementVersionId:v(f,'req'),state:'open',note:v(f,'note')});await refresh();}));
 correctionEditor(card,n);notices.append(card);
 }
 const sources=currentSources(model.c);if(sources.length){const picker=choice('notice-source','Reviewed notice for automatic suggestions',sources.map(x=>[x.uploadId,x.title+' · '+x.versionId])),results=el('div');notices.append(picker,button('Suggest objections from notice',async()=>{const source=sources.find(x=>x.uploadId===picker.querySelector('select').value);const result=await req('/uploads/'+source.uploadId+'/objections');results.replaceChildren(el('p',result.label,'muted'));if(result.truncated)results.append(el('p','Incomplete extraction; inspect the original manually.','muted'));for(const x of result.candidates)results.append(item(el('p',x.quote),el('small',x.categories.join(', ')),button('Import suggested objection',async()=>{if(!confirm('Preserve this exact objection?'))return;await post('/rejection-notices',{id:id(),spanId:id(),documentVersionId:source.versionId,page:x.page,start:x.start,end:x.end,quote:x.quote,textSha256:x.textSha256});await refresh();})));}),results);}
 notices.append(button('Import rejection objection',()=>{notices.querySelector('.notice-editor')?.remove();const editor=el('div',undefined,'notice-editor'),details=el('div');pickSource(editor,(source,span)=>{const noticeId=id(),spanId=id();details.replaceChildren(el('p',span.quote),button('Confirm import',async()=>{if(!confirm('Preserve this exact external objection as a review blocker?'))return;await post('/rejection-notices',{id:noticeId,spanId,documentVersionId:source.versionId,...span});await refresh();}));});editor.append(details);notices.append(editor);}));
 root.append(notices);
 const cases=panel('Rejection cases');for(const c of model.r.cases){const current=model.c.requirements.find(r=>r.id===c.requirementId),stale=current&&current.versionId!==c.requirementVersionId;const card=item(state(c.state),el('p',c.note),el('small',c.id));if(stale)card.append(form([field('note','Rebind explanation')],'Reopen against current requirement',async f=>{await post('/rejections',{id:c.id,priorRevision:c.revision,requirementVersionId:current.versionId,state:'open',note:v(f,'note')});await refresh();}));else card.append(form([field('note','Review note')],c.state==='open'?'Record resolution':'Reopen',async f=>{await post('/rejections',{id:c.id,priorRevision:c.revision,requirementVersionId:c.requirementVersionId,state:c.state==='open'?'resolution-recorded':'open',note:v(f,'note')});await refresh();}));cases.append(card);}if(options().length)cases.append(form([choice('req','Requirement',options()),field('note','Rejection details')],'Open case',async f=>{await post('/rejections',{id:id(),priorRevision:0,requirementVersionId:v(f,'req'),state:'open',note:v(f,'note')});await refresh();}));root.append(cases);
 const rel=panel('Contract relationships');for(const x of model.r.contractRelations??[]){const card=item(state(x.relation+' · '+x.state),el('p',x.quote),el('p',x.note));card.append(button('Revise relationship',()=>{card.querySelector('.relation-editor')?.remove();const area=el('div',undefined,'relation-editor');relationEditor(area,x);card.append(area);}));rel.append(card);}rel.append(button('New contract relationship',()=>{rel.querySelector('.new-relation')?.remove();const area=el('div',undefined,'new-relation');relationEditor(area,null);rel.append(area);}));root.append(rel);}
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
$('portal-open').addEventListener('click',()=>{if(busy)return;epoch++;$('connect').hidden=true;$('portal').hidden=false;$('portal-form').elements.release.focus();});
$('portal-back').addEventListener('click',reset);
$('portal-form').addEventListener('submit',e=>{
 e.preventDefault();if(busy)return;
 // Never keep a previous capability visible after a new access attempt, even when it fails.
 const f=new FormData($('portal-form')),box=$('portal-results');epoch++;box.replaceChildren();
 $('portal-form').elements.secret.value='';
 run(async()=>{
 const g=epoch,guard=()=>{if(g!==epoch||$('portal').hidden)throw Error('Portal session changed.');};
 const release=valid(v(f,'release')),token=v(f,'secret').trim();if(!/^[A-Za-z0-9_-]{43}$/.test(token))throw Error('Invalid share token.');
 const share='Share '+token,path='/v1/shared-index/'+release,result=await req(path,{share});
 if(await digest(new TextEncoder().encode(result.json))!==result.sha256)throw Error('Index hash mismatch.');guard();
 const index=JSON.parse(result.json);if(!Array.isArray(index.documents)||index.documents.length>200)throw Error('Invalid selected index.');
 for(const d of index.documents)valid(d.documentVersionId);
 box.replaceChildren(el('h2','Selected documents'),el('p','Hash checked; signature trust requires independently provisioned public key.','muted'));
 for(const d of index.documents)box.append(item(el('h3','Revision '+d.revision),el('small',d.documentVersionId),el('p',d.originalSha256)));
 box.append(button('Check approved originals',async()=>{
 guard();const r=await req(path+'/bundle',{share});if(await digest(new TextEncoder().encode(r.json))!==r.sha256)throw Error('Bundle hash mismatch.');guard();
 const ids=JSON.parse(r.json).originalDocumentVersionIds;if(!Array.isArray(ids)||ids.length>50||new Set(ids).size!==ids.length)throw Error('Invalid original selection.');
 ids.forEach(valid);box.querySelector('.original-options')?.remove();const originals=el('div',undefined,'original-options');
 for(const x of ids)originals.append(button('Download '+x,async()=>{guard();const blob=await req(path+'/originals/'+x,{share,download:true});guard();const document=index.documents.find(d=>d.documentVersionId===x);if(!document||await digest(await blob.arrayBuffer())!==document.originalSha256)throw Error('Original hash mismatch.');guard();download(blob,x);}));
 box.append(originals);
 }));note('Index opened.');
 });
});
