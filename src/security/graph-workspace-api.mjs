import {createHash} from 'node:crypto';
import {buildRejectionPreflight} from './rejection-preflight.mjs';
import {compareSubmissionGraph} from './change-impact.mjs';
import {resolveLocalMilestone} from './prooflock-planner.mjs';
import {validateAlertPolicy} from './prooflock-insights.mjs';
import {decimalToMinor} from './financial-intelligence.mjs';
import {buildDraftHandoverPdf,normalizeHandoverConfig} from './handover-templates.mjs';
import {UnsupportedExtraction} from './contractiq-extraction.mjs';
import {EvidenceAccessDenied} from './evidence-retrieval.mjs';
import {verifyIdentityToken} from './verify-identity.mjs';
import {decodeStrictJson} from './provider-identity.mjs';
import {ReleaseDenied,ReleaseConflict} from './evidence-release.mjs';
const U='([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',route=new RegExp('^/api/v1/tenants/'+U+'/projects/'+U+'/verification(?:/(requirement|rule-review|link|link-review|dependency-propose|dependency-review|dependency-removal-propose|dependency-removal-review|prooflock|milestone-write|window-propose|window-review|alert-policy-write|recovery-propose|recovery-review|financial-summary|financial-write|financial-review|project-intelligence|project-intelligence-export|chronology-write|chronology-review|ack-list|ack-grant|ack-revoke|ack-record|resolution-list|resolution-assign|resolution-advance|extract|import-source|submission-list|submission-inspect|submission-impact|submission-prepare|submission-review|submission-authorize|submission-download|submission-handover|submission-register|submission-workbook|submission-custom|draft-handover|customer-package-grant|customer-package-revoke|customer-package-preview|customer-package-download|customer-package-list))?$'),id=new RegExp('^'+U+'$'),v4=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,hash=/^[a-f0-9]{64}$/;
export function isGraphWorkspaceRequest(req){return typeof req.url==='string'&&route.test(req.url);}
export function isGraphWorkspaceMutation(req){return req.method==='POST'&&typeof req.url==='string'&&!!route.exec(req.url)?.[3]&&!['submission-list','prooflock','financial-summary','project-intelligence','project-intelligence-export','ack-list','resolution-list','draft-handover','customer-package-list'].includes(route.exec(req.url)[3]);}
function response(res,status,data){
 if(res.destroyed||res.writableEnded)return;
 const body=JSON.stringify(data);if(Buffer.byteLength(body)>4*1024*1024)throw Error('workspace response limit');
 res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",'Cross-Origin-Resource-Policy':'same-origin','Connection':'close','Content-Length':Buffer.byteLength(body)});res.end(body);
}
function denied(res,status){return response(res,status,{error:status===401?'authentication_required':status===404?'not_found':status===409?'conflict':status===429?'rate_limited':status===503?'temporarily_unavailable':'request_denied'});}
async function read(req,action){
 let n=0;const chunks=[],timer=setTimeout(()=>req.destroy(),3000);timer.unref();
 try{
  for await(const c of req){n+=c.length;if(n>8192||n>Number(req.headers['content-length']))throw Error('invalid body');chunks.push(c);}
  if(n!==Number(req.headers['content-length']))throw Error('invalid body');
  const v=decodeStrictJson(Buffer.concat(chunks).toString('base64url'));
  const shapes={'submission-inspect':['submissionId'],'submission-impact':['submissionId'],'submission-prepare':['submissionId'],'submission-review':['submissionId','sha256','decision','reason'],'submission-authorize':['submissionId','sha256'],'submission-download':['submissionId','sha256'],'submission-handover':['submissionId','sha256'],'submission-register':['submissionId','sha256'],'submission-workbook':['submissionId','sha256'],'submission-custom':['submissionId','sha256','configuration'],'customer-package-grant':['grantId','submissionId','sha256','recipientId','minutes'],'customer-package-revoke':['grantId'],'customer-package-preview':['grantId'],'customer-package-download':['grantId','submissionId','sha256'],extract:['evidenceId','sha256'],'import-source':['evidenceId','sha256','line','quoteSha256','requirementId','versionId','applicability'],requirement:['requirementId','versionId','expectedRevision','title','criterion','applicability'],'rule-review':['versionId','decision','reason'],link:['versionId','linkId','evidenceId','sha256'],'link-review':['linkId','decision','reason'],'dependency-propose':['versionId','edgeId','prerequisiteId'],'dependency-review':['edgeId','decision','reason'],'dependency-removal-propose':['versionId','removalId','prerequisiteId','reason'],'dependency-removal-review':['removalId','decision','reason'],'milestone-write':['milestoneId','revisionId','expectedRevision','title','confirmed','localTime','timezone','offsetMinutes'],'window-propose':['versionId','windowId','milestoneId','leadMinutes','irreversibility','reason'],'window-review':['windowId','decision','reason'],'alert-policy-write':['policyId','expectedRevision','timezone','quietStart','quietEnd','criticalOverride'],'recovery-propose':['recoveryId','windowId','revisionId','versionId','evidenceId','sha256','approach','reason'],'recovery-review':['recoveryId','decision','reason'],'financial-write':['recordId','versionId','expectedRevision','reference','kind','title','currency','taxBasis','amount','dueAt','sourceEvidenceId','sourceSha256','conditionVersions'],'financial-review':['versionId','decision','reason'],'chronology-write':['eventId','submissionId','submissionSha256','type','description','assertedAt','sourceEvidenceId','sourceSha256'],'chronology-review':['eventId','decision','reason'],'ack-grant':['grantId','submissionId','sha256','recipientId','hours'],'ack-revoke':['grantId'],'ack-record':['grantId','eventId','sha256','kind','reason'],'resolution-assign':['taskId','versionId','assigneeId','reason'],'resolution-advance':['taskId','eventId','expectedRevision','kind','reason']},keys=shapes[action];
  if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).length!==keys.length||keys.some(k=>!Object.hasOwn(v,k)))throw Error('invalid fields');
  const isId=k=>typeof v[k]==='string'&&v[k].length===36&&id.test(v[k]),isV4=k=>typeof v[k]==='string'&&v[k].length===36&&v4.test(v[k]);
  const text=(x,n)=>typeof x==='string'&&[...x].length>=1&&[...x].length<=n&&Buffer.byteLength(x)<=4*n&&x===x.trim()&&!/[\x00-\x1f\x7f-\x9f\ud800-\udfff]/u.test(x);
  if(action.startsWith('customer-package-')){
   if(!isId('grantId'))throw Error('invalid share');
   if(['customer-package-grant','customer-package-download'].includes(action)&&(!isV4('submissionId')||typeof v.sha256!=='string'||!hash.test(v.sha256)))throw Error('invalid package');
   if(action==='customer-package-grant'&&(!isV4('grantId')||!isId('recipientId')||!Number.isInteger(v.minutes)||v.minutes<1||v.minutes>60))throw Error('invalid grant');
  }else if(action.startsWith('submission-')){
   if(!isV4('submissionId'))throw Error('invalid submission');
   if(!['submission-prepare','submission-inspect','submission-impact'].includes(action)&&(typeof v.sha256!=='string'||v.sha256.length!==64||!hash.test(v.sha256)))throw Error('invalid digest');
   if(action==='submission-custom')normalizeHandoverConfig(v.configuration);
   if(action==='submission-review'&&(!['approved','rejected'].includes(v.decision)||!text(v.reason,512)))throw Error('invalid review');
  }else if(action==='extract'||action==='import-source'){
   if(!isId('evidenceId')||typeof v.sha256!=='string'||v.sha256.length!==64||!hash.test(v.sha256))throw Error('invalid source');
   if(action==='import-source'&&(!isV4('requirementId')||!isV4('versionId')||!Number.isInteger(v.line)||v.line<1||v.line>262144||typeof v.quoteSha256!=='string'||v.quoteSha256.length!==64||!hash.test(v.quoteSha256)||!['required','optional','not_applicable','unknown'].includes(v.applicability)))throw Error('invalid source line');
  }else if(action==='requirement'){
   if(!isV4('requirementId')||!isV4('versionId')||!Number.isInteger(v.expectedRevision)||v.expectedRevision<0||v.expectedRevision>15||!text(v.title,128)||!text(v.criterion,1024)||!['required','optional','not_applicable','unknown'].includes(v.applicability))throw Error('invalid requirement');
  }else if(action==='milestone-write'){
   if(!isV4('milestoneId')||!isV4('revisionId')||!Number.isInteger(v.expectedRevision)||v.expectedRevision<0||v.expectedRevision>15||!text(v.title,128)||typeof v.confirmed!=='boolean'||typeof v.timezone!=='string'||v.timezone.length>80||!/^(?:UTC|[A-Za-z][A-Za-z0-9_+.-]*(?:\/[A-Za-z0-9_+.-]+)+)$/.test(v.timezone))throw Error('invalid milestone');
   new Intl.DateTimeFormat('en',{timeZone:v.timezone});
   if(v.confirmed)resolveLocalMilestone(v.localTime,v.timezone,v.offsetMinutes);
   else if(v.localTime!==null||v.offsetMinutes!==null)throw Error('unknown milestone cannot specify time');
  }else if(action==='window-propose'){
   if(!isId('versionId')||!isV4('windowId')||!isId('milestoneId')||!Number.isInteger(v.leadMinutes)||v.leadMinutes<0||v.leadMinutes>525600||!['reversible','costly','irreversible'].includes(v.irreversibility)||!text(v.reason,512))throw Error('invalid window');
  }else if(action==='ack-grant'){
   if(!isV4('grantId')||!isId('submissionId')||!isId('recipientId')||typeof v.sha256!=='string'||!hash.test(v.sha256)||!Number.isInteger(v.hours)||v.hours<1||v.hours>168)throw Error('invalid grant');
  }else if(action==='ack-revoke'){
   if(!isId('grantId'))throw Error('invalid grant');
  }else if(action==='ack-record'){
   if(!isId('grantId')||!isV4('eventId')||typeof v.sha256!=='string'||!hash.test(v.sha256)||!['receipt_attested','acceptance_attested','rejection_attested'].includes(v.kind)||!text(v.reason,512))throw Error('invalid acknowledgement');
  }else if(action==='resolution-assign'){
   if(!isV4('taskId')||!isId('versionId')||!isId('assigneeId')||!text(v.reason,512))throw Error('invalid assignment');
  }else if(action==='resolution-advance'){
   if(!isId('taskId')||!isV4('eventId')||!Number.isInteger(v.expectedRevision)||v.expectedRevision<0||v.expectedRevision>15||!['submitted','returned','closed'].includes(v.kind)||!text(v.reason,512))throw Error('invalid transition');
  }else if(action==='chronology-write'){
   if(!isV4('eventId')||!isId('sourceEvidenceId')||typeof v.sourceSha256!=='string'||!hash.test(v.sourceSha256)||!text(v.description,1024)||!['submission_asserted','delivery_asserted','receipt_asserted','acceptance_asserted','rejection_asserted','dispute_asserted','response_asserted','correspondence','correction_asserted'].includes(v.type)||(v.submissionId===null)!==(v.submissionSha256===null)||(v.submissionId!==null&&(!isId('submissionId')||typeof v.submissionSha256!=='string'||!hash.test(v.submissionSha256)))||(v.submissionId===null&&['submission_asserted','delivery_asserted','receipt_asserted','acceptance_asserted','rejection_asserted'].includes(v.type)))throw Error('invalid chronology');
   if(v.assertedAt!==null&&(typeof v.assertedAt!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(v.assertedAt)||!Number.isFinite(Date.parse(v.assertedAt))||new Date(v.assertedAt).toISOString()!==v.assertedAt||Date.parse(v.assertedAt)>Date.now()))throw Error('invalid asserted date');
  }else if(action==='chronology-review'){
   if(!isId('eventId')||!['source_supports','source_does_not_support','inconclusive'].includes(v.decision)||!text(v.reason,512))throw Error('invalid chronology review');
  }else if(action==='financial-write'){
   if(!isV4('recordId')||!isV4('versionId')||!Number.isInteger(v.expectedRevision)||v.expectedRevision<0||v.expectedRevision>15||typeof v.reference!=='string'||!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(v.reference)||!['milestone','retention','disputed'].includes(v.kind)||!text(v.title,128)||!['tax_inclusive','tax_exclusive','tax_not_applicable'].includes(v.taxBasis)||!isId('sourceEvidenceId')||typeof v.sourceSha256!=='string'||!hash.test(v.sourceSha256)||!Array.isArray(v.conditionVersions)||v.conditionVersions.length>32||!v.conditionVersions.every(x=>typeof x==='string'&&id.test(x))||new Set(v.conditionVersions).size!==v.conditionVersions.length)throw Error('invalid financial record');
   decimalToMinor(v.amount===null?'0':v.amount,v.currency);
   if(v.dueAt!==null&&(typeof v.dueAt!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(v.dueAt)||!Number.isFinite(Date.parse(v.dueAt))||new Date(v.dueAt).toISOString()!==v.dueAt))throw Error('invalid reminder date');
  }else if(action==='financial-review'){
   if(!isId('versionId')||!['approved','rejected'].includes(v.decision)||!text(v.reason,512))throw Error('invalid financial review');
  }else if(action==='recovery-propose'){
   if(!isV4('recoveryId')||!isId('windowId')||!isId('revisionId')||!isId('versionId')||!isId('evidenceId')||typeof v.sha256!=='string'||v.sha256.length!==64||!hash.test(v.sha256)||!['contemporaneous_record','independent_inspection','documented_exception_request'].includes(v.approach)||!text(v.reason,512))throw Error('invalid recovery proposal');
  }else if(action==='recovery-review'){
   if(!isId('recoveryId')||!['approved','rejected'].includes(v.decision)||!text(v.reason,512))throw Error('invalid recovery review');
  }else if(action==='alert-policy-write'){
   if(!isV4('policyId')||!Number.isInteger(v.expectedRevision)||v.expectedRevision<0||v.expectedRevision>31)throw Error('invalid policy');
   validateAlertPolicy({revision:v.expectedRevision,timezone:v.timezone,quietStart:v.quietStart,quietEnd:v.quietEnd,criticalOverride:v.criticalOverride});
  }else if(action==='window-review'){
   if(!isId('windowId')||!['approved','rejected'].includes(v.decision)||!text(v.reason,512))throw Error('invalid window review');
  }else if(action==='dependency-removal-propose'){
   if(!isId('versionId')||!isV4('removalId')||!isId('prerequisiteId')||!text(v.reason,512))throw Error('invalid removal');
  }else if(action==='dependency-removal-review'){
   if(!isId('removalId')||!['approved','rejected'].includes(v.decision)||!text(v.reason,512))throw Error('invalid removal review');
  }else if(action==='dependency-propose'){
   if(!isId('versionId')||!isV4('edgeId')||!isId('prerequisiteId'))throw Error('invalid dependency');
  }else if(action==='dependency-review'){
   if(!isId('edgeId')||!['approved','rejected'].includes(v.decision)||!text(v.reason,512))throw Error('invalid dependency review');
  }else if(action==='link'){
   if(!isId('versionId')||!isV4('linkId')||!isId('evidenceId')||typeof v.sha256!=='string'||v.sha256.length!==64||!hash.test(v.sha256))throw Error('invalid link');
  }else if(!(action==='rule-review'?isId('versionId')&&['approved','rejected'].includes(v.decision):isId('linkId')&&['pass','fail','unknown'].includes(v.decision))||!text(v.reason,512))throw Error('invalid review');
  return v;
 }finally{clearTimeout(timer);for(const b of chunks)b.fill(0);}
}
export function createGraphWorkspaceApi({origin,verifier,admission,resolveSession,workflow,extract,assembleSubmission}){
 const u=new URL(origin);
 if(u.protocol!=='https:'||u.href!==u.origin+'/'||typeof resolveSession!=='function'||!['assessment','writeRequirement','reviewRequirement','linkEvidence','reviewLink','prepareSubmission','reviewSubmission','authorizeSubmission','listSubmissions','inspectSubmission'].every(k=>typeof workflow?.[k]==='function')||typeof admission?.peer!=='function'||typeof admission?.actor!=='function')throw Error('invalid workspace API');
 let active=0;
 return async function workspace(req,res){
  if(!isGraphWorkspaceRequest(req))return denied(res,404);
  const m=route.exec(req.url),action=m?.[3],mutation=!!action&&!['submission-list','prooflock','financial-summary','project-intelligence','project-intelligence-export','ack-list','resolution-list','draft-handover','customer-package-list'].includes(action);
  if(req.method!==(mutation?'POST':'GET'))return denied(res,405);
  const h=req.headers,seen=new Set();
  for(let i=0;i<req.rawHeaders.length;i+=2){const k=req.rawHeaders[i].toLowerCase();if(seen.has(k))return denied(res,400);seen.add(k);}
  if(h.host!==u.host||h.authorization!==undefined||h['transfer-encoding']!==undefined||h['content-encoding']!==undefined||h.expect!==undefined||h.range!==undefined||
   (mutation?(h['content-type']!=='application/json'||!/^[1-9][0-9]{0,3}$/.test(h['content-length']??'')||Number(h['content-length'])>8192):(h['content-length']!==undefined&&h['content-length']!=='0')))return denied(res,400);
  if(mutation&&h.origin!==u.origin||h.origin!==undefined&&h.origin!==u.origin||['cross-site','same-site'].includes(h['sec-fetch-site']))return denied(res,403);
  if(active>=8)return denied(res,429);active++;
  const controller=new AbortController(),abort=()=>controller.abort();res.once('close',abort);
  try{
   if(!await admission.peer(req.socket.remoteAddress))return denied(res,429);
   const token=await resolveSession(req);if(!token)return denied(res,401);
   let p;try{p=verifyIdentityToken(token,verifier);}catch{return denied(res,401);}
   if(!await admission.actor(p.actorId))return denied(res,429);
   if(res.destroyed)return;
   const [,tenantId,projectId]=m,scope={token,tenantId,projectId};
   const proofLockEnabled=['proofLock','writeMilestone','proposeEvidenceWindow','reviewEvidenceWindow'].every(k=>typeof workflow[k]==='function');
   const financialEnabled=['financialSummary','writeFinancialRecord','reviewFinancialRecord'].every(k=>typeof workflow[k]==='function');
   const intelligenceEnabled=['projectIntelligence','recordChronology','reviewChronology'].every(k=>typeof workflow[k]==='function');
   if(action==='project-intelligence'||action==='project-intelligence-export'){
    if(!intelligenceEnabled)return denied(res,404);const archive=await workflow.projectIntelligence(scope);
    if(action==='project-intelligence')return response(res,200,archive);
    if(!archive.canWrite)return denied(res,404);
    const body=JSON.stringify(archive);if(Buffer.byteLength(body)>4*1024*1024)throw Error('archive response limit');
    res.writeHead(200,{'Content-Type':'application/json; charset=utf-8','Content-Disposition':'attachment; filename="project-intelligence-'+projectId+'.json"','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; sandbox; frame-ancestors 'none'",'Cross-Origin-Resource-Policy':'same-origin','Connection':'close','Content-Length':Buffer.byteLength(body),'X-Archive-SHA256':createHash('sha256').update(body).digest('hex')});res.end(body);return;
   }
   const customerAccessEnabled=typeof assembleSubmission==='function'&&['grantCustomerPackage','revokeCustomerPackage','previewCustomerPackage','readCustomerPackage','customerPackageList'].every(k=>typeof workflow[k]==='function');
   if(action==='customer-package-list'){if(!customerAccessEnabled)return denied(res,404);return response(res,200,{items:await workflow.customerPackageList(scope)});}
   const coordinationEnabled=['acknowledgementList','grantAcknowledgement','revokeAcknowledgement','recordAcknowledgement','resolutionList','assignResolution','advanceResolution'].every(k=>typeof workflow[k]==='function');
   if(action==='ack-list'||action==='resolution-list'){if(!coordinationEnabled)return denied(res,404);return response(res,200,action==='ack-list'?await workflow.acknowledgementList(scope):await workflow.resolutionList(scope));}
   if(action==='financial-summary'){if(!financialEnabled)return denied(res,404);return response(res,200,await workflow.financialSummary(scope));}
   if(action==='prooflock'){
    if(!proofLockEnabled)return denied(res,404);
    return response(res,200,{...await workflow.proofLock(scope),actorId:p.actorId});
   }
   if(action==='submission-list')return response(res,200,{items:await workflow.listSubmissions(scope),downloadEnabled:typeof assembleSubmission==='function'});
   if(action==='draft-handover'){
    const g=await workflow.assessment(scope);if(!g.canWrite||g.archived)return denied(res,404);const data=buildDraftHandoverPdf(g);
    try{if(res.destroyed)return;res.writeHead(200,{'Content-Type':'application/pdf','Content-Disposition':'attachment; filename="draft-handover-'+projectId+'.pdf"','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; sandbox; frame-ancestors 'none'",'Cross-Origin-Resource-Policy':'same-origin','Connection':'close','Content-Length':data.length});await new Promise(r=>{const done=()=>{res.removeListener('finish',done);res.removeListener('close',done);r();};res.once('finish',done);res.once('close',done);res.end(data);});return;}finally{data.fill(0);}
   }
   if(!mutation){const assessment=await workflow.assessment(scope),removalEnabled=['proposeDependencyRemoval','reviewDependencyRemoval','dependencyRemovalCandidates'].every(k=>typeof workflow[k]==='function'),removalCandidates=removalEnabled&&assessment.canWrite?await workflow.dependencyRemovalCandidates(scope):[];return response(res,200,{...assessment,preflight:buildRejectionPreflight(assessment),extractionEnabled:typeof extract==='function',dependencyManagementEnabled:typeof workflow.proposeDependency==='function'&&typeof workflow.reviewDependency==='function',dependencyRemovalEnabled:removalEnabled,removalCandidates,proofLockEnabled,financialEnabled,intelligenceEnabled,coordinationEnabled,customerAccessEnabled});}
   let input;try{input=await read(req,action);}catch{return denied(res,400);}
   controller.signal.throwIfAborted();
   const args={...input,...scope};
   if(['customer-package-grant','customer-package-revoke','customer-package-preview'].includes(action)){
    if(!customerAccessEnabled)return denied(res,404);
    if(action==='customer-package-preview')return response(res,200,await workflow.previewCustomerPackage(args));
    if(action==='customer-package-grant')return response(res,200,{grantId:await workflow.grantCustomerPackage(args)});
    return response(res,200,{revoked:await workflow.revokeCustomerPackage(args)});
   }
   if(action==='submission-prepare')return response(res,200,await workflow.prepareSubmission(args));
   if(action==='submission-inspect')return response(res,200,await workflow.inspectSubmission(args));
   if(action==='submission-impact'){
    const baseline=await workflow.inspectSubmission(args);
    controller.signal.throwIfAborted();
    const current=await workflow.assessment(scope);
    controller.signal.throwIfAborted();
    return response(res,200,compareSubmissionGraph(baseline,current,{tenantId,projectId,submissionId:input.submissionId}));
   }
   if(action==='submission-review')return response(res,200,{reviewed:await workflow.reviewSubmission(args)});
   if(action==='submission-authorize')return response(res,200,{authorized:await workflow.authorizeSubmission(args)});
   if(['submission-download','submission-handover','submission-register','submission-workbook','submission-custom','customer-package-download'].includes(action)){
    if(typeof assembleSubmission!=='function'||action==='customer-package-download'&&!customerAccessEnabled)return denied(res,404);
    const data=await assembleSubmission(args,{signal:controller.signal,profile:action==='customer-package-download'?'handover-v1':action==='submission-custom'?normalizeHandoverConfig(input.configuration):action==='submission-handover'?'handover-v1':action==='submission-register'?'register-v1':action==='submission-workbook'?'workbook-v1':null});
    try{
     if(res.destroyed)return;
     res.writeHead(200,{'Content-Type':'application/zip','Content-Disposition':'attachment; filename="submission-'+input.submissionId+'.zip"','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; sandbox; frame-ancestors 'none'",'Cross-Origin-Resource-Policy':'same-origin','Connection':'close','Content-Length':data.length,'X-Package-SHA256':createHash('sha256').update(data).digest('hex')});
     await new Promise(r=>{const done=()=>{res.removeListener('finish',done);res.removeListener('close',done);r();};res.once('finish',done);res.once('close',done);res.end(data);});return;
    }finally{data.fill(0);}
   }
   if(action==='extract'||action==='import-source'){
    if(typeof extract!=='function')return denied(res,404);
    return response(res,200,await extract(args,{importLine:action==='import-source',signal:controller.signal}));
   }
   if(['ack-grant','ack-revoke','ack-record','resolution-assign','resolution-advance'].includes(action)){
    if(!coordinationEnabled)return denied(res,404);
    const methods={'ack-grant':'grantAcknowledgement','ack-revoke':'revokeAcknowledgement','ack-record':'recordAcknowledgement','resolution-assign':'assignResolution','resolution-advance':'advanceResolution'};
    return response(res,200,{result:await workflow[methods[action]](args)});
   }
   if(action==='chronology-write'||action==='chronology-review'){if(!intelligenceEnabled)return denied(res,404);return response(res,200,action==='chronology-write'?{eventId:await workflow.recordChronology(args)}:{reviewed:await workflow.reviewChronology(args)});}
   if(action==='financial-write'||action==='financial-review'){if(!financialEnabled)return denied(res,404);return response(res,200,action==='financial-write'?await workflow.writeFinancialRecord(args):{reviewed:await workflow.reviewFinancialRecord(args)});}
   if(action==='recovery-propose'){if(typeof workflow.proposeRecovery!=='function')return denied(res,404);return response(res,200,{recoveryId:await workflow.proposeRecovery(args)});}
   if(action==='recovery-review'){if(typeof workflow.reviewRecovery!=='function')return denied(res,404);return response(res,200,{reviewed:await workflow.reviewRecovery(args)});}
   if(action==='alert-policy-write'){if(typeof workflow.writeProofLockAlertPolicy!=='function')return denied(res,404);return response(res,200,await workflow.writeProofLockAlertPolicy(args));}
   if(['milestone-write','window-propose','window-review'].includes(action)){
    if(!proofLockEnabled)return denied(res,404);
    if(action==='milestone-write')return response(res,200,await workflow.writeMilestone(args));
    if(action==='window-propose')return response(res,200,{windowId:await workflow.proposeEvidenceWindow(args)});
    return response(res,200,{reviewed:await workflow.reviewEvidenceWindow(args)});
   }
   if(action==='dependency-removal-propose'||action==='dependency-removal-review'){
    if(!['proposeDependencyRemoval','reviewDependencyRemoval','dependencyRemovalCandidates'].every(k=>typeof workflow[k]==='function'))return denied(res,404);
    return response(res,200,action==='dependency-removal-propose'?{removalId:await workflow.proposeDependencyRemoval(args)}:{reviewed:await workflow.reviewDependencyRemoval(args)});
   }
   if(action==='dependency-propose'||action==='dependency-review'){
    if(typeof workflow.proposeDependency!=='function'||typeof workflow.reviewDependency!=='function')return denied(res,404);
    return response(res,200,action==='dependency-propose'?{edgeId:await workflow.proposeDependency(args)}:{reviewed:await workflow.reviewDependency(args)});
   }
   if(action==='requirement')return response(res,200,await workflow.writeRequirement(args));
   if(action==='rule-review')return response(res,200,{reviewed:await workflow.reviewRequirement(args)});
   if(action==='link')return response(res,200,{linkId:await workflow.linkEvidence(args)});
   return response(res,200,{reviewed:await workflow.reviewLink(args)});
  }catch(e){if(res.headersSent){res.destroy();return;}return denied(res,e instanceof ReleaseDenied||e instanceof EvidenceAccessDenied?404:e instanceof ReleaseConflict?409:e instanceof UnsupportedExtraction?422:503);}
  finally{res.removeListener('close',abort);active--;}
 };
}
