import {createHash} from 'node:crypto';
import {zip} from './verification-report-export.mjs';
import {buildHandoverDerivatives,HANDOVER_PROFILES,normalizeHandoverConfig} from './handover-templates.mjs';
import {ReleaseConflict} from './evidence-release.mjs';
import {normalizeTemplateReference} from './template-reference.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
const types={'text/plain; charset=utf-8':'txt','application/pdf':'pdf','image/png':'png','application/vnd.openxmlformats-officedocument.wordprocessingml.document':'docx','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':'xlsx'};
const id=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
export function createSubmissionPackage({workflow,retrieve}){
 if(typeof workflow?.readSubmission!=='function'||typeof retrieve!=='function')throw Error('invalid submission packager');
 let active=0;
 return async function assemble(input,{signal,profile=null}){
  let saved=null;
  if(profile!==null&&typeof profile==='object')profile=normalizeHandoverConfig(profile);else if(profile!==null&&!HANDOVER_PROFILES.includes(profile))throw Error('invalid handover profile');
  if(active>=2)throw Error('submission capacity');active++;
  const files=[];let out;
  try{
   signal.throwIfAborted();
   if(input.templateId!==undefined||input.templateVersionId!==undefined){
    if(input.grantId!==undefined||profile!==null||typeof workflow.readExportTemplate!=='function')throw Error('invalid template input');
    const r=await workflow.readExportTemplate(input);saved={template:normalizeTemplateReference(r.template),configuration:normalizeHandoverConfig(r.configuration)};
    if(saved.template.templateId!==input.templateId||saved.template.versionId!==input.templateVersionId)throw new ReleaseConflict('template identity mismatch');
    profile=saved.configuration;
   }
   const custom=profile!==null&&typeof profile==='object';
   const read=input.grantId===undefined?workflow.readSubmission:workflow.readCustomerPackage;if(typeof read!=='function')throw Error('submission unavailable');
   const receipt=await read(input),manifest=Buffer.from(receipt.manifest,'utf8');
   if(manifest.length>2097152||hash(manifest)!==input.sha256||receipt.sha256!==input.sha256||receipt.submissionId!==input.submissionId)throw new ReleaseConflict('manifest mismatch');
   const m=JSON.parse(receipt.manifest);
   if(m.version!==1||m.tenantId!==input.tenantId||m.projectId!==input.projectId||m.summary?.status!=='criteria_satisfied'||!Array.isArray(m.evidence)||m.evidence.length<1||m.evidence.length>64)throw new ReleaseConflict('invalid manifest');
   const set=new Set();let total=0;
   for(const e of m.evidence){
    if(typeof e.id!=='string'||e.id.length!==36||!id.test(e.id)||set.has(e.id)||typeof e.sha256!=='string'||!/^[a-f0-9]{64}$/.test(e.sha256)||e.sha256.length!==64||!Object.hasOwn(types,e.mediaType)||!Number.isInteger(e.bytes)||e.bytes<1||e.bytes>262144)throw new ReleaseConflict('invalid inventory');
    set.add(e.id);total+=e.bytes;
   }
   if(total>16777216)throw Error('submission capacity');
   files.push(['submission.json',manifest]);
   for(const e of m.evidence){
    signal.throwIfAborted();
    const object=await retrieve({...input,evidenceId:e.id});
    if(!Buffer.isBuffer(object.data))throw Error('invalid object');
    files.push(['evidence-'+e.id+'.'+types[e.mediaType],object.data]);
    if(object.data.length!==e.bytes||object.sha256!==e.sha256||object.mediaType!==e.mediaType||hash(object.data)!==e.sha256)throw new ReleaseConflict('evidence mismatch');
   }
   if(profile!==null)files.push(...buildHandoverDerivatives(m,input.sha256,profile));
   const {manifest:ignored,...authorization}=receipt;
   const index=Buffer.from(JSON.stringify({version:saved?4:custom?3:profile===null?1:2,...(saved?{template:saved.template,configuration:profile}:custom?{configuration:profile}:profile===null?{}:{profile}),authorization,files:files.map(([name,data])=>({name,bytes:data.length,sha256:hash(data)}))},null,2)+'\n');
   files.push(['package-index.json',index]);out=zip(files);if(out.length>20*1024*1024)throw Error('submission capacity');
   signal.throwIfAborted();
   // A second DB transaction checks exact graph, current actor generations
   // and expiry after all plaintext retrieval and assembly.
   if(saved){const r=await workflow.readExportTemplate(input);if(JSON.stringify({template:normalizeTemplateReference(r.template),configuration:normalizeHandoverConfig(r.configuration)})!==JSON.stringify(saved))throw new ReleaseConflict('template changed');}
   const latest=await read(input);
   if(JSON.stringify(latest)!==JSON.stringify(receipt))throw new ReleaseConflict('approval changed');
   signal.throwIfAborted();const result=out;out=null;return result;
  }finally{for(const [,data] of files)data.fill(0);out?.fill(0);active--;}
 };
}
