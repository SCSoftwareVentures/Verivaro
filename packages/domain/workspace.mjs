import {evaluateGraph} from './graph.mjs';
import {evidenceWindow} from '../rules/prooflock.ts';
import {createHash} from 'node:crypto';
const sha=s=>createHash('sha256').update(s,'utf8').digest('hex');
const cmp=(a,b)=>a.id<b.id?-1:a.id>b.id?1:0;
export function evaluateWorkspace(scope,w){
 const report=evaluateGraph(scope,w.graph);
 const found=new Map(report.findings.map(f=>[f.requirementId,f]));
 const milestones=w.milestones.map(m=>{
  const f=found.get(m.requirementId);
  const window=evidenceWindow({...m,now:w.asOf});
  const current=!!f&&f.revision===m.requirementRevision;
  const covered=current&&f.status==='verified-configured-checks';
  const status=!current?'revision-review-required':window.status==='unknown'?'schedule-unconfirmed':covered?'evidence-present-timing-unverified':window.status==='due-or-overdue'?'evidence-due-or-overdue':'evidence-needed-before-deadline';
  return {...m,due:window.due,status,covered,requiresAttention:!current||window.status==='unknown'||!covered};
 }).sort(cmp);
 const cases=w.cases.map(c=>{const f=found.get(c.requirementId);const resolved=!!f&&f.revision===c.requirementRevision&&f.status==='verified-configured-checks';return {...c,requiresAttention:c.state==='open'||!resolved};}).sort(cmp);
 const contractRelations=(w.contractRelations??[]).map(r=>({...r,requiresAttention:r.state!=='withdrawn'&&(r.state!=='reviewed'||!r.current)})).sort(cmp);
 const operationalBlockers=milestones.filter(m=>m.requiresAttention).length+cases.filter(c=>c.requiresAttention).length+contractRelations.filter(c=>c.requiresAttention).length;
 return {...report,documentaryReady:report.ready,ready:report.ready&&operationalBlockers===0,operationalBlockers,asOf:w.asOf,milestones,cases,contractRelations,label:'Configured documentary and workflow checks only. Evidence timing, authenticity, compliance and payment entitlement are not certified.'};
}
export function handoverManifest(scope,stored){
 if(typeof stored?.payload!=='string'||sha(stored.payload)!==stored.sha256)throw Error('snapshot integrity failure');
 const w=JSON.parse(stored.payload),report=evaluateWorkspace(scope,w);
 const lineage=new Map(w.lineage.map(l=>[l.id,l]));
 const sources=w.graph.sources.map(({text,...s})=>{const l=lineage.get(s.id);return {...s,originalSha256:l?.originalSha256??null,textSha256:sha(text),pages:l?.pages??[]};}).sort(cmp);
 // No full extracted text, storage paths, signing keys or access credentials in the exported manifest.
 // Quotes, notes and IDs are potentially sensitive. Internal authorised review only.
 const manifest={schema:'verivaro-handover-draft-v1',id:stored.id,scope,asOf:w.asOf,generation:w.graph.generation,disposition:report.ready?'CONFIGURED_CHECKS_READY_DRAFT':'BLOCKED_DRAFT',sources,requirements:[...w.graph.requirements].sort(cmp),evidence:[...w.graph.evidence].sort(cmp),report};
 const json=JSON.stringify(manifest);
 return {id:stored.id,json,sha256:sha(json),stale:stored.stale,releaseAuthorised:false};
}
