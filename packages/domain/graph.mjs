// Node 22 native TS stripping is enabled by the project test/start commands.
import {evaluate} from './evidence.ts';
import {createHash} from 'node:crypto';
export function reviewDigest(pages){
 return createHash('sha256').update(pages.map(p=>p.text_value).join('\n\f\n'),'utf8').digest('hex');
}
export function evaluateGraph(scope,g){
 if(!g||typeof g.scopeConfirmed!=='boolean'||! /^\d+$/.test(g.generation)||!Array.isArray(g.sources)||!Array.isArray(g.requirements)||!Array.isArray(g.evidence))throw Error('invalid persisted graph');
 const sources=g.sources.map(s=>({...s,...scope}));const byId=new Map(sources.map(s=>[s.id,s]));
 // Resolve only requested Unicode code-point offsets. Each referenced source is
 // scanned once, with no full-page code-point array or repeated prefix allocation.
 const offsets=new Map();
 for(const r of [...g.requirements,...g.evidence]){
 const s=r.span,doc=byId.get(s?.sourceId);
 if(!doc||typeof doc.text!=='string'||!Number.isSafeInteger(s.start)||!Number.isSafeInteger(s.end)||s.start<0||s.end<=s.start||s.end>doc.text.length)throw Error('invalid persisted span');
 let map=offsets.get(s.sourceId);if(!map){map=new Map();offsets.set(s.sourceId,map);}map.set(s.start,0);map.set(s.end,0);
 }
 for(const [id,map] of offsets){
 const text=byId.get(id).text,targets=[...map.keys()].sort((a,b)=>a-b);
 let cp=0,utf16=0,i=0;
 while(i<targets.length){
 if(cp===targets[i]){map.set(targets[i++],utf16);continue;}
 if(utf16>=text.length)throw Error('invalid persisted span');
 const code=text.codePointAt(utf16);utf16+=code>0xffff?2:1;cp++;
 }
 }
 const span=s=>{const map=offsets.get(s.sourceId);return {...s,start:map.get(s.start),end:map.get(s.end)};};
 const input={scope,sources,requirements:g.requirements.map(r=>({...r,...scope,span:span(r.span)})),evidence:g.evidence.map(e=>({...e,...scope,span:span(e.span)}))};
 const report=evaluate(input);
 return {...report,ready:report.ready&&g.scopeConfirmed,configuredChecksReady:report.ready,scopeConfirmed:g.scopeConfirmed,generation:g.generation,actions:report.findings.filter(f=>f.status!=='verified-configured-checks'&&f.status!=='not-applicable').sort((a,b)=>Number(b.blocker)-Number(a.blocker)||a.requirementId.localeCompare(b.requirementId)).map(f=>({requirementId:f.requirementId,priority:f.blocker?'mandatory':'advisory',reason:f.reason,action:f.status==='conflicting'?'Resolve contradictory reviewed sources':f.status==='missing'?'Supply current evidence':f.status==='unknown'?'Review source revisions and provenance':'Obtain authorised evidence review'})),label:'Configured documentary checks only; scope confirmation is a human assertion, not certification or complete obligation discovery.'};
}
