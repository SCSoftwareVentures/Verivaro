// Node 22 native TS stripping is enabled by the project test/start commands.
import {evaluate} from './evidence.ts';
import {createHash} from 'node:crypto';
export function reviewDigest(pages){
 return createHash('sha256').update(pages.map(p=>p.text_value).join('\n\f\n'),'utf8').digest('hex');
}
export function evaluateGraph(scope,g){
 if(!g||typeof g.scopeConfirmed!=='boolean'||! /^\d+$/.test(g.generation)||!Array.isArray(g.sources)||!Array.isArray(g.requirements)||!Array.isArray(g.evidence))throw Error('invalid persisted graph');
 const sources=g.sources.map(s=>({...s,...scope}));const byId=new Map(sources.map(s=>[s.id,s]));
 // Convert Unicode code-point offsets to JS UTF-16 offsets, preserving exact source text.
 const span=s=>{const doc=byId.get(s.sourceId);if(!doc||!Number.isSafeInteger(s.start)||!Number.isSafeInteger(s.end)||s.start<0||s.end<=s.start||s.end>=[...doc.text].length+1)throw Error('invalid persisted span');const cp=[...doc.text];return {...s,start:cp.slice(0,s.start).join('').length,end:cp.slice(0,s.end).join('').length};};
 const input={scope,sources,requirements:g.requirements.map(r=>({...r,...scope,span:span(r.span)})),evidence:g.evidence.map(e=>({...e,...scope,span:span(e.span)}))};
 const report=evaluate(input);
 return {...report,ready:report.ready&&g.scopeConfirmed,configuredChecksReady:report.ready,scopeConfirmed:g.scopeConfirmed,generation:g.generation,actions:report.findings.filter(f=>f.status!=='verified-configured-checks'&&f.status!=='not-applicable').sort((a,b)=>Number(b.blocker)-Number(a.blocker)||a.requirementId.localeCompare(b.requirementId)).map(f=>({requirementId:f.requirementId,priority:f.blocker?'mandatory':'advisory',reason:f.reason,action:f.status==='conflicting'?'Resolve contradictory reviewed sources':f.status==='missing'?'Supply current evidence':f.status==='unknown'?'Review source revisions and provenance':'Obtain authorised evidence review'})),label:'Configured documentary checks only; scope confirmation is a human assertion, not certification or complete obligation discovery.'};
}
