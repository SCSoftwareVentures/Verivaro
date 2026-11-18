import {cents,format} from '../rules/money.ts';
import {evaluateWorkspace} from './workspace.mjs';
import {createHash} from 'node:crypto';
const order=(a,b)=>a<b?-1:a>b?1:0;
export function evaluateFinance(scope,f){
 const report=evaluateWorkspace(scope,f.workspace),findings=new Map(report.findings.map(x=>[x.requirementId,x]));
 const ids=new Set(),groups=new Map();
 const items=f.items.map(m=>{
 if(ids.has(m.id)||m.currency!=='AUD'||!['milestone','retention'].includes(m.category)||!['inclusive','exclusive'].includes(m.taxBasis)||typeof m.sourceCurrent!=='boolean')throw Error('invalid finance record');
 ids.add(m.id);const n=cents(m.amount);
 const checks=m.conditions.map(c=>{const result=findings.get(c.id);return {...c,status:!result||result.revision!==c.revision?'revision-review-required':result.status};});
 const revisionIssue=!m.sourceCurrent||checks.some(c=>c.status==='revision-review-required');
 const conditionsMet=checks.length>0&&checks.every(c=>c.status==='verified-configured-checks');
 const status=revisionIssue?'revision-review-required':!checks.length?'conditions-unconfigured':!conditionsMet?'documentary-issues':!report.scopeConfirmed?'scope-unconfirmed':'configured-documentary-conditions-met';
 const retentionStatus=m.category!=='retention'?null:revisionIssue?'review-required':!m.releaseOn?'date-unknown':m.releaseOn<f.localDate?'recorded-date-passed':m.releaseOn===f.localDate?'recorded-date-today':'recorded-date-upcoming';
 const key=m.category+':'+m.taxBasis;
 const g=groups.get(key)??{category:m.category,currency:'AUD',taxBasis:m.taxBasis,recorded:0n,current:0n,needsReview:0n,configuredConditionsMet:0n};
 g.recorded+=n;
 if(!m.sourceCurrent)g.needsReview+=n;else {g.current+=n;if(status==='configured-documentary-conditions-met')g.configuredConditionsMet+=n;}
 groups.set(key,g);
 return {...m,checks,status,retentionStatus};
 }).sort((a,b)=>order(a.id,b.id));
 const totals=[...groups.entries()].sort((a,b)=>order(a[0],b[0])).map(([,g])=>({...g,recorded:format(g.recorded),current:format(g.current),needsReview:format(g.needsReview),configuredConditionsMet:format(g.configuredConditionsMet)}));
 return {asOf:f.workspace.asOf,localDate:f.localDate,generation:report.generation,scopeConfirmed:report.scopeConfirmed,items,totals,events:f.events,history:f.history,label:'Reviewed recorded amounts only. Milestone and retention totals are separate and must not be added. Documentary status is not a legal right to payment, outstanding balance, release entitlement or proof of receipt.'};
}
export function disputePack(scope,finance,id){
 const item=finance.items.find(m=>m.id===id);if(!item)return null;
 const events=finance.events.filter(e=>e.financeId===id),history=finance.history.filter(r=>r.id===id);
 const json=JSON.stringify({schema:'verivaro-dispute-draft-v1',scope,asOf:finance.asOf,item,history,events,label:'Internal factual record; event dates and submission, delivery, receipt, acceptance, rejection or payment are member assertions, not independently verified events. Source hashes establish references only. No legal finding.'});
 return {json,sha256:createHash('sha256').update(json,'utf8').digest('hex'),releaseAuthorised:false};
}
