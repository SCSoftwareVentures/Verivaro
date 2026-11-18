import {createHash} from 'node:crypto';
export const sha=s=>createHash('sha256').update(s).digest('hex');
const source=(id,documentId,text)=>({id,documentId,text,revision:1,current:true,reviewed:true,scan:'clean'});
function span(d,quote){const start=d.text.indexOf(quote);if(start<0)throw Error('fixture span');return {sourceId:d.id,start:[...d.text.slice(0,start)].length,end:[...d.text.slice(0,start+quote.length)].length,quote};}
export function makeCase(project,scenario){
 const {id,kind,value,label,template}=project,variant=scenario.variant??'labeled';
 const scope={tenantId:'synthetic-'+id,projectId:'pack-'+id};
 const contract=source('contract-v1','contract','📄 '+template+' — '+label+' must be '+value);
 const certificate=source('cert-v1','certificate',variant==='bare'?value:variant==='contextual'?'Fictional record '+id+'\n'+label+': '+value+'\nReviewed by synthetic issuer':label+': '+value);
 const req={id:'r',revision:1,approved:true,applicability:'applicable',mandatory:true,span:span(contract,contract.text),criterion:{kind,expected:value}};
 const evidence={id:'e',requirementId:'r',requirementRevision:1,span:span(certificate,value),kind,value,review:'approved'};
 const w={asOf:'2026-11-18T00:00:00.000Z',graph:{generation:'8',scopeConfirmed:true,sources:[contract,certificate],requirements:[req],evidence:[evidence]},milestones:[],cases:[],lineage:[],contractRelations:[],rejectionNotices:[]};
 const g=w.graph;
 function addOther(text,opts={}){const d={...source('other-v1','other',text),...opts};g.sources.push(d);return d;}
 function wrong(review='approved'){const text=kind==='expiry date'?'2029-01-01':'WRONG-'+id;const d=addOther(label+': '+text);return {...evidence,id:'other-link',review,value:text,span:span(d,text)};}
 const milestone=(confirmed=true)=>({id:'m',requirementId:'r',requirementRevision:1,milestone:confirmed?'2026-11-19T00:00:00.000Z':null,confirmed,leadMinutes:120,irreversibility:'irreversible'});
 switch(scenario.id){
 case 'missing':g.evidence=[];break;
 case 'rejected':evidence.review='rejected';break;
 case 'pending':evidence.review='pending';break;
 case 'wrong-value':g.evidence=[wrong()];break;
 case 'two-values':g.evidence.push(wrong());break;
 case 'stale-evidence':certificate.current=false;g.sources.push({...source('cert-v2','certificate',value+' superseded'),revision:2});break;
 case 'stale-contract':contract.current=false;g.sources.push({...source('contract-v2','contract','Revised: '+value),revision:2});break;
 case 'unreviewed-evidence':certificate.reviewed=false;break;
 case 'pending-scan':certificate.scan='pending';break;
 case 'fabricated-quote':evidence.span.quote='X'.repeat([...value].length);break;
 case 'wrong-kind':evidence.kind='unrelated-kind';break;
 case 'stale-requirement-link':req.revision=2;break;
 case 'unapproved-requirement':req.approved=false;break;
 case 'unknown-applicability':req.applicability='unknown';break;
 case 'unconfirmed-scope':g.scopeConfirmed=false;break;
 case 'unconfirmed-milestone':w.milestones=[milestone(false)];break;
 case 'open-rejection':w.cases=[{id:'case',requirementId:'r',requirementRevision:1,state:'open'}];break;
 case 'unmapped-notice':{const d=addOther('Missing certificate');w.rejectionNotices=[{id:'notice',documentVersionId:d.id,page:1,start:0,end:[...d.text].length,quote:d.text,textSha256:sha(d.text),history:[]}];break;}
 case 'unresolved-relation':w.contractRelations=[{id:'relation',state:'unresolved',current:true,amendmentVersionId:addOther('Variation is unresolved').id,baseVersionId:contract.id}];break;
 case 'self-evidence':evidence.span=span(contract,value);break;
 case 'valid':break;
 case 'duplicate-agreement':{const d=addOther(label+': '+value);g.evidence.push({...evidence,id:'agree2',span:span(d,value)});break;}
 case 'rejected-conflict-ignored':g.evidence.push(wrong('rejected'));break;
 case 'old-link-ignored':req.revision=2;g.evidence.push({...evidence,id:'historical',requirementRevision:1});evidence.requirementRevision=2;break;
 case 'old-document-unlinked':g.sources.push({...source('cert-old','certificate','Old unrelated text'),revision:1,current:false});certificate.revision=2;break;
 case 'resolved-rejection':w.cases=[{id:'case',requirementId:'r',requirementRevision:1,state:'resolution-recorded'}];break;
 case 'reviewed-relation':w.contractRelations=[{id:'relation',state:'reviewed',current:true,amendmentVersionId:addOther('Reviewed variation').id,baseVersionId:contract.id}];break;
 case 'confirmed-milestone':w.milestones=[milestone()];break;
 case 'applicable-plus-reviewed-exception':g.requirements.push({...req,id:'exception',applicability:'not-applicable'});break;
 case 'unicode-source':certificate.text='🧾 測試 '+certificate.text;evidence.span=span(certificate,value);break;
 default:throw Error('unknown scenario '+scenario.id);
 }
 w.lineage=g.sources.map(d=>({id:d.id,originalSha256:sha('synthetic-original:'+d.id+':'+d.text),textSha256:sha(d.text),pages:[{page:1,start:0,length:[...d.text].length,sha256:sha(d.text),method:'utf8-exact'}]}));
 return {scope,w};
}
