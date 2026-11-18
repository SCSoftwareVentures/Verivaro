import {evaluate} from './packages/domain/evidence.ts';
const scope={tenantId:'synthetic-tenant',projectId:'synthetic-project'};
const p={...scope,id:'contract-v1',documentId:'contract',revision:1,text:'Serial required: HVAC-001',scan:'clean',reviewed:true,current:true};
const c={...scope,id:'certificate-v1',documentId:'certificate',revision:1,text:'HVAC-002',scan:'clean',reviewed:true,current:true};
const req={...scope,id:'r1',revision:1,approved:true,applicability:'applicable',mandatory:true,span:{sourceId:p.id,start:0,end:p.text.length,quote:p.text},criterion:{kind:'serial',expected:'HVAC-001'}};
const e={...scope,id:'e1',requirementId:req.id,requirementRevision:1,span:{sourceId:c.id,start:0,end:c.text.length,quote:c.text},kind:'serial',value:c.text,review:'approved'};
console.log(JSON.stringify(evaluate({scope,sources:[p,c],requirements:[req],evidence:[e]}),null,2));
