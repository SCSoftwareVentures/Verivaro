import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createVerificationExport} from '../../src/security/verification-report-export.mjs';
const root=process.argv[2];if(!root)throw Error('fixture destination required');
const now='2026-11-19T00:00:00.000Z',id=n=>'11111111-1111-4111-8111-'+String(n).padStart(12,'0');
const evidence=Array.from({length:28},(_,i)=>({id:id(i+10),sha256:'a'.repeat(64),registeredAt:now,bytes:256,mediaType:'text/plain; charset=utf-8',scanPolicy:'clamd-instream-format-v2',storage:'encrypted'}));
const reviews=evidence.slice(0,12).map((e,i)=>({id:id(i+300),evidenceId:e.id,sha256:e.sha256,submittedAt:now,reviewedAt:now,decision:'approved',reason:'verified',releasedAt:now,state:'released'}));
const report={version:1,generatedAt:now,tenantId:id(1),project:{id:id(2),name:'W'.repeat(128)+' (fixture) café',revision:7,archivedAt:null},summary:{evidence:evidence.length,encrypted:evidence.length,bytes:evidence.length*256,requests:reviews.length,states:{released:reviews.length}},evidence,reviews,attestation:'unsigned database snapshot; not an independently signed custody checkpoint'};
await writeFile(join(root,'package.zip'),createVerificationExport(report,'zip'),{mode:0o600});
