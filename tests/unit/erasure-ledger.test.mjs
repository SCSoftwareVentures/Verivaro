import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {signErasurePlan,verifyErasureLedger,parsePlan} from '../../packages/security/erasure-ledger.mjs';
const keys=generateKeyPairSync('ed25519'),other=generateKeyPairSync('ed25519'),u='00000000-0000-0000-0000-000000000001';
const plan={schema:'verivaro-erasure-plan-v1',tenantId:u,projectId:u,requestId:u,policyRevision:1,generation:'3',objectKeys:['00000000-0000-4000-8000-000000000002'],rowCounts:{documents:1}};
const row=p=>{const json=JSON.stringify(p);return {json,sha256:createHash('sha256').update(json).digest('hex')};};
test('signed external ledger rejects wrong keys, mutated content and unsafe object names',()=>{
 const bytes=signErasurePlan(row(plan),keys.privateKey);assert.deepEqual(verifyErasureLedger(bytes,keys.publicKey).plan,plan);assert.throws(()=>verifyErasureLedger(bytes,other.publicKey));
 const altered=JSON.parse(bytes);altered.plan=row({...plan,generation:'4'});assert.throws(()=>verifyErasureLedger(Buffer.from(JSON.stringify(altered)),keys.publicKey));
 assert.throws(()=>parsePlan(row({...plan,objectKeys:['../escape']})));assert.throws(()=>parsePlan(row({...plan,objectKeys:[...plan.objectKeys,...plan.objectKeys]})));
});
