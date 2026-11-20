import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {validateEvidence,sealEvidence,openEvidence} from '../../src/security/evidence-objects.mjs';
import {createEvidenceIngestion,IngestionRejected} from '../../src/security/evidence-ingestion.mjs';
import {extractRequirementCandidates,UnsupportedExtraction} from '../../src/security/contractiq-extraction.mjs';
import {officeFixtures} from '../fixtures/office-evidence-fixture.mjs';
import {planBatchImport,encodeBatchCheckpoint,decodeBatchCheckpoint} from '../../src/security/batch-import.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
test('Office evidence accepts only strict schemas, authenticates original media and bytes, and refuses premature source imports',()=>{
 const key=randomBytes(32),tenantId=randomUUID(),projectId=randomUUID();
 for(const [mediaType,data] of officeFixtures()){
  assert.deepEqual(validateEvidence(data,mediaType),data);
  const m=sealEvidence(data,{tenantId,projectId,key,keyId:'fixture',mediaType});assert.deepEqual(openEvidence(m,key),data);
  assert.throws(()=>openEvidence({...m,mediaType:'application/pdf'},key));
  assert.throws(()=>validateEvidence(Buffer.concat([data,Buffer.from('tail')]),mediaType));
  assert.throws(()=>extractRequirementCandidates(data,mediaType),UnsupportedExtraction);
 }
});
test('Office ingestion scans exact original and rejects malformed bytes before commit',async()=>{
 const key=randomBytes(32),tenantId=randomUUID(),projectId=randomUUID(),signal=new AbortController().signal;let scans=0,commits=0;
 for(const [mediaType,data] of officeFixtures()){
  const ingest=createEvidenceIngestion({key,keyId:'fixture',db:{authorize:async()=>true,commit:async({object})=>{commits++;assert.equal(object.sha256,hash(data));assert.equal(object.mediaType,mediaType);assert.deepEqual(openEvidence(object,key),data);return {id:object.id};}},scan:async bytes=>{scans++;assert.deepEqual(bytes,data);return 'clean';}});
  await ingest({tenantId,projectId,requestId:randomUUID(),data,mediaType,signal});
  await assert.rejects(ingest({tenantId,projectId,requestId:randomUUID(),data:Buffer.concat([data,Buffer.from('tail')]),mediaType,signal}),IngestionRejected);
 }
 assert.equal(scans,2);assert.equal(commits,2);
});
test('Office batch checkpoints retain exact original and declared format',async()=>{
 const files=officeFixtures().map(([type,b],i)=>{const f=new Blob([b],{type});Object.defineProperty(f,'name',{value:i?'test.xlsx':'test.docx'});return f;});
 const plan=await planBatchImport(files,{digest:async b=>hash(b),randomId:randomUUID});assert.ok(plan.rows.every(r=>r.state==='ready'));
 const scope={actorId:randomUUID(),tenantId:randomUUID(),projectId:randomUUID()},plain=await encodeBatchCheckpoint(plan,scope,async b=>hash(b));
 const restored=await decodeBatchCheckpoint(plain,scope,async b=>hash(b),plan.batchId);assert.deepEqual(restored.rows.map(r=>[r.mediaType,r.sha256]),plan.rows.map(r=>[r.mediaType,r.sha256]));
});
