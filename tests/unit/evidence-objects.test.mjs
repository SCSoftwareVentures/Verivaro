import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {sealEvidence,openEvidence,validateTextEvidence,MAX_EVIDENCE_UPLOAD} from '../../src/security/evidence-objects.mjs';
import {createClamdScanner} from '../../src/security/clamd-scanner.mjs';
import {scannerFixture} from '../fixtures/clamd-fixture.mjs';
test('evidence cipher authenticates scope, size and plaintext hash; invalid text denied',()=>{
 const key=randomBytes(32),data=Buffer.from('Fixture text\n'),m=sealEvidence(data,{key,keyId:'v1',tenantId:randomUUID(),projectId:randomUUID()});
 assert.deepEqual(openEvidence(m,key),data);assert.notDeepEqual(m.envelope,data);
 for(const altered of [{...m,projectId:randomUUID()},{...m,keyId:'v2'},{...m,sha256:'0'.repeat(64)},{...m,envelope:Buffer.from(m.envelope).fill(0)}])assert.throws(()=>openEvidence(altered,key));
 assert.throws(()=>openEvidence(m,randomBytes(32)));
 for(const x of [Buffer.from([0xff]),Buffer.from('a\0b'),Buffer.alloc(MAX_EVIDENCE_UPLOAD+1,65),Buffer.from('  ')])assert.throws(()=>validateTextEvidence(x));
});
test('real Unix socket INSTREAM protocol accepts only clean response; infection and scanner failure distinct',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'vv-scan-'));let fixture;
 try{
  fixture=await scannerFixture(dir);const scan=createClamdScanner({socketPath:fixture.socketPath}),signal=new AbortController().signal,data=Buffer.from('fixture');
  assert.equal(await scan(data,signal),'clean');fixture.setVerdict('infected');assert.equal(await scan(data,signal),'infected');
  fixture.setVerdict('error');await assert.rejects(scan(data,signal));
  fixture.setVerdict('disconnect');await assert.rejects(scan(data,signal));assert.equal(fixture.calls,4);
 }finally{await fixture?.close();await rm(dir,{recursive:true,force:true});}
});
