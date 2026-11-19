import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import {createSubmissionPackage} from '../../src/security/submission-package.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
function fixture(){
 const tenantId=randomUUID(),projectId=randomUUID(),submissionId=randomUUID(),evidenceId=randomUUID(),bytes=Buffer.from('Exact approved evidence'),mediaType='text/plain; charset=utf-8';
 const manifest=JSON.stringify({version:1,tenantId,projectId,summary:{status:'criteria_satisfied'},evidence:[{id:evidenceId,sha256:hash(bytes),bytes:bytes.length,mediaType}]});
 const sha256=hash(manifest),receipt={submissionId,sha256,manifest,authorizedAt:'fixture',authorization:'internal owner-authorized download only'};
 return {input:{tenantId,projectId,submissionId,sha256},receipt,bytes,mediaType,evidenceId};
}
test('package includes exact approved bytes, canonical manifest and index; buffers cleared',async()=>{
 const f=fixture(),buffers=[];let reads=0;
 const assemble=createSubmissionPackage({workflow:{readSubmission:async()=>{reads++;return f.receipt;}},retrieve:async x=>{assert.equal(x.evidenceId,f.evidenceId);const data=Buffer.from(f.bytes);buffers.push(data);return {data,sha256:hash(data),mediaType:f.mediaType};}});
 const zip=await assemble(f.input,{signal:new AbortController().signal});assert.equal(reads,2);assert.ok(buffers.every(b=>b.every(x=>x===0)));
 let offset=0;const entries=new Map();while(zip.readUInt32LE(offset)===0x04034b50){const n=zip.readUInt16LE(offset+26),length=zip.readUInt32LE(offset+18),name=zip.toString('ascii',offset+30,offset+30+n);entries.set(name,zip.subarray(offset+30+n,offset+30+n+length));offset+=30+n+length;}
 assert.deepEqual([...entries.keys()],['submission.json','evidence-'+f.evidenceId+'.txt','package-index.json']);assert.equal(entries.get('submission.json').toString(),f.receipt.manifest);assert.ok(entries.get('evidence-'+f.evidenceId+'.txt').equals(f.bytes));for(const e of JSON.parse(entries.get('package-index.json')).files)assert.equal(hash(entries.get(e.name)),e.sha256);
});
test('mismatched bytes and final stale authorization fail closed',async()=>{
 const f=fixture(),bad=Buffer.alloc(f.bytes.length),signal=new AbortController().signal;
 const tampered=createSubmissionPackage({workflow:{readSubmission:async()=>f.receipt},retrieve:async()=>({data:bad,sha256:hash(f.bytes),mediaType:f.mediaType})});
 await assert.rejects(tampered(f.input,{signal}),/evidence mismatch/);
 let reads=0;const stale=createSubmissionPackage({workflow:{readSubmission:async()=>{if(++reads===2)throw Error('stale');return f.receipt;}},retrieve:async()=>({data:Buffer.from(f.bytes),sha256:hash(f.bytes),mediaType:f.mediaType})});
 await assert.rejects(stale(f.input,{signal}),/stale/);
});
