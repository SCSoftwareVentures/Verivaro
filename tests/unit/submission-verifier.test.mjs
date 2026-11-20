import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {createSubmissionPackage} from '../../src/security/submission-package.mjs';
import {zip} from '../../src/security/verification-report-export.mjs';
import {verifySubmissionPackage,MAX_SUBMISSION_ARCHIVE} from '../../src/security/submission-verifier.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
async function fixture(){
 const tenantId=randomUUID(),projectId=randomUUID(),submissionId=randomUUID(),id=randomUUID(),bytes=Buffer.from('Original evidence'),mediaType='text/plain; charset=utf-8';
 const manifest=JSON.stringify({version:1,tenantId,projectId,summary:{status:'criteria_satisfied'},evidence:[{id,bytes:bytes.length,sha256:hash(bytes),mediaType}]});
 const sha256=hash(manifest),receipt={submissionId,sha256,manifest,authorization:'internal owner-authorized download only'};
 const assemble=createSubmissionPackage({workflow:{readSubmission:async()=>receipt},retrieve:async()=>({data:Buffer.from(bytes),sha256:hash(bytes),mediaType})});
 const archive=await assemble({tenantId,projectId,submissionId,sha256},{signal:new AbortController().signal});
 const files=[];let p=0;while(archive.readUInt32LE(p)===0x04034b50){const n=archive.readUInt16LE(p+26),s=archive.readUInt32LE(p+22);files.push([archive.toString('ascii',p+30,p+30+n),Buffer.from(archive.subarray(p+30+n,p+30+n+s))]);p+=30+n+s;}
 return {archive,files,sha256,submissionId,bytes};
}
const verify=(f,a=f.archive,m=f.sha256)=>verifySubmissionPackage(a,{expectedPackageSha256:hash(a),expectedManifestSha256:m});
test('offline verifier accepts actual generated package and does not claim authenticity',async()=>{
 const f=await fixture(),copy=Buffer.from(f.archive),v=verify(f);
 assert.equal(v.integrityVerified,true);assert.equal(v.authenticityVerified,false);assert.equal(v.evidenceCount,1);assert.equal(v.evidenceBytes,f.bytes.length);assert.equal(v.submissionId,f.submissionId);assert.deepEqual(f.archive,copy);
});
test('requires externally supplied exact digests and bounds',async()=>{
 const f=await fixture();
 for(const opts of [undefined,{}, {expectedPackageSha256:'0'.repeat(64),expectedManifestSha256:f.sha256},{expectedPackageSha256:hash(f.archive),expectedManifestSha256:'0'.repeat(64)}])assert.throws(()=>verifySubmissionPackage(f.archive,opts),/verification failed/);
 assert.throws(()=>verify(f,Buffer.alloc(MAX_SUBMISSION_ARCHIVE+1)),/verification failed/);
});
test('rejects trailing bytes, malformed directory, truncation and unsupported compression even with recalculated ZIP hash',async()=>{
 const f=await fixture(),bad=Buffer.from(f.archive),compressed=Buffer.from(f.archive);
 bad[bad.length-23]^=1;compressed.writeUInt16LE(8,8);
 for(const a of [Buffer.concat([f.archive,Buffer.from('extra')]),bad,compressed,f.archive.subarray(0,-1)])assert.throws(()=>verify(f,a),/verification failed/);
});
test('rejects duplicate entries, traversal, substituted evidence, inconsistent index and missing objects',async()=>{
 const f=await fixture(),[manifest,evidence,index]=f.files;
 const wrong=Buffer.from(evidence[1]);wrong[0]^=1;
 const badIndex=JSON.parse(index[1]);badIndex.files[1].sha256='0'.repeat(64);
 for(const entries of [[manifest,evidence,evidence,index],[manifest,['../evil.txt',evidence[1]],index],[manifest,[evidence[0],wrong],index],[manifest,evidence,[index[0],Buffer.from(JSON.stringify(badIndex))]],[manifest,index]])assert.throws(()=>verify(f,zip(entries)),/verification failed/);
});
test('rejects evidence omission from manifest reconciliation and non-approved readiness state',async()=>{
 const f=await fixture(),[manifest,evidence,index]=f.files;
 const m=JSON.parse(manifest[1]);m.summary.status='blocked';
 const changed=Buffer.from(JSON.stringify(m)),h=hash(changed),idx=JSON.parse(index[1]);idx.authorization.sha256=h;idx.files[0].sha256=h;idx.files[0].bytes=changed.length;
 assert.throws(()=>verify(f,zip([[manifest[0],changed],evidence,[index[0],Buffer.from(JSON.stringify(idx))]]),h),/verification failed/);
});
