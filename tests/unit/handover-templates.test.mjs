import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {buildHandoverDerivatives,csvCell} from '../../src/security/handover-templates.mjs';
import {createSubmissionPackage} from '../../src/security/submission-package.mjs';
import {verifySubmissionPackage} from '../../src/security/submission-verifier.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
function fixture(){
 const tenantId=randomUUID(),projectId=randomUUID(),submissionId=randomUUID(),id=randomUUID(),bytes=Buffer.from('Original evidence'),mediaType='text/plain; charset=utf-8';
 const m={version:1,tenantId,projectId,projectName:'Test (project)',summary:{status:'criteria_satisfied'},requirements:[{requirementId:randomUUID(),versionId:randomUUID(),title:'=HYPERLINK("x")',applicability:'required',state:'satisfied',ruleDecision:'approved',links:[{evidenceId:id,sha256:hash(bytes)}]}],evidence:[{id,bytes:bytes.length,sha256:hash(bytes),mediaType}]};
 const manifest=JSON.stringify(m),sha256=hash(manifest),receipt={submissionId,sha256,manifest,authorization:'internal owner-authorized download only'};
 return {m,bytes,mediaType,receipt,input:{tenantId,projectId,submissionId,sha256}};
}
test('formula cells escaped; quoting preserves original text',()=>{for(const s of ['=cmd','  +1','\uFEFF@cmd','-1','\tvalue'])assert.ok(csvCell(s).startsWith(String.fromCharCode(34,39)));assert.equal(csvCell('a"b'),'"a""b"');});
test('two profiles deterministic; PDF and safe registers; no source mutation',()=>{const f=fixture(),copy=JSON.stringify(f.m),a=buildHandoverDerivatives(f.m,f.input.sha256,'handover-v1'),b=buildHandoverDerivatives(f.m,f.input.sha256,'register-v1');assert.ok(a[0][1].subarray(0,8).toString()==='%PDF-1.4');assert.notDeepEqual(a[0][1],b[0][1]);assert.deepEqual(a,buildHandoverDerivatives(f.m,f.input.sha256,'handover-v1'));assert.match(a[1][1].toString(),/'=HYPERLINK/);assert.equal(JSON.stringify(f.m),copy);});
test('both profiles verified offline with external digests; tampering denied',async()=>{const f=fixture(),assemble=createSubmissionPackage({workflow:{readSubmission:async()=>f.receipt},retrieve:async()=>({data:Buffer.from(f.bytes),sha256:hash(f.bytes),mediaType:f.mediaType})});for(const profile of ['handover-v1','register-v1']){const archive=await assemble(f.input,{signal:new AbortController().signal,profile}),result=verifySubmissionPackage(archive,{expectedPackageSha256:hash(archive),expectedManifestSha256:f.input.sha256});assert.equal(result.integrityVerified,true);assert.equal(result.evidenceCount,1);assert.equal(result.authenticityVerified,false);const bad=Buffer.from(archive);bad[100]^=1;assert.throws(()=>verifySubmissionPackage(bad,{expectedPackageSha256:hash(bad),expectedManifestSha256:f.input.sha256}));}});
test('blocked, unreferenced evidence and unsupported profiles fail closed',()=>{const f=fixture();assert.throws(()=>buildHandoverDerivatives(f.m,f.input.sha256,'custom'));f.m.requirements[0].state='missing_evidence';assert.throws(()=>buildHandoverDerivatives(f.m,f.input.sha256,'handover-v1'));f.m.requirements[0].state='satisfied';f.m.requirements[0].links=[];assert.throws(()=>buildHandoverDerivatives(f.m,f.input.sha256,'handover-v1'));});
