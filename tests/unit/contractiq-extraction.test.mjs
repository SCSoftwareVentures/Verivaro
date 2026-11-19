import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {extractRequirementCandidates,createContractIQ} from '../../src/security/contractiq-extraction.mjs';
import {canonicalTextPdf} from '../../src/security/evidence-formats.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex'),type='text/plain; charset=utf-8';
test('source candidates retain exact trimmed line and negation, deterministic whole-file and quote hashes',()=>{
 const data=Buffer.from('Introduction\r\n  Equipment must carry a label.  \r\nStaff shall not bypass guards.\nMustard is optional.\n');
 const r=extractRequirementCandidates(data,type);assert.equal(r.sha256,hash(data));assert.deepEqual(r.candidates.map(c=>[c.line,c.quote,c.page]),[[2,'Equipment must carry a label.',null],[3,'Staff shall not bypass guards.',null]]);
 assert.equal(r.candidates[0].quoteSha256,hash(r.candidates[0].quote));
 const pdf=canonicalTextPdf(['General','Work must comply.']);assert.deepEqual(extractRequirementCandidates(pdf,'application/pdf').candidates.map(c=>[c.page,c.line,c.quote]),[[1,2,'Work must comply.']]);
 assert.throws(()=>extractRequirementCandidates(Buffer.from('%PDF-1.4 corrupt'),'application/pdf'));
});
test('bounded candidate output explicitly reports truncation and skipped lines',()=>{
 const r=extractRequirementCandidates(Buffer.from(Array(70).fill('Work must comply.').join('\n')+'\nMust '+ 'a'.repeat(1025)),type);
 assert.equal(r.candidates.length,64);assert.equal(r.matched,71);assert.equal(r.skipped,1);assert.equal(r.truncated,true);
});
test('import derives quote from source rather than caller, checks hash and zeroes buffer',async()=>{
 const bytes=Buffer.from('Work must comply.'),sha256=hash(bytes),seen=[];
 const run=createContractIQ({retrieve:async()=>({data:Buffer.from(bytes),mediaType:type,sha256}),workflow:{assessment:async()=>({canWrite:true}),importSourceLine:async v=>{seen.push(v);return 'ok';}}});
 const signal=new AbortController().signal;
 await assert.rejects(run({sha256,line:1,quoteSha256:'0'.repeat(64)},{importLine:true,signal}));
 assert.equal(await run({sha256,line:1,quoteSha256:hash(bytes),quote:'fake'},{importLine:true,signal}),'ok');assert.equal(seen[0].quote,bytes.toString());
});
