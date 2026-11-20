import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {extractRequirementCandidates,createContractIQ} from '../../src/security/contractiq-extraction.mjs';
import {canonicalTextPdf,canonicalPagedTextPdf} from '../../src/security/evidence-formats.mjs';
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
 const bytes=Buffer.from('Work must comply.'),sha256=hash(bytes),seen=[],retrieved=[];
 const run=createContractIQ({retrieve:async()=>{const data=Buffer.from(bytes);retrieved.push(data);return {data,mediaType:type,sha256};},workflow:{assessment:async()=>({canWrite:true}),importSourceLine:async v=>{seen.push(v);return 'ok';}}});
 const signal=new AbortController().signal;
 await assert.rejects(run({sha256,line:1,quoteSha256:'0'.repeat(64)},{importLine:true,signal}));
 assert.equal(await run({sha256,line:1,quoteSha256:hash(bytes),quote:'fake'},{importLine:true,signal}),'ok');assert.equal(seen[0].quote,bytes.toString());assert.ok(retrieved.every(b=>b.every(x=>x===0)));
});

test('extended obligation cues retain the exact original and versioned algorithm',()=>{const r=extractRequirementCandidates(Buffer.from('General\nContractor undertakes to provide inspection results.\nNo substitution is permitted.\nEquipment must carry ID.\nReference table'),type);assert.deepEqual(r.candidates.map(x=>[x.line,x.algorithm,x.category]),[[2,'obligation-line-v2','obligation_candidate'],[3,'obligation-line-v2','prohibition'],[4,'modal-line-v1','obligation_candidate']]);assert.equal(r.candidates[0].quoteSha256,hash('Contractor undertakes to provide inspection results.'));});

 test('bounded source cursor reaches every eligible line and refuses invalid cursors',()=>{
 const data=Buffer.from(Array.from({length:140},(_,i)=>i===64?'Optional note':i===65?'Must '+ 'x'.repeat(1025):'Work must comply '+(i+1)+'.').join('\n'));
 const a=extractRequirementCandidates(data,type),b=extractRequirementCandidates(data,type,{afterLine:a.nextAfterLine}),c=extractRequirementCandidates(data,type,{afterLine:b.nextAfterLine});
 assert.deepEqual([a.candidates.length,b.candidates.length,c.candidates.length],[64,64,10]);assert.equal(a.nextAfterLine,64);assert.equal(b.nextAfterLine,130);assert.equal(c.nextAfterLine,null);assert.equal(c.truncated,false);assert.equal(b.candidates[0].line,67);assert.equal(new Set([...a.candidates,...b.candidates,...c.candidates].map(x=>x.line)).size,138);assert.equal(c.matched,139);assert.equal(c.skipped,1);
 for(const afterLine of [-1,1.5,'1',262145,null])assert.throws(()=>extractRequirementCandidates(data,type,{afterLine}),RangeError);
 assert.deepEqual(extractRequirementCandidates(data,type,{afterLine:140}).candidates,[]);
 });
 test('source import verifies late lines independently of pagination or supplied cursor',async()=>{
 const quote='Contractor must provide late evidence.',bytes=Buffer.from(Array(80).fill('Work must comply.').concat(quote).join('\n')),sha256=hash(bytes),seen=[];
 const run=createContractIQ({retrieve:async()=>({data:Buffer.from(bytes),mediaType:type,sha256}),workflow:{assessment:async()=>({canWrite:true}),importSourceLine:async v=>{seen.push(v);return 'ok';}}});const signal=new AbortController().signal;
 assert.equal(await run({sha256,line:81,quoteSha256:hash(quote),afterLine:999,quote:'forged'},{importLine:true,signal}),'ok');assert.equal(seen[0].quote,quote);
 await assert.rejects(run({sha256,line:80,quoteSha256:hash(quote)},{importLine:true,signal}));await assert.rejects(run({sha256,line:82,quoteSha256:hash(quote)},{importLine:true,signal}));
 });

test('multi-page PDF candidates retain actual page and global line across pagination',async()=>{
 const pages=[Array(40).fill('Work must comply.'),Array(40).fill('Work is mandatory.'),['Equipment must carry ID.']],data=canonicalPagedTextPdf(pages),sha256=hash(data);
 const a=extractRequirementCandidates(data,'application/pdf'),b=extractRequirementCandidates(data,'application/pdf',{afterLine:a.nextAfterLine});
 assert.deepEqual(a.candidates.slice(39,41).map(x=>[x.line,x.page]),[[40,1],[41,2]]);
 assert.deepEqual(b.candidates.at(-1),{line:81,page:3,quote:pages[2][0],quoteSha256:hash(pages[2][0]),algorithm:'modal-line-v1',category:'obligation_candidate'});
 assert.equal(b.truncated,false);
 const seen=[],run=createContractIQ({retrieve:async()=>({data:Buffer.from(data),mediaType:'application/pdf',sha256}),workflow:{assessment:async()=>({canWrite:true}),importSourceLine:async v=>seen.push(v)}});
 await run({sha256,line:81,quoteSha256:hash(pages[2][0]),page:1},{importLine:true,signal:new AbortController().signal});assert.equal(seen[0].page,3);
});

test('compressed PDF candidates retain exact escaped text, digest and original page location',()=>{
 const quote='Contractor must retain (signed) C:\\records.',data=canonicalPagedTextPdf([['General'],[quote]],{compressed:true});
 const r=extractRequirementCandidates(data,'application/pdf');assert.equal(r.sha256,hash(data));assert.deepEqual(r.candidates.map(c=>[c.page,c.line,c.quote,c.quoteSha256]),[[2,2,quote,hash(quote)]]);
});
