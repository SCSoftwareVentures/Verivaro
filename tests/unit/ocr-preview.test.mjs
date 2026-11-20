import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fixturePng} from '../fixtures/evidence-formats-fixture.mjs';
import {parseOcrTsv,createOcrPreview,createTesseractEngine,OCR_MAX_OUTPUT} from '../../src/security/ocr-preview.mjs';
import {ReleaseDenied,ReleaseConflict} from '../../src/security/evidence-release.mjs';
const head='level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n';
const parent=['1\t1\t0\t0\t0\t0\t0\t0\t100\t60\t-1\t','2\t1\t1\t0\t0\t0\t10\t10\t80\t20\t-1\t','3\t1\t1\t1\t0\t0\t10\t10\t80\t20\t-1\t','4\t1\t1\t1\t1\t0\t10\t10\t80\t20\t-1\t'];
const a='5\t1\t1\t1\t1\t1\t10\t10\t30\t20\t96.25\tMust',b='5\t1\t1\t1\t1\t2\t45\t10\t45\t20\t62.75\tcomply.';
const tsv=(rows=[...parent,a,b])=>Buffer.from(head+rows.join('\n')+'\n');
const dims={width:100,height:60},hash=b=>createHash('sha256').update(b).digest('hex');
test('OCR TSV retains region bounds, text digest and conservative review flag',()=>{
 const [r]=parseOcrTsv(tsv(),dims);assert.equal(r.quote,'Must comply.');assert.equal(r.quoteSha256,hash(r.quote));assert.equal(r.confidence,79.5);assert.equal(r.minWordConfidence,62.75);assert.deepEqual(r.box,{left:10,top:10,width:80,height:20});assert.equal(r.reviewRequired,true);
 assert.deepEqual(parseOcrTsv(tsv(parent.slice(0,1)),dims),[]);
});
test('malformed TSV, duplicate rows, invalid confidence, bad hierarchy and out-of-image geometry are rejected',()=>{
 for(const rows of [[...parent,a,a],[...parent,b.replace('62.75','101')],[...parent,a.replace('30\t20','99\t20')],[parent[0],a],[...parent,a.replace('Must','<bad>\tcolumn')],[...parent,a.replace('Must','bad\u202e')],[...parent,a.replace('96.25','NaN')]])assert.throws(()=>parseOcrTsv(tsv(rows),dims));
 assert.throws(()=>parseOcrTsv(Buffer.alloc(OCR_MAX_OUTPUT+1),dims));
});
test('preview verifies scoped original, never imports, rechecks authorization and clears buffers',async()=>{
 const data=fixturePng({width:100,height:60,pixels:Buffer.alloc(60*301)}),sha256=hash(data),retrieved=[],outputs=[],signal=new AbortController().signal;
 let allowed=true,flip=false,recognized=0;
 const preview=createOcrPreview({assessment:async()=>({canWrite:allowed}),retrieve:async()=>{const b=Buffer.from(data);retrieved.push(b);return {data:b,sha256,mediaType:'image/png'};},recognize:async b=>{assert.deepEqual(b,data);recognized++;let out=tsv();outputs.push(out);if(flip)allowed=false;return out;}});
 const r=await preview({sha256},{signal});assert.equal(r.verified,false);assert.equal(r.regions[0].quote,'Must comply.');assert.ok(retrieved.every(b=>b.every(x=>x===0)));assert.ok(outputs.every(b=>b.every(x=>x===0)));
 await assert.rejects(preview({sha256:'0'.repeat(64)},{signal}),ReleaseConflict);
 flip=true;await assert.rejects(preview({sha256},{signal}),ReleaseDenied);await assert.rejects(preview({sha256},{signal}),ReleaseDenied);assert.equal(recognized,2);
});
test('missing executable and cancellation fail closed',async()=>{
 const run=createTesseractEngine({binaryPath:'/nonexistent/tesseract',timeoutMs:1000}),data=fixturePng();
 await assert.rejects(run(data,new AbortController().signal));const ac=new AbortController();ac.abort();await assert.rejects(run(data,ac.signal));
});
