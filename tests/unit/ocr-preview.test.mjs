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

test('archived assessment blocks the read-only preview before original access',async()=>{
 const preview=createOcrPreview({assessment:async()=>({canWrite:true,archived:true}),retrieve:async()=>{throw Error('must not retrieve');},recognize:async()=>{throw Error('must not recognize');}});
 await assert.rejects(preview({sha256:'0'.repeat(64)},{signal:new AbortController().signal}),ReleaseDenied);
});

test('OCR import rederives exact region and requires explicit author confirmation',async()=>{
 const data=fixturePng({width:100,height:60,pixels:Buffer.alloc(60*301)}),sha256=hash(data),calls=[],signal=new AbortController().signal;
 const preview=createOcrPreview({retrieve:async()=>({data:Buffer.from(data),sha256,mediaType:'image/png'}),assessment:async()=>({canWrite:true}),recognize:async()=>tsv(),importSource:async x=>calls.push(x)});
 const r=(await preview({sha256},{signal})).regions[0],input={sha256,ordinal:r.ordinal,quoteSha256:r.quoteSha256,regionDigest:r.regionDigest,confirm:true,location:{forged:true}};
 await assert.rejects(preview({...input,confirm:false},{signal,importRegion:true}),ReleaseDenied);
 await assert.rejects(preview({...input,regionDigest:'0'.repeat(64)},{signal,importRegion:true}),ReleaseConflict);
 await preview(input,{signal,importRegion:true});assert.equal(calls.length,1);assert.deepEqual(calls[0].location.box,r.box);assert.equal(calls[0].quote,r.quote);assert.equal(calls[0].location.regionDigest,r.regionDigest);
});

test('canonical image-only PDF preview binds PDF and raster hashes, and import repeats exact image recognition',async()=>{
 const {canonicalScannedPdf,readCanonicalScannedPdf}=await import('../../src/security/scanned-pdf.mjs');
 const img=fixturePng({width:100,height:60,pixels:Buffer.alloc(60*301)}),pdf=canonicalScannedPdf(img),pdfSha=hash(pdf),scan=readCanonicalScannedPdf(pdf),calls=[];
 const p=createOcrPreview({retrieve:async()=>({data:Buffer.from(pdf),sha256:pdfSha,mediaType:'application/pdf'}),assessment:async()=>({canWrite:true}),recognize:async b=>{assert.deepEqual(b,scan.png);return tsv();},importSource:async a=>calls.push(a)});
 const signal=new AbortController().signal,out=await p({sha256:pdfSha},{signal});assert.equal(out.page,1);assert.equal(out.rasterSha256,scan.rasterSha256);
 const r=out.regions[0],args={sha256:pdfSha,ordinal:r.ordinal,regionDigest:r.regionDigest,quoteSha256:r.quoteSha256,confirm:true};
 await p({...args,location:{page:99}},{signal,importRegion:true});assert.equal(calls.length,1);assert.equal(calls[0].location.page,1);assert.equal(calls[0].location.rasterSha256,scan.rasterSha256);
 await assert.rejects(p({...args,regionDigest:'f'.repeat(64)},{signal,importRegion:true}),ReleaseConflict);
 const textPdf=(await import('../../src/security/evidence-formats.mjs')).canonicalTextPdf(['Equipment must carry ID.']);
 const bad=createOcrPreview({retrieve:async()=>({data:Buffer.from(textPdf),sha256:hash(textPdf),mediaType:'application/pdf'}),assessment:async()=>({canWrite:true}),recognize:async()=>{throw Error('OCR must not run');}});
 await assert.rejects(bad({sha256:hash(textPdf)},{signal}),ReleaseConflict);
 scan.png.fill(0);
});
