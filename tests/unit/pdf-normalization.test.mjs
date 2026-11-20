import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {canonicalTextPdf} from '../../src/security/evidence-formats.mjs';
import {readCanonicalScannedPdf} from '../../src/security/scanned-pdf.mjs';
import {readCanonicalMultipageScannedPdf} from '../../src/security/scanned-pdf-multipage.mjs';
import {normalizeExternalPdf,inspectPdfInfo,ppmToCanonicalPng,createOfflinePoppler} from '../../src/security/pdf-normalization.mjs';
const report=n=>Buffer.from('Title: Sample\nPages: '+n+'\nEncrypted: no\nJavaScript: no\nProducer: test\n');
const ppm=(w=16,h=12)=>{const rgb=Buffer.alloc(w*h*3,255);rgb[3]=0;return Buffer.concat([Buffer.from('P6\n'+w+' '+h+'\n255\n'),rgb]);};
const source=canonicalTextPdf(['Equipment must carry ID.']),sha=b=>createHash('sha256').update(b).digest('hex');
test('validated offline output is canonical and cryptographically bound to original bytes',async()=>{
 const p=async count=>normalizeExternalPdf(source,{renderer:{inspect:async()=>report(count),render:async()=>ppm()},signal:new AbortController().signal});
 const one=await p(1);assert.equal(one.manifest.sourceSha256,sha(source));assert.equal(one.manifest.derivedSha256,sha(one.pdf));assert.equal(one.manifest.originalRetained,false);assert.equal(one.manifest.reviewRequired,true);const r=readCanonicalScannedPdf(one.pdf);r.png.fill(0);
 const many=await p(4);assert.equal(many.manifest.pageCount,4);assert.equal(many.manifest.pages.length,4);const multi=readCanonicalMultipageScannedPdf(many.pdf,{page:4});assert.equal(multi.page,4);multi.png.fill(0);
});
test('rejects active, encrypted, oversized, nonexistent and malformed PDF inputs',async()=>{
 for(const s of [report(0),report(5),Buffer.from('Pages: 1\nEncrypted: yes (print:yes)\nJavaScript: no\n'),Buffer.from('Pages: 1\nEncrypted: no\nJavaScript: yes\n'),Buffer.from('Pages: 1\nPages: 1\nEncrypted: no\nJavaScript: no\n'),Buffer.from('Pages: 1\nEncrypted: no\n')])assert.throws(()=>inspectPdfInfo(s));
 for(const p of [ppm(721,1),Buffer.concat([ppm(),Buffer.from('junk')]),Buffer.from('P3\n2 2\n255\nabc'),Buffer.alloc(20)])assert.throws(()=>ppmToCanonicalPng(p));
 await assert.rejects(normalizeExternalPdf(Buffer.alloc(100,7),{renderer:{inspect:async()=>report(1),render:async()=>ppm()},signal:new AbortController().signal}));
 await assert.rejects(normalizeExternalPdf(source,{renderer:{inspect:async()=>report(1),render:async()=>Buffer.alloc(10)},signal:new AbortController().signal}));
});
test('per-page abort and timeouts fail closed; no normalizer renders when preflight is denied',async()=>{
 let renders=0;const ac=new AbortController();
 const renderer={inspect:async()=>report(2),render:async()=>{renders++;ac.abort();return ppm();}};
 await assert.rejects(normalizeExternalPdf(source,{renderer,signal:ac.signal}));assert.equal(renders,1);
 let invoked=0;await assert.rejects(normalizeExternalPdf(source,{renderer:{inspect:async()=>report(5),render:async()=>{invoked++;return ppm();}},signal:new AbortController().signal}));assert.equal(invoked,0);
 assert.throws(()=>createOfflinePoppler({pdfinfoPath:'pdfinfo'}));assert.throws(()=>createOfflinePoppler({timeoutMs:40000}));
});
