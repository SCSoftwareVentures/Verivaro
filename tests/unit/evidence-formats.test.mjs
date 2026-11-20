import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {deflateSync} from 'node:zlib';
import {canonicalTextPdf,canonicalPagedTextPdf,readCanonicalPdfPages,validatePdf,validatePng} from '../../src/security/evidence-formats.mjs';
import {fixturePng} from '../fixtures/evidence-formats-fixture.mjs';
import {sealEvidence,openEvidence,validateEvidence} from '../../src/security/evidence-objects.mjs';
test('strict PNG validates CRC, size, allowed chunks and pixel boundaries',()=>{
 const good=fixturePng();assert.deepEqual(validatePng(good),good);
 const bad=Buffer.from(good);bad[20]^=1;
 for(const b of [bad,fixturePng({width:4294967295}),fixturePng({extra:true}),fixturePng({pixels:Buffer.from([5,0,0,0])}),fixturePng({pixels:Buffer.alloc(100000)}),Buffer.concat([good,Buffer.from('tail')]),good.subarray(0,-1)])assert.throws(()=>validatePng(b));
 assert.throws(()=>validateEvidence(good,'application/pdf'));
});
test('canonical PDF validates exact object graph and offsets; active or appended content denied',()=>{
 const good=canonicalTextPdf(['Evidence fixture','Reference 123']);assert.deepEqual(validatePdf(good),good);
 for(const b of [Buffer.from(good.toString().replace('/Catalog','/JavaScript')),Buffer.from(good.toString().replace('startxref','startxrf')),Buffer.concat([good,Buffer.from('tail')]),Buffer.from('%PDF-1.7\n%%EOF\n')])assert.throws(()=>validatePdf(b));
 const key=randomBytes(32),m=sealEvidence(good,{key,keyId:'v2',tenantId:randomUUID(),projectId:randomUUID(),mediaType:'application/pdf'});
 assert.deepEqual(openEvidence(m,key),good);assert.throws(()=>openEvidence({...m,mediaType:'image/png'},key));assert.throws(()=>openEvidence({...m,mediaType:'text/plain; charset=utf-8'},key));
});

test('canonical multi-page PDF preserves page order and denies altered graph, oversized counts and trailing content',()=>{
 const pages=[['First page'],['Second page','Work must comply.'],['Third page']];
 const pdf=canonicalPagedTextPdf(pages);assert.deepEqual(readCanonicalPdfPages(pdf),pages);assert.deepEqual(validatePdf(pdf),pdf);
 assert.deepEqual(canonicalPagedTextPdf([pages[0]]),canonicalTextPdf(pages[0]));
 for(const b of [Buffer.from(pdf.toString().replace('/Count 3','/Count 2')),Buffer.from(pdf.toString().replace('/Kids [3 0 R 6 0 R','/Kids [6 0 R 3 0 R')),Buffer.concat([pdf,Buffer.from('tail')]),pdf.subarray(0,-1),Buffer.from(pdf.toString().replace('/Helvetica','/JavaScript'))])assert.throws(()=>readCanonicalPdfPages(b));
 assert.throws(()=>canonicalPagedTextPdf(Array.from({length:33},()=>['a'])));
 assert.throws(()=>canonicalPagedTextPdf([Array(41).fill('a')]));
 assert.throws(()=>canonicalPagedTextPdf([[]]));
 const max=Array.from({length:32},()=>Array(40).fill('a'.repeat(90)));assert.deepEqual(readCanonicalPdfPages(canonicalPagedTextPdf(max)),max);
});

test('FlateDecode PDF accepts independent compression levels and exact escaped literal text',()=>{
 const pages=[['A (test) must include C:\\docs.','Delivery must be < 5 days & documented.'],['No substitution is permitted.']];
 for(const level of [0,1,6,9]){
  const pdf=canonicalPagedTextPdf(pages,{compressed:true,level});
  assert.deepEqual(readCanonicalPdfPages(pdf),pages);assert.deepEqual(validatePdf(pdf),pdf);
  const start=pdf.indexOf(Buffer.from('stream\n'))+7,altered=Buffer.from(pdf);altered[start]^=255;
  assert.throws(()=>validatePdf(altered));assert.throws(()=>validatePdf(Buffer.concat([pdf,Buffer.from('tail')])));
 }
 assert.deepEqual(readCanonicalPdfPages(canonicalPagedTextPdf(pages)),pages);
 const raw=canonicalPagedTextPdf([['Work must comply.']]);
 assert.throws(()=>validatePdf(Buffer.from(raw.toString().replace('Work must comply.','Work (must) comply.'))));
});
// Replace a single compressed stream and independently rebuild xref by exact byte offsets.
function replaceCompressedPayload(pdf,payload){
 let s=pdf.toString('latin1'),m=/<< \/Length (\d+) \/Filter \/FlateDecode >>\nstream\n/.exec(s),start=m.index+m[0].length,end=start+Number(m[1]);
 s=s.slice(0,m.index)+'<< /Length '+payload.length+' /Filter /FlateDecode >>\nstream\n'+payload.toString('latin1')+s.slice(end);
 const x=s.lastIndexOf('\nxref\n')+1,body=s.slice(0,x),offsets=[...body.matchAll(/^\d+ 0 obj$/gm)].map(m=>m.index);
 return Buffer.from(body+'xref\n0 '+(offsets.length+1)+'\n0000000000 65535 f \n'+offsets.map(x=>String(x).padStart(10,'0')+' 00000 n \n').join('')+'trailer\n<< /Size '+(offsets.length+1)+' /Root 1 0 R >>\nstartxref\n'+x+'\n%%EOF\n','latin1');
}
test('compressed streams reject expansion bombs, trailing deflate members and extra PDF operators',()=>{
 const pdf=canonicalPagedTextPdf([['Work must comply.']],{compressed:true});
 const valid=deflateSync(Buffer.from('BT\n/F1 12 Tf\n50 750 Td\n(Work must comply.) Tj\nET\n'));
 for(const payload of [deflateSync(Buffer.alloc(100000,65)),Buffer.concat([valid,Buffer.from('tail')]),Buffer.concat([valid,valid]),deflateSync(Buffer.from('BT\n/F1 12 Tf\n50 750 Td\n(Work must comply.) Tj\n/JavaScript Do\nET\n'))]){
  assert.throws(()=>validatePdf(replaceCompressedPayload(pdf,payload)));
 }
 assert.deepEqual(readCanonicalPdfPages(replaceCompressedPayload(pdf,valid)),[['Work must comply.']]);
});

test('single-page image-only PDF verifies exact image graph, payload length and canonical original bytes',async()=>{
 const {canonicalScannedPdf,readCanonicalScannedPdf}=await import('../../src/security/scanned-pdf.mjs');
 const w=32,h=18,pixels=Buffer.alloc(h*(w*3+1));for(let y=0;y<h;y++)pixels[y*(w*3+1)+1]=y;
 const source=fixturePng({width:w,height:h,pixels}),pdf=canonicalScannedPdf(source),scan=readCanonicalScannedPdf(pdf);
 assert.equal(scan.page,1);assert.equal(scan.width,w);assert.equal(scan.height,h);assert.equal(scan.png.length>0,true);
 assert.deepEqual(validateEvidence(pdf,'application/pdf'),pdf);
 assert.equal(scan.rasterSha256,(await import('node:crypto')).createHash('sha256').update(scan.png).digest('hex'));
 assert.deepEqual(readCanonicalScannedPdf(canonicalScannedPdf(scan.png)).png,scan.png);
 assert.throws(()=>readCanonicalPdfPages(pdf));
 for(const changed of [Buffer.concat([pdf,Buffer.from('tail')]),Buffer.from(pdf.toString('latin1').replace('/Subtype /Image','/Subtype /JavaScript'),'latin1'),Buffer.from(pdf.toString('latin1').replace('/Count 1','/Count 2'),'latin1'),pdf.subarray(0,pdf.length-1),Buffer.from(pdf.toString('latin1').replace('/Filter /FlateDecode','/Filter /JBIG2Decode'),'latin1')])assert.throws(()=>validateEvidence(changed,'application/pdf'));
 assert.throws(()=>canonicalScannedPdf(fixturePng({width:1,height:1,pixels:Buffer.from([0,1,2,3]),extra:true})));
 scan.png.fill(0);
});

test('four-page canonical scan validates exact object graph and page provenance',async()=>{
 const {canonicalMultipageScannedPdf,readCanonicalMultipageScannedPdf}=await import('../../src/security/scanned-pdf-multipage.mjs');
 const pngs=Array.from({length:4},(_,i)=>{const pixels=Buffer.alloc(60*301);pixels[1]=i+1;return fixturePng({width:100,height:60,pixels});});
 const pdf=canonicalMultipageScannedPdf(pngs);
 assert.deepEqual(validateEvidence(pdf,'application/pdf'),pdf);
 for(let i=1;i<=4;i++){const r=readCanonicalMultipageScannedPdf(pdf,{page:i});assert.equal(r.pageCount,4);assert.equal(r.page,i);r.png.fill(0);}
 for(const tampered of [Buffer.concat([pdf,Buffer.from('tail')]),Buffer.from(pdf.toString('latin1').replace('/Count 4','/Count 3'),'latin1'),Buffer.from(pdf.toString('latin1').replace('/Im0 Do','/JS Do'),'latin1'),pdf.subarray(0,-1)])assert.throws(()=>validateEvidence(tampered,'application/pdf'));
 for(const bad of [0,5,2.5])assert.throws(()=>readCanonicalMultipageScannedPdf(pdf,{page:bad}));
 assert.throws(()=>canonicalMultipageScannedPdf([pngs[0]]));assert.throws(()=>canonicalMultipageScannedPdf([...pngs,pngs[0]]));
});
