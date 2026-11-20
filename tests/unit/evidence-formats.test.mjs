import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
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
