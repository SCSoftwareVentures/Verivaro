import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {canonicalTextPdf,validatePdf,validatePng} from '../../src/security/evidence-formats.mjs';
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
