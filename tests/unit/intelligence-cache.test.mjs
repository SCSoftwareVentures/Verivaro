import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createScopedIntelligence,createBoundedMemo,intelligenceFingerprint} from '../../packages/domain/intelligence-cache.mjs';
import {lexicalIntelligence} from '../../packages/domain/intelligence.mjs';
const sha=s=>createHash('sha256').update(s).digest('hex');
const page=(n,t,method='ocr')=>({page:n,text_value:t,text_sha256:sha(t),method});
const scope={tenantId:'t',projectId:'p',uploadId:'u'};
const pages=[page(1,'📄 Must provide certificate'),page(2,'Required before delivery')];
test('unchanged page results reused; changed page and method invalidated',async()=>{
 const cache=createScopedIntelligence();const a=await cache.analyse(scope,pages);assert.deepEqual(a.candidates,lexicalIntelligence(pages).candidates);
 a.candidates[0].quote='tampered';const b=await cache.analyse(scope,pages);assert.notEqual(b.candidates[0].quote,'tampered');assert.equal(cache.stats().hits,1);
 const changed=[pages[0],page(2,'Required after approval')];const c=await cache.analyse(scope,changed);assert.deepEqual(c.candidates,lexicalIntelligence(changed).candidates);assert.equal(cache.stats().hits,2);
 const method=[page(1,pages[0].text_value,'pdf-text'),changed[1]];assert.equal((await cache.analyse(scope,method)).candidates[0].method,'pdf-text');
});
test('identical content never shares results across tenant/project/upload',async()=>{
 const cache=createScopedIntelligence();await cache.analyse(scope,pages);
 for(const k of ['tenantId','projectId','uploadId'])await cache.analyse({...scope,[k]:'different'},pages);
 assert.equal(cache.stats().hits,0);
});
test('actual content, page boundaries and metadata validated before lookup',async()=>{
 const cache=createScopedIntelligence();await cache.analyse(scope,pages);
 await assert.rejects(cache.analyse(scope,[{...pages[0],text_value:'forged'}]));
 assert.notEqual(intelligenceFingerprint([page(1,'a\n\f\nb')]),intelligenceFingerprint([page(1,'a'),page(2,'b')]));
 assert.notEqual(intelligenceFingerprint(pages),intelligenceFingerprint([...pages].reverse()));
 await assert.rejects(cache.analyse(scope,[pages[0],pages[0]]));
});
test('bounded cache expiration, size, eviction and immutable copies',()=>{
 let now=0;const memo=createBoundedMemo({maxEntries:2,maxBytes:100,ttlMs:10,clock:()=>now});
 memo.set('a',{v:'x'});memo.set('b',{v:'y'});const a=memo.get('a');a.v='tamper';memo.set('c',{v:'z'});
 assert.equal(memo.get('b'),undefined);assert.deepEqual(memo.get('a'),{v:'x'});memo.set('huge',{v:'X'.repeat(200)});assert.equal(memo.get('huge'),undefined);
 now=11;assert.equal(memo.stats().entries,0);assert.equal(memo.stats().bytes,0);
});
test('concurrent equivalent provider work coalesces and validated result is cached',async()=>{
 let calls=0,done;const provider=()=>{calls++;return new Promise(resolve=>{done=resolve;});};
 const cache=createScopedIntelligence({provider});const a=cache.analyse(scope,pages,{useProvider:true}),b=cache.analyse(scope,pages,{useProvider:true});
 await Promise.resolve();assert.equal(calls,1);done([]);assert.equal((await a).providerStatus,'validated-spans-only');assert.equal((await b).providerStatus,'validated-spans-only');
 await cache.analyse(scope,pages,{useProvider:true});assert.equal(calls,1);
});
test('failed provider outputs are never cached as success',async()=>{
 let calls=0;const cache=createScopedIntelligence({provider:async()=>{calls++;throw Error('fail');}});
 for(let i=0;i<2;i++)assert.equal((await cache.analyse(scope,pages,{useProvider:true})).providerStatus,'rejected-or-unavailable');assert.equal(calls,2);
});
test('page cache respects global cap and exact uncached order',async()=>{
 const cache=createScopedIntelligence();const p=[page(1,'Must submit\n'.repeat(198)),page(2,'Must sign\n'.repeat(5))];
 assert.deepEqual((await cache.analyse(scope,p)).candidates,lexicalIntelligence(p).candidates);assert.equal((await cache.analyse(scope,p)).truncated,true);
});
