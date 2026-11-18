import assert from 'node:assert/strict';
import {performance} from 'node:perf_hooks';
import {evaluateGraph} from '../../packages/domain/graph.mjs';
import {evaluate} from '../../packages/domain/evidence.ts';
import {createScopedIntelligence} from '../../packages/domain/intelligence-cache.mjs';
import {lexicalIntelligence} from '../../packages/domain/intelligence.mjs';
import {sha} from './corpus.mjs';
const scope={tenantId:'synthetic',projectId:'large',uploadId:'u'};
const source=(id,documentId,text)=>({id,documentId,text,revision:1,current:true,reviewed:true,scan:'clean'});
const contract=source('contract','contract','Must provide ABC');
const text='📄 data '.repeat(14000)+'ABC',cpLength=[...text].length;
const d=source('document','document',text);
const g={generation:'1',scopeConfirmed:true,sources:[contract,d],requirements:[{id:'r',revision:1,approved:true,applicability:'applicable',mandatory:true,criterion:{kind:'serial',expected:'ABC'},span:{sourceId:'contract',start:0,end:16,quote:'Must provide ABC'}}],evidence:Array.from({length:500},(_,i)=>({id:'e'+i,requirementId:'r',requirementRevision:1,span:{sourceId:'document',start:cpLength-3,end:cpLength,quote:'ABC'},kind:'serial',value:'ABC',review:'approved'}))};
function reference(){
 const byId=new Map(g.sources.map(x=>[x.id,x]));
 const convert=s=>{const cp=[...byId.get(s.sourceId).text];return {...s,start:cp.slice(0,s.start).join('').length,end:cp.slice(0,s.end).join('').length};};
 return evaluate({scope,sources:g.sources.map(s=>({...s,...scope})),requirements:g.requirements.map(r=>({...r,...scope,span:convert(r.span)})),evidence:g.evidence.map(e=>({...e,...scope,span:convert(e.span)}))});
}
let before=performance.now();const baseline=reference(),referenceMs=performance.now()-before;before=performance.now();const actual=evaluateGraph(scope,g),optimisedMs=performance.now()-before;
 assert.equal(actual.ready,true);assert.deepEqual(actual.findings,baseline.findings);assert.equal(actual.coverage,baseline.coverage);
 const pages=Array.from({length:10},(_,i)=>{const t='Fictional note '+i+'\n'.repeat(200)+'Certificate must be submitted.';return {page:i+1,text_value:t,text_sha256:sha(t),method:'pdf-text'};});
 const cache=createScopedIntelligence();before=performance.now();const cold=await cache.analyse(scope,pages);const coldMs=performance.now()-before;
 assert.deepEqual(cold.candidates,lexicalIntelligence(pages).candidates);
 before=performance.now();const warm=await cache.analyse(scope,pages);const warmMs=performance.now()-before;assert.deepEqual(warm,cold);
 const changed=pages.slice(),t='Replacement certificate required';changed[9]={...changed[9],text_value:t,text_sha256:sha(t)};
 const hitsBefore=cache.stats().hits;before=performance.now();const incremental=await cache.analyse(scope,changed);const changedMs=performance.now()-before;
 assert.equal(cache.stats().hits-hitsBefore,9);assert.deepEqual(incremental.candidates,lexicalIntelligence(changed).candidates);
 console.log(JSON.stringify({revision:process.env.GITHUB_SHA??null,sourceCodepoints:cpLength,evidenceLinks:g.evidence.length,referenceMs,optimisedMs,ratio:referenceMs/optimisedMs,coldMs,warmMs,changedMs,reusedUnchangedPages:9,sourcePages:10,cache:cache.stats(),note:'Synthetic domain timings, not end-to-end SLA'},null,2));
