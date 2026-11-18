import {createHash} from 'node:crypto';
import {lexicalIntelligence,createIntelligence} from './intelligence.mjs';
const hash=s=>createHash('sha256').update(s,'utf8').digest('hex');
const ENGINE='vv-offline-intelligence-v2';
/** Recompute actual digests before cache lookup. Bind ordered page boundaries and extraction method. */
export function intelligenceFingerprint(pages){
 if(!Array.isArray(pages)||pages.length>20)throw Error('invalid pages');
 let total=0;const seen=new Set(),identity=[];
 for(const p of pages){
 if(!p||!Number.isSafeInteger(p.page)||p.page<1||p.page>20||seen.has(p.page)||typeof p.text_value!=='string'||typeof p.method!=='string'||p.method.length>80||hash(p.text_value)!==p.text_sha256)throw Error('invalid page digest or metadata');
 total+=Buffer.byteLength(p.text_value);if(total>1048576)throw Error('page budget');
 seen.add(p.page);identity.push([p.page,p.text_sha256,p.method]);
 }
 return hash(JSON.stringify(identity));
}
export function createBoundedMemo({maxEntries=128,maxBytes=4*1024*1024,ttlMs=60000,clock=()=>performance.now()}={}){
 if(!Number.isSafeInteger(maxEntries)||maxEntries<1||maxEntries>1024||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>16*1024*1024||!Number.isSafeInteger(ttlMs)||ttlMs<1||ttlMs>300000)throw Error('invalid cache limits');
 const map=new Map();let bytes=0,hits=0,misses=0,evictions=0;
 const remove=k=>{const e=map.get(k);if(e){bytes-=e.size;map.delete(k);}};
 const expire=()=>{const now=clock();for(const [k,e] of map)if(e.expires<=now)remove(k);};
 return {
 get(k){expire();const e=map.get(k);if(!e){misses++;return undefined;}hits++;map.delete(k);map.set(k,e);return JSON.parse(e.json);},
 set(k,value){expire();const json=JSON.stringify(value);if(typeof json!=='string')return;
 const size=Buffer.byteLength(k)+Buffer.byteLength(json);if(size>maxBytes)return;
 remove(k);while(map.size>=maxEntries||bytes+size>maxBytes){remove(map.keys().next().value);evictions++;}
 map.set(k,{json,size,expires:clock()+ttlMs});bytes+=size;
 },
 stats(){expire();return {entries:map.size,bytes,hits,misses,evictions};}
 };
}
/** Process-private cache. Caller must authenticate database scope and re-authorise every result.
 * No readiness, authority, or negative provider result is cached.
 */
export function createScopedIntelligence({provider=null,cacheOptions={},timeoutMs=8000}={}){
 const memo=createBoundedMemo(cacheOptions),inflight=new Map();
 const scopeKey=scope=>{
 const ids=[scope?.tenantId,scope?.projectId,scope?.uploadId];
 if(ids.some(x=>typeof x!=='string'||!x||x.length>128))throw Error('invalid intelligence scope');
 return JSON.stringify(ids);
 };
 const run=createIntelligence({provider,timeoutMs,deterministic:(pages,cacheContext)=>{
 const candidates=[];
 for(const p of pages){
 const key=JSON.stringify([ENGINE,'page',cacheContext,p.page,p.text_sha256,p.method]);
 let r=memo.get(key);if(!r){r=lexicalIntelligence([p]);memo.set(key,r);}
 for(const c of r.candidates){candidates.push(c);if(candidates.length===200)return {candidates,truncated:true};}
 if(r.truncated)return {candidates,truncated:true};
 }
 return {candidates,truncated:false};
 }});
 async function analyse(scope,pages,{useProvider=false}={}){
 const context=scopeKey(scope),snapshot=pages.map(({page,text_value,text_sha256,method})=>({page,text_value,text_sha256,method}));
 const fingerprint=intelligenceFingerprint(snapshot);
 const key=JSON.stringify([ENGINE,'result',context,fingerprint,useProvider]);
 const cached=memo.get(key);if(cached)return cached;
 const existing=inflight.get(key);if(existing)return structuredClone(await existing);
 // Do not queue unlimited unique work. Existing provider quota remains authoritative.
 if(inflight.size>=16)return run(snapshot,{useProvider:false,cacheContext:context});
 const work=run(snapshot,{useProvider,cacheContext:context}).then(result=>{
 if(result.providerStatus==='not-requested'||result.providerStatus==='validated-spans-only')memo.set(key,result);
 return result;
 });
 inflight.set(key,work);
 try{return structuredClone(await work);}finally{if(inflight.get(key)===work)inflight.delete(key);}
 }
 return {analyse,stats:()=>({...memo.stats(),inflight:inflight.size})};
}
