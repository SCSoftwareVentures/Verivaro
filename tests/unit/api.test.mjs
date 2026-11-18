import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {mkdtemp,rm,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createService,SQL} from '../../packages/api/service.mjs';
import {createHttpServer} from '../../packages/api/http.mjs';
const U=n=>'00000000-0000-0000-0000-'+String(n).padStart(12,'0');
const tenant=U(1),project=U(2),doc=U(3),intent=U(4),key=U(5),now=100000;
const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const config={issuer:'https://issuer.invalid',audience:'verivaro-api',jwks:[{...publicKey.export({format:'jwk'}),kid:'test'}]};
const enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
const token=sub=>{const s=enc({alg:'RS256',kid:'test',typ:'at+jwt'})+'.'+enc({iss:config.issuer,sub,aud:config.audience,iat:now-5,exp:now+90});return 'Bearer '+s+'.'+sign('RSA-SHA256',Buffer.from(s),privateKey).toString('base64url');};
const payload=Buffer.from('%PDF-1.7\nsynthetic'),hash=createHash('sha256').update(payload).digest('hex');
const sqlError=code=>Object.assign(new Error('sensitive internal diagnostic'),{code});
async function fixture(t){
 const root=await mkdtemp(join(tmpdir(),'vv-api-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const state={log:[],received:false,revoked:false,failReceipt:false,failRollback:false,failCommit:false,tx:0};
 const client={async query(q,args=[]){
 state.log.push(['runtime',q,args]); if(q===SQL.tx)return {rows:[{tx:String(++state.tx)}]};
 if(q===SQL.project)return {rows:[{id:project,name:'Synthetic',timezone:'UTC',secret:'never return'}]};
 if(q===SQL.document||q===SQL.intent)return {rows:[{id:q===SQL.document?args[2]:args[3]}]};
 if(q===SQL.status){if(state.revoked)throw sqlError('42501');return {rows:[{sha256:hash,bytes:String(payload.length),media_type:'application/pdf',received:state.received}]};}
 if(q==='ROLLBACK'&&state.failRollback)throw Error('rollback broken');
 if(q==='COMMIT'&&state.failCommit)throw Error('commit broken');
 return {rows:[]};
 },release(destroy){state.log.push(['release',destroy]);}};
 const runtimePool={async connect(){state.log.push(['connect']);return client;}};
 const signerPool={async query(q,args){state.log.push(['signer',q,args]);if(args[1]!=='a'||args[2]!==tenant||args[3]!==project||state.revoked)throw sqlError('42501');return {rows:[{context:'{}',signature:'a'.repeat(64)}]};}};
 const workerPool={async query(q,args){state.log.push(['worker',q,args]);if(state.failReceipt)throw Error('worker failed');state.received=true;return {rows:[{id:intent}]};}};
 return {service:createService({runtimePool,signerPool,workerPool,issuerConfig:config,keyId:key,quarantineRoot:root,now:()=>now}),state,root};
}
test('valid request binds identity to actual scoped transaction and returns allowlisted columns',async t=>{const {service,state}=await fixture(t);assert.deepEqual(await service.project(token('a'),tenant,project),{id:project,name:'Synthetic',timezone:'UTC'});assert.deepEqual(state.log.find(x=>x[0]==='signer')[2],[config.issuer,'a',tenant,project,'1',key,now+90]);assert.deepEqual(state.log.at(-1),['release',false]);});
test('invalid token never opens database connection',async t=>{const {service,state}=await fixture(t);await assert.rejects(service.project('Bearer invalid',tenant,project),{status:401});assert.deepEqual(state.log,[]);});
test('foreign tenant and actor denied without running business query',async t=>{const {service,state}=await fixture(t);await assert.rejects(service.project(token('a'),U(9),project),{status:404});await assert.rejects(service.project(token('b'),tenant,project),{status:404});assert.equal(state.log.some(x=>x[1]===SQL.project),false);assert.equal(state.log.filter(x=>x[1]==='ROLLBACK').length,2);});
test('document creation and upload intent parameterized',async t=>{const {service,state}=await fixture(t);await service.createDocument(token('a'),tenant,project,{id:doc,title:"' OR 1=1;"});await service.requestUpload(token('a'),tenant,project,doc,{id:intent,sha256:hash,bytes:payload.length,mediaType:'application/pdf'});assert.deepEqual(state.log.find(x=>x[1]===SQL.document)[2],[tenant,project,doc,"' OR 1=1;"]);await assert.rejects(service.createDocument(token('a'),tenant,project,{id:doc,title:'x',actor:'b'}),{status:400});});
test('stream quarantined with second current authorization and no secret storage key returned',async t=>{const {service,state,root}=await fixture(t);const out=await service.upload(token('a'),tenant,project,intent,[payload]);assert.deepEqual(out,{id:intent,state:'quarantined',replayed:false});assert.equal(state.log.filter(x=>x[1]===SQL.status).length,2);assert.equal(state.log.filter(x=>x[0]==='worker').length,1);assert.equal((await readdir(root)).length,1);assert.deepEqual(await service.upload(token('a'),tenant,project,intent,[payload]),{id:intent,state:'quarantined',replayed:true});assert.equal((await readdir(root)).length,1);});
test('wrong digest never records receipt',async t=>{const {service,state,root}=await fixture(t);await assert.rejects(service.upload(token('a'),tenant,project,intent,[Buffer.alloc(payload.length)]),{status:422});assert.equal(state.log.some(x=>x[0]==='worker'),false);assert.deepEqual(await readdir(root),[]);});
test('revocation during stream prevents receipt authorization',async t=>{const {service,state,root}=await fixture(t);async function* body(){yield payload;state.revoked=true;}await assert.rejects(service.upload(token('a'),tenant,project,intent,body()),{status:404});assert.equal(state.log.some(x=>x[0]==='worker'),false);assert.equal((await readdir(root)).length,1);});
test('worker failure leaves private orphan for reconciliation, never reports success',async t=>{const {service,state,root}=await fixture(t);state.failReceipt=true;await assert.rejects(service.upload(token('a'),tenant,project,intent,[payload]),{status:503});assert.equal(state.received,false);assert.equal((await readdir(root)).length,1);});
test('unknown commit result destroys connection',async t=>{const {service,state}=await fixture(t);state.failCommit=true;await assert.rejects(service.project(token('a'),tenant,project),{status:503});assert.deepEqual(state.log.at(-1),['release',true]);});
test('failed rollback destroys connection',async t=>{const {service,state}=await fixture(t);state.failRollback=true;await assert.rejects(service.project(token('b'),tenant,project),{status:404});assert.deepEqual(state.log.at(-1),['release',true]);});
test('HTTP loopback maps scopes and hides database details',async t=>{const {service}=await fixture(t);const server=createHttpServer(service);await new Promise((r,j)=>{server.once('error',j);server.listen(0,'127.0.0.1',r);});t.after(()=>new Promise(r=>server.close(r)));const url='http://127.0.0.1:'+server.address().port+'/v1/tenants/'+tenant+'/projects/'+project;
 const ok=await fetch(url,{headers:{authorization:token('a')}});assert.equal(ok.status,200);assert.equal(ok.headers.get('cache-control'),'no-store');assert.equal((await ok.json()).name,'Synthetic');
 const denied=await fetch(url,{headers:{authorization:token('b')}});assert.equal(denied.status,404);assert.equal((await denied.json()).code,'resource_unavailable');
 const unauth=await fetch(url);assert.equal(unauth.status,401);await unauth.json();
 const up=await fetch(url+'/uploads/'+intent,{method:'PUT',headers:{authorization:token('a'),'content-type':'application/octet-stream'},body:payload});assert.equal(up.status,202);assert.deepEqual(await up.json(),{id:intent,state:'quarantined',replayed:false});});
