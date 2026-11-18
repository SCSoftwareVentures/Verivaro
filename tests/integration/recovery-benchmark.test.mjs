import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {generateKeyPairSync,sign,createHash,randomUUID} from 'node:crypto';
import {mkdtemp,rm,mkdir,writeFile,readFile,unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createPostgresService} from '../../packages/api/postgres.mjs';
import {createHttpServer} from '../../packages/api/http.mjs';
import {processOneScan} from '../../packages/worker/maintenance.mjs';
import {processOneExtraction} from '../../packages/worker/extraction.mjs';
import {readVerifiedQuarantine} from '../../packages/security/quarantine.mjs';
const exec=promisify(execFile),sha=b=>createHash('sha256').update(b).digest('hex');
const U=(p,n)=>p+'0000000-0000-0000-0000-'+String(n).padStart(12,'0');
const tenant=U('0',1),project=U('2',1),actor=U('1',1),key=U('3',1);
const keys=generateKeyPairSync('rsa',{modulusLength:2048}),config={issuer:'https://issuer.invalid',audience:'verivaro-api',jwks:[{...keys.publicKey.export({format:'jwk'}),kid:'test'}]};
const enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
function token(sub){const now=Math.floor(Date.now()/1000),s=enc({alg:'RS256',kid:'test',typ:'at+jwt'})+'.'+enc({iss:config.issuer,sub,aud:config.audience,iat:now-5,exp:now+300});return 'Bearer '+s+'.'+sign('RSA-SHA256',Buffer.from(s),keys.privateKey).toString('base64url');}
const cfg=(role,database)=>({host:process.env.PGHOST,port:Number(process.env.PGPORT),database,user:'vv_test_'+role,password:'vv-ci-'+role+'-only'});
const scanner=(b,m)=>({sha256:m.sha256,outcome:'clean',engine:'synthetic-only',engineVersion:'1'});
async function start(database,root,keyId=key){
 const app=createPostgresService({database:Object.fromEntries(['runtime','signer','worker','capability'].map(r=>[r,cfg(r,database)])),issuerConfig:config,keyId,quarantineRoot:root,downloadScanner:scanner});
 const server=createHttpServer(app.service);await new Promise((r,j)=>{server.once('error',j);server.listen(0,'127.0.0.1',r);});
 const url='http://127.0.0.1:'+server.address().port+'/v1/tenants/'+tenant+'/projects/'+project;
 return {url,close:async()=>{await new Promise(r=>server.close(r));await app.close();},call:async(method,path,body,who='a',raw=false)=>{
 const headers={authorization:token(who)};if(body!==undefined)headers['content-type']=raw?'application/octet-stream':'application/json';
 const res=await fetch(url+path,{method,headers,body:body===undefined?undefined:raw?body:JSON.stringify(body),signal:AbortSignal.timeout(15000)});
 return {status:res.status,body:await res.json()};
 }};
}
const percentile=(a,p)=>a.slice().sort((x,y)=>x-y)[Math.ceil(a.length*p)-1];
async function load(api){
 const samples=[];let next=0;const total=120,wall=performance.now();
 await Promise.all(Array.from({length:4},async()=>{for(;;){const i=next++;if(i>=total)return;const paths=['','/catalog','/readiness','/finance'],path=paths[i%4],who=i%10===0?'b':'a',begin=performance.now();
 const r=await api.call('GET',path,undefined,who);samples.push(performance.now()-begin);
 assert.equal(r.status,who==='b'?404:200);
 if(who==='b')assert.equal(r.body.code,'resource_unavailable');
 else if(path==='/readiness')assert.equal(r.body.ready,false);
 }}));
 const elapsed=performance.now()-wall,p95=percentile(samples,.95);
 console.log('VV_BENCHMARK '+JSON.stringify({requests:total,concurrency:4,elapsedMs:Math.round(elapsed),p50Ms:Math.round(percentile(samples,.5)),p95Ms:Math.round(p95),maxMs:Math.round(Math.max(...samples)),requestsPerSecond:Number((total*1000/elapsed).toFixed(2)),unexpectedResponses:0}));
 assert.equal(samples.length,total);assert.ok(p95<5000,'bounded CI p95 budget exceeded');
}
test('isolated PostgreSQL load, quiesced database and original-file backup, fresh database restore and recovery',{skip:process.env.VV_LIVE_TEST!=='1',timeout:180000},async t=>{
 const source=process.env.PGDATABASE;
 // Intentionally refuse any real or differently named database.
 assert.equal(source,'verivaro_test');assert.equal(process.env.PGHOST,'127.0.0.1');
 const target='verivaro_restore_'+randomUUID().replaceAll('-','');
 const dir=await mkdtemp(join(tmpdir(),'vv-dr-')),root=join(dir,'source'),backup=join(dir,'backup'),restored=join(dir,'restored');
 for(const d of [root,backup,restored])await mkdir(d,{mode:0o700});
 const admin=new pg.Pool(),worker=new pg.Pool(cfg('worker',source)),parser=new pg.Pool(cfg('parser',source));
 let api,copy,restoreAdmin,restoreWorker,restoreParser;
 t.after(async()=>{await api?.close();await copy?.close();await Promise.all([worker.end(),parser.end(),restoreAdmin?.end(),restoreWorker?.end(),restoreParser?.end()]);await admin.query('DROP DATABASE IF EXISTS '+target+' WITH (FORCE)');await admin.end();await rm(dir,{recursive:true,force:true});});
 api=await start(source,root);
 const docs=[];
 for(let i=0;i<12;i++){
 const d=U('4',200+i),u=U('6',200+i),body=Buffer.from('Synthetic recovery fixture '+i+' MUST retain exact bytes.'),digest=sha(body);
 assert.equal((await api.call('POST','/documents',{id:d,title:'Recovery fixture '+i})).status,201);
 assert.equal((await api.call('POST','/documents/'+d+'/uploads',{id:u,sha256:digest,bytes:body.length,mediaType:'text/plain'})).status,202);
 assert.equal((await api.call('PUT','/uploads/'+u,body,'a',true)).status,202);
 docs.push({d,u,body,digest});
 if(i<11){
 assert.equal((await processOneScan(worker,root,scanner)).state,'complete');assert.equal((await processOneExtraction(parser,root)).state,'complete');
 const review=await api.call('GET','/uploads/'+u+'/review');assert.equal(review.status,200);
 assert.equal((await api.call('POST','/uploads/'+u+'/promote',{id:U('5',200+i),priorRevision:0,sourceSha256:digest,textDigest:review.body.textDigest})).status,201);
 }}
 await load(api);
 // Concurrent exact retry cannot manufacture duplicate logical documents.
 const duplicate=U('4',250),r=await Promise.all(Array.from({length:4},()=>api.call('POST','/documents',{id:duplicate,title:'Same exact retry'})));
 assert.ok(r.every(x=>x.status===201));assert.equal(Number((await admin.query('SELECT count(*) FROM vv_app.document WHERE id=$1',[duplicate])).rows[0].count),1);
 // Quiesce application and workers. No claim of an online consistent snapshot.
 await api.close();api=null;
 const backupStart=performance.now();
 const rows=(await admin.query('SELECT object_key,actual_sha256,actual_bytes,media_type FROM vv_app.quarantine_receipt ORDER BY object_key')).rows;
 assert.equal(rows.length,12);
 function receipt(r){return {objectKey:r.object_key,sha256:r.actual_sha256,bytes:Number(r.actual_bytes),mediaType:r.media_type,state:'quarantined'};}
 for(const r of rows){const b=await readVerifiedQuarantine(root,receipt(r));await writeFile(join(backup,r.object_key),b,{flag:'wx',mode:0o600});}
 const dump=join(dir,'snapshot.dump');
 await exec('/usr/lib/postgresql/16/bin/pg_dump',['--format=custom','--file='+dump,'--dbname='+source],{timeout:60000,maxBuffer:2*1024*1024});
 const dumpSha=sha(await readFile(dump)),backupMs=performance.now()-backupStart;
 const before=(await admin.query('SELECT (SELECT count(*) FROM vv_app.document)::int AS documents,(SELECT count(*) FROM vv_app.document_version)::int AS versions,(SELECT count(*) FROM vv_private.ingestion_audit)::int AS audit')).rows[0];
 // Simulate source loss after backup, without touching any external/system data.
 await unlink(join(root,rows[0].object_key));await assert.rejects(readVerifiedQuarantine(root,receipt(rows[0])));
 const restoreStart=performance.now();await admin.query('CREATE DATABASE '+target);
 assert.equal(sha(await readFile(dump)),dumpSha);
 await exec('/usr/lib/postgresql/16/bin/pg_restore',['--exit-on-error','--dbname='+target,dump],{timeout:60000,maxBuffer:4*1024*1024});
 for(const r of rows){const b=await readFile(join(backup,r.object_key));assert.equal(sha(b),r.actual_sha256);await writeFile(join(restored,r.object_key),b,{flag:'wx',mode:0o600});assert.deepEqual(await readVerifiedQuarantine(restored,receipt(r)),b);}
 restoreAdmin=new pg.Pool({database:target});restoreWorker=new pg.Pool(cfg('worker',target));restoreParser=new pg.Pool(cfg('parser',target));
 const after=(await restoreAdmin.query('SELECT (SELECT count(*) FROM vv_app.document)::int AS documents,(SELECT count(*) FROM vv_app.document_version)::int AS versions,(SELECT count(*) FROM vv_private.ingestion_audit)::int AS audit')).rows[0];
 assert.deepEqual(after,before);
 const unprotected=await restoreAdmin.query("SELECT count(*)::int AS n FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname IN ('vv_app','vv_private') AND c.relkind='r' AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)");assert.equal(unprotected.rows[0].n,0);
 // Recovery cutover policy: invalidate restored context signing key, rotate it and revoke all sharing capabilities.
 const newKey=randomUUID();await restoreAdmin.query('WITH disabled AS (UPDATE vv_private.context_key SET active=false RETURNING id) INSERT INTO vv_private.context_key(id,secret,active) VALUES($1,vv_crypto.gen_random_bytes(32),true)',[newKey]);
 await restoreAdmin.query('UPDATE vv_private.index_grant SET revoked_at=clock_timestamp(),revoked_by=created_by WHERE revoked_at IS NULL');
 copy=await start(target,restored,newKey);
 const inventory=await copy.call('GET','/catalog');assert.equal(inventory.status,200);assert.equal(inventory.body.documents.length,13);assert.equal((await copy.call('GET','/catalog',undefined,'b')).status,404);
 assert.equal((await copy.call('GET','/uploads/'+docs[11].u)).body.state,'quarantined');
 assert.equal((await processOneScan(restoreWorker,restored,scanner)).state,'complete');
 assert.equal((await processOneExtraction(restoreParser,restored)).state,'complete');
 assert.equal((await copy.call('GET','/uploads/'+docs[11].u+'/review')).status,200);
 const original=await fetch(copy.url+'/uploads/'+docs[0].u+'/original',{headers:{authorization:token('a')}});assert.equal(original.status,200);assert.deepEqual(Buffer.from(await original.arrayBuffer()),docs[0].body);
 const victim=rows.find(x=>x.actual_sha256===docs[0].digest);await writeFile(join(restored,victim.object_key),Buffer.alloc(docs[0].body.length,88));
 const tampered=await fetch(copy.url+'/uploads/'+docs[0].u+'/original',{headers:{authorization:token('a')}});assert.equal(tampered.status,503);
 console.log('VV_RECOVERY '+JSON.stringify({documents:before.documents,canonicalVersions:before.versions,verifiedOriginals:rows.length,auditEvents:before.audit,backupMs:Math.round(backupMs),restoreAndVerifyMs:Math.round(performance.now()-restoreStart),recoveredPendingScanAndExtraction:true,sourceLossDetected:true,tamperedRestoreDenied:true,unexpectedRecordLoss:0}));
});
