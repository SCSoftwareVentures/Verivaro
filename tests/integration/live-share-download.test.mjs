import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve,join} from 'node:path';
import {createServer} from 'node:http';
import {randomUUID,createHash} from 'node:crypto';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {generateShareToken} from '../../src/security/share-token.mjs';
import {createShareResolver} from '../../src/security/share-resolver.mjs';
import {createPrivateFileStore} from '../../src/security/private-file-store.mjs';
import {createShareDownloadHandler} from '../../src/security/share-download.mjs';
if(process.env.PGDATABASE!=='verivaro_test'||process.env.VV_LIVE_TEST!=='1'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_SHARE_PASSWORD)throw Error('disposable CI required');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const config={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:1,connectionTimeoutMillis:3000,idleTimeoutMillis:5000};
test('real HTTP + dedicated PostgreSQL gateway + private file delivery', {timeout:30000},async t=>{
 const admin=new Pool({...config,user:process.env.PGUSER,password:process.env.PGPASSWORD});
 const gateway=new Pool({...config,user:'vv_ci_share',password:process.env.VV_SHARE_PASSWORD});
 const folder=await mkdtemp(join(tmpdir(),'vv-live-download-'));
 const artifact=randomUUID(),exportId=randomUUID(),shareId=randomUUID();
 const actor='81000000-0000-4000-8000-000000000001',tenant='11111111-1111-4111-8111-111111111111',project='33333333-3333-4333-8333-333333333333';
 const bytes=Buffer.from('synthetic isolated released export');
 const hash=createHash('sha256').update(bytes).digest('hex');
 const {token,digest}=generateShareToken();
 const resolver=createShareResolver(gateway,{expectedLogin:'vv_ci_share'});
 let server;
 try{
  await admin.query('SELECT verivaro_sharing.register_export($1,$2,$3,$4,$5,true)',[exportId,tenant,project,artifact,hash]);
  const signer=await admin.connect();
  try{
   await signer.query('BEGIN');
   const signed=(await signer.query('SELECT verivaro_private.ci_sign($1,$2,pg_backend_pid(),pg_current_xact_id()::text) AS context',[tenant,actor])).rows[0].context;
   await signer.query('SET LOCAL ROLE verivaro_runtime');
   await signer.query("SELECT set_config('verivaro.signed_context',$1,true)",[signed]);
   await signer.query("SELECT verivaro_sharing.issue_share($1,$2,$3,clock_timestamp()+interval '10 minutes')",[exportId,shareId,digest]);
   await signer.query('COMMIT');
  }finally{signer.release(true);}
  await writeFile(join(folder,artifact),bytes);
  server=createServer(createShareDownloadHandler({resolveShare:resolver,openArtifact:createPrivateFileStore(folder),maxBytes:1024}));
  await new Promise((r,j)=>{server.once('error',j);server.listen(0,'127.0.0.1',r);});
  const request=credential=>fetch('http://127.0.0.1:'+server.address().port+'/public/share/download',{method:'POST',headers:{Authorization:'Bearer '+credential}});
  const res=await request(token);
  assert.equal(res.status,200);assert.deepEqual(Buffer.from(await res.arrayBuffer()),bytes);
  assert.equal((await request(generateShareToken().token)).status,404);
  await writeFile(join(folder,artifact),Buffer.from('corrupt'));
  const bad=await request(token);assert.equal(bad.status,404);assert.equal(await bad.text(),'Not available\n');
  await writeFile(join(folder,artifact),bytes);
  await admin.query('SELECT verivaro_sharing.revoke_export($1)',[exportId]);
  const revoked=await request(token);assert.equal(revoked.status,404);assert.equal(await revoked.text(),'Not available\n');
  assert.equal(await resolver(digest),null);
  await assert.rejects(gateway.query('SELECT * FROM verivaro.projects'),e=>e.code==='42501');
  await assert.rejects(gateway.query('SELECT * FROM verivaro_private.share_grants'),e=>e.code==='42501');
 }finally{
  if(server)await new Promise(r=>{server.closeAllConnections();server.close(r);});
  await gateway.end();await admin.end();await rm(folder,{recursive:true,force:true});
 }
});
