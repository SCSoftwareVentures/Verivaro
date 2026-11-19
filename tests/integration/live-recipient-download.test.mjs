import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve,join} from 'node:path';
import {createServer} from 'node:http';
import {randomUUID,createHash,generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {generateShareToken} from '../../src/security/share-token.mjs';
import {createShareResolver} from '../../src/security/share-resolver.mjs';
import {createPrivateFileStore} from '../../src/security/private-file-store.mjs';
import {createShareDownloadHandler} from '../../src/security/share-download.mjs';
if(process.env.PGDATABASE!=='verivaro_test'||process.env.VV_LIVE_TEST!=='1'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_RECIPIENT_PASSWORD||!process.env.VV_SHARE_PASSWORD)throw Error('disposable CI required');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const config={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:1,connectionTimeoutMillis:3000,idleTimeoutMillis:5000};
const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const recipient=randomUUID(),other=randomUUID(),sid=randomUUID(),otherSid=randomUUID(),replacement=randomUUID();
const encode=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
function jwt(actor=recipient,session=sid,overrides={}){
 const now=Math.floor(Date.now()/1000);
 const body=encode({alg:'RS256',typ:'JWT'})+'.'+encode({iss:'fixture',aud:'recipient-download',sub:actor,sid:session,iat:now-5,nbf:now-5,exp:now+120,...overrides});
 return body+'.'+sign('RSA-SHA256',Buffer.from(body),privateKey).toString('base64url');
}
test('recipient-bound sensitive delivery through real HTTP, PostgreSQL and files', {timeout:45000},async t=>{
 const admin=new Pool({...config,user:process.env.PGUSER,password:process.env.PGPASSWORD});
 const bearer=new Pool({...config,user:'verivaro_share_gateway',password:process.env.VV_SHARE_PASSWORD});
 const gateway=new Pool({...config,user:'verivaro_recipient_gateway',password:process.env.VV_RECIPIENT_PASSWORD});
 const directory=await mkdtemp(join(tmpdir(),'vv-recipient-'));
 const artifact=randomUUID(),exportId=randomUUID(),shareId=randomUUID();
 const owner='81000000-0000-4000-8000-000000000001',tenant='11111111-1111-4111-8111-111111111111',project='33333333-3333-4333-8333-333333333333';
 const bytes=Buffer.from('synthetic sensitive export'),hash=createHash('sha256').update(bytes).digest('hex');
 const {token,digest}=generateShareToken();
 const resolver=createShareResolver(gateway,{recipientBound:true});
 let server;
 try{
  for(const [a,s] of [[recipient,sid],[other,otherSid],[recipient,replacement]])
   await admin.query("INSERT INTO verivaro_private.identity_sessions(actor_id,session_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '30 minutes')",[a,s]);
  await admin.query('SELECT verivaro_sharing.register_export($1,$2,$3,$4,$5,false)',[exportId,tenant,project,artifact,hash]);
  const client=await admin.connect();
  try{
   await client.query('BEGIN');
   const signed=(await client.query('SELECT verivaro_private.ci_sign($1,$2,pg_backend_pid(),pg_current_xact_id()::text) AS context',[tenant,owner])).rows[0].context;
   await client.query('SET LOCAL ROLE verivaro_runtime');
   await client.query("SELECT set_config('verivaro.signed_context',$1,true)",[signed]);
   await client.query("SELECT verivaro_sharing.issue_recipient_share($1,$2,$3,clock_timestamp()+interval '10 minutes',$4)",[exportId,shareId,digest,recipient]);
   await client.query('COMMIT');
  }finally{client.release(true);}
  await writeFile(join(directory,artifact),bytes);
  server=createServer(createShareDownloadHandler({resolveShare:createShareResolver(bearer),resolveRecipientShare:resolver,recipientVerifier:{publicKey,issuer:'fixture',audience:'recipient-download'},openArtifact:createPrivateFileStore(directory),maxBytes:1024,perPeerPerMinute:100}));
  await new Promise((r,j)=>{server.once('error',j);server.listen(0,'127.0.0.1',r);});
  const request=(identity,route='/public/share/recipient-download',credential=token)=>fetch('http://127.0.0.1:'+server.address().port+route,{method:'POST',headers:{Authorization:'Bearer '+credential,...(identity?{'X-Verivaro-Recipient':identity}:{})}});
  const valid=await request(jwt());assert.equal(valid.status,200);assert.deepEqual(Buffer.from(await valid.arrayBuffer()),bytes);
  for(const identity of [null,jwt(other,otherSid),jwt(recipient,otherSid),jwt(recipient,randomUUID()),jwt(recipient,sid,{aud:'wrong'}),jwt(recipient,sid,{exp:Math.floor(Date.now()/1000)-1}),jwt()+'x']){
   const res=await request(identity);assert.equal(res.status,404);assert.equal(await res.text(),'Not available\n');
  }
  assert.equal((await request(null,'/public/share/download')).status,404);
  assert.equal((await request(jwt(),'/public/share/download')).status,404);
  assert.equal((await request(jwt(),undefined,generateShareToken().token)).status,404);
  await admin.query('UPDATE verivaro_private.identity_sessions SET revoked_at=clock_timestamp() WHERE session_id=$1',[sid]);
  assert.equal((await request(jwt())).status,404);
  assert.equal((await request(jwt(recipient,replacement))).status,200);
  await admin.query('INSERT INTO verivaro_private.disabled_actors(actor_id) VALUES($1)',[recipient]);
  assert.equal((await request(jwt(recipient,replacement))).status,404);
  await admin.query('DELETE FROM verivaro_private.disabled_actors WHERE actor_id=$1',[recipient]);
  assert.equal((await request(jwt(recipient,replacement))).status,404);
  await assert.rejects(gateway.query('SELECT * FROM verivaro.projects'),e=>e.code==='42501');
  await assert.rejects(gateway.query('SELECT * FROM verivaro_private.identity_sessions'),e=>e.code==='42501');
  await assert.rejects(gateway.query('SELECT * FROM verivaro_sharing.resolve_share($1)',[digest]),e=>e.code==='42501');
  await assert.rejects(bearer.query('SELECT * FROM verivaro_sharing.resolve_recipient_share($1,$2,$3,$4)',[digest,recipient,replacement,Math.floor(Date.now()/1000)+60]),e=>e.code==='42501');
 }finally{
  if(server)await new Promise(r=>{server.closeAllConnections();server.close(r);});
  await gateway.end();await bearer.end();await admin.end();await rm(directory,{recursive:true,force:true});
 }
});
