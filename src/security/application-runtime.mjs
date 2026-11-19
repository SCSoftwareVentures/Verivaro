import {createServer} from 'node:https';
import {createPrivateKey,createPublicKey,X509Certificate} from 'node:crypto';
import {readPrivate,loadServicePoolConfig} from './service-pool-config.mjs';
import {assertServiceLogin} from './service-login.mjs';
import {createRotatingProviderVerifier} from './provider-key-rotation.mjs';
import {createIdentityDatabase} from './identity-database.mjs';
import {createAuthenticationGateway} from './authentication-gateway.mjs';
import {createBrowserAuthentication} from './browser-authentication.mjs';
import {createScopedDatabase} from './scoped-database.mjs';
import {createApiAdmission,apiPeer} from './api-admission.mjs';
import {createEvidenceUploadHandler,isEvidenceUpload} from './evidence-upload-api.mjs';
import {createIngestionDatabase,createEvidenceIngestion} from './evidence-ingestion.mjs';
import {createClamdScanner} from './clamd-scanner.mjs';
import {createApplicationApi,isRenameRequest} from './application-api.mjs';
const roles={identity:'verivaro_identity_service',runtime:'verivaro_runtime',admission:'verivaro_api_admission'};
const baseHeaders={'Cache-Control':'no-store, private','Content-Type':'text/plain; charset=utf-8','Strict-Transport-Security':'max-age=31536000','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",'Cross-Origin-Resource-Policy':'same-origin','Permissions-Policy':'camera=(), microphone=(), geolocation=()'};
function exact(o,keys){if(!o||typeof o!=='object'||Array.isArray(o)||Object.keys(o).length!==keys.length||keys.some(k=>!Object.hasOwn(o,k)))throw Error('invalid application configuration');}
async function readText(path,max=65536){const b=await readPrivate(path,max);try{return b.toString('utf8');}finally{b.fill(0);}}
async function readKey(path){const raw=(await readText(path,128)).trim(),key=Buffer.from(raw,'base64url');if(key.length!==32||key.toString('base64url')!==raw)throw Error('invalid application key');return key;}
function reply(res,status,body='',extra={}){
 if(res.destroyed||res.writableEnded)return;
 res.writeHead(status,{...baseHeaders,'Content-Length':Buffer.byteLength(body),...extra});res.end(body);
}
function invalidHeaders(req,host){
 const seen=new Set(),critical=new Set(['host','cookie','origin','authorization','content-length','transfer-encoding','content-encoding','expect','sec-fetch-site','content-type','idempotency-key','x-evidence-sha256']);
 for(let i=0;i<req.rawHeaders.length;i+=2){const h=req.rawHeaders[i].toLowerCase();if(critical.has(h)&&seen.has(h))return true;seen.add(h);}
 return req.headers.host!==host||req.headers.authorization!==undefined||req.headers['transfer-encoding']!==undefined||req.headers['content-encoding']!==undefined||
 (!isRenameRequest(req)&&!isEvidenceUpload(req)&&req.headers['content-length']!==undefined&&req.headers['content-length']!=='0')||req.headers.expect!==undefined;
}
const page='<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Verivaro</title><main><h1>Verivaro</h1><p>Secure verification workspace.</p><form action="/auth/login" method="post"><button>Sign in</button></form><form action="/auth/logout" method="post"><button>Sign out</button></form><form action="/auth/logout-all" method="post"><button>Sign out on all devices</button></form></main></html>';
// Only file paths and bounded deployment settings; no environment fallbacks.
export async function createApplicationRuntime({configPath,Pool,fetcher=fetch,report=()=>{}}){
 if(typeof Pool!=='function')throw Error('missing database driver');
 const cfg=JSON.parse(await readText(configPath,16384));
 const enabled=Object.hasOwn(cfg,'ingestion'),serviceRoles=enabled?{...roles,ingestion:'verivaro_evidence_ingestor'}:roles;
 exact(cfg,['origin','listenHost','listenPort','tlsKeyFile','tlsCertFile','database','logins','provider','local','secrets',...(enabled?['ingestion']:[])]);
 if(enabled)exact(cfg.ingestion,['keyId','keyFile','scannerSocket']);
 const origin=new URL(cfg.origin);
 if(origin.protocol!=='https:'||origin.href!==origin.origin+'/'||!['127.0.0.1','::1','0.0.0.0'].includes(cfg.listenHost)||!Number.isInteger(cfg.listenPort)||cfg.listenPort<1024||cfg.listenPort>65535)throw Error('invalid listener configuration');
 exact(cfg.database,['host','port','name','caFile']);exact(cfg.logins,Object.keys(serviceRoles));
 exact(cfg.provider,['issuer','audience','authorizationEndpoint','tokenEndpoint','requiredAcr','requiredAmr','authorityFile','checkpointFile','catalogueFile','signatureFile','clientSecretFile']);
 exact(cfg.local,['issuer','audience','signingKeyFile']);
 exact(cfg.secrets,['browserKeyFile','contextKeyFile','admissionKeyFile']);
 const pools={},credentials=[],rawKeys=[];
 let server;
 try{
  for(const [name,role] of Object.entries(serviceRoles)){
   const login=cfg.logins[name];exact(login,['user','passwordFile']);
   const settings=await loadServicePoolConfig({role,max:4,env:{PGHOST:cfg.database.host,PGPORT:String(cfg.database.port),PGDATABASE:cfg.database.name,PGUSER:login.user,VV_DB_CA_FILE:cfg.database.caFile,VV_DB_PASSWORD_FILE:login.passwordFile}});
   credentials.push(settings.password);
   if(credentials.slice(0,-1).includes(settings.password))throw Error('duplicate database credential');
   if(Object.values(pools).some(p=>p.options.user===settings.user))throw Error('duplicate service login');
   const pool=new Pool(settings);pools[name]=pool;pool.on('error',()=>report('application_idle_connection_failed'));
   const client=await pool.connect();
   try{await client.query('DISCARD ALL');await assertServiceLogin(client,role,settings.user);
    const r=await client.query('SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid()');if(r.rows[0]?.ssl!==true)throw Error('database TLS required');
   }finally{client.release(true);}
  }
  for(const name of ['browserKeyFile','contextKeyFile','admissionKeyFile'])rawKeys.push(await readKey(cfg.secrets[name]));
  if(rawKeys.some((k,i)=>rawKeys.slice(0,i).some(p=>p.equals(k))))throw Error('duplicate application key');
  const [browserKey,contextKey,admissionKey]=rawKeys;
  const privateKey=createPrivateKey(await readText(cfg.local.signingKeyFile)),publicKey=createPublicKey(privateKey);
  const verifier={publicKey,issuer:cfg.local.issuer,audience:cfg.local.audience};
  const p=cfg.provider,provider=createRotatingProviderVerifier({issuer:p.issuer,audience:p.audience,requiredAcr:p.requiredAcr,requiredAmr:p.requiredAmr,authorityKey:await readText(p.authorityFile),checkpoint:JSON.parse(await readText(p.checkpointFile,4096)),catalogue:await readPrivate(p.catalogueFile,65536),signature:await readPrivate(p.signatureFile,64)});
  const db=createIdentityDatabase(pools.identity,{expectedLogin:cfg.logins.identity.user}),gateway=createAuthenticationGateway({db,provider,localIssuer:verifier.issuer,localAudience:verifier.audience,privateKey});
  const admission=createApiAdmission(pools.admission,{key:admissionKey,expectedLogin:cfg.logins.admission.user});
  const browser=createBrowserAuthentication({db,gateway,provider,localVerifier:verifier,origin:origin.origin,authorizationEndpoint:p.authorizationEndpoint,tokenEndpoint:p.tokenEndpoint,clientSecret:(await readText(p.clientSecretFile,1024)).trim(),key:browserKey,requiredAcr:p.requiredAcr,fetcher});
  const scoped=createScopedDatabase(pools.runtime,{verifier,key:contextKey,expectedLogin:cfg.logins.runtime.user});
  const api=createApplicationApi({resolveSession:browser.resolveSession,scoped,admission,verifier,origin:origin.origin});
  let upload;
  if(enabled){
   const evidenceKey=await readKey(cfg.ingestion.keyFile);rawKeys.push(evidenceKey);
   if(rawKeys.slice(0,-1).some(k=>k.equals(evidenceKey)))throw Error('duplicate evidence key');
   const ingestDb=createIngestionDatabase(pools.ingestion,{verifier,contextKey,expectedLogin:cfg.logins.ingestion.user});
   const ingest=createEvidenceIngestion({db:ingestDb,scan:createClamdScanner({socketPath:cfg.ingestion.scannerSocket}),key:evidenceKey,keyId:cfg.ingestion.keyId});
   upload=createEvidenceUploadHandler({origin:origin.origin,verifier,admission,resolveSession:browser.resolveSession,ingest});
  }
  const tlsKey=await readPrivate(cfg.tlsKeyFile,65536),cert=await readPrivate(cfg.tlsCertFile,65536);rawKeys.push(tlsKey);
  const leaf=new X509Certificate(cert);
  if(!leaf.checkHost(origin.hostname,{subject:'never'})||Date.parse(leaf.validFrom)>Date.now()||Date.parse(leaf.validTo)<=Date.now()||!leaf.checkPrivateKey(createPrivateKey(tlsKey)))throw Error('invalid listener certificate');
  let draining=false,active=0;
  const work=new Set(),peers=new Map();
  async function dispatch(req,res){
   res.setHeader('Strict-Transport-Security',baseHeaders['Strict-Transport-Security']);res.setHeader('Permissions-Policy',baseHeaders['Permissions-Policy']);
   if(draining)return reply(res,503,'Temporarily unavailable',{'Connection':'close'});
   if(invalidHeaders(req,origin.host)||typeof req.url!=='string'||!req.url.startsWith('/')||req.url.length>8192)return reply(res,400,'Request denied',{'Connection':'close'});
   if(req.headers['sec-fetch-site']==='cross-site'&&req.url.split('?')[0]!=='/auth/callback')return reply(res,403,'Request denied');
   if(req.url==='/'&&req.method==='GET')return reply(res,200,page,{'Content-Type':'text/html; charset=utf-8'});
   if(active>=24)return reply(res,429,'Temporarily unavailable',{'Retry-After':'5'});
   active++;
   try{
    if(isEvidenceUpload(req))return upload?await upload(req,res):reply(res,404,'Not found',{'Connection':'close'});
    if(req.url.startsWith('/api/'))return await api(req,res);
    if(req.url.startsWith('/auth/')){
     if(!await admission.peer(req.socket.remoteAddress))return reply(res,429,'Temporarily unavailable',{'Retry-After':'60'});
     if(!res.destroyed)await browser.handler(req,res);
     return;
    }
    return reply(res,404,'Not found');
   }catch{report('application_request_failed');return reply(res,503,'Temporarily unavailable');}
   finally{active--;}
  }
  server=createServer({key:tlsKey,cert,minVersion:'TLSv1.2',handshakeTimeout:5000,requestTimeout:10000,headersTimeout:5000,keepAliveTimeout:2000,maxHeaderSize:12288,insecureHTTPParser:false},(req,res)=>{
   const pending=dispatch(req,res);work.add(pending);pending.catch(()=>res.destroy()).finally(()=>work.delete(pending));
  });
  server.maxConnections=128;server.maxRequestsPerSocket=32;server.maxHeadersCount=64;
  server.setTimeout(15000,s=>s.destroy());
  server.on('connection',socket=>{
   const peer=apiPeer(socket.remoteAddress),n=peers.get(peer)??0;
   if(n>=16){socket.destroy();return;}
   peers.set(peer,n+1);socket.once('close',()=>{const left=(peers.get(peer)??1)-1;if(left)peers.set(peer,left);else peers.delete(peer);});
  });
  server.on('checkContinue',(req,res)=>reply(res,417,'Request denied',{'Connection':'close'}));
  server.on('checkExpectation',(req,res)=>reply(res,417,'Request denied',{'Connection':'close'}));
  server.on('upgrade',(_req,socket)=>socket.destroy());
  server.on('connect',(_req,socket)=>socket.destroy());
  server.on('clientError',(_err,socket)=>socket.destroy());
  for(const k of rawKeys)k.fill(0);
  let stopped;
  return Object.freeze({server,listen:()=>new Promise((resolve,reject)=>{server.once('error',reject);server.listen(cfg.listenPort,cfg.listenHost,()=>{server.removeListener('error',reject);resolve(server.address());});}),
   stop(){if(stopped)return stopped;draining=true;stopped=(async()=>{
    const closing=new Promise(r=>server.close(()=>r()));server.closeIdleConnections();
    const timer=setTimeout(()=>server.closeAllConnections(),5000);timer.unref();
    try{await closing;await Promise.allSettled([...work]);}finally{clearTimeout(timer);await Promise.all(Object.values(pools).map(p=>p.end()));}
   })();return stopped;}
  });
 }catch(e){for(const k of rawKeys)k.fill(0);server?.close();await Promise.allSettled(Object.values(pools).map(p=>p.end()));throw Error('application startup denied');}
}
