import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {assertServiceLogin,validateServiceIdentity} from './service-login.mjs';
const role='verivaro_evidence_auditor',UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/,HASH=/^[a-f0-9]{64}$/,DB=/^[a-z][a-z0-9_]{0,62}$/;
const max=1024*1024,sha=b=>createHash('sha256').update(b).digest('hex'),encode=x=>Buffer.from(JSON.stringify(x));
function rows(input){
 if(!Array.isArray(input)||input.length>4096)throw Error('invalid custody inventory');
 const ids=new Set(),result=[];
 for(const r of input){
  if(!r||typeof r.id!=='string'||!UUID.test(r.id)||ids.has(r.id)||typeof r.digest!=='string'||!HASH.test(r.digest)||typeof r.encrypted!=='boolean')throw Error('invalid custody record');
  ids.add(r.id);result.push({id:r.id,digest:r.digest,encrypted:r.encrypted});
 }
 return result.sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
}
function scope(installationId,database){if(!UUID.test(installationId??'')||!DB.test(database??''))throw Error('invalid custody scope');}
function date(s){if(typeof s!=='string'||!Number.isFinite(Date.parse(s))||new Date(s).toISOString()!==s)throw Error('invalid checkpoint time');return Date.parse(s);}
function publicKey(k){const p=k?.type==='public'?k:createPublicKey(k);if(p.asymmetricKeyType!=='ed25519')throw Error('invalid checkpoint key');return p;}
function anchor(a){if(!a||!Number.isSafeInteger(a.sequence)||a.sequence<1||typeof a.digest!=='string'||!HASH.test(a.digest))throw Error('trusted checkpoint required');}
function consistent(old,next){
 const map=new Map(next.map(x=>[x.id,x]));
 for(const x of old){const r=map.get(x.id);if(!r||r.digest!==x.digest||r.encrypted!==x.encrypted)throw Error('custody history changed');}
}
export function verifyEvidenceCheckpoint({manifest,signature,verificationKey,checkpoint,installationId,database,now=Date.now(),maxAgeMs}){
 scope(installationId,database);anchor(checkpoint);
 if(!Number.isFinite(now)||!Buffer.isBuffer(manifest)||manifest.length>max||!Buffer.isBuffer(signature)||signature.length!==64||sha(manifest)!==checkpoint.digest||!verify(null,manifest,publicKey(verificationKey),signature))throw Error('untrusted custody checkpoint');
 const m=JSON.parse(manifest.toString('utf8')),created=date(m.createdAt);
 if(m.version!==1||m.installationId!==installationId||m.database!==database||m.sequence!==checkpoint.sequence||created>now+5000||
 !(m.sequence===1?m.previousDigest===null:typeof m.previousDigest==='string'&&HASH.test(m.previousDigest))||
 (maxAgeMs!==undefined&&(!Number.isSafeInteger(maxAgeMs)||maxAgeMs<1||now-created>maxAgeMs)))throw Error('custody checkpoint scope or freshness denied');
 const canonical={version:1,installationId,database,sequence:m.sequence,previousDigest:m.previousDigest,createdAt:m.createdAt,records:rows(m.records)};
 if(!encode(canonical).equals(manifest))throw Error('noncanonical custody manifest');
 return canonical;
}
// Independent signer, not an application runtime service. For successors the
// previous trusted digest and its signed full inventory are mandatory.
export function signEvidenceCheckpoint({inventory,installationId,database,signingKey,previous,initial=false,now=Date.now()}){
 scope(installationId,database);
 if(!Number.isFinite(now))throw Error('invalid checkpoint time');
 const k=signingKey?.type==='private'?signingKey:createPrivateKey(signingKey);
 if(k.asymmetricKeyType!=='ed25519')throw Error('invalid checkpoint key');
 const records=rows(inventory);
 let sequence=1,previousDigest=null;
 if(previous){
  if(initial)throw Error('ambiguous checkpoint genesis');
  const old=verifyEvidenceCheckpoint({...previous,installationId,database,verificationKey:createPublicKey(k),now});
  if(date(old.createdAt)>now||old.sequence===Number.MAX_SAFE_INTEGER)throw Error('checkpoint chronology denied');
  consistent(old.records,records);sequence=old.sequence+1;previousDigest=previous.checkpoint.digest;
 }else if(initial!==true)throw Error('explicit initial checkpoint required');
 const manifest=encode({version:1,installationId,database,sequence,previousDigest,createdAt:new Date(now).toISOString(),records});
 if(manifest.length>max)throw Error('custody manifest too large');
 return {manifest,signature:sign(null,manifest,k),checkpoint:{sequence,digest:sha(manifest)}};
}
// Verify a transition from an independently trusted prior checkpoint, or
// compare the latest checkpoint to a newer live snapshot. No implicit reset.
export function verifyEvidenceTransition({previous,next,verificationKey,installationId,database,now=Date.now()}){
 const opts={verificationKey,installationId,database,now};
 const a=verifyEvidenceCheckpoint({...previous,...opts}),b=verifyEvidenceCheckpoint({...next,...opts});
 if(b.sequence!==a.sequence+1||b.previousDigest!==previous.checkpoint.digest||date(b.createdAt)<date(a.createdAt))throw Error('custody chain discontinuity');
 consistent(a.records,b.records);return {sequence:b.sequence,records:b.records.length,added:b.records.length-a.records.length};
}
export function compareEvidenceInventory({inventory,...cfg}){
 const m=verifyEvidenceCheckpoint(cfg),current=rows(inventory);consistent(m.records,current);
 return {attested:m.records.length,unattested:current.length-m.records.length,encryptedAttested:m.records.filter(r=>r.encrypted).length};
}
export function createEvidenceAuditor(pool,{expectedLogin}){
 validateServiceIdentity(role,expectedLogin);
 if(typeof pool?.connect!=='function')throw Error('invalid custody audit pool');
 return async function inventory(){
  const c=await pool.connect();let tx=false,clean=false;
  try{
   await c.query('DISCARD ALL');await assertServiceLogin(c,role,expectedLogin);await c.query('SET ROLE '+role);
   await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');tx=true;
   await c.query("SET LOCAL statement_timeout='30s'");await c.query("SET LOCAL lock_timeout='2s'");await c.query("SET LOCAL idle_in_transaction_session_timeout='10s'");
   const r=await c.query('SELECT * FROM verivaro_ingestion.attestation_inventory()');
   const result=rows(r.rows);await c.query('COMMIT');tx=false;await c.query('DISCARD ALL');clean=true;return result;
  }catch{if(tx)try{await c.query('ROLLBACK');}catch{}throw Error('custody inventory unavailable');}
  finally{c.release(clean?undefined:new Error('discard custody connection'));}
 };
}
