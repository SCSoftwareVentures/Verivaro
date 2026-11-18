import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {open,lstat,realpath} from 'node:fs/promises';
import {join} from 'node:path';
import {removeAbandonedObject} from './quarantine.mjs';
const digest=b=>createHash('sha256').update(b).digest('hex');
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const key=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const hex=/^[a-f0-9]{64}$/;
const message=b=>Buffer.concat([Buffer.from('verivaro-erasure-ledger-v1\0'),b]);
export function parsePlan(row){
 if(typeof row?.json!=='string'||Buffer.byteLength(row.json)>1048576||digest(row.json)!==row.sha256)throw Error('plan integrity failure');
 const p=JSON.parse(row.json);
 if(p.schema!=='verivaro-erasure-plan-v1'||![p.tenantId,p.projectId,p.requestId].every(x=>uuid.test(x))||!Number.isSafeInteger(p.policyRevision)||p.policyRevision<1||!/^\d+$/.test(p.generation)||!Array.isArray(p.objectKeys)||p.objectKeys.length>4000||new Set(p.objectKeys).size!==p.objectKeys.length||!p.objectKeys.every(x=>typeof x==='string'&&key.test(x))||!p.rowCounts||Object.values(p.rowCounts).some(n=>!Number.isSafeInteger(n)||n<0))throw Error('invalid erasure plan');
 return p;
}
export function signErasurePlan(row,privateKey){
 parsePlan(row);const k=privateKey?.type==='private'?privateKey:createPrivateKey(privateKey);if(k.asymmetricKeyType!=='ed25519')throw Error('Ed25519 required');
 const bytes=Buffer.from(row.json);return Buffer.from(JSON.stringify({schema:'verivaro-erasure-ledger-v1',plan:row,signature:sign(null,message(bytes),k).toString('base64url')})+'\n');
}
export function verifyErasureLedger(bytes,publicKey){
 if(!Buffer.isBuffer(bytes)||bytes.length>2097152)throw Error('invalid ledger bytes');
 const l=JSON.parse(bytes.toString('utf8')),k=publicKey?.type==='public'?publicKey:createPublicKey(publicKey);
 if(l.schema!=='verivaro-erasure-ledger-v1'||k.asymmetricKeyType!=='ed25519'||typeof l.signature!=='string'||! /^[A-Za-z0-9_-]{86}$/.test(l.signature))throw Error('invalid ledger');
 const plan=parsePlan(l.plan);if(!verify(null,message(Buffer.from(l.plan.json)),k,Buffer.from(l.signature,'base64url')))throw Error('ledger signature invalid');
 return {plan,planSha256:l.plan.sha256,ledgerSha256:digest(bytes)};
}
async function privateDirectory(dir){
 const s=await lstat(dir);if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o077)!==0||s.uid!==process.getuid())throw Error('private operator directory required');return realpath(dir);
}
function sameScope(p,t,project,request){return p.tenantId===t&&p.projectId===project&&p.requestId===request;}
/** Trusted offline operator only. Supervisor must stop all services and workers, ensure
 * backup/retention/legal approval and use a separate durable ledger store. No HTTP route. */
export async function executeOfflineErasure({pool,quarantineRoot,ledgerDirectory,privateKey,tenantId,projectId,requestId,expectedPlanSha256,quiesced=false}){
 if(quiesced!==true||![tenantId,projectId,requestId].every(x=>uuid.test(x))||!hex.test(expectedPlanSha256))throw Error('explicit offline approval required');
 const root=await privateDirectory(quarantineRoot),dir=await privateDirectory(ledgerDirectory);
 if(root===dir||root.startsWith(dir+'/')||dir.startsWith(root+'/'))throw Error('separate ledger directory required');
 const c=await pool.connect();let ledger,committed=false;
 try{
 await c.query('BEGIN');await c.query("SET LOCAL lock_timeout='5s'");await c.query("SET LOCAL statement_timeout='30s'");
 const {rows}=await c.query('SELECT vv_api.prepare_project_erasure($1,$2,$3) AS plan',[tenantId,projectId,requestId]);
 const row=rows[0]?.plan,p=parsePlan(row);if(!sameScope(p,tenantId,projectId,requestId)||row.sha256!==expectedPlanSha256)throw Error('approved plan changed');
 ledger=signErasurePlan(row,privateKey);const verified=verifyErasureLedger(ledger,createPublicKey(privateKey));
 const filename=join(dir,requestId+'.json');const f=await open(filename,'wx',0o600);try{await f.writeFile(ledger);await f.sync();}finally{await f.close();}
 const d=await open(dir,'r');try{await d.sync();}finally{await d.close();}
 const applied=await c.query('SELECT vv_api.apply_project_erasure($1,$2,$3,$4,$5) AS result',[tenantId,projectId,requestId,verified.planSha256,verified.ledgerSha256]);
 if(applied.rows[0]?.result?.projectRowsRemoved!==true||applied.rows[0].result.objectCount!==p.objectKeys.length)throw Error('invalid erasure result');
 await c.query('COMMIT');committed=true;
 }catch(e){if(!committed)await c.query('ROLLBACK').catch(()=>{});throw e;}finally{c.release(!committed);}
 // Crash after commit is recoverable using the durable signed ledger; never unlink before commit.
 return reconcileErasedObjects({pool,quarantineRoot:root,ledger,publicKey:createPublicKey(privateKey)});
}
export async function reconcileErasedObjects({pool,quarantineRoot,ledger,publicKey}){
 const v=verifyErasureLedger(ledger,publicKey),p=v.plan;
 const q=await pool.query('SELECT vv_api.erasure_restore_status($1,$2,$3,$4,$5) AS safe',[p.tenantId,p.projectId,p.requestId,v.planSha256,v.ledgerSha256]);
 if(q.rows[0]?.safe!==true)throw Error('restore or incomplete erasure detected; do not reopen service');
 const root=await privateDirectory(quarantineRoot);
 for(const k of p.objectKeys)await removeAbandonedObject(root,k);
 const dir=await open(root,'r');try{await dir.sync();}finally{await dir.close();}
 return {projectRowsRemoved:true,originalObjectsAbsent:p.objectKeys.length,physicalMediaErasureCertified:false,backupErasureCertified:false};
}
/** A restore must supply the complete externally trusted ledger inventory. A missing
 * tombstone blocks cutover, rather than resurrecting data or replaying without approval. */
export async function checkRestoreErasureLedger({pool,quarantineRoot,ledgers,publicKey,expectedLedgerSha256s}){
 if(!Array.isArray(ledgers)||!Array.isArray(expectedLedgerSha256s)||ledgers.length!==expectedLedgerSha256s.length||new Set(expectedLedgerSha256s).size!==expectedLedgerSha256s.length||!expectedLedgerSha256s.every(x=>hex.test(x)))throw Error('complete trusted ledger inventory required');
 const actual=ledgers.map(b=>digest(b)).sort(),expected=[...expectedLedgerSha256s].sort();
 if(actual.some((x,i)=>x!==expected[i]))throw Error('ledger inventory mismatch');
 const root=await privateDirectory(quarantineRoot);
 for(const ledger of ledgers){
 const v=verifyErasureLedger(ledger,publicKey),p=v.plan;
 const q=await pool.query('SELECT vv_api.erasure_restore_status($1,$2,$3,$4,$5) AS safe',[p.tenantId,p.projectId,p.requestId,v.planSha256,v.ledgerSha256]);
 if(q.rows[0]?.safe!==true)throw Error('restored database lacks erasure tombstone; cutover blocked');
 for(const k of p.objectKeys){try{await lstat(join(root,k));throw Error('restored erased object; cutover blocked');}catch(e){if(e.code!=='ENOENT')throw e;}}
 }
 return {cutoverLedgerCheckPassed:true,checked:ledgers.length};
}
