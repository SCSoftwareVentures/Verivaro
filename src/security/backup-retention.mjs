import {createHash,createPublicKey,verify} from 'node:crypto';
import {validBackupKeyId} from './backup-keyring.mjs';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const HASH=/^[a-f0-9]{64}$/;
const DAY=86400000;
function time(value){
 if(typeof value!=='string')throw Error('invalid timestamp');
 const date=new Date(value);if(!Number.isFinite(date.getTime())||date.toISOString()!==value)throw Error('invalid timestamp');return date.getTime();
}
// Pure plan, never filesystem mutation. The signed catalogue must be supplied
// by a separately trusted custodian, not discovered from the backup directory.
export function planBackupRetention({catalogue,signature,verificationKey,expectedDigest,installationId,activeKeyId,now=Date.now(),retentionDays=30,minimumCopies=3}){
 if(!Buffer.isBuffer(catalogue)||catalogue.length>4*1024*1024||!Buffer.isBuffer(signature)||signature.length!==64||
 !HASH.test(expectedDigest)||!UUID.test(installationId)||!validBackupKeyId(activeKeyId)||!Number.isFinite(now)||
 !Number.isInteger(retentionDays)||retentionDays<7||retentionDays>3650||!Number.isInteger(minimumCopies)||minimumCopies<3||minimumCopies>100)throw Error('invalid retention configuration');
 const key=verificationKey?.type==='public'?verificationKey:createPublicKey(verificationKey);
 if(key.asymmetricKeyType!=='ed25519'||createHash('sha256').update(catalogue).digest('hex')!==expectedDigest||!verify(null,catalogue,key,signature))throw Error('untrusted retention catalogue');
 const data=JSON.parse(catalogue.toString('utf8'));
 if(data.version!==1||data.installationId!==installationId||!Array.isArray(data.backups)||data.backups.length>10000||
 now-time(data.issuedAt)>DAY||time(data.issuedAt)>now+5000)throw Error('stale retention catalogue');
 const ids=new Set(),sequences=new Set();
 const rows=data.backups.map(r=>{
  if(!UUID.test(r.backupId)||ids.has(r.backupId)||!Number.isSafeInteger(r.sequence)||r.sequence<1||sequences.has(r.sequence)||
   !Array.isArray(r.keyIds)||r.keyIds.length<1||r.keyIds.length>17||new Set(r.keyIds).size!==r.keyIds.length||r.keyIds.some(k=>k!==null&&!validBackupKeyId(k))||
   typeof r.legalHold!=='boolean'||typeof r.inProgress!=='boolean'||typeof r.complete!=='boolean'||typeof r.offsiteVerified!=='boolean')throw Error('invalid retention row');
  const created=time(r.createdAt),tested=r.restoreVerifiedAt===null?null:time(r.restoreVerifiedAt);
  if(created>now+5000||tested!==null&&(tested<created||tested>now+5000))throw Error('invalid verification time');
  ids.add(r.backupId);sequences.add(r.sequence);return {...r,created,tested};
 }).sort((a,b)=>b.sequence-a.sequence);
 // Always preserve the latest catalogue entry and at least N independently
 // restored, off-site-verified complete backups; incomplete/held backups
 // require manual investigation, never an automatic deletion.
 const verified=rows.filter(r=>r.complete&&r.offsiteVerified&&!r.inProgress&&r.tested!==null);
 const keep=new Set([rows[0]?.backupId,...verified.slice(0,minimumCopies).map(r=>r.backupId)]);
 const entries=rows.map(r=>{
  let reason=null;
  if(r.legalHold)reason='legal_hold';
  else if(r.inProgress||!r.complete)reason='incomplete_or_active';
  else if(keep.has(r.backupId))reason='protected_recovery_copy';
  else if(verified.length<minimumCopies)reason='insufficient_verified_copies';
  else if(!r.offsiteVerified||r.tested===null)reason='unverified_copy';
  else if(now-r.created<retentionDays*DAY)reason='within_retention';
  return {backupId:r.backupId,decision:reason?'retain':'eligible_for_review',reason:reason??'retention_expired'};
 });
 // Eligibility is not deletion. All existing archives, including candidates,
 // still block key retirement until their removal is independently confirmed.
 const keyBlockers=new Map();
 for(const r of rows)for(const k of r.keyIds){
  if(k===activeKeyId)continue;
  const list=keyBlockers.get(k)??[];list.push(r.backupId);keyBlockers.set(k,list);
 }
 return Object.freeze({entries,keyRetirementBlockers:[...keyBlockers].map(([keyId,backupIds])=>({keyId,backupIds})),verifiedCopies:verified.length,destructiveAction:false});
}
