import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomUUID,sign} from 'node:crypto';
import {planBackupRetention} from '../../src/security/backup-retention.mjs';
const now=Date.parse('2026-11-19T00:00:00Z'),day=86400000;
const d=n=>new Date(now-n*day).toISOString();
const {privateKey,publicKey}=generateKeyPairSync('ed25519');
const installationId=randomUUID();
const row=(sequence,age,extra={})=>({backupId:randomUUID(),sequence,createdAt:d(age),restoreVerifiedAt:d(age-1),keyIds:['old'],legalHold:false,inProgress:false,complete:true,offsiteVerified:true,...extra});
function args(backups,extra={}){
 const catalogue=Buffer.from(JSON.stringify({version:1,installationId,issuedAt:d(0),backups,...extra}));
 return {catalogue,signature:sign(null,catalogue,privateKey),expectedDigest:createHash('sha256').update(catalogue).digest('hex'),verificationKey:publicKey,installationId,activeKeyId:'new',now};
}
test('retention protects latest, three verified copies, holds, incomplete and unverified copies',()=>{
 const rows=[row(8,2,{keyIds:['new']}),row(7,5),row(6,35),row(5,40),row(4,45,{legalHold:true}),row(3,50,{complete:false}),row(2,55,{offsiteVerified:false}),row(1,60,{restoreVerifiedAt:null,keyIds:[null]})];
 const p=planBackupRetention(args(rows));
 assert.equal(p.destructiveAction,false);assert.equal(p.verifiedCopies,5);
 assert.deepEqual(p.entries.filter(e=>e.decision==='eligible_for_review').map(e=>e.backupId),[rows[3].backupId]);
 assert.ok(p.keyRetirementBlockers.find(e=>e.keyId==='old').backupIds.includes(rows[3].backupId));
 assert.ok(p.keyRetirementBlockers.find(e=>e.keyId===null).backupIds.includes(rows[7].backupId));
});
test('retention rejects stale, tampered, duplicate and wrong-scope catalogue',()=>{
 const r=row(1,40),a=args([r]);
 for(const bad of [{...a,expectedDigest:'a'.repeat(64)},{...a,installationId:randomUUID()},{...a,now:now+2*day},args([r,r]),args([r],{issuedAt:d(2)})])assert.throws(()=>planBackupRetention(bad));
 assert.equal(planBackupRetention(a).entries[0].decision,'retain');
});
