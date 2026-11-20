import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,writeFile,unlink,rename,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,randomUUID,generateKeyPairSync} from 'node:crypto';
import {createLocalPdfDeletionLedger} from '../../src/security/pdf-deletion-ledger.mjs';
import {createLocalPdfDeletionReplica} from '../../src/security/pdf-deletion-replica.mjs';
import {auditPdfDeletionRecovery} from '../../src/security/pdf-deletion-recovery.mjs';
const id=()=>randomUUID(),digest=b=>createHash('sha256').update(b).digest('hex'),signal=()=>new AbortController().signal;
test('read-only classifier distinguishes interruption phases and signed completion',async()=>{
 const vaultRoot=await mkdtemp(join(tmpdir(),'vv-recovery-vault-')),root=await mkdtemp(join(tmpdir(),'vv-recovery-ledger-')),replicaRoot=await mkdtemp(join(tmpdir(),'vv-recovery-copy-')),key=generateKeyPairSync('ed25519');
 const replica=createLocalPdfDeletionReplica({root:replicaRoot,trustedKey:key.publicKey}),ledger=createLocalPdfDeletionLedger({root,privateKey:key.privateKey,replica});
 const meta={tenantId:id(),projectId:id(),quarantineId:id(),sha256:'a'.repeat(64)},original=join(vaultRoot,meta.quarantineId+'.vvq'),intent=join(vaultRoot,meta.quarantineId+'.delete-intent'),tomb=join(vaultRoot,meta.quarantineId+'.deleted');
 try{
  await writeFile(original,Buffer.alloc(29),{mode:0o600});
  const audit=()=>auditPdfDeletionRecovery({root:vaultRoot,meta,ledger,signal:signal()});
  assert.equal((await audit()).status,'retained_no_deletion');
  const prepared=await ledger.prepare(meta,'b'.repeat(64),signal());
  assert.equal((await audit()).status,'prepared_original_still_present');
  const record={version:1,kind:'original-pdf-delete-intent',quarantineId:meta.quarantineId,tenantId:meta.tenantId,projectId:meta.projectId,sha256:meta.sha256,authorizationSha256:prepared.body.authorizationSha256,preparedSha256:digest(Buffer.from(JSON.stringify(prepared))),deletionId:prepared.body.deletionId,issuedAt:new Date().toISOString()};
  await writeFile(intent,JSON.stringify(record),{mode:0o600});
  assert.equal((await audit()).status,'interrupted_before_unlink');
  await unlink(original);
  assert.equal((await audit()).status,'missing_original_pending_completion');
  await ledger.complete(meta,prepared,original,signal());
  assert.equal((await audit()).status,'signed_completion_local_tombstone_pending');
  await rename(intent,tomb);
  const complete=await audit();assert.equal(complete.status,'signed_completion_verified');assert.equal(complete.completedVerified,true);assert.equal(complete.manualReconciliationRequired,false);
  const corrupt={...record,sourceSha256:'b'.repeat(64)};
  await writeFile(tomb,JSON.stringify(corrupt));await assert.rejects(audit());
 }finally{ledger.close();replica.close();await rm(vaultRoot,{recursive:true,force:true});await rm(root,{recursive:true,force:true});await rm(replicaRoot,{recursive:true,force:true});}
});
test('unexplained missing originals and contradictory final states fail closed',async()=>{
 const vaultRoot=await mkdtemp(join(tmpdir(),'vv-recovery-vault-')),root=await mkdtemp(join(tmpdir(),'vv-recovery-ledger-')),replicaRoot=await mkdtemp(join(tmpdir(),'vv-recovery-copy-')),key=generateKeyPairSync('ed25519');
 const replica=createLocalPdfDeletionReplica({root:replicaRoot,trustedKey:key.publicKey}),ledger=createLocalPdfDeletionLedger({root,privateKey:key.privateKey,replica});
 const meta={tenantId:id(),projectId:id(),quarantineId:id(),sha256:'a'.repeat(64)};
 try{
  const probe=()=>auditPdfDeletionRecovery({root:vaultRoot,meta,ledger,signal:signal()});
  await assert.rejects(probe());
  await ledger.prepare(meta,'b'.repeat(64),signal());await assert.rejects(probe());
 }finally{ledger.close();replica.close();await rm(vaultRoot,{recursive:true,force:true});await rm(root,{recursive:true,force:true});await rm(replicaRoot,{recursive:true,force:true});}
});
