import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readdir,readFile,writeFile,unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {createLocalPdfDeletionLedger,verifyPdfDeletionEvidence} from '../../src/security/pdf-deletion-ledger.mjs';
import {createLocalPdfDeletionReplica} from '../../src/security/pdf-deletion-replica.mjs';
const m=()=>({tenantId:randomUUID(),projectId:randomUUID(),quarantineId:randomUUID(),sha256:'d'.repeat(64)}),signal=()=>new AbortController().signal;
test('independently verified read-after-write replica is required before successful stage or completion',async()=>{
 const ledgerRoot=await mkdtemp(join(tmpdir(),'vv-del-ledger-')),replicaRoot=await mkdtemp(join(tmpdir(),'vv-del-replica-')),key=generateKeyPairSync('ed25519'),meta=m(),original=join(ledgerRoot,'encrypted.original');
 const replica=createLocalPdfDeletionReplica({root:replicaRoot,trustedKey:key.publicKey}),ledger=createLocalPdfDeletionLedger({root:ledgerRoot,privateKey:key.privateKey,replica});
 try{
  assert.equal(ledger.replicated,true);await writeFile(original,'encrypted original',{mode:0o600});
  const prepared=await ledger.prepare(meta,'a'.repeat(64),signal());
  assert.deepEqual(await ledger.read(meta,{signal:signal()}),await replica.read(meta,{signal:signal()}));
  await assert.rejects(ledger.complete(meta,prepared,original,signal()));
  await unlink(original);
  const completed=await ledger.complete(meta,prepared,original,signal());
  assert.equal(verifyPdfDeletionEvidence(completed,key.publicKey,{meta,prepared}).kind,'completed');
  assert.equal((await replica.read(meta,{signal:signal()})).status,'completed');
  const archive=await replica.read(meta,{signal:signal()});
  // Even when the signer-side ledger is destroyed, independently trusted
  // signed archive records remain readable, but deletion stays disabled.
  const files=(await readdir(ledgerRoot)).filter(x=>x.endsWith('.prepared')||x.endsWith('.completed'));
  for(const f of files)await unlink(join(ledgerRoot,f));
  assert.equal(verifyPdfDeletionEvidence(archive.completed,key.publicKey,{meta,prepared:archive.prepared}).kind,'completed');
  await assert.rejects(ledger.read(meta,{signal:signal()}));
 }finally{ledger.close();replica.close();await rm(ledgerRoot,{recursive:true,force:true});await rm(replicaRoot,{recursive:true,force:true});}
});
test('missing or modified replica prevents success even when signer-side prepared record exists',async()=>{
 const ledgerRoot=await mkdtemp(join(tmpdir(),'vv-del-ledger-')),replicaRoot=await mkdtemp(join(tmpdir(),'vv-del-replica-')),key=generateKeyPairSync('ed25519'),meta=m();
 const replica=createLocalPdfDeletionReplica({root:replicaRoot,trustedKey:key.publicKey}),ledger=createLocalPdfDeletionLedger({root:ledgerRoot,privateKey:key.privateKey,replica});
 try{
  const prepared=await ledger.prepare(meta,'a'.repeat(64),signal());
  const dest=join(replicaRoot,(await readdir(replicaRoot)).find(x=>x.endsWith('.prepared')));
  const bytes=await readFile(dest);await writeFile(dest,bytes.subarray(0,-1));
  await assert.rejects(ledger.read(meta,{signal:signal()}));
  await writeFile(dest,bytes);
  assert.equal((await ledger.read(meta,{signal:signal()})).status,'prepared');
  await assert.rejects(replica.write(meta,prepared,signal()));
 }finally{ledger.close();replica.close();await rm(ledgerRoot,{recursive:true,force:true});await rm(replicaRoot,{recursive:true,force:true});}
});
