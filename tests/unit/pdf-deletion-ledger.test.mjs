import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readdir,writeFile,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID,generateKeyPairSync,randomBytes} from 'node:crypto';
import {createLocalPdfDeletionLedger,verifyPdfDeletionEvidence} from '../../src/security/pdf-deletion-ledger.mjs';
const mk=()=>({tenantId:randomUUID(),projectId:randomUUID(),quarantineId:randomUUID(),sha256:'b'.repeat(64)}),signal=()=>new AbortController().signal;
test('prepared receipt is durable and independently verifiable before unlink; completed only after absence',async()=>{
 const root=await mkdtemp(join(tmpdir(),'vv-signed-receipts-')),keys=generateKeyPairSync('ed25519'),meta=mk(),path=join(root,'source.bin'),ledger=createLocalPdfDeletionLedger({root,privateKey:keys.privateKey});
 try{
  await writeFile(path,Buffer.from('encrypted source'),{mode:0o600});
  assert.equal((await ledger.read(meta,{signal:signal()})).status,'none');
  const prep=await ledger.prepare(meta,'c'.repeat(64),signal());
  assert.equal((await ledger.read(meta,{signal:signal()})).status,'prepared');
  assert.equal(verifyPdfDeletionEvidence(prep,keys.publicKey,{meta}).kind,'prepared');
  await assert.rejects(ledger.complete(meta,prep,path,signal()));
  await assert.rejects(ledger.prepare(meta,'c'.repeat(64),signal()));
  await (await import('node:fs/promises')).unlink(path);
  const final=await ledger.complete(meta,prep,path,signal());
  assert.equal(verifyPdfDeletionEvidence(final,keys.publicKey,{meta,prepared:prep}).kind,'completed');
  assert.equal((await ledger.read(meta,{signal:signal()})).status,'completed');
  assert.deepEqual((await readdir(root)).filter(x=>x.endsWith('.prepared')||x.endsWith('.completed')).length,2);
  await assert.rejects(ledger.complete(meta,prep,path,signal()));
 }finally{ledger.close();await rm(root,{recursive:true,force:true});}
});
test('tampering, wrong key, truncated archive and tenant substitution fail closed',async()=>{
 const root=await mkdtemp(join(tmpdir(),'vv-signed-receipts-')),key=generateKeyPairSync('ed25519'),meta=mk(),ledger=createLocalPdfDeletionLedger({root,privateKey:key.privateKey});
 try{
  const p=await ledger.prepare(meta,'0'.repeat(64),signal());
  assert.throws(()=>verifyPdfDeletionEvidence(p,generateKeyPairSync('ed25519').publicKey));
  assert.throws(()=>verifyPdfDeletionEvidence({...p,body:{...p.body,tenantId:randomUUID()}},key.publicKey));
  assert.throws(()=>verifyPdfDeletionEvidence(p,key.publicKey,{meta:{...meta,sha256:'a'.repeat(64)}}));
  const path=join(root,(await readdir(root)).find(x=>x.endsWith('.prepared')));
  const good=await readFile(path);await writeFile(path,good.subarray(0,-1));
  await assert.rejects(ledger.read(meta,{signal:signal()}));
  await writeFile(path,good);
  const out=await ledger.read(meta,{signal:signal()});assert.equal(out.status,'prepared');
 }finally{ledger.close();await rm(root,{recursive:true,force:true});}
});
test('signing key and archive directory must be separate and restricted',async()=>{
 const root=await mkdtemp(join(tmpdir(),'vv-signed-receipts-')),pair=generateKeyPairSync('ed25519'),ledger=createLocalPdfDeletionLedger({root,privateKey:pair.privateKey});
 try{
  const status=await ledger.read(mk(),{signal:signal()});assert.equal(status.status,'none');
  await (await import('node:fs/promises')).chmod(root,0o777);
  await assert.rejects(ledger.read(mk(),{signal:signal()}));
  assert.throws(()=>createLocalPdfDeletionLedger({root:'relative',privateKey:pair.privateKey}));
 }finally{ledger.close();await rm(root,{recursive:true,force:true});}
});
