import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,mkdir,readFile,writeFile,rm,unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {encodeWitnessGenesis,openReferenceWitnessJournal} from '../../src/security/provider-witness-journal.mjs';
import {openReceiptGuardedReferenceWitness} from '../../src/security/provider-witness-anchor-gate.mjs';
import {openReferenceWitnessReceiptPublisher} from '../../src/security/provider-witness-publisher-reference.mjs';
import {createUnsignedWitnessAuditStatement,canonicalWitnessAuditStatement} from '../../src/security/provider-witness-audit-receipt.mjs';

const scope={issuer:'https://issuer.example.invalid',audience:'verivaro-internal'};
const first={sequence:1,digest:'1'.repeat(64)},second={sequence:2,digest:'2'.repeat(64)},
 third={sequence:3,digest:'3'.repeat(64)};
const date='2026-11-21T02:00:00.000Z';
async function lab(t){
 const root=await mkdtemp(join(tmpdir(),'vv-reference-publisher-'));
 const journalDirectory=join(root,'journal'),publisherDirectory=join(root,'publisher');
 await mkdir(journalDirectory,{mode:0o700});
 await mkdir(publisherDirectory,{mode:0o700});
 t.after(()=>rm(root,{recursive:true,force:true}));
 const genesis=encodeWitnessGenesis({...scope,checkpoint:first});
 await writeFile(join(journalDirectory,'witness-journal.jsonl'),genesis.bytes,{mode:0o600});
 const signer=generateKeyPairSync('ed25519');
 const receipt=s=>({statement:s,signature:sign(null,canonicalWitnessAuditStatement(s),signer.privateKey).toString('base64url')});
 const genesisStatement=createUnsignedWitnessAuditStatement({
  ...scope,checkpoint:first,count:1,headHash:genesis.headHash,issuedAt:date
 });
 const initial=receipt(genesisStatement);
 const receiptPath=join(publisherDirectory,'signed-witness-receipt.json');
 await writeFile(receiptPath,JSON.stringify(initial)+'\n',{mode:0o600});
 let signCount=0;
 const signStatement=async bytes=>{signCount++;return sign(null,bytes,signer.privateKey).toString('base64url');};
 const floor={count:1,headHash:genesis.headHash};
 const publisherConfig=(newFloor=floor)=>({
  directory:publisherDirectory,...scope,trustedPublicKey:signer.publicKey,
  trustedFloor:newFloor,signStatement
 });
 const guardConfig=(publisher,newFloor=floor)=>({
  directory:journalDirectory,...scope,anchor:publisher,trustedPublicKey:signer.publicKey,
  trustedFloor:newFloor,ioTimeoutMs:700,clock:()=>new Date(date)
 });
 return {root,journalDirectory,publisherDirectory,receiptPath,
  signer,initial,floor,publisherConfig,guardConfig,receipt,
  signCount:()=>signCount
 };
}
function statement(state,checkpoint,count,headHash){
 return createUnsignedWitnessAuditStatement({...scope,checkpoint,count,headHash,issuedAt:date});
}
test('publisher and guard agree after fsynced publication; independent floor required for restart',async t=>{
 const f=await lab(t),publisher=await openReferenceWitnessReceiptPublisher(f.publisherConfig());
 const guard=await openReceiptGuardedReferenceWitness(f.guardConfig(publisher));
 assert.deepEqual(await guard.read(scope),first);
 assert.deepEqual(await guard.compareAndSwap({...scope,previous:first,next:second}),second);
 assert.deepEqual(await guard.read(scope),second);
 assert.equal(f.signCount(),1);
 const accepted=await guard.audit();
 await guard.close();
 await publisher.close();
 await assert.rejects(openReferenceWitnessReceiptPublisher(f.publisherConfig()),/unavailable/);
 const updatedFloor={count:accepted.count,headHash:accepted.headHash};
 const again=await openReferenceWitnessReceiptPublisher(f.publisherConfig(updatedFloor));
 const recovered=await openReceiptGuardedReferenceWitness(f.guardConfig(again,updatedFloor));
 assert.deepEqual(await recovered.read(scope),second);
 await recovered.close();await again.close();
});
test('competing external publisher CAS calls commit exactly one signed receipt',async t=>{
 const f=await lab(t),publisher=await openReferenceWitnessReceiptPublisher(f.publisherConfig());
 t.after(()=>publisher.close().catch(()=>{}));
 const previous=await publisher.read(scope);
 const proposed=statement(null,second,2,'a'.repeat(64));
 const results=await Promise.allSettled(Array.from({length:16},()=>
  publisher.compareAndSwap({...scope,previous,statement:proposed})));
 assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(results.filter(x=>x.status==='rejected').length,15);
 assert.equal(f.signCount(),1);
 const current=await publisher.read(scope);
 assert.equal(current.statement.count,2);
 await assert.rejects(publisher.compareAndSwap({...scope,previous,statement:proposed}),/conflict/);
 assert.equal(f.signCount(),1);
});
test('replayed, wrong-scope, forked and non-monotonic publisher statements never replace a receipt',async t=>{
 const f=await lab(t),publisher=await openReferenceWitnessReceiptPublisher(f.publisherConfig());
 t.after(()=>publisher.close().catch(()=>{}));
 const previous=await publisher.read(scope),head='b'.repeat(64);
 for(const candidate of [
  statement(null,second,3,head),
  statement(null,first,2,head),
  statement(null,second,2,previous.statement.headHash),
  createUnsignedWitnessAuditStatement({issuer:scope.issuer,audience:'other',
   checkpoint:second,count:2,headHash:head,issuedAt:date})
 ]){
  await assert.rejects(publisher.compareAndSwap({...scope,previous,statement:candidate}),
   /invalid transition/);
 }
 await assert.rejects(publisher.compareAndSwap({...scope,previous:{...previous,signature:'a'.repeat(86)},
  statement:statement(null,second,2,head)}),/conflict|unavailable/);
 assert.equal(f.signCount(),0);
 assert.equal((await publisher.read(scope)).statement.count,1);
});
test('two simultaneous publishers cannot acquire the same exclusive disk lease',async t=>{
 const f=await lab(t),publisher=await openReferenceWitnessReceiptPublisher(f.publisherConfig());
 await assert.rejects(openReferenceWitnessReceiptPublisher(f.publisherConfig()));
 await publisher.close();
 const reopened=await openReferenceWitnessReceiptPublisher(f.publisherConfig());
 await reopened.close();
});
test('tampering, truncation and old signed snapshots fail startup with independently pinned head',async t=>{
 const f=await lab(t),publisher=await openReferenceWitnessReceiptPublisher(f.publisherConfig());
 const previous=await publisher.read(scope);
 const accepted=await publisher.compareAndSwap({...scope,previous,
  statement:statement(null,second,2,'c'.repeat(64))});
 await publisher.close();
 const currentFloor={count:2,headHash:accepted.statement.headHash};
 await assert.rejects(openReferenceWitnessReceiptPublisher(f.publisherConfig()),/unavailable/);
 const correct=await readFile(f.receiptPath);
 await writeFile(f.receiptPath,JSON.stringify(f.initial)+'\n');
 await assert.rejects(openReferenceWitnessReceiptPublisher(f.publisherConfig(currentFloor)),/unavailable/);
 await writeFile(f.receiptPath,correct.subarray(0,correct.length-6));
 await assert.rejects(openReferenceWitnessReceiptPublisher(f.publisherConfig(currentFloor)),/unavailable/);
 await writeFile(f.receiptPath,correct);
 const restored=await openReferenceWitnessReceiptPublisher(f.publisherConfig(currentFloor));
 assert.equal((await restored.read(scope)).statement.count,2);
 await restored.close();
});
test('injected signer outage latches denial and retains abandoned lock for supervised recovery',async t=>{
 const f=await lab(t);
 const publisher=await openReferenceWitnessReceiptPublisher({
  ...f.publisherConfig(),signStatement:async()=>{throw Error('unavailable signer');}
 });
 const previous=await publisher.read(scope);
 await assert.rejects(publisher.compareAndSwap({...scope,previous,
  statement:statement(null,second,2,'d'.repeat(64))}),/unavailable/);
 await assert.rejects(publisher.read(scope),/unavailable/);
 await publisher.close();
 await assert.rejects(openReferenceWitnessReceiptPublisher(f.publisherConfig()));
 assert.deepEqual(JSON.parse((await readFile(f.receiptPath)).toString()).statement.checkpoint,first);
});
test('ACK loss after publisher commit is uncertain, never retried; operator can restart with verified new floor',async t=>{
 const f=await lab(t),publisher=await openReferenceWitnessReceiptPublisher(f.publisherConfig());
 const guard=await openReceiptGuardedReferenceWitness(f.guardConfig({
  read:s=>publisher.read(s),
  compareAndSwap:async request=>{
   await publisher.compareAndSwap(request);
   throw Error('synthetic lost acknowledgement');
  }
 }));
 await assert.rejects(guard.compareAndSwap({...scope,previous:first,next:second}),/unavailable/);
 assert.equal(f.signCount(),1);
 await assert.rejects(guard.read(scope),/unavailable/);
 await guard.close();await publisher.close();
 await assert.rejects(openReferenceWitnessReceiptPublisher(f.publisherConfig()),/unavailable/);
 // Independent operator supplies updated floor after verifying the persisted
 // publisher receipt AND the completed local journal.
 const latest=JSON.parse((await readFile(f.receiptPath)).toString()).statement;
 const floor={count:latest.count,headHash:latest.headHash};
 const recoveredPublisher=await openReferenceWitnessReceiptPublisher(f.publisherConfig(floor));
 const guard2=await openReceiptGuardedReferenceWitness(f.guardConfig(recoveredPublisher,floor));
 assert.deepEqual(await guard2.read(scope),second);
 await guard2.close();await recoveredPublisher.close();
});

test('mutating a live signed receipt permanently faults the publisher even after restoring its bytes',async t=>{
 const f=await lab(t),publisher=await openReferenceWitnessReceiptPublisher(f.publisherConfig());
 const original=await readFile(f.receiptPath);
 await writeFile(f.receiptPath,Buffer.from(original.toString('utf8').replace('"sequence":1','"sequence":2')));
 await assert.rejects(publisher.read(scope),/unavailable/);
 await writeFile(f.receiptPath,original);
 await assert.rejects(publisher.read(scope),/unavailable/);
 await publisher.close();
 // A fault must retain the lock to force an operator review before reopening.
 await assert.rejects(openReferenceWitnessReceiptPublisher(f.publisherConfig()),/unavailable/);
});
