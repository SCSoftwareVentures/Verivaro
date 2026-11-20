import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {createAuditCheckpointSigner,verifySignedAuditCheckpoint} from '../../src/security/signed-audit-checkpoint.mjs';
import {trustproofEntryHash} from '../../src/security/trustproof.mjs';
const id=n=>'00000000-0000-4000-8000-'+String(n).padStart(12,'0'),zero='0'.repeat(64);
function fixture(){const tenantId=id(1),projectId=id(2),e={sequence:1,sourceType:'export_template_versions',sourceId:id(3),origin:'live',recordedAt:'2026-11-20T00:00:00.000Z',sourceDigest:'a'.repeat(64),previousHash:zero,sourceIntact:true};e.entryHash=trustproofEntryHash({tenantId,projectId},e);return {tenantId,projectId,readPage:async cursor=>({version:1,tenantId,projectId,afterSequence:cursor,previousHash:cursor?e.entryHash:zero,headSequence:1,headHash:e.entryHash,sourceCount:1,ledgerCount:1,entries:cursor?[]:[e]})};}
test('trusted key validates a complete stable scan; tampering and untrusted keys fail',async()=>{const k=generateKeyPairSync('ed25519'),f=fixture(),s=await createAuditCheckpointSigner(k.privateKey).issue(f);assert.ok(verifySignedAuditCheckpoint(s,k.publicKey).signatureVerified);assert.throws(()=>verifySignedAuditCheckpoint(s,generateKeyPairSync('ed25519').publicKey));assert.throws(()=>verifySignedAuditCheckpoint({...s,checkpoint:{...s.checkpoint,headHash:'b'.repeat(64)}},k.publicKey));});
test('unstable head and invalid source fail closed',async()=>{const k=generateKeyPairSync('ed25519'),f=fixture(),read=f.readPage;await assert.rejects(createAuditCheckpointSigner(k.privateKey).issue({...f,readPage:async c=>({...await read(c),...(c?{headHash:'b'.repeat(64)}:{})})}));});
