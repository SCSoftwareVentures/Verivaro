import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {createReleaseSigner,verifyRelease} from '../../packages/security/releases.mjs';
const keys=generateKeyPairSync('ed25519'),other=generateKeyPairSync('ed25519'),json='{"release":"synthetic"}',row={json,sha256:createHash('sha256').update(json).digest('hex')};
test('Ed25519 signs exact release bytes and pinned key ID',()=>{const s=createReleaseSigner({keyId:'demo',privateKey:keys.privateKey}),a=s.sign(row);assert.equal(verifyRelease(a,{keyId:'demo',publicKey:keys.publicKey}),true);assert.equal(verifyRelease(a,{keyId:'demo',publicKey:other.publicKey}),false);assert.equal(verifyRelease(a,{keyId:'different',publicKey:keys.publicKey}),false);assert.equal(verifyRelease({...a,json:json+' '},{keyId:'demo',publicKey:keys.publicKey}),false);assert.deepEqual(s.sign(row),a);});
test('signing refuses changed or malformed snapshot',()=>{const s=createReleaseSigner({keyId:'demo',privateKey:keys.privateKey});assert.throws(()=>s.sign({...row,json:'changed'}));});
