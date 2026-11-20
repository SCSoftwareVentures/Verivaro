import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {generateShareToken,digestShareToken} from '../../src/security/share-token.mjs';
test('share tokens use 256 random bits and canonical digest',()=>{
 const generated=Array.from({length:100},()=>generateShareToken());
 assert.equal(new Set(generated.map(x=>x.token)).size,100);
 for(const {token,digest} of generated){
  assert.equal(token.length,43);
  assert.equal(digest.length,32);
  assert.deepEqual(digest,createHash('sha256').update(Buffer.from(token,'base64url')).digest());
  assert.deepEqual(digestShareToken(token),digest);
 }
});
test('rejects malformed, oversized and noncanonical share tokens',()=>{
 for(const token of [null,{},'a'.repeat(42),'a'.repeat(44),'a'.repeat(100000),'A'.repeat(42)+'B','+'.repeat(43),'A'.repeat(43)+'='])
  assert.throws(()=>digestShareToken(token),/invalid/);
});
