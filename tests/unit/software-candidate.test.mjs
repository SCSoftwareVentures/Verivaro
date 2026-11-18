import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {sha256,publicFingerprint,signCandidate,verifyCandidate} from '../../packages/security/software-candidate.mjs';
const key=generateKeyPairSync('ed25519'),other=generateKeyPairSync('ed25519'),revision='a'.repeat(40);
const artifacts=new Map(['source.tar','sbom.cdx.json','dependency-licenses.json','npm-audit.json','source-files.json','candidate-evidence.json'].map(n=>[n,Buffer.from(n)]));
const fingerprint=publicFingerprint(key.publicKey),manifest={schema:'verivaro-software-candidate-v1',revision,signingMode:'ci-ephemeral',signerFingerprint:fingerprint,productionApproved:false,artifacts:[...artifacts].map(([name,b])=>({name,bytes:b.length,sha256:sha256(b)}))};
test('candidate exact bytes and external trust anchor verify; substitutions fail closed',()=>{
 const signed=signCandidate(manifest,key.privateKey),args={...signed,publicKey:key.publicKey,expectedRevision:revision,expectedFingerprint:fingerprint,expectedMode:'ci-ephemeral',artifacts};
 assert.equal(verifyCandidate(args).productionApproved,false);
 for(const patch of [{publicKey:other.publicKey},{expectedRevision:'b'.repeat(40)},{expectedFingerprint:'b'.repeat(64)},{expectedMode:'buyer-offline'},{body:Buffer.concat([signed.body,Buffer.from(' ')] )},{signature:Buffer.alloc(64)},{artifacts:new Map([...artifacts,['malicious.sh',Buffer.from('x')]])},{artifacts:new Map([...artifacts,['source.tar',Buffer.from('tampered')]])}])assert.throws(()=>verifyCandidate({...args,...patch}));
});
test('manifest never permits production approval, duplicate paths or arbitrary names',()=>{
 assert.throws(()=>signCandidate({...manifest,productionApproved:true},key.privateKey));
 assert.throws(()=>signCandidate({...manifest,artifacts:[...manifest.artifacts,manifest.artifacts[0]]},key.privateKey));
 assert.throws(()=>signCandidate({...manifest,artifacts:[...manifest.artifacts,{name:'../escape',bytes:1,sha256:'a'.repeat(64)}]},key.privateKey));
 assert.throws(()=>signCandidate(manifest,other.privateKey));
});
