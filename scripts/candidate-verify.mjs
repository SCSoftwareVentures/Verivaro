import {readFileSync,readdirSync,lstatSync} from 'node:fs';
import {join} from 'node:path';
import {verifyCandidate} from '../packages/security/software-candidate.mjs';
const [dir,publicKeyPath,revision,fingerprint,mode]=process.argv.slice(2);
if(process.argv.length!==7||!dir||!publicKeyPath)throw Error('usage: candidate-verify.mjs DIRECTORY TRUSTED_PUBLIC_KEY EXPECTED_SHA EXPECTED_FINGERPRINT MODE');
const files=readdirSync(dir),meta=new Set(['manifest.json','manifest.sig','candidate-public.pem']);
for(const f of files){const s=lstatSync(join(dir,f));if(!s.isFile()||s.size>64*1024*1024)throw Error('unexpected artifact type or size');}
const manifest=verifyCandidate({body:readFileSync(join(dir,'manifest.json')),signature:readFileSync(join(dir,'manifest.sig')),publicKey:readFileSync(publicKeyPath),expectedRevision:revision,expectedFingerprint:fingerprint,expectedMode:mode,artifacts:new Map(files.filter(f=>!meta.has(f)).map(f=>[f,readFileSync(join(dir,f))]))});
console.log(JSON.stringify({verified:true,revision:manifest.revision,artifacts:manifest.artifacts.length,signingMode:manifest.signingMode,productionApproved:false}));
