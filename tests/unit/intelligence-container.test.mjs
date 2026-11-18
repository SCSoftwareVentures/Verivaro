import test from 'node:test';
import assert from 'node:assert/strict';
import {intelligenceContainerArgs} from '../../packages/security/intelligence-container.mjs';
test('immutable image and fixed no-network hardened policy',()=>{
 const id='sha256:'+'a'.repeat(64),a=intelligenceContainerArgs(id);
 assert.equal(a.at(-1),id);
 for(const flag of ['--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--user=65532:65532','--memory=128m','--memory-swap=128m','--cpus=0.5','--pids-limit=32','--pull=never','--log-driver=none'])assert.ok(a.includes(flag));
 assert.ok(a.every(x=>!x.startsWith('--volume')&&!x.startsWith('--mount')&&x!=='--privileged'));
 for(const bad of ['node:latest','--privileged','sha256:'+'A'.repeat(64),'sha256:abc',null])assert.throws(()=>intelligenceContainerArgs(bad),/immutable/);
});
