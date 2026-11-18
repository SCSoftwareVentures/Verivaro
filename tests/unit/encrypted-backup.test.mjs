import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtemp,rm,writeFile,readFile,readdir,open,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {encryptBackup,decryptBackup} from '../../packages/security/encrypted-backup.mjs';
test('streaming encrypted backup authenticates content, identity and size before publication',async t=>{
 const dir=await mkdtemp(join(tmpdir(),'vv-backup-test-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 const input=join(dir,'source'),encoded=join(dir,'cipher'),decoded=join(dir,'restored'),key=randomBytes(32),opts={key,keyId:'rotation-one',context:'project-backup:synthetic'};
 const bytes=randomBytes(5*1024*1024+37);await writeFile(input,bytes,{mode:0o600});
 const e=await encryptBackup(input,encoded,opts);assert.equal(e.plaintextSha256,createHash('sha256').update(bytes).digest('hex'));assert.equal(e.chunkBytes,1048576);
 assert.equal((await stat(encoded)).size,bytes.length+76);assert.notDeepEqual((await readFile(encoded)).subarray(60,100),bytes.subarray(0,40));
 await assert.rejects(decryptBackup(encoded,decoded,{...opts,key:randomBytes(32)}));
 await assert.rejects(decryptBackup(encoded,decoded,{...opts,context:'other'}));
 await assert.rejects(decryptBackup(encoded,decoded,{...opts,maxBytes:10}));
 assert.equal((await decryptBackup(encoded,decoded,opts)).plaintextSha256,e.plaintextSha256);assert.deepEqual(await readFile(decoded),bytes);
 await assert.rejects(decryptBackup(encoded,decoded,opts));const f=await open(encoded,'r+');await f.write(Buffer.from([0x55]),0,1,70);await f.close();
 // Force exact corruption even if byte already 0x55.
 const data=await readFile(encoded);data[71]^=0xff;await writeFile(encoded,data);
 await assert.rejects(decryptBackup(encoded,join(dir,'bad-output'),opts));
 assert.equal((await readdir(dir)).some(x=>x.startsWith('.vv-backup-stage-')||x==='bad-output'),false);
});
