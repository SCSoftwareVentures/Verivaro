import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {createPortableBuyerBundle,verifyPortableBuyerBundle} from '../../src/demo/buyer-portable-bundle.mjs';
import {zip} from '../../src/security/verification-report-export.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
function entries(archive){
 const result=[];let offset=0;
 while(archive.readUInt32LE(offset)===0x04034b50){
  const n=archive.readUInt16LE(offset+26),size=archive.readUInt32LE(offset+22);
  result.push([archive.subarray(offset+30,offset+30+n).toString('ascii'),
   Buffer.from(archive.subarray(offset+30+n,offset+30+n+size))]);
  offset+=30+n+size;
 }
 return result;
}
test('buyer ZIP is reproducible, portable and always labelled synthetic',async()=>{
 const [a,b]=await Promise.all([createPortableBuyerBundle(),createPortableBuyerBundle()]);
 assert.equal(a.archiveSha256,b.archiveSha256);
 assert.ok(a.archive.equals(b.archive));
 assert.equal(a.synthetic,true);
 assert.equal(a.authenticityVerified,false);
 assert.equal(a.fileCount,7);
 const valid=verifyPortableBuyerBundle(a.archive,{expectedArchiveSha256:a.archiveSha256});
 assert.equal(valid.integrityVerified,true);
 assert.equal(valid.authenticityVerified,false);
 const files=entries(a.archive);
 assert.deepEqual(files.map(x=>x[0]),[
  'index.html','buyer-showcase.css','buyer-showcase.js',
  'buyer-demo.json','README.txt','preview.mjs','manifest.json'
 ]);
 const html=files[0][1].toString(),script=files[2][1].toString();
 assert.match(html,/href="\.\/buyer-showcase\.css"/);
 assert.match(html,/src="\.\/buyer-showcase\.js"/);
 assert.match(script,/new URL\('\.\/buyer-demo\.json',document\.baseURI\)/);
 const fixture=JSON.parse(files[3][1].toString()),m=JSON.parse(files[6][1].toString());
 assert.deepEqual(fixture.stages.map(x=>x.blockers),[1,1,1,0]);
 assert.equal(fixture.handover.authenticityVerified,false);
 assert.equal(m.releaseApproved,false);
 assert.equal(m.files.length,6);
 assert.ok(files[4][1].toString().includes('No real users'));
 const syntax=spawnSync(process.execPath,['--check','--input-type=module','-'],{
  input:files[5][1],encoding:'utf8'
 });
 assert.equal(syntax.status,0,syntax.stderr);
});
test('ZIP verification fails closed on changed bytes, changed metadata and spoofed readiness',async()=>{
 const p=await createPortableBuyerBundle();
 assert.throws(()=>verifyPortableBuyerBundle(p.archive,{expectedArchiveSha256:'0'.repeat(64)}),
  /verification failed/);
 const broken=Buffer.from(p.archive);broken[50]^=1;
 assert.throws(()=>verifyPortableBuyerBundle(broken,{expectedArchiveSha256:p.archiveSha256}),
  /verification failed/);
 // Even if an adversary recomputes the ZIP hash, a silent byte flip must fail
 // the canonical STORE / CRC / directory validation.
 assert.throws(()=>verifyPortableBuyerBundle(broken,{expectedArchiveSha256:sha(broken)}),
  /verification failed/);
 const files=entries(p.archive);
 const falsified=files.map(([name,data])=>[name,Buffer.from(data)]);
 const fixture=JSON.parse(falsified[3][1].toString());
 fixture.releaseApproved=true;
 falsified[3][1]=Buffer.from(JSON.stringify(fixture));
 const rebundled=zip(falsified);
 assert.throws(()=>verifyPortableBuyerBundle(rebundled,{expectedArchiveSha256:sha(rebundled)}),
  /verification failed/);
 // A refreshed, internally consistent manifest is still rejected if it
 // attempts to upgrade the synthetic release status.
 const manifest=JSON.parse(falsified[6][1].toString());
 manifest.files[3].bytes=falsified[3][1].length;
 manifest.files[3].sha256=sha(falsified[3][1]);
 manifest.releaseApproved=true;
 falsified[6][1]=Buffer.from(JSON.stringify(manifest));
 const upgraded=zip(falsified);
 assert.throws(()=>verifyPortableBuyerBundle(upgraded,{expectedArchiveSha256:sha(upgraded)}),
  /verification failed/);
});
