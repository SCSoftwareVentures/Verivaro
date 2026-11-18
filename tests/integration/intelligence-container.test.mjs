import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {intelligenceContainerArgs} from '../../packages/security/intelligence-container.mjs';
import {validateProviderProposals} from '../../packages/domain/intelligence.mjs';
const image=process.env.VV_INTELLIGENCE_IMAGE;
const base=()=>intelligenceContainerArgs(image);
function execute(extra=[],input){
 const name='vv-ci-'+randomUUID(),a=base();
 try{return spawnSync('docker',[...a.slice(0,-1),'--name='+name,...extra.slice(0,extra.length?1:0),image,...extra.slice(1)],{input,timeout:15000,killSignal:'SIGKILL',maxBuffer:262144,encoding:'utf8'});}
 finally{spawnSync('docker',['rm','-f',name],{timeout:5000,stdio:'ignore'});}
}
test('real container runs actual source-grounded worker',()=>{
 const text='📄 Certificate to be submitted before handover.';
 const pages=[{page:1,text_value:text,text_sha256:createHash('sha256').update(text).digest('hex'),method:'utf8-exact'}];
 const r=execute([],JSON.stringify({pages}));assert.equal(r.status,0,r.stderr);
 const valid=validateProviderProposals(pages,JSON.parse(r.stdout));assert.equal(valid.length,1);assert.equal(valid[0].state,'needs-review');
});
test('actual Linux namespace, read-only filesystem, UID and privilege controls',()=>{
 // CI-only diagnostic overrides the trusted worker entrypoint; never exposed by the production runner.
 const probe=`const fs=require('node:fs'),os=require('node:os'),assert=require('node:assert/strict');
 assert.equal(process.getuid(),65532);
 assert.ok(Object.values(os.networkInterfaces()).flat().every(x=>x.internal));
 const status=fs.readFileSync('/proc/self/status','utf8');
 assert.match(status,/^CapEff:\\s+0+$/m);assert.match(status,/^NoNewPrivs:\\s+1$/m);
 assert.throws(()=>fs.writeFileSync('/tmp/vv-probe','x'),e=>['EROFS','EACCES'].includes(e.code));
 assert.equal(fs.existsSync('/var/run/docker.sock'),false);
 assert.equal(fs.existsSync('/run/podman/podman.sock'),false);
 if(fs.existsSync('/sys/fs/cgroup/memory.max')){assert.equal(fs.readFileSync('/sys/fs/cgroup/memory.max','utf8').trim(),'134217728');assert.equal(fs.readFileSync('/sys/fs/cgroup/pids.max','utf8').trim(),'32');const [quota,period]=fs.readFileSync('/sys/fs/cgroup/cpu.max','utf8').trim().split(' ').map(Number);assert.equal(quota/period,0.5);}
 else throw Error('cgroup v2 required for acceptance');
 console.log('isolated');`;
 const r=execute(['--entrypoint=/usr/local/bin/node','-e',probe]);assert.equal(r.status,0,r.stderr);assert.equal(r.stdout.trim(),'isolated');
});
test('actual container enforces independent deadline on CPU-bound work',()=>{
 const start=Date.now();
 const r=execute(['--entrypoint=/usr/bin/timeout','--signal=KILL','5s','/usr/local/bin/node','-e','for(;;){}']);
 assert.ok([124,137].includes(r.status),JSON.stringify({status:r.status,signal:r.signal,stderr:r.stderr}));assert.ok(Date.now()-start<15000);
});
