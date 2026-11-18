import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,rm,lstat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as sleep} from 'node:timers/promises';
import {createClamdScanner} from '../../packages/security/clamd.mjs';
import {quarantineUpload,scanQuarantine} from '../../packages/security/quarantine.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
test('actual ClamAV daemon recognises an inert custom signature and clean fixture; unavailable daemon fails closed',{timeout:60000},async()=>{
 const root=await mkdtemp(join(tmpdir(),'vv-real-clamd-')),db=join(root,'db'),files=join(root,'files'),socket=join(root,'clamd.sock'),conf=join(root,'clamd.conf');
 let child,exited=false,logs='';
 const flagged=Buffer.from('VERIVARO harmless custom signature fixture '.repeat(12)),clean=Buffer.from('VERIVARO benign unmatched fixture '.repeat(12));
 try{
 await mkdir(db,{mode:0o700});await mkdir(files,{mode:0o700});
 await writeFile(join(db,'verivaro-test.hdb'),createHash('md5').update(flagged).digest('hex')+':'+flagged.length+':Verivaro.Custom.Test.Fixture\n');
 await writeFile(conf,['Foreground yes','DatabaseDirectory '+db,'LocalSocket '+socket,'LocalSocketMode 0600','StreamMaxLength 50M','MaxFileSize 50M','MaxScanSize 100M','MaxThreads 2','MaxQueue 4','ReadTimeout 10','CommandReadTimeout 5'].join('\n')+'\n');
 child=spawn('/usr/sbin/clamd',['--config-file='+conf],{stdio:['ignore','pipe','pipe'],env:{PATH:'/usr/sbin:/usr/bin:/bin',LANG:'C',HOME:root}});
 child.on('error',e=>{logs+=e.message;exited=true;});child.on('exit',()=>{exited=true;});
 for(const s of [child.stdout,child.stderr])s.on('data',b=>{logs=(logs+b.toString()).slice(-8000);});
 let ready=false;for(let i=0;i<100&&!exited;i++){try{if((await lstat(socket)).isSocket()){ready=true;break;}}catch{}await sleep(200);}
 assert.ok(ready,'daemon did not start: '+logs);
 const scanner=createClamdScanner({socketPath:socket,timeoutMs:5000});
 const upload=b=>quarantineUpload(files,{sha256:sha(b),bytes:b.length,mediaType:'text/plain'},[b]);
 const a=await upload(clean),b=await upload(flagged);
 const first=await scanQuarantine(files,a,scanner,{timeoutMs:12000});assert.equal(first.outcome,'clean',logs);assert.equal(first.engine,'ClamAV');
 const second=await scanQuarantine(files,b,scanner,{timeoutMs:12000});assert.equal(second.outcome,'rejected',logs);
 const unavailable=await scanQuarantine(files,a,createClamdScanner({socketPath:join(root,'missing.sock'),timeoutMs:1000}));assert.equal(unavailable.outcome,'unavailable');
 }finally{
 if(child&&!exited){child.kill('SIGTERM');for(let i=0;i<30&&!exited;i++)await sleep(100);if(!exited)child.kill('SIGKILL');}
 await rm(root,{recursive:true,force:true});
 }
});
