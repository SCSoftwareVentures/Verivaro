import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {createConnection,createServer} from 'node:net';
import {startOcrWorker,createOcrSocketClient} from '../../src/security/ocr-socket.mjs';
import {fixturePng} from '../fixtures/evidence-formats-fixture.mjs';
const tsv=()=>Buffer.from('level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n1\t1\t0\t0\t0\t0\t0\t0\t1\t1\t-1\t\n');
test('actual Unix socket authenticates requests, refuses wrong keys, validates output and cleans up',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'vv-ocr-')),socketPath=join(dir,'w.sock'),key=randomBytes(32),data=fixturePng();let calls=0,invalid=false;
 let worker,client,wrong;
 try{
  worker=await startOcrWorker({socketPath,key,recognize:async b=>{assert.deepEqual(b,data);calls++;return invalid?Buffer.from('invalid'):tsv();}});
  client=createOcrSocketClient({socketPath,key});wrong=createOcrSocketClient({socketPath,key:randomBytes(32)});
  const signal=new AbortController().signal;
  assert.deepEqual(await client(data,signal),tsv());assert.equal(calls,1);
  await assert.rejects(wrong(data,signal));assert.equal(calls,1);
  await assert.rejects(client(Buffer.concat([data,Buffer.from('x')]),signal));assert.equal(calls,1);
  invalid=true;await assert.rejects(client(data,signal));assert.equal(calls,2);
  invalid=false;assert.deepEqual(await client(data,signal),tsv());
  await chmod(dir,0o777);await assert.rejects(client(data,signal));await chmod(dir,0o700);
 }finally{client?.close();wrong?.close();await worker?.close();key.fill(0);await rm(dir,{recursive:true,force:true});}
});
test('forged response and cancellation fail closed',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'vv-ocr-')),socketPath=join(dir,'w.sock'),key=randomBytes(32),data=fixturePng();
 let leaked=0;const peers=new Set(),fake=createServer({allowHalfOpen:true},s=>{peers.add(s);s.on('error',()=>{});s.once('close',()=>peers.delete(s));s.on('data',b=>{leaked+=b.length;s.write(randomBytes(64));});s.on('end',()=>s.end());});
 let client;
 try{
  await new Promise(r=>fake.listen(socketPath,r));await chmod(socketPath,0o660);
  client=createOcrSocketClient({socketPath,key,timeoutMs:1000});await assert.rejects(client(data,new AbortController().signal));assert.equal(leaked,32);
  const ac=new AbortController();ac.abort();await assert.rejects(client(data,ac.signal));
 }finally{client?.close();for(const s of peers)s.destroy();await new Promise(r=>fake.close(r));await rm(dir,{recursive:true,force:true});key.fill(0);}
});
