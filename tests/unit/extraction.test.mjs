import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createServer} from 'node:net';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {quarantineUpload,scanQuarantine} from '../../packages/security/quarantine.mjs';
import {createClamdScanner} from '../../packages/security/clamd.mjs';
import {processOneExtraction} from '../../packages/worker/extraction.mjs';
const data=Buffer.from('\ufeffExact Unicode \u{1f4c4}\r\nsynthetic');
const hash=b=>createHash('sha256').update(b).digest('hex');
async function fixture(t,b=data,type='text/plain'){const root=await mkdtemp(join(tmpdir(),'vv-extract-'));t.after(()=>rm(root,{recursive:true,force:true}));const receipt=await quarantineUpload(root,{bytes:b.length,sha256:hash(b),mediaType:type},[b]);return {root,receipt};}
async function daemon(t,root,response){const socketPath=join(root,'clamd.sock');const sockets=new Set();let seen=null;const server=createServer(s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));s.on('error',()=>{});let all=Buffer.alloc(0);s.on('data',b=>{
 all=Buffer.concat([all,b]);
 if(all.subarray(0,9).equals(Buffer.from('zVERSION\0'))){s.end('ClamAV 1.4.0/123/example\0');return;}
 if(all.length<10||!all.subarray(0,10).equals(Buffer.from('zINSTREAM\0')))return;
 let pos=10,parts=[];while(pos+4<=all.length){const len=all.readUInt32BE(pos);pos+=4;if(len===0){seen=Buffer.concat(parts);s.end(response+'\0');return;}if(pos+len>all.length)return;parts.push(all.subarray(pos,pos+len));pos+=len;}
 });});await new Promise((r,j)=>{server.once('error',j);server.listen(socketPath,r);});t.after(async()=>{for(const s of sockets)s.destroy();await new Promise(r=>server.close(r));});return {scanner:createClamdScanner({socketPath}),seen:()=>seen};}
test('ClamAV protocol streams exact bytes and accepts only explicit verdict',async t=>{const {root,receipt}=await fixture(t);const d=await daemon(t,root,'stream: OK');const result=await scanQuarantine(root,receipt,d.scanner);assert.equal(result.outcome,'clean');assert.deepEqual(d.seen(),data);assert.equal(result.engine,'ClamAV');assert.equal(result.state,'quarantined');});
test('ClamAV detection is rejected, not released',async t=>{const {root,receipt}=await fixture(t);const d=await daemon(t,root,'stream: Synthetic.Test FOUND');assert.equal((await scanQuarantine(root,receipt,d.scanner)).outcome,'rejected');});
test('ClamAV limit error fails closed',async t=>{const {root,receipt}=await fixture(t);const d=await daemon(t,root,'INSTREAM size limit exceeded. ERROR');assert.equal((await scanQuarantine(root,receipt,d.scanner)).outcome,'unavailable');});
test('no daemon fails closed',async t=>{const {root,receipt}=await fixture(t);assert.equal((await scanQuarantine(root,receipt,createClamdScanner({socketPath:join(root,'absent.sock')}))).outcome,'unavailable');});
function pool(receipt,check){return {async query(q,args){if(q.includes('claim_extract'))return {rows:[{object_key:receipt.objectKey,sha256:receipt.sha256,bytes:receipt.bytes,media_type:receipt.mediaType}]};check(args);return {rows:[{state:args[1]==='unavailable'?'queued':args[1]}]};}};}
test('exact UTF-8 preserves BOM, unicode and newlines',async t=>{const {root,receipt}=await fixture(t);const result=await processOneExtraction(pool(receipt,args=>{assert.equal(args[1],'complete');assert.deepEqual(Buffer.from(args[2]),data);}),root);assert.equal(result.state,'complete');});
test('modified file fails extraction',async t=>{const {root,receipt}=await fixture(t);await writeFile(join(root,receipt.objectKey),Buffer.alloc(data.length));assert.equal((await processOneExtraction(pool(receipt,args=>assert.deepEqual(args.slice(1),['unavailable',null])),root)).state,'queued');});
test('PDF explicitly unsupported in exact-text adapter',async t=>{const {root,receipt}=await fixture(t,Buffer.from('%PDF-1.7\nsynthetic'),'application/pdf');assert.equal((await processOneExtraction(pool(receipt,args=>assert.deepEqual(args.slice(1),['unsupported',null])),root)).state,'unsupported');});
