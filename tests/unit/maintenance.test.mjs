import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {quarantineUpload} from '../../packages/security/quarantine.mjs';
import {recoverBatch,processOneScan} from '../../packages/worker/maintenance.mjs';
const data=Buffer.from('%PDF-1.7\nsynthetic'),sha256=createHash('sha256').update(data).digest('hex');
async function fixture(t){const root=await mkdtemp(join(tmpdir(),'vv-recovery-'));t.after(()=>rm(root,{recursive:true,force:true}));const receipt=await quarantineUpload(root,{sha256,bytes:data.length,mediaType:'application/pdf'},[data]);return {root,receipt};}
test('recovery deletes only exact abandoned keys, retries missing safely',async t=>{const {root,receipt}=await fixture(t);const second=await quarantineUpload(root,{sha256,bytes:data.length,mediaType:'application/pdf'},[data]);const pool={async query(){return {rows:[{object_key:receipt.objectKey},{object_key:'../escape'}]};}};assert.deepEqual(await recoverBatch(pool,root),{selected:2,removed:1,missing:0,failed:1});assert.deepEqual(await readdir(root),[second.objectKey]);assert.deepEqual(await recoverBatch(pool,root),{selected:2,removed:0,missing:1,failed:1});});
test('durable scanner pass remains quarantined, results bound to lease',async t=>{const {root,receipt}=await fixture(t);let token;const pool={async query(q,args){if(q.includes('claim_scan')){token=args[0];return {rows:[{object_key:receipt.objectKey,sha256,bytes:String(data.length),media_type:'application/pdf'}]};}assert.equal(args[0],token);assert.deepEqual(args.slice(1),['clean','synthetic-only','1']);return {rows:[{state:'complete'}]};}};assert.deepEqual(await processOneScan(pool,root,()=>({outcome:'clean',sha256,engine:'synthetic-only',engineVersion:'1'})),{state:'complete',outcome:'clean'});assert.equal((await readdir(root)).length,1);});
test('no scanner gives unavailable, not clean',async t=>{const {root,receipt}=await fixture(t);const pool={async query(q,args){if(q.includes('claim_scan'))return {rows:[{object_key:receipt.objectKey,sha256,bytes:data.length,media_type:'application/pdf'}]};assert.deepEqual(args.slice(1),['unavailable',null,null]);return {rows:[{state:'queued'}]};}};assert.deepEqual(await processOneScan(pool,root,null),{state:'queued',outcome:'unavailable'});});
