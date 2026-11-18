import test from 'node:test';
import assert from 'node:assert/strict';
import {createUploadQueue} from '../../packages/web/upload-queue.mjs';
const job={intentId:'u',documentId:'d',title:'Test',newDocument:true,sha256:'a'.repeat(64),mediaType:'text/plain',file:new Blob(['test'])};
test('lost document response replays exact IDs; lost upload response replays same intent',async()=>{
 const q=createUploadQueue();q.enqueue(job);const calls=[];let failAt=1;
 const send=async(path,body,raw)=>{calls.push({path,body,raw});if(calls.length===failAt)throw Error('connection lost');return {state:'quarantined'};};
 await assert.rejects(q.flush('u',send));assert.equal(q.list()[0].stage,'queued');failAt=4;await assert.rejects(q.flush('u',send));assert.deepEqual(calls[0],calls[1]);assert.equal(q.list()[0].stage,'intent-acknowledged');await q.flush('u',send);assert.equal(calls[3].path,calls[4].path);assert.equal(calls[3].raw,calls[4].raw);assert.equal(q.list().length,0);
});
test('session close stops multi-stage replay and clears files',async()=>{const q=createUploadQueue();q.enqueue(job);let calls=0;await assert.rejects(q.flush('u',async()=>{calls++;q.close();return {};}),/closed/);assert.equal(calls,1);assert.equal(q.list().length,0);assert.throws(()=>q.enqueue(job));});
test('queue limit, no raw file in visible listing, no false completion',async()=>{const q=createUploadQueue({maxBytes:4,maxItems:1});q.enqueue(job);assert.equal(q.list()[0].file,undefined);assert.throws(()=>q.enqueue({...job,intentId:'v'}));await assert.rejects(q.flush('u',async()=>({state:'pending'})));assert.equal(q.list()[0].stage,'intent-acknowledged');q.discard('u');assert.equal(q.list().length,0);});
