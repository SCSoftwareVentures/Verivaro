import test from 'node:test';
import assert from 'node:assert/strict';
import {runSecurityMonitor} from '../../src/security/monitor-worker.mjs';
test('worker retries failures sequentially and never reports sensitive error contents',async()=>{
 const ctrl=new AbortController(),events=[];let calls=0,active=0,peak=0;
 await runSecurityMonitor({signal:ctrl.signal,intervalMs:10,evaluate:async()=>{active++;peak=Math.max(peak,active);try{if(++calls===1)throw Error('private data');}finally{active--;}},report:x=>{events.push(x);if(events.length===3)ctrl.abort();}});
 assert.deepEqual(events,['monitor_evaluation_failed','monitor_evaluation_ok','monitor_evaluation_ok']);assert.equal(peak,1);
});
