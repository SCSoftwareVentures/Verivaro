import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac,randomBytes,randomUUID} from 'node:crypto';
import {createAlertTransport,runAlertSender} from '../../src/security/alert-sender.mjs';
const event={event_id:'1',incident_id:randomUUID(),kind:'integrity_failure',severity:'critical',action:'opened',occurred_at:new Date()};
test('configured HTTPS destination, stable idempotency key, signed minimal payload, no redirects',async()=>{
 const key=randomBytes(32),installationId=randomUUID(),calls=[];
 const deliver=createAlertTransport({endpoint:'https://alerts.example.invalid/receiver',installationId,key,now:()=>1700000000000,fetcher:async(url,options)=>{calls.push({url,options});return {status:200};}});
 assert.equal(await deliver({...event,token:'not part of payload'}),'accepted');assert.equal(await deliver(event),'accepted');
 const {url,options}=calls[0];assert.equal(url,'https://alerts.example.invalid/receiver');assert.equal(options.redirect,'error');
 assert.equal(options.headers['Idempotency-Key'],installationId+':1');
 assert.equal(calls[1].options.headers['Idempotency-Key'],options.headers['Idempotency-Key']);
 assert.equal(options.headers['X-Verivaro-Signature'],'sha256='+createHmac('sha256',key).update('1700000000.'+options.body).digest('hex'));
 assert.equal(JSON.parse(options.body).token,undefined);
 for(const endpoint of ['http://example.invalid','https://name:pass@example.invalid','https://example.invalid/?extra=yes'])assert.throws(()=>createAlertTransport({endpoint,installationId,key}));
});
test('retry classification and sender loop records outcomes; failures do not leak',async()=>{
 const key=randomBytes(32),installationId=randomUUID();
 for(const [status,result] of [[204,'accepted'],[429,'retry'],[503,'retry'],[400,'permanent'],[302,'permanent']]){
  const deliver=createAlertTransport({endpoint:'https://example.invalid/',installationId,key,fetcher:async()=>({status})});
  assert.equal(await deliver(event),result);
 }
 const ctrl=new AbortController(),reports=[],finished=[];
 let attempts=0;
 await runAlertSender({db:{claim:async()=>{if(++attempts===1)throw Error('sensitive');return event;},finish:async(e,o)=>{finished.push(o);return true;}},deliver:async()=> 'retry',signal:ctrl.signal,intervalMs:10,report:x=>{reports.push(x);if(reports.length===2)ctrl.abort();}});
 assert.deepEqual(reports,['alert_worker_failed','alert_attempt_recorded']);assert.deepEqual(finished,['retry']);
});
