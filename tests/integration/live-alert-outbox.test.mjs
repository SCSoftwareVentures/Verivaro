import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomUUID,randomBytes} from 'node:crypto';
import {createAlertDatabase} from '../../src/security/alert-database.mjs';
import {createAlertTransport} from '../../src/security/alert-sender.mjs';
if(process.env.PGDATABASE!=='verivaro_test'||process.env.VV_LIVE_TEST!=='1'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_ALERT_A_PASSWORD||!process.env.VV_ALERT_B_PASSWORD)throw Error('disposable CI required');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const config={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:2,connectionTimeoutMillis:3000};
test('durable alert claims, fenced retries, terminal failures and controlled incident resolution',{timeout:30000},async()=>{
 const admin=new Pool({...config,user:process.env.PGUSER,password:process.env.PGPASSWORD});
 const pa=new Pool({...config,user:'vv_ci_alert_a',password:process.env.VV_ALERT_A_PASSWORD}),pb=new Pool({...config,user:'vv_ci_alert_b',password:process.env.VV_ALERT_B_PASSWORD});
 const a=createAlertDatabase(pa,{expectedLogin:'vv_ci_alert_a'}),b=createAlertDatabase(pb,{expectedLogin:'vv_ci_alert_b'});
 const i=randomUUID();
 try{
  await admin.query("INSERT INTO verivaro_private.security_incidents(id,kind,severity,closed_at) VALUES($1,'delivery_failures','warning',clock_timestamp())",[i]);
  // All queue fixtures are synthetic; explicitly isolate from previous monitor tests.
  await admin.query('DELETE FROM verivaro_private.alert_outbox');
  await admin.query("INSERT INTO verivaro_private.security_incident_events(incident_id,action) VALUES($1,'opened')",[i]);
  const claims=await Promise.all([a.claim(),b.claim()]);
  assert.equal(claims.filter(Boolean).length,1);
  const first=claims.find(Boolean),owner=claims[0]?a:b,other=claims[0]?b:a;
  assert.equal(first.attempt,1);assert.equal(await other.finish(first,'accepted'),false);
  assert.equal(await owner.finish(first,'retry'),true);assert.equal(await owner.finish(first,'retry'),false);assert.equal(await a.claim(),null);
  await admin.query("UPDATE verivaro_private.alert_outbox SET next_at=clock_timestamp()-interval '1 second' WHERE event_id=$1",[first.event_id]);
  const second=await other.claim();assert.equal(second.event_id,first.event_id);assert.notEqual(second.claim_id,first.claim_id);assert.equal(second.attempt,2);
  assert.equal(await owner.finish(first,'accepted'),false);
  await admin.query("UPDATE verivaro_private.alert_outbox SET claim_until=clock_timestamp()-interval '1 second' WHERE event_id=$1",[first.event_id]);
  const third=await owner.claim();assert.equal(third.attempt,3);assert.equal(await other.finish(second,'accepted'),false);
  const received=[];
  const deliver=createAlertTransport({endpoint:'https://alerts.example.invalid/receiver',installationId:randomUUID(),key:randomBytes(32),fetcher:async(u,o)=>{received.push(JSON.parse(o.body));return {status:204};}});
  assert.equal(await owner.finish(third,await deliver(third)),true);assert.equal(received.length,1);assert.equal(await b.claim(),null);
  const dead=(await admin.query("INSERT INTO verivaro_private.security_incident_events(incident_id,action) VALUES($1,'escalated') RETURNING id",[i])).rows[0].id;
  await admin.query('UPDATE verivaro_private.alert_outbox SET attempts=4 WHERE event_id=$1',[dead]);
  const last=await a.claim();assert.equal(last.attempt,5);assert.equal(await a.finish(last,'retry'),true);assert.equal(await b.claim(),null);
  const health=(await admin.query('SELECT * FROM verivaro_monitor.alert_delivery_health()')).rows[0];
  assert.equal(health.delivered,'1');assert.equal(health.dead,'1');
  assert.equal((await admin.query('SELECT count(*)::int AS n FROM verivaro_private.alert_outbox')).rows[0].n,2);
  await assert.rejects(pa.query('SELECT * FROM verivaro_private.alert_outbox'),e=>e.code==='42501');
  await assert.rejects(pa.query('SELECT verivaro_monitor.resolve_incident(NULL,NULL,NULL)'),e=>e.code==='42501');
  const incident=(await admin.query("SELECT id FROM verivaro_private.security_incidents WHERE closed_at IS NULL AND acknowledged_at IS NULL LIMIT 1")).rows[0].id;
  const op=await admin.connect();
  try{
   await op.query('SET ROLE verivaro_incident_operator');
   await assert.rejects(op.query('SELECT verivaro_monitor.close_incident($1)',[incident]),e=>e.code==='42501');
   const ref=randomUUID();
   assert.equal((await op.query("SELECT verivaro_monitor.resolve_incident($1,$2,'remediated') AS ok",[incident,ref])).rows[0].ok,false);
   assert.equal((await op.query('SELECT verivaro_monitor.acknowledge($1) AS ok',[incident])).rows[0].ok,true);
   assert.equal((await op.query("SELECT verivaro_monitor.resolve_incident($1,$2,'remediated') AS ok",[incident,ref])).rows[0].ok,true);
   assert.equal((await op.query("SELECT verivaro_monitor.resolve_incident($1,$2,'remediated') AS ok",[incident,ref])).rows[0].ok,false);
  }finally{op.release(true);}
  assert.equal((await admin.query('SELECT count(*)::int AS n FROM verivaro_private.incident_resolutions WHERE incident_id=$1',[incident])).rows[0].n,1);
 }finally{await pa.end();await pb.end();await admin.end();}
});
