import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {createServer} from 'node:http';
import {createMonitorDatabase} from '../../src/security/monitor-database.mjs';
import {runSecurityMonitor} from '../../src/security/monitor-worker.mjs';
import {createMonitorDashboard} from '../../src/security/monitor-dashboard.mjs';
if(process.env.PGDATABASE!=='verivaro_test'||process.env.VV_LIVE_TEST!=='1'||!process.env.VV_TEST_DRIVER_DIR||!process.env.VV_MONITOR_WORKER_PASSWORD||!process.env.VV_MONITOR_READER_PASSWORD)throw Error('disposable CI required');
const {Pool}=createRequire(resolve(process.env.VV_TEST_DRIVER_DIR,'package.json'))('pg');
const config={host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,max:2,connectionTimeoutMillis:3000,idleTimeoutMillis:5000};
test('live monitor worker, read-only dashboard, stable alert IDs and stale health', {timeout:30000},async()=>{
 const admin=new Pool({...config,user:process.env.PGUSER,password:process.env.PGPASSWORD});
 const wp=new Pool({...config,user:'vv_ci_monitor_worker',password:process.env.VV_MONITOR_WORKER_PASSWORD});
 const rp=new Pool({...config,user:'vv_ci_monitor_reader',password:process.env.VV_MONITOR_READER_PASSWORD});
 const worker=createMonitorDatabase(wp,{mode:'worker',expectedLogin:'vv_ci_monitor_worker'}),reader=createMonitorDatabase(rp,{mode:'reader',expectedLogin:'vv_ci_monitor_reader'});
 let server;
 try{
  const ctrl=new AbortController(),reports=[];
  await runSecurityMonitor({evaluate:worker.evaluate,signal:ctrl.signal,intervalMs:10,report:x=>{reports.push(x);if(reports.length===2)ctrl.abort();}});
  assert.deepEqual(reports,['monitor_evaluation_ok','monitor_evaluation_ok']);
  const first=await reader.snapshot();
  assert.ok(first.health.evaluated_at);assert.ok(first.incidents.length>=4);assert.ok(first.alerts.length>=4);
  await worker.evaluate();const second=await reader.snapshot();
  assert.deepEqual(second.alerts.map(x=>x.event_id),first.alerts.map(x=>x.event_id));
  const password=randomBytes(32).toString('base64url');
  const authorization='Basic '+Buffer.from('operator:'+password).toString('base64');
  server=createServer(createMonitorDashboard({snapshot:reader.snapshot,password}));
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const url='http://127.0.0.1:'+server.address().port+'/';
  assert.equal((await fetch(url)).status,401);
  const res=await fetch(url,{headers:{authorization}});assert.equal(res.status,200);assert.match(res.headers.get('cache-control'),/no-store/);
  const html=await res.text();assert.match(html,/CRITICAL INCIDENTS OPEN/);assert.match(html,/Internal alert inbox/);assert.doesNotMatch(html,/vv_ci_admission_a/);
  assert.equal((await fetch(url,{method:'POST',headers:{authorization}})).status,404);
  await admin.query("UPDATE verivaro_private.monitor_state SET evaluated_at=clock_timestamp()-interval '10 minutes'");
  const stale=await fetch(url,{headers:{authorization}});assert.equal(stale.status,503);assert.match(await stale.text(),/MONITOR STALE/);
  await assert.rejects(rp.query('SELECT verivaro_monitor.evaluate()'),e=>e.code==='42501');
  await assert.rejects(rp.query('SELECT verivaro_monitor.close_incident(NULL)'),e=>e.code==='42501');
  await assert.rejects(rp.query('SELECT * FROM verivaro_private.security_incident_events'),e=>e.code==='42501');
  await assert.rejects(wp.query('SELECT * FROM verivaro_monitor.recent_alerts()'),e=>e.code==='42501');
 }finally{
  if(server)await new Promise(r=>{server.closeAllConnections();server.close(r);});
  await admin.end();await wp.end();await rp.end();
 }
});
