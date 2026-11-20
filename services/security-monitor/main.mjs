import {loadServicePoolConfig} from '../../src/security/service-pool-config.mjs';
import {createAlertDatabase} from '../../src/security/alert-database.mjs';
import {createAlertTransport,runAlertSender} from '../../src/security/alert-sender.mjs';
import {createRequire} from 'node:module';
import {createServer} from 'node:http';
import {createMonitorDatabase} from '../../src/security/monitor-database.mjs';
import {runSecurityMonitor} from '../../src/security/monitor-worker.mjs';
import {createMonitorDashboard} from '../../src/security/monitor-dashboard.mjs';
const mode=process.argv[2];
if(!['worker','reader','alerts'].includes(mode)||!process.env.PGUSER||!process.env.PGDATABASE||!process.env.PGHOST)throw Error('explicit monitor database configuration required');
const {Pool}=createRequire(new URL('./driver/package.json',import.meta.url))('pg');
const role=mode==='alerts'?'verivaro_alert_sender':mode==='worker'?'verivaro_monitor_worker':'verivaro_monitor_reader';
const settings=await loadServicePoolConfig({role,max:mode==='worker'?1:2});
const expectedLogin=settings.user;
const pool=new Pool(settings);
pool.on('error',()=>process.stderr.write('monitor_idle_connection_failed\n'));
const db=mode==='alerts'?createAlertDatabase(pool,{expectedLogin}):createMonitorDatabase(pool,{mode,expectedLogin});
const controller=new AbortController();
let server;
const stop=()=>{controller.abort();server?.close();};
process.once('SIGTERM',stop);process.once('SIGINT',stop);
try{
 if(mode==='worker')await runSecurityMonitor({evaluate:db.evaluate,signal:controller.signal,report:x=>process.stdout.write(x+'\n')});
 else if(mode==='alerts'){
  if(process.env.VV_ALERTS_ENABLED!=='1')throw Error('explicit alert activation required');
  const raw=process.env.VV_ALERT_HMAC_KEY??'';
  const key=Buffer.from(raw,'base64url');
  if(key.length!==32||key.toString('base64url')!==raw)throw Error('invalid alert credential');
  const deliver=createAlertTransport({endpoint:process.env.VV_ALERT_ENDPOINT,installationId:process.env.VV_INSTALLATION_ID,key});
  key.fill(0);
  await runAlertSender({db,deliver,signal:controller.signal,report:x=>process.stdout.write(x+'\n')});
 }else{
  const port=Number(process.env.VV_MONITOR_PORT??'8787');
  if(!Number.isInteger(port)||port<1024||port>65535)throw Error('invalid dashboard port');
  server=createServer({requestTimeout:10000,headersTimeout:5000,keepAliveTimeout:2000,maxHeaderSize:4096},createMonitorDashboard({snapshot:db.snapshot,password:process.env.VV_MONITOR_PASSWORD}));
  await new Promise((r,j)=>{server.once('error',j);server.once('close',r);server.listen(port,'127.0.0.1');if(controller.signal.aborted)server.close();});
 }
}finally{await pool.end();}
