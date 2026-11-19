import {createHmac} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const kinds=new Set(['access_denials','integrity_failure','resource_pressure','stranded_reservation','delivery_failures']);
export function createAlertTransport({endpoint,installationId,key,fetcher=fetch,now=Date.now}){
 const url=new URL(endpoint);
 if(url.protocol!=='https:'||url.username||url.password||url.hash||url.search||!uuid.test(installationId)||!Buffer.isBuffer(key)||key.length!==32||typeof fetcher!=='function')throw Error('invalid alert destination');
 // Endpoint is deployment-approved, never taken from incidents or HTTP input.
 const secret=Buffer.from(key),target=url.href;
 return async function deliver(e){
  const id=String(e.event_id);
  if(!/^[1-9][0-9]{0,18}$/.test(id)||!uuid.test(e.incident_id)||!kinds.has(e.kind)||!['critical','warning'].includes(e.severity)||!['opened','escalated'].includes(e.action))throw Error('invalid alert event');
  const timestamp=String(Math.floor(now()/1000)),deliveryId=installationId+':'+id;
  const body=JSON.stringify({version:1,delivery_id:deliveryId,incident_id:e.incident_id,kind:e.kind,severity:e.severity,action:e.action,occurred_at:new Date(e.occurred_at).toISOString()});
  const signature=createHmac('sha256',secret).update(timestamp+'.'+body).digest('hex');
  try{
   const response=await fetcher(target,{method:'POST',redirect:'error',signal:AbortSignal.timeout(5000),headers:{'Content-Type':'application/json','Idempotency-Key':deliveryId,'X-Verivaro-Timestamp':timestamp,'X-Verivaro-Signature':'sha256='+signature},body});
   // Never retain or log the remote response body.
   await response.body?.cancel();
   if(response.status>=200&&response.status<300)return 'accepted';
   return response.status===408||response.status===425||response.status===429||response.status>=500?'retry':'permanent';
  }catch{return 'retry';}
 };
}
export async function runAlertSender({db,deliver,signal,intervalMs=5000,report=()=>{}}){
 if(!db||typeof db.claim!=='function'||typeof db.finish!=='function'||typeof deliver!=='function'||!signal||!Number.isInteger(intervalMs)||intervalMs<10||intervalMs>60000)throw Error('invalid alert sender');
 while(!signal.aborted){
  try{
   const event=await db.claim();
   if(event){
    const outcome=await deliver(event);
    const recorded=await db.finish(event,outcome);
    report(recorded?'alert_attempt_recorded':'alert_claim_lost');
   }
  }catch{report('alert_worker_failed');}
  if(signal.aborted)break;
  try{await delay(intervalMs,undefined,{signal});}catch(e){if(e.name!=='AbortError')throw e;}
 }
}
