import {setTimeout as delay} from 'node:timers/promises';
// Sequential evaluations, no overlapping ticks or unbounded retry queue.
export async function runSecurityMonitor({evaluate,signal,intervalMs=60000,report=()=>{}}){
 if(typeof evaluate!=='function'||!signal||!Number.isSafeInteger(intervalMs)||intervalMs<10||intervalMs>300000||typeof report!=='function')throw Error('invalid monitor worker');
 while(!signal.aborted){
  try{
   await evaluate();
   report('monitor_evaluation_ok');
  }catch{
   report('monitor_evaluation_failed');
  }
  if(signal.aborted)break;
  try{await delay(intervalMs,undefined,{signal});}
  catch(e){if(e.name!=='AbortError')throw e;}
 }
}
