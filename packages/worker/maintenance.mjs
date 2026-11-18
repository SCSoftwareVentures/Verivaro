import {randomUUID} from 'node:crypto';
import {removeAbandonedObject,scanQuarantine} from '../security/quarantine.mjs';
/** Run once per scheduler tick with dedicated recovery credentials. No implicit background execution. */
export async function recoverBatch(pool,root,batch=50){
 if(!Number.isSafeInteger(batch)||batch<1||batch>100)throw Error('invalid batch');
 const {rows}=await pool.query('SELECT * FROM vv_api.recover_files($1)',[batch]);let removed=0,missing=0,failed=0;
 for(const row of rows){try{if(await removeAbandonedObject(root,row.object_key))removed++;else missing++;}catch{failed++;}}
 return {selected:rows.length,removed,missing,failed};
}
/** Claim durable job, verify bytes again, report the leased scan result. Missing scanner fails closed. */
export async function processOneScan(pool,root,scanner,{timeoutMs=10000}={}){
 const token=randomUUID();
 const {rows}=await pool.query('SELECT * FROM vv_api.claim_scan($1)',[token]);
 if(rows.length===0)return {state:'idle'};
 if(rows.length!==1)throw Error('invalid job response');
 const r=rows[0];let verdict;
 try{verdict=await scanQuarantine(root,{objectKey:r.object_key,sha256:r.sha256,bytes:Number(r.bytes),mediaType:r.media_type,state:'quarantined'},scanner,{timeoutMs});}
 catch{verdict={outcome:'unavailable',engine:null,engineVersion:null};}
 const finished=await pool.query('SELECT vv_api.finish_scan($1,$2,$3,$4) AS state',[token,verdict.outcome,verdict.engine,verdict.engineVersion]);
 return {state:finished.rows[0].state,outcome:verdict.outcome};
}
