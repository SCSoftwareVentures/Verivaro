/** Session-only queue: no durable browser storage, no credentials, no implicit retries.
 * Replays exact document and intent IDs after ambiguous network failures.
 * Caller must discard the queue on scope/account change.
 */
export function createUploadQueue({maxItems=5,maxBytes=50*1024*1024}={}){
 const jobs=new Map();let active=false,closed=false;
 function guard(){if(closed)throw Error('Upload queue closed.');}
 function enqueue(j){
 guard();
 if(active||jobs.has(j.intentId)||jobs.size>=maxItems||!j.file||!Number.isSafeInteger(j.file.size)||j.file.size<1||j.file.size+[...jobs.values()].reduce((n,x)=>n+x.file.size,0)>maxBytes)throw Error('Session capture limit reached.');
 jobs.set(j.intentId,{...j,stage:'queued'});return j.intentId;
 }
 function list(){return [...jobs.values()].map(({file,...j})=>({...j,bytes:file.size}));}
 function discard(k){guard();if(active)throw Error('Upload is in progress.');jobs.delete(k);}
 function close(){closed=true;jobs.clear();}
 async function flush(k,send){
 guard();if(active)throw Error('Upload in progress.');
 const j=jobs.get(k);if(!j)throw Error('Capture not found.');
 active=true;const safe=async(path,body,raw)=>{guard();const result=await send(path,body,raw);guard();return result;};
 try{
 // Stage changes only after an acknowledged server response. If response is lost, replay same IDs.
 if(j.stage==='queued'){if(j.newDocument)await safe('/documents',{id:j.documentId,title:j.title});j.stage='document-acknowledged';}
 if(j.stage==='document-acknowledged'){await safe('/documents/'+j.documentId+(j.milestoneId?'/milestone-uploads':'/uploads'),{id:j.intentId,sha256:j.sha256,bytes:j.file.size,mediaType:j.mediaType,...(j.milestoneId?{milestoneId:j.milestoneId,milestoneRevision:j.milestoneRevision}:{})});j.stage='intent-acknowledged';}
 if(j.stage==='intent-acknowledged'){const r=await safe('/uploads/'+j.intentId,undefined,j.file);if(r?.state!=='quarantined')throw Error('Quarantine not acknowledged.');jobs.delete(k);}
 return {state:'quarantined'};
 }finally{active=false;}
 }
 return {enqueue,list,discard,close,flush,snapshot:()=>{guard();return [...jobs.values()].map(({stage,...j})=>({...j}));}};
}
