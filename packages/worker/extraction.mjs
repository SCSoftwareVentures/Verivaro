import {randomUUID} from 'node:crypto';
import {readVerifiedQuarantine} from '../security/quarantine.mjs';
/** First deterministic extraction adapter: exact UTF-8 text only. No AI, no inference, no release. */
export async function processOneExtraction(pool,root){
 const token=randomUUID();
 const {rows}=await pool.query('SELECT * FROM vv_api.claim_extract($1)',[token]);
 if(rows.length===0)return {state:'idle'};
 if(rows.length!==1)throw Error('invalid extraction job');
 const r=rows[0];let result='unavailable',content=null;
 if(r.media_type!=='text/plain'||Number(r.bytes)>1048576)result='unsupported';
 else try{
  const bytes=await readVerifiedQuarantine(root,{objectKey:r.object_key,sha256:r.sha256,bytes:Number(r.bytes),mediaType:r.media_type,state:'quarantined'},{maxBytes:1048576});
  const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
  if(!text.includes('\0')&&Buffer.from(text,'utf8').equals(bytes)){content=text;result='complete';}
 }catch{}
 const finished=await pool.query('SELECT vv_api.finish_extract($1,$2,$3) AS state',[token,result,content]);
 return {state:finished.rows[0].state};
}
