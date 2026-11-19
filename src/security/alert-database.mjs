import {assertServiceLogin,validateServiceIdentity} from './service-login.mjs';
// Dedicated alert sender pool; never takes caller-controlled SQL.
export function createAlertDatabase(pool,{expectedLogin}={}){
 if(!pool||typeof pool.connect!=='function')throw Error('invalid alert pool');
 validateServiceIdentity('verivaro_alert_sender',expectedLogin);
 async function run(sql,values){
  const c=await pool.connect();let tx=false,clean=false;
  try{
   await c.query('DISCARD ALL');
   await assertServiceLogin(c,'verivaro_alert_sender',expectedLogin);
   await c.query('SET ROLE verivaro_alert_sender');
   await c.query('BEGIN ISOLATION LEVEL READ COMMITTED');tx=true;
   await c.query("SET LOCAL statement_timeout='3s'");
   await c.query("SET LOCAL lock_timeout='1s'");
   await c.query("SET LOCAL idle_in_transaction_session_timeout='5s'");
   const result=await c.query(sql,values);
   if(result.rows.length>1)throw Error('invalid outbox result');
   await c.query('COMMIT');tx=false;
   await c.query('DISCARD ALL');clean=true;
   return result.rows[0]??null;
  }catch{
   if(tx)try{await c.query('ROLLBACK');}catch{}
   throw Error('alert database failure');
  }finally{c.release(clean?undefined:new Error('discard alert connection'));}
 }
 return Object.freeze({
  claim:()=>run('SELECT * FROM verivaro_alerting.claim()'),
  async finish(event,outcome){
   const row=await run('SELECT verivaro_alerting.finish($1::bigint,$2::uuid,$3::text) AS ok',[event.event_id,event.claim_id,outcome]);
   return row?.ok===true;
  }
 });
}
