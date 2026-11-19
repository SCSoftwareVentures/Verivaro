import {assertServiceLogin,validateServiceIdentity} from './service-login.mjs';
const role='verivaro_identity_service';
export function createIdentityDatabase(pool,{expectedLogin}={}){
 validateServiceIdentity(role,expectedLogin);
 if(typeof pool?.connect!=='function')throw Error('invalid identity pool');
 async function run(sql,values){
  const c=await pool.connect();let tx=false,clean=false;
  try{
   await c.query('DISCARD ALL');await assertServiceLogin(c,role,expectedLogin);
   await c.query('SET ROLE '+role);await c.query('BEGIN ISOLATION LEVEL READ COMMITTED');tx=true;
   await c.query("SET LOCAL statement_timeout='5s'");await c.query("SET LOCAL lock_timeout='2s'");await c.query("SET LOCAL idle_in_transaction_session_timeout='10s'");
   const result=await c.query(sql,values);if(result.rows.length!==1)throw Error('unexpected identity result');
   await c.query('COMMIT');tx=false;await c.query('DISCARD ALL');clean=true;return result.rows[0];
  }catch{if(tx)try{await c.query('ROLLBACK');}catch{}throw Error('identity operation denied');}
  finally{c.release(clean?undefined:new Error('discard identity lease'));}
 }
 return Object.freeze({
  async begin(nonce,binding,issuer,audience){return (await run('SELECT verivaro_identity.begin_login($1,$2,$3,$4) AS ok',[nonce,binding,issuer,audience])).ok===true;},
  async redeem({nonce,binding,issuer,audience,subjectDigest,sessionId,authenticatedAt,expiresAt}){
   const r=await run('SELECT verivaro_identity.redeem_login($1,$2,$3,$4,$5,$6,$7,$8) AS actor_id',[nonce,binding,issuer,audience,subjectDigest,sessionId,new Date(authenticatedAt*1000),new Date(expiresAt*1000)]);
   return r.actor_id;
  },
  async storeFlow(s,c,e){return (await run('SELECT verivaro_identity.store_browser_flow($1,$2,$3) AS ok',[s,c,e])).ok===true;},
  async takeFlow(s,c){return (await run('SELECT verivaro_identity.take_browser_flow($1,$2) AS envelope',[s,c])).envelope;},
  async storeBrowserSession(h,s,e){return (await run('SELECT verivaro_identity.store_browser_session($1,$2,$3) AS ok',[h,s,e])).ok===true;},
  async readBrowserSession(h){return (await run('SELECT verivaro_identity.read_browser_session($1) AS envelope',[h])).envelope;},
  async logoutBrowser(h){return (await run('SELECT verivaro_identity.logout_browser($1) AS ok',[h])).ok===true;},
  async revoke(actor,session){return (await run('SELECT verivaro_identity.revoke_session($1,$2) AS ok',[actor,session])).ok===true;}
 });
}
