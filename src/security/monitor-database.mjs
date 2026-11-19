// Fixed role and operation surface; dedicated pool per process.
export function createMonitorDatabase(pool,{mode}){
 if(!pool||typeof pool.connect!=='function'||!['worker','reader'].includes(mode))throw Error('invalid monitor database');
 const role=mode==='worker'?'verivaro_monitor_worker':'verivaro_monitor_reader';
 async function run(operation){
  const c=await pool.connect();let tx=false,clean=false;
  try{
   await c.query('DISCARD ALL');
   const login=await c.query("SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication AS privileged FROM pg_catalog.pg_roles WHERE rolname=session_user");
   if(login.rows.length!==1||login.rows[0].privileged!==false)throw Error('unsafe login');
   await c.query('SET ROLE '+role);
   await c.query(mode==='reader'?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN ISOLATION LEVEL READ COMMITTED');tx=true;
   await c.query("SET LOCAL statement_timeout='3s'");
   await c.query("SET LOCAL lock_timeout='1s'");
   await c.query("SET LOCAL idle_in_transaction_session_timeout='5s'");
   let result;
   if(operation==='evaluate'&&mode==='worker'){
    const r=await c.query('SELECT verivaro_monitor.evaluate() AS opened');
    result=r.rows[0]?.opened;
    if(!Number.isInteger(result)||result<0||result>5)throw Error('invalid evaluation');
   }else if(operation==='snapshot'&&mode==='reader'){
    const h=await c.query('SELECT * FROM verivaro_monitor.health()');
    const i=await c.query('SELECT * FROM verivaro_monitor.list_open()');
    const a=await c.query('SELECT * FROM verivaro_monitor.recent_alerts()');
    if(h.rows.length!==1||i.rows.length>5||a.rows.length>50)throw Error('invalid snapshot');
    result={health:h.rows[0],incidents:i.rows,alerts:a.rows};
   }else throw Error('invalid monitor operation');
   await c.query('COMMIT');tx=false;
   await c.query('DISCARD ALL');clean=true;
   return result;
  }catch{
   if(tx)try{await c.query('ROLLBACK');}catch{}
   throw Error('monitor database operation failed');
  }finally{c.release(clean?undefined:new Error('discard monitor connection'));}
 }
 return Object.freeze(mode==='worker'?{evaluate:()=>run('evaluate')}:{snapshot:()=>run('snapshot')});
}
