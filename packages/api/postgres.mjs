import pg from 'pg';
import {createService} from './service.mjs';
const {Pool}=pg;
/** Explicit, independent credentials from operator. No implicit env/URL fallback. */
export function createPostgresService({database,issuerConfig,keyId,quarantineRoot,now,releaseSigning,downloadScanner,intelligenceProvider}){
 const entries=['runtime','signer','worker',...(database?.capability?['capability']:[])].map(role=>database?.[role]);
 if(entries.some(c=>!c||typeof c.user!=='string'||!c.user||typeof c.password!=='string'||!c.password||typeof c.host!=='string'||!c.host||typeof c.database!=='string'||!c.database||!Number.isSafeInteger(c.port)||c.port<1||c.port>65535)||new Set(entries.map(c=>c.user)).size!==entries.length)throw Error('distinct explicit database identities required');
 const allowed=new Set(['host','port','database','user','password','ssl']);
 if(entries.some(c=>Object.keys(c).some(k=>!allowed.has(k))))throw Error('unsupported database configuration');
 const pools=entries.map(c=>new Pool({...c,max:4,connectionTimeoutMillis:5000,idleTimeoutMillis:10000,statement_timeout:10000,query_timeout:12000,application_name:'verivaro'}));
 // Avoid exposing idle connection error details; subsequent operations fail closed.
 for(const pool of pools)pool.on('error',()=>{});
 const service=createService({runtimePool:pools[0],signerPool:pools[1],workerPool:pools[2],issuerConfig,keyId,quarantineRoot,capabilityPool:pools[3],releaseSigning,downloadScanner,intelligenceProvider,...(now?{now}:{})});
 return {service,close:()=>Promise.all(pools.map(p=>p.end()))};
}
