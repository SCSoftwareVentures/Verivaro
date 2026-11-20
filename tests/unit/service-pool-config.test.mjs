import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,chmod,symlink,rm} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {loadServicePoolConfig} from '../../src/security/service-pool-config.mjs';
import {assertServiceLogin,validateServiceIdentity} from '../../src/security/service-login.mjs';
test('fixed service role and pinned identity reject unsafe configuration and mismatched database response',async()=>{
 const role='verivaro_monitor_worker',calls=[];
 const client={query:async(sql,values)=>{calls.push({sql,values});return {rows:[{privileged:false,login_name:'wrong'}]};}};
 await assert.rejects(assertServiceLogin(client,role,'vv_worker'));
 assert.equal(calls[0].sql,'SET search_path TO pg_catalog');assert.deepEqual(calls[1].values,[role,'vv_worker']);
 assert.throws(()=>validateServiceIdentity('postgres','vv_worker'));assert.throws(()=>validateServiceIdentity(role,role));
});
test('private credentials only; loopback exception explicit; no environment TLS downgrade',async t=>{
 const root=await mkdtemp(join(tmpdir(),'vv-service-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const pw=join(root,'password'),link=join(root,'link'),secret=randomBytes(32).toString('base64url');
 await writeFile(pw,secret+'\n',{mode:0o600});await symlink(pw,link);
 const env={PGHOST:'127.0.0.1',PGUSER:'vv_worker',PGDATABASE:'verivaro_test',VV_DB_PASSWORD_FILE:pw,VV_ALLOW_LOCAL_PLAINTEXT:'1'};
 const role='verivaro_monitor_worker';
 const config=await loadServicePoolConfig({env,role});assert.equal(config.password,secret);assert.equal(config.ssl,false);assert.equal(config.user,'vv_worker');
 for(const bad of [{PGHOST:'db.example.invalid'},{PGPASSWORD:secret},{PGSSLMODE:'disable'},{NODE_TLS_REJECT_UNAUTHORIZED:'0'},{PGOPTIONS:'-c role=postgres'},{VV_DB_PASSWORD_FILE:link},{PGUSER:role},{VV_ALLOW_LOCAL_PLAINTEXT:undefined}])await assert.rejects(loadServicePoolConfig({role,env:{...env,...bad}}));
 await chmod(pw,0o644);await assert.rejects(loadServicePoolConfig({role,env}));
});
