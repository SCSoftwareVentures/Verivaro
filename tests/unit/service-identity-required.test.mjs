import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createScopedDatabase} from '../../src/security/scoped-database.mjs';
import {createShareResolver} from '../../src/security/share-resolver.mjs';
import {createDistributedAdmission} from '../../src/security/distributed-admission.mjs';
import {createMonitorDatabase} from '../../src/security/monitor-database.mjs';
import {createAlertDatabase} from '../../src/security/alert-database.mjs';
test('all five adapters reject missing or non-string pinned login before checkout',()=>{
 const pool={connect(){throw Error('must not connect');}},key=randomBytes(32);
 for(const expectedLogin of [undefined,null,1,'postgres;','verivaro_runtime']){
  for(const make of [
   ()=>createScopedDatabase(pool,{verifier:{},key,expectedLogin}),
   ()=>createShareResolver(pool,{expectedLogin}),
   ()=>createDistributedAdmission(pool,{peerKey:key,expectedLogin}),
   ()=>createMonitorDatabase(pool,{mode:'worker',expectedLogin}),
   ()=>createAlertDatabase(pool,{expectedLogin})
  ])assert.throws(make,/invalid service identity/);
 }
});
