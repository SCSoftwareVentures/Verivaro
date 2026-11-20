import test from 'node:test';
import assert from 'node:assert/strict';
import {createClamdScanner} from '../../src/security/clamd-scanner.mjs';
if(!process.env.VV_REAL_CLAMD_SOCKET)throw Error('real clamd fixture required');
test('actual ClamAV daemon detects harmless antivirus test signature and accepts clean bytes',async()=>{
 const scan=createClamdScanner({socketPath:process.env.VV_REAL_CLAMD_SOCKET,timeoutMs:10000}),signal=new AbortController().signal;
 const eicar=Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
 assert.equal(eicar.length,68);
 assert.equal(await scan(Buffer.from('Verivaro clean evidence fixture'),signal),'clean');
 assert.equal(await scan(eicar,signal),'infected');
 console.log('actual_clamd_engine_detection_gate_passed');
});
