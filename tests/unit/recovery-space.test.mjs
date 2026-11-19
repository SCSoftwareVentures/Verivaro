import test from 'node:test';
import assert from 'node:assert/strict';
import {requireRecoverySpace} from '../../src/security/recovery-space.mjs';
test('recovery storage preflight fails closed with low space, nonsensical stats and inspection error',async()=>{
 const inspect=async()=>({bavail:10n,bsize:4096n});
 await requireRecoverySpace('/fixture',40960,{minimumFreeBytes:0,inspect});
 await assert.rejects(requireRecoverySpace('/fixture',40961,{minimumFreeBytes:0,inspect}));
 await assert.rejects(requireRecoverySpace('/fixture',1,{inspect}));
 await assert.rejects(requireRecoverySpace('/fixture',1,{inspect:async()=>({bavail:-1n,bsize:4096n})}));
 await assert.rejects(requireRecoverySpace('/fixture',1,{inspect:async()=>{throw Error('fixture');}}));
});
