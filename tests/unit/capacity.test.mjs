import test from 'node:test';
import assert from 'node:assert/strict';
import {createCapabilityGate,CapacityError} from '../../packages/security/capacity.mjs';
test('capacity rejects excess work and frees slots after errors',async()=>{let finish;const gate=createCapabilityGate({maxConcurrent:1,maxPerMinute:8});const first=gate(()=>new Promise(r=>{finish=r;}));await assert.rejects(gate(()=>1),CapacityError);finish(2);assert.equal(await first,2);await assert.rejects(gate(()=>{throw Error('failure');}));assert.equal(await gate(()=>3),3);});
test('request budget resets after one minute and counts failed operations',async()=>{let now=0;const gate=createCapabilityGate({maxConcurrent:1,maxPerMinute:2,clock:()=>now});await assert.rejects(gate(()=>{throw Error('failure');}));assert.equal(await gate(()=>1),1);await assert.rejects(gate(()=>2),CapacityError);now=60000;assert.equal(await gate(()=>3),3);});
