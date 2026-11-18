import test from 'node:test';
import assert from 'node:assert/strict';
import {labelFor,parseLabel,qrMatrix} from '../../packages/web/qr-label.mjs';
const uid='00000000-0000-0000-0000-000000000001';
test('QR label is a strict revision pointer, not arbitrary URL or credential',()=>{const s=labelFor(uid,2147483647);assert.deepEqual(parseLabel(s),{milestoneId:uid,milestoneRevision:2147483647});assert.throws(()=>parseLabel('https://example.com'));assert.throws(()=>parseLabel('VV1:'+uid+':0'));assert.equal(qrMatrix(s).length,29);assert.throws(()=>labelFor(uid,2147483648));});
