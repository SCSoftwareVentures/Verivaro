import test from 'node:test';
import assert from 'node:assert/strict';
import {apiPeer} from '../../src/security/api-admission.mjs';
test('API peer normalization aggregates IPv6 subnet and mapped IPv4',()=>{
 assert.equal(apiPeer('::ffff:192.0.2.5'),'192.0.2.5');
 assert.equal(apiPeer('2001:db8:abcd:1::2'),apiPeer('2001:db8:abcd:1:abcd:ef01:2345:6789'));
 assert.notEqual(apiPeer('2001:db8:abcd:1::2'),apiPeer('2001:db8:abcd:2::2'));
 assert.equal(apiPeer('spoofed'),'unknown');
});
