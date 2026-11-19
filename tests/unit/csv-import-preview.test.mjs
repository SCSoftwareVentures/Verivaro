import test from 'node:test';
import assert from 'node:assert/strict';
import {previewRequirementCsv} from '../../src/security/csv-import-preview.mjs';
const mapping={title:'Name',criterion:'Rule',applicability:'Type'},preview=s=>previewRequirementCsv(Buffer.from(s),mapping);
test('explicit mapping, quoted commas and invalid rows reconciled without writes',()=>{const p=preview('Name,Rule,Type\r\nA,"x, y",required\r\nB,z,bad\r\nA,"x, y",required\r\nC,z\r\n');assert.equal(p.rows,4);assert.equal(p.accepted.length,1);assert.equal(p.accepted[0].criterion,'x, y');assert.equal(p.errors.length,3);assert.equal(p.writes,0);});
test('reject malformed syntax, duplicate headers, missing maps and oversized data',()=>{for(const s of ['Name,Rule,Type\nA,"x,required','Name,Name,Type\nA,x,required','Name,Rule,Other\nA,x,required','Name,Rule,Type\n'+ 'x'.repeat(262144)])assert.throws(()=>preview(s));});
