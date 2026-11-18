import test from 'node:test';
import assert from 'node:assert/strict';
import {proposeRequirements,suggestMatches} from '../../packages/domain/proposals.mjs';
const p={page:2,text_value:'📄 note\r\nSerial MUST be ABC-123\r\nA suggestion',text_sha256:'a'.repeat(64),method:'ocr'};
test('proposal preserves exact code-point offsets, page and unreviewed status',()=>{const r=proposeRequirements([p]);assert.equal(r.candidates.length,1);const c=r.candidates[0];assert.equal([...p.text_value].slice(c.start,c.end).join(''),c.quote);assert.equal(c.page,2);assert.equal(c.state,'needs-review');});
test('literal matches do not assert approved evidence',()=>{const r=suggestMatches([p],'ABC-123');assert.equal(r.matches.length,1);assert.equal(r.matches[0].state,'needs-review');assert.equal(suggestMatches([p],'ABC-124').matches.length,0);});
test('limits proposals and flags truncation',()=>assert.equal(proposeRequirements([{...p,text_value:'Must provide certificate\n'.repeat(201)}]).truncated,true));
