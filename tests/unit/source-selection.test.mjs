import test from 'node:test';
import assert from 'node:assert/strict';
import {selectedSpan,selectedAmount,currentSources,textareaSpan} from '../../packages/web/source-selection.mjs';
const page={page:1,text_value:'📄 AUD 1250.00 due',text_sha256:'a'.repeat(64)};
test('UTF16 selection produces exact Unicode code point offsets',()=>{const s=selectedSpan(page,3,14);assert.deepEqual(s,{page:1,start:2,end:13,quote:'AUD 1250.00',textSha256:page.text_sha256});assert.equal(selectedAmount(s),'1250.00');});
test('reject surrogate splits, invalid bounds, empty and nonliteral amounts',()=>{assert.throws(()=>selectedSpan(page,1,4));assert.throws(()=>selectedSpan(page,0,300));assert.throws(()=>selectedSpan(page,2,3));assert.throws(()=>selectedAmount({quote:'$1,250'}));assert.throws(()=>selectedAmount({quote:'AUD 1.0'}));});
test('only current canonical reviewed source selectable',()=>{const c={documents:[{id:'d',title:'Doc',currentVersionId:'v2',uploads:[{id:'a',state:'reviewed',versionId:'v1'},{id:'b',state:'reviewed',versionId:'v2'},{id:'c',state:'extraction-complete',versionId:'v2'}]}]};assert.deepEqual(currentSources(c),[{versionId:'v2',documentId:'d',title:'Doc',uploadId:'b'}]);});

test('browser CRLF normalization retains original canonical offsets and text',()=>{const p={...page,text_value:'Header\r\n📄 AUD 1250.00\rTail'},display='Header\n📄 AUD 1250.00\nTail',s=textareaSpan(p,display,10,21);assert.equal(s.quote,'AUD 1250.00');assert.equal(s.start,10);assert.equal(s.end,21);assert.equal(textareaSpan(p,display,5,9).quote,'r\r\n📄');});
