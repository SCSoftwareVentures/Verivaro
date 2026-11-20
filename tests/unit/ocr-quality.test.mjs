import test from 'node:test';
import assert from 'node:assert/strict';
import {scoreOcrCases} from '../../src/security/ocr-quality.mjs';
test('perfect OCR returns zero CER/WER, exact identifiers and p95 latency',()=>{
 const x=scoreOcrCases([{id:'one',reference:'Valve V-204 must be checked.',observed:'Valve V-204 must be checked.',elapsedMs:15}]);
 assert.equal(x.characterErrorRate,0);assert.equal(x.wordErrorRate,0);assert.equal(x.criticalIdentifierRecall,1);assert.equal(x.exactLineRate,1);assert.equal(x.elapsedMs.p95,15);
});
test('edit distance and duplicate critical IDs count missing OCR digits',()=>{
 const x=scoreOcrCases([{id:'a',reference:'ID 42 42 must comply.',observed:'ID 42 is missing.',elapsedMs:2}]);
 assert.equal(x.criticalIdentifierRecall,0.5);assert.ok(x.wordErrorRate>0);assert.ok(x.characterErrorRate>0);assert.equal(x.exactLineRate,0);
});
test('Unicode whitespace normalization and percentile values are deterministic',()=>{
 const x=scoreOcrCases([{id:'a',reference:'A  B\nC',observed:'A B C',elapsedMs:4},{id:'b',reference:'Valve V-5',observed:'Valve V-6',elapsedMs:12}]);
 assert.equal(x.exactLineRate,0.5);assert.equal(x.criticalIdentifierRecall,0);assert.equal(x.elapsedMs.p50,4);assert.equal(x.elapsedMs.p95,12);
});
test('reject invalid, oversized, duplicate and control-containing benchmark samples',()=>{
 const good={id:'a',reference:'A',observed:'A',elapsedMs:0};
 for(const rows of [[],[{...good,reference:' '}],[{...good,observed:'x'.repeat(1025)}],[good,good],[{...good,elapsedMs:-1}],[{...good,reference:'a\u0000b'}],Array(33).fill(null)])assert.throws(()=>scoreOcrCases(rows));
});
