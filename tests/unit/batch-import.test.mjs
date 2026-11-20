import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {safeImportPath,planBatchImport} from '../../src/security/batch-import.mjs';
const digest=b=>createHash('sha256').update(b).digest('hex');
const file=(name,path='',type='text/plain')=>Object.assign(new Blob(['same bytes'],{type}),{name,webkitRelativePath:path});
test('folder lineage is data only; traversal and control names rejected',()=>{assert.equal(safeImportPath('x.txt','folder/x.txt'),true);for(const p of ['../x.txt','/x.txt','C:/x.txt','a\\x.txt','a//x.txt','a/./x.txt','a/\u202ex.txt','a/ x.txt'])assert.equal(safeImportPath('x.txt',p),false);});
test('duplicates preserve distinct request IDs and source counts; unsupported remains visible',async()=>{const p=await planBatchImport([file('a.txt','one/a.txt'),file('a.txt','two/a.txt'),file('bad.exe','','application/octet-stream')],{digest,randomId:randomUUID});assert.equal(p.rows.length,3);assert.equal(p.rows[1].duplicate,true);assert.notEqual(p.rows[0].requestId,p.rows[1].requestId);assert.equal(p.rows[2].state,'unsupported');await assert.rejects(planBatchImport(Array(13).fill(file('x.txt')),{digest,randomId:randomUUID}));});
