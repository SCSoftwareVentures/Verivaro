import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import {createVerificationExport,createVerificationPdf} from '../../src/security/verification-report-export.mjs';
const digest=b=>createHash('sha256').update(b).digest('hex');
function fixture(n=1){
 const d='2026-11-19T00:00:00.000Z',evidence=Array.from({length:n},()=>({id:randomUUID(),sha256:'a'.repeat(64),registeredAt:d,bytes:1,mediaType:'text/plain; charset=utf-8',scanPolicy:'clamd-instream-format-v2',storage:'encrypted'}));
 return {version:1,generatedAt:d,tenantId:randomUUID(),project:{id:randomUUID(),name:'Project (A) \\ /JavaScript café',revision:0,archivedAt:null},summary:{evidence:n,encrypted:n,bytes:n,requests:0,states:{}},evidence,reviews:[],attestation:'unsigned database snapshot; not an independently signed custody checkpoint'};
}
function checkPdf(b){
 const s=b.toString('ascii');assert.ok(s.startsWith('%PDF-1.4\n'));assert.ok(s.endsWith('%%EOF\n'));const x=Number(/startxref\n(\d+)\n/.exec(s)[1]);assert.equal(s.slice(x,x+4),'xref');
 const entries=s.slice(x).split('\n'),count=Number(entries[1].split(' ')[1]);for(let i=1;i<count;i++){const offset=Number(entries[2+i].slice(0,10));assert.ok(s.slice(offset).startsWith(i+' 0 obj\n'));}
 for(const m of s.matchAll(/<< \/Length (\d+) >>\nstream\n([\s\S]*?)endstream/g))assert.equal(Buffer.byteLength(m[2]),Number(m[1]));
 assert.doesNotMatch(s,/\/(?:OpenAction|JavaScript|Launch|EmbeddedFile)\s+<</);
 return s;
}
test('professional PDF is bounded, deterministic, escaped and complete',()=>{
 const report=fixture(70),h=digest(Buffer.from(JSON.stringify(report))),b=createVerificationPdf(report,h),s=checkPdf(b);
 assert.ok(b.equals(createVerificationPdf(report,h)));assert.ok(s.includes(h));assert.ok(s.includes('UNSIGNED DATABASE SNAPSHOT'));assert.ok(s.includes('\\\\'));assert.ok(s.includes('\\(A\\)'));assert.ok(s.includes('[U+00E9]'));
 for(const e of report.evidence)assert.ok(s.includes(e.id));
 assert.ok(Number(/\/Type \/Pages \/Count (\d+)/.exec(s)[1])>3);
 assert.throws(()=>createVerificationExport({...report,summary:{...report.summary,evidence:0}},'pdf'));
 assert.throws(()=>createVerificationExport({...report,evidence:[...report.evidence,report.evidence[0]]},'zip'));
});
test('portable package contains one exact snapshot, PDF, manifest and verifiable hashes',()=>{
 const report=fixture(),archive=createVerificationExport(report,'zip'),files=new Map();let p=0;
 while(archive.readUInt32LE(p)===0x04034b50){
  const n=archive.readUInt16LE(p+26),size=archive.readUInt32LE(p+18),name=archive.toString('ascii',p+30,p+30+n),data=archive.subarray(p+30+n,p+30+n+size);assert.equal(archive.readUInt16LE(p+8),0);files.set(name,data);p+=30+n+size;
 }
 assert.equal(archive.readUInt32LE(p),0x02014b50);assert.equal(archive.readUInt32LE(archive.length-22),0x06054b50);
 assert.deepEqual([...files.keys()],['verification.json','verification.pdf','manifest.json']);assert.deepEqual(JSON.parse(files.get('verification.json')),report);
 const m=JSON.parse(files.get('manifest.json'));for(const x of m.files){assert.equal(x.sha256,digest(files.get(x.name)));assert.equal(x.bytes,files.get(x.name).length);}
 assert.ok(checkPdf(files.get('verification.pdf')).includes(digest(files.get('verification.json'))));
});
test('maximum supported evidence count paginates without missing IDs or excessive size',()=>{
 const report=fixture(4096),b=createVerificationExport(report,'pdf');assert.ok(b.length<8*1024*1024);const s=checkPdf(b);assert.ok(s.includes(report.evidence.at(-1).id));
});
