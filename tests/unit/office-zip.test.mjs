import test from 'node:test';
import assert from 'node:assert/strict';
import {deflateRawSync} from 'node:zlib';
import {crc32} from '../../src/security/evidence-formats.mjs';
import {zip} from '../../src/security/verification-report-export.mjs';
import {createRegisterXlsx} from '../../src/security/xlsx-register.mjs';
import {readOfficeZip,preflightOfficePackage} from '../../src/security/office-zip.mjs';
// Independent ZIP producer for both STORE and raw DEFLATE.
function fixture(parts,method=8){
 const local=[],central=[];let offset=0,cs=0;
 for(const [name,value] of parts){
  const data=Buffer.from(value),n=Buffer.from(name),encoded=method===8?deflateRawSync(data):data,h=Buffer.alloc(30),c=Buffer.alloc(46),crc=crc32(data);
  h.writeUInt32LE(0x04034b50);h.writeUInt16LE(20,4);h.writeUInt16LE(method,8);h.writeUInt32LE(crc,14);h.writeUInt32LE(encoded.length,18);h.writeUInt32LE(data.length,22);h.writeUInt16LE(n.length,26);
  c.writeUInt32LE(0x02014b50);c.writeUInt16LE(20,4);c.writeUInt16LE(20,6);c.writeUInt16LE(method,10);c.writeUInt32LE(crc,16);c.writeUInt32LE(encoded.length,20);c.writeUInt32LE(data.length,24);c.writeUInt16LE(n.length,28);c.writeUInt32LE(offset,42);
  local.push(h,n,encoded);central.push(c,n);offset+=h.length+n.length+encoded.length;cs+=c.length+n.length;
 }
 const e=Buffer.alloc(22);e.writeUInt32LE(0x06054b50);e.writeUInt16LE(parts.length,8);e.writeUInt16LE(parts.length,10);e.writeUInt32LE(cs,12);e.writeUInt32LE(offset,16);return Buffer.concat([...local,...central,e]);
}
const parts=[['[Content_Types].xml','<Types/>'],['_rels/.rels','<Relationships/>'],['word/document.xml','<document>Original</document>']];
test('bounded ZIP reader accepts ordinary stored and compressed structures and returns exact bytes',()=>{
 for(const method of [0,8]){const map=readOfficeZip(fixture(parts,method));assert.deepEqual([...map].map(([n,b])=>[n,b.toString()]),parts);}
 assert.equal(preflightOfficePackage(fixture(parts),'docx').entries.length,3);
 assert.equal(preflightOfficePackage(createRegisterXlsx([['A']],[['B']]),'xlsx').entries.length,6);
});
test('fails closed for path traversal, case aliases, non-XML parts, extra data, mismatched records and archive limits',()=>{
 const good=fixture(parts),central=good.readUInt32LE(good.length-6);
 const tamper=(fn)=>{const b=Buffer.from(good);fn(b);return b;};
 for(const bad of [fixture([['../evil.xml','x']]),fixture([['A.xml','x'],['a.xml','y']]),fixture([['word/vbaProject.bin','x']]),fixture([['a.xml','x'.repeat(262145)]]),fixture(Array.from({length:5},(_,i)=>['a'+i+'.xml','x'.repeat(240000)])),fixture(Array.from({length:65},(_,i)=>['a'+i+'.xml','x'])),Buffer.concat([good,Buffer.from('tail')]),tamper(b=>b.writeUInt16LE(1,central+8)),tamper(b=>b.writeUInt32LE(0xa0000000,central+38)),tamper(b=>b.writeUInt32LE(1,central+42)),tamper(b=>b.writeUInt32LE(0,14)),tamper(b=>b[30]^=1)])assert.throws(()=>readOfficeZip(b));
});
test('preflight refuses wrong package type, embedded payloads and dangerous XML constructs',()=>{
 assert.throws(()=>preflightOfficePackage(fixture(parts),'xlsx'));
 for(const extras of [[['word/embeddings/object.xml','<x/>']],[['word/_rels/document.xml.rels','<Relationship TargetMode="External" Target="https://example.com"/>']],[['word/styles.xml','<!DOCTYPE x [<!ENTITY y SYSTEM "file:///etc/passwd">]><x/>']],[['word/styles.xml','<x><![CDATA[bad]]></x>']]])assert.throws(()=>preflightOfficePackage(fixture([...parts,...extras]),'docx'));
 const external=zip(parts.map(([n,s])=>[n,Buffer.from(s)]));assert.equal(preflightOfficePackage(external,'docx').kind,'docx');
});
