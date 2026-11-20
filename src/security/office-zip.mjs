import {inflateRawSync} from 'node:zlib';
import {crc32} from './evidence-formats.mjs';
const MAX_INPUT=256*1024,MAX_PART=256*1024,MAX_EXPANDED=1024*1024,MAX_ENTRIES=64;
const fail=()=>{throw Error('unsupported Office ZIP package');};
// Strict subset: single disk, known lengths, no descriptors/extra fields,
// encryption, comments, ZIP64, symlinks, directories or nested archives.
function safeName(raw){
 const name=raw.toString('ascii');
 if(!Buffer.from(name,'ascii').equals(raw)||name.length<1||name.length>180)return null;
 if(name.split('/').some(x=>!x||x==='.'||x==='..'||!/^[A-Za-z0-9_.\[\]-]+$/.test(x)))return null;
 if(!/\.(?:xml|rels)$/i.test(name))return null;
 return name;
}
export function readOfficeZip(archive){
 if(!Buffer.isBuffer(archive)||archive.length<22||archive.length>MAX_INPUT)fail();
 const end=archive.length-22;
 if(archive.readUInt32LE(end)!==0x06054b50||archive.readUInt16LE(end+4)!==0||archive.readUInt16LE(end+6)!==0||archive.readUInt16LE(end+20)!==0)fail();
 const count=archive.readUInt16LE(end+10),centralBytes=archive.readUInt32LE(end+12),centralStart=archive.readUInt32LE(end+16);
 if(count<1||count>MAX_ENTRIES||archive.readUInt16LE(end+8)!==count||centralStart<31||centralStart+centralBytes!==end)fail();
 let c=centralStart,p=0,total=0;
 const entries=[],names=new Set();
 try{
  for(let i=0;i<count;i++){
   if(c+46>end||archive.readUInt32LE(c)!==0x02014b50||p+30>centralStart||archive.readUInt32LE(p)!==0x04034b50)fail();
   const flags=archive.readUInt16LE(c+8),method=archive.readUInt16LE(c+10),crc=archive.readUInt32LE(c+16),compressed=archive.readUInt32LE(c+20),size=archive.readUInt32LE(c+24),n=archive.readUInt16LE(c+28),attr=archive.readUInt32LE(c+38),kind=(attr>>>16)&0xf000;
   if(![0,0x800].includes(flags)||![0,8].includes(method)||archive.readUInt16LE(c+6)>20||archive.readUInt16LE(c+30)!==0||archive.readUInt16LE(c+32)!==0||archive.readUInt16LE(c+34)!==0||archive.readUInt32LE(c+42)!==p||![0,0x8000].includes(kind)||(attr&0x10)!==0||n<1||n>180||c+46+n>end||size<1||size>MAX_PART||compressed<1||compressed>MAX_INPUT)fail();
   total+=size;if(total>MAX_EXPANDED||method===0&&compressed!==size)fail();
   const nameBytes=archive.subarray(c+46,c+46+n),name=safeName(nameBytes);
   if(!name||names.has(name.toLowerCase()))fail();
   const start=p+30+n,stop=start+compressed;
   if(stop>centralStart||archive.readUInt16LE(p+4)!==archive.readUInt16LE(c+6)||archive.readUInt16LE(p+6)!==flags||archive.readUInt16LE(p+8)!==method||archive.readUInt16LE(p+10)!==archive.readUInt16LE(c+12)||archive.readUInt16LE(p+12)!==archive.readUInt16LE(c+14)||archive.readUInt32LE(p+14)!==crc||archive.readUInt32LE(p+18)!==compressed||archive.readUInt32LE(p+22)!==size||archive.readUInt16LE(p+26)!==n||archive.readUInt16LE(p+28)!==0||!archive.subarray(p+30,start).equals(nameBytes))fail();
   let data;
   try{
    if(method===0)data=Buffer.from(archive.subarray(start,stop));
    else{const r=inflateRawSync(archive.subarray(start,stop),{maxOutputLength:size,info:true});data=r.buffer;if(r.engine.bytesWritten!==compressed)fail();}
    if(data.length!==size||crc32(data)!==crc)fail();
    entries.push([name,data]);data=null;
   }finally{data?.fill(0);}
   names.add(name.toLowerCase());p=stop;c+=46+n;
  }
  if(p!==centralStart||c!==end)fail();
  return new Map(entries);
 }catch(e){for(const [,data] of entries)data.fill(0);throw e;}
}
// Package preflight only; no XML parsing, source import or evidence admission.
// Callers must still validate XML schema, relationships and exact source spans.
export function preflightOfficePackage(archive,kind){
 if(!['docx','xlsx'].includes(kind))fail();
 const entries=readOfficeZip(archive);
 try{
  const required=kind==='docx'?['[Content_Types].xml','_rels/.rels','word/document.xml']:['[Content_Types].xml','_rels/.rels','xl/workbook.xml','xl/_rels/workbook.xml.rels','xl/worksheets/sheet1.xml'];
  const allowed=kind==='docx'?/^(?:\[Content_Types\]\.xml|_rels\/\.rels|docProps\/(?:core|app)\.xml|word\/(?:document|styles|numbering|settings|fontTable|webSettings)\.xml|word\/_rels\/document\.xml\.rels|word\/theme\/theme1\.xml)$/:/^(?:\[Content_Types\]\.xml|_rels\/\.rels|docProps\/(?:core|app)\.xml|xl\/(?:workbook|styles|sharedStrings)\.xml|xl\/_rels\/workbook\.xml\.rels|xl\/worksheets\/sheet(?:[1-9]|[1-5][0-9]|6[0-4])\.xml|xl\/theme\/theme1\.xml)$/;
  if(required.some(n=>!entries.has(n)))fail();
  for(const [name,bytes] of entries){
   if(!allowed.test(name))fail();
   const xml=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
   // Conservative lexical guard, not a substitute for a real XML parser.
   if(!xml.trimStart().startsWith('<')||/<!DOCTYPE|<!ENTITY|<!\[CDATA\[|<!--|<\?(?!xml(?:\s|\?))|[\x00-\x08\x0b\x0c\x0e-\x1f]/i.test(xml))fail();
   if(name.endsWith('.rels')&&(/TargetMode\s*=|&#|&[A-Za-z]+;|(?:https?|file|ftp):\/\/(?!schemas\.openxmlformats\.org\/)/i.test(xml)))fail();
  }
  return Object.freeze({kind,entries:Object.freeze([...entries].map(([name,b])=>Object.freeze({name,bytes:b.length}))),expandedBytes:[...entries.values()].reduce((n,b)=>n+b.length,0)});
 }finally{for(const data of entries.values())data.fill(0);}
}
