import {inflateSync} from 'node:zlib';
const signature=Buffer.from([137,80,78,71,13,10,26,10]);
const crcTable=Array.from({length:256},(_,i)=>{let c=i;for(let j=0;j<8;j++)c=c&1?0xedb88320^(c>>>1):c>>>1;return c>>>0;});
export function crc32(b){let c=0xffffffff;for(const v of b)c=crcTable[(c^v)&255]^(c>>>8);return (c^0xffffffff)>>>0;}
export const TYPES=Object.freeze(['text/plain; charset=utf-8','image/png','application/pdf']);
export function validatePng(b){
 if(!b.subarray(0,8).equals(signature))throw Error('invalid PNG');
 let pos=8,w,h,channels,phase=0,idat=[],size=0;
 while(pos<b.length){
  if(pos+12>b.length)throw Error('truncated PNG');
  const n=b.readUInt32BE(pos),end=pos+12+n;
  if(end>b.length||crc32(b.subarray(pos+4,end-4))!==b.readUInt32BE(end-4))throw Error('invalid PNG chunk');
  const type=b.toString('ascii',pos+4,pos+8),d=b.subarray(pos+8,end-4);
  if(type==='IHDR'&&phase===0&&n===13){
   w=d.readUInt32BE(0);h=d.readUInt32BE(4);channels=d[9]===2?3:d[9]===6?4:0;
   if(!w||!h||w>2048||h>2048||w*h>1048576||d[8]!==8||!channels||d[10]||d[11]||d[12])throw Error('unsupported PNG');
   phase=1;
  }else if(type==='IDAT'&&(phase===1||phase===2)&&n>0){phase=2;idat.push(d);size+=n;if(idat.length>128)throw Error('too many PNG chunks');}
  else if(type==='IEND'&&phase===2&&n===0&&end===b.length){phase=3;pos=end;break;}
  else throw Error('unsupported PNG chunk');
  pos=end;
 }
 if(phase!==3||pos!==b.length)throw Error('incomplete PNG');
 const stride=w*channels+1,expected=stride*h;
 const {buffer,engine}=inflateSync(Buffer.concat(idat,size),{maxOutputLength:expected,info:true});
 if(buffer.length!==expected||engine.bytesWritten!==size)throw Error('invalid PNG pixels');
 for(let i=0;i<buffer.length;i+=stride)if(buffer[i]>4)throw Error('invalid PNG filter');
 return b;
}
// Deliberately narrow canonical PDF subset: one page, Helvetica, plain ASCII
// text only. Exact reconstruction also verifies all object/xref offsets.
// General PDF, attachments, images, compressed streams and active content reject.
export function canonicalTextPdf(lines){
 if(!Array.isArray(lines)||lines.length<1||lines.length>40||lines.some(x=>typeof x!=='string'||!/^[A-Za-z0-9 .,!?_:;@+\/-]{1,90}$/.test(x)))throw Error('unsupported PDF text');
 const stream='BT\n/F1 12 Tf\n50 750 Td\n'+lines.map((s,i)=>(i?'0 -16 Td\n':'')+'('+s+') Tj\n').join('')+'ET\n';
 const objs=['<< /Type /Catalog /Pages 2 0 R >>','<< /Type /Pages /Kids [3 0 R] /Count 1 >>','<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>','<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>','<< /Length '+Buffer.byteLength(stream)+' >>\nstream\n'+stream+'endstream'];
 let out='%PDF-1.4\n',offsets=[];
 for(let i=0;i<objs.length;i++){offsets.push(Buffer.byteLength(out));out+=(i+1)+' 0 obj\n'+objs[i]+'\nendobj\n';}
 const xref=Buffer.byteLength(out);
 out+='xref\n0 6\n0000000000 65535 f \n'+offsets.map(x=>String(x).padStart(10,'0')+' 00000 n \n').join('')+'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n'+xref+'\n%%EOF\n';
 return Buffer.from(out);
}
export function validatePdf(b){
 if(b.length>16384)throw Error('unsupported PDF size');
 const s=b.toString('latin1'),matches=[...s.matchAll(/^\(([A-Za-z0-9 .,!?_:;@+\/-]{1,90})\) Tj$/gm)].map(x=>x[1]);
 if(!canonicalTextPdf(matches).equals(b))throw Error('unsupported PDF structure');
 return b;
}
