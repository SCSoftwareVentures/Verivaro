import {inflateSync,deflateSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {crc32,validatePng} from './evidence-formats.mjs';
const SIG=Buffer.from([137,80,78,71,13,10,26,10]),LIMIT=262144,MAX_PIXELS=1048576;
const fail=()=>{throw Error('unsupported image-only PDF');};
const sha=b=>createHash('sha256').update(b).digest('hex');
function chunk(type,data){
 const tag=Buffer.from(type,'ascii'),size=Buffer.alloc(4),crc=Buffer.alloc(4);
 size.writeUInt32BE(data.length);crc.writeUInt32BE(crc32(Buffer.concat([tag,data])));
 return Buffer.concat([size,tag,data,crc]);
}
function rasterToPng(rgb,w,h){
 const stride=w*3,filtered=Buffer.alloc(h*(stride+1));
 try{
  for(let y=0;y<h;y++)rgb.copy(filtered,y*(stride+1)+1,y*stride,(y+1)*stride);
  const header=Buffer.alloc(13);header.writeUInt32BE(w,0);header.writeUInt32BE(h,4);header[8]=8;header[9]=2;
  const png=Buffer.concat([SIG,chunk('IHDR',header),chunk('IDAT',deflateSync(filtered,{level:6})),chunk('IEND',Buffer.alloc(0))]);
  if(png.length>LIMIT)fail();validatePng(png);return png;
 }finally{filtered.fill(0);}
}
function fromPng(png){
 validatePng(png);if(png.length>LIMIT||png[25]!==2)fail();
 const w=png.readUInt32BE(16),h=png.readUInt32BE(20),stride=w*3;
 if(w*h>MAX_PIXELS||w>2048||h>2048)fail();
 let i=8,parts=[],size=0;
 while(i<png.length){const len=png.readUInt32BE(i),type=png.toString('ascii',i+4,i+8);
  if(type==='IDAT'){const piece=png.subarray(i+8,i+8+len);parts.push(piece);size+=len;}
  i+=len+12;
 }
 const {buffer,engine}=inflateSync(Buffer.concat(parts,size),{maxOutputLength:(stride+1)*h,info:true});
 try{
  if(engine.bytesWritten!==size||buffer.length!==(stride+1)*h)fail();
  const rgb=Buffer.alloc(stride*h);
  for(let y=0;y<h;y++){if(buffer[y*(stride+1)]!==0){rgb.fill(0);fail();}buffer.copy(rgb,y*stride,y*(stride+1)+1,(y+1)*(stride+1));}
  return {w,h,rgb};
 }finally{buffer.fill(0);}
}
export function packCanonicalRaster(w,h,compressed){
 if(!Number.isSafeInteger(w)||!Number.isSafeInteger(h)||w<1||h<1||w>2048||h>2048||w*h>MAX_PIXELS||!Buffer.isBuffer(compressed)||compressed.length<1||compressed.length>LIMIT)fail();
 const content='q\n'+w+' 0 0 '+h+' 0 0 cm\n/Im0 Do\nQ\n',encoded=compressed.toString('latin1');
 const objects=[
  '<< /Type /Catalog /Pages 2 0 R >>',
  '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
  '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 '+w+' '+h+'] /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>',
  '<< /Type /XObject /Subtype /Image /Width '+w+' /Height '+h+' /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length '+compressed.length+' >>\nstream\n'+encoded+'\nendstream',
  '<< /Length '+content.length+' >>\nstream\n'+content+'endstream'
 ];
 let out='%PDF-1.4\n';const offsets=[];
 for(let i=0;i<objects.length;i++){offsets.push(out.length);out+=(i+1)+' 0 obj\n'+objects[i]+'\nendobj\n';}
 const xref=out.length;
 out+='xref\n0 6\n0000000000 65535 f \n'+offsets.map(x=>String(x).padStart(10,'0')+' 00000 n \n').join('')+'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n'+xref+'\n%%EOF\n';
 const result=Buffer.from(out,'latin1');if(result.length>LIMIT)fail();return result;
}
// Canonical single-page RGB-only producer. Does not accept ordinary PDFs.
export function canonicalScannedPdf(png){
 if(!Buffer.isBuffer(png)||png.length<1||png.length>LIMIT)fail();
 const {w,h,rgb}=fromPng(png);
 try{return packCanonicalRaster(w,h,deflateSync(rgb,{level:6}));}finally{rgb.fill(0);}
}
export function readCanonicalScannedPdf(pdf){
 if(!Buffer.isBuffer(pdf)||pdf.length<1||pdf.length>LIMIT)fail();
 const s=pdf.toString('latin1'),m=/^%PDF-1\.4\n1 0 obj\n<< \/Type \/Catalog \/Pages 2 0 R >>\nendobj\n2 0 obj\n<< \/Type \/Pages \/Kids \[3 0 R\] \/Count 1 >>\nendobj\n3 0 obj\n<< \/Type \/Page \/Parent 2 0 R \/MediaBox \[0 0 ([1-9][0-9]{0,3}) ([1-9][0-9]{0,3})\] \/Resources << \/XObject << \/Im0 4 0 R >> >> \/Contents 5 0 R >>\nendobj\n4 0 obj\n<< \/Type \/XObject \/Subtype \/Image \/Width ([1-9][0-9]{0,3}) \/Height ([1-9][0-9]{0,3}) \/ColorSpace \/DeviceRGB \/BitsPerComponent 8 \/Filter \/FlateDecode \/Length ([1-9][0-9]{0,5}) >>\nstream\n/.exec(s);
 if(!m||m[1]!==m[3]||m[2]!==m[4])fail();
 const w=Number(m[1]),h=Number(m[2]),n=Number(m[5]),start=m[0].length,end=start+n;
 if(w>2048||h>2048||w*h>MAX_PIXELS||n>LIMIT||end>pdf.length||s.slice(end,end+18)!=='\nendstream\nendobj\n')fail();
 const compressed=pdf.subarray(start,end);
 if(!packCanonicalRaster(w,h,compressed).equals(pdf))fail(); // all objects, offsets and bytes, no active extras
 const {buffer,engine}=inflateSync(compressed,{maxOutputLength:w*h*3,info:true});
 try{
  if(buffer.length!==w*h*3||engine.bytesWritten!==n)fail();
  const png=rasterToPng(buffer,w,h);return {page:1,width:w,height:h,png,rasterSha256:sha(png),format:'bounded-image-pdf-v1'};
 }finally{buffer.fill(0);}
}
