import {canonicalScannedPdf,readCanonicalScannedPdf,packCanonicalRaster} from './scanned-pdf.mjs';
const MAX=262144,MAX_PAGES=4,MAX_TOTAL_PIXELS=2097152;
const deny=()=>{throw Error('unsupported multipage image-only PDF');};
const imageHeader=/4 0 obj\n<< \/Type \/XObject \/Subtype \/Image \/Width ([1-9][0-9]{0,3}) \/Height ([1-9][0-9]{0,3}) \/ColorSpace \/DeviceRGB \/BitsPerComponent 8 \/Filter \/FlateDecode \/Length ([1-9][0-9]{0,5}) >>\nstream\n/;
function content(w,h){return 'q\n'+w+' 0 0 '+h+' 0 0 cm\n/Im0 Do\nQ\n';}
function pack(pages){
 if(!Array.isArray(pages)||pages.length<2||pages.length>MAX_PAGES||pages.reduce((n,p)=>n+p.w*p.h,0)>MAX_TOTAL_PIXELS)deny();
 const kids=pages.map((_,i)=>(3+i*3)+' 0 R').join(' '),objects=['<< /Type /Catalog /Pages 2 0 R >>','<< /Type /Pages /Kids ['+kids+'] /Count '+pages.length+' >>'];
 for(let i=0;i<pages.length;i++){
  const {w,h,payload}=pages[i],pid=3+i*3,imageId=pid+1,contentId=pid+2;
  if(!Number.isInteger(w)||!Number.isInteger(h)||w<1||h<1||w>2048||h>2048||w*h>1048576||!Buffer.isBuffer(payload)||payload.length<1||payload.length>MAX)deny();
  const draw=content(w,h);
  objects.push('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 '+w+' '+h+'] /Resources << /XObject << /Im0 '+imageId+' 0 R >> >> /Contents '+contentId+' 0 R >>');
  objects.push('<< /Type /XObject /Subtype /Image /Width '+w+' /Height '+h+' /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length '+payload.length+' >>\nstream\n'+payload.toString('latin1')+'\nendstream');
  objects.push('<< /Length '+draw.length+' >>\nstream\n'+draw+'endstream');
 }
 let doc='%PDF-1.4\n',offsets=[];for(let i=0;i<objects.length;i++){offsets.push(doc.length);doc+=(i+1)+' 0 obj\n'+objects[i]+'\nendobj\n';}
 const xref=doc.length,count=objects.length+1;
 doc+='xref\n0 '+count+'\n0000000000 65535 f \n'+offsets.map(o=>String(o).padStart(10,'0')+' 00000 n \n').join('')+'trailer\n<< /Size '+count+' /Root 1 0 R >>\nstartxref\n'+xref+'\n%%EOF\n';
 const result=Buffer.from(doc,'latin1');if(result.length>MAX)deny();return result;
}
export function canonicalMultipageScannedPdf(pngs){
 if(!Array.isArray(pngs)||pngs.length<2||pngs.length>MAX_PAGES)deny();
 const pages=pngs.map(png=>{
  const single=canonicalScannedPdf(png),scan=readCanonicalScannedPdf(single);
  try{
   const m=imageHeader.exec(single.toString('latin1'));if(!m)deny();
   const start=m.index+m[0].length,n=Number(m[3]);
   return {w:scan.width,h:scan.height,payload:Buffer.from(single.subarray(start,start+n))};
  }finally{scan.png.fill(0);}
 });
 try{return pack(pages);}finally{for(const p of pages)p.payload.fill(0);}
}
export function readCanonicalMultipageScannedPdf(pdf,{page=1}={}){
 if(!Buffer.isBuffer(pdf)||pdf.length<1||pdf.length>MAX||!Number.isInteger(page)||page<1||page>MAX_PAGES)deny();
 const s=pdf.toString('latin1'),top=/^%PDF-1\.4\n1 0 obj\n<< \/Type \/Catalog \/Pages 2 0 R >>\nendobj\n2 0 obj\n<< \/Type \/Pages \/Kids \[([0-9 R]+)\] \/Count ([2-4]) >>\nendobj\n/.exec(s);
 if(!top)deny();const count=Number(top[2]),kids=Array.from({length:count},(_,i)=>(3+3*i)+' 0 R').join(' ');
 if(top[1]!==kids||page>count)deny();
 const pages=[];let at=top[0].length;
 for(let i=0;i<count;i++){
  const pid=3+3*i,imageId=pid+1,contentId=pid+2;
  const first=/^([1-9][0-9]{0,2}) 0 obj\n<< \/Type \/Page \/Parent 2 0 R \/MediaBox \[0 0 ([1-9][0-9]{0,3}) ([1-9][0-9]{0,3})\] \/Resources << \/XObject << \/Im0 ([1-9][0-9]{0,2}) 0 R >> >> \/Contents ([1-9][0-9]{0,2}) 0 R >>\nendobj\n/.exec(s.slice(at));
  if(!first||Number(first[1])!==pid||Number(first[4])!==imageId||Number(first[5])!==contentId)deny();
  at+=first[0].length;const w=Number(first[2]),h=Number(first[3]);
  const head=/^([1-9][0-9]{0,2}) 0 obj\n<< \/Type \/XObject \/Subtype \/Image \/Width ([1-9][0-9]{0,3}) \/Height ([1-9][0-9]{0,3}) \/ColorSpace \/DeviceRGB \/BitsPerComponent 8 \/Filter \/FlateDecode \/Length ([1-9][0-9]{0,5}) >>\nstream\n/.exec(s.slice(at));
  if(!head||Number(head[1])!==imageId||Number(head[2])!==w||Number(head[3])!==h)deny();
  at+=head[0].length;const n=Number(head[4]);if(n<1||n>MAX||at+n>pdf.length)deny();
  const payload=Buffer.from(pdf.subarray(at,at+n));at+=n;
  const tail='\nendstream\nendobj\n'+contentId+' 0 obj\n<< /Length '+content(w,h).length+' >>\nstream\n'+content(w,h)+'endstream\nendobj\n';
  if(s.slice(at,at+tail.length)!==tail)deny();
  at+=tail.length;pages.push({w,h,payload});
 }
 let selected;
 try{
  if(!pack(pages).equals(pdf))deny();
  for(let i=0;i<count;i++){
   const p=pages[i],one=packCanonicalRaster(p.w,p.h,p.payload),verified=readCanonicalScannedPdf(one);
   if(i===page-1)selected=verified;
   else verified.png.fill(0);
  }
  return {...selected,page,pageCount:count,format:'bounded-multipage-image-pdf-v1'};
 }catch(e){selected?.png?.fill(0);throw e;}
 finally{for(const p of pages)p.payload.fill(0);}
}
