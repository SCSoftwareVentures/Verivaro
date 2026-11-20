import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {isAbsolute} from 'node:path';
import {canonicalScannedPdf,canonicalPngFromRgb,readCanonicalScannedPdf} from './scanned-pdf.mjs';
import {canonicalMultipageScannedPdf,readCanonicalMultipageScannedPdf} from './scanned-pdf-multipage.mjs';
const reject=()=>{throw Error('external PDF normalization denied');};
const hash=b=>createHash('sha256').update(b).digest('hex');
export const PDF_NORMALIZER_MAX_SOURCE=262144;
export const PDF_NORMALIZER_MAX_PAGES=4;
export const PDF_NORMALIZER_MAX_RASTER=720;
const maxOutput=PDF_NORMALIZER_MAX_RASTER*PDF_NORMALIZER_MAX_RASTER*3+128;
const header=/^%PDF-1\.[0-7]\r?\n/;
function requiredField(s,label){
 const matches=[...s.matchAll(new RegExp('^'+label+':\\s*([^\\r\\n]+)$','gm'))];
 if(matches.length!==1)reject();
 return matches[0][1].trim();
}
export function inspectPdfInfo(report){
 if(!Buffer.isBuffer(report)||report.length<50||report.length>8192)reject();
 const content=new TextDecoder('utf-8',{fatal:true}).decode(report);
 if(!/^[\x09\x0a\x0d\x20-\x7e]*$/.test(content))reject();
 const pages=requiredField(content,'Pages'),encrypted=requiredField(content,'Encrypted'),javascript=requiredField(content,'JavaScript');
 if(!/^[1-4]$/.test(pages)||!/^no(?:\s|$)/.test(encrypted)||javascript!=='no')reject();
 return Number(pages);
}
export function ppmToCanonicalPng(ppm){
 if(!Buffer.isBuffer(ppm)||ppm.length<12||ppm.length>maxOutput)reject();
 const match=/^P6\n([1-9][0-9]{0,3}) ([1-9][0-9]{0,3})\n255\n/.exec(ppm.subarray(0,64).toString('latin1'));
 if(!match)reject();
 const width=Number(match[1]),height=Number(match[2]),start=match[0].length;
 if(width>PDF_NORMALIZER_MAX_RASTER||height>PDF_NORMALIZER_MAX_RASTER||width*height>PDF_NORMALIZER_MAX_RASTER**2||ppm.length-start!==width*height*3)reject();
 const rgb=Buffer.from(ppm.subarray(start));
 try{return {width,height,png:canonicalPngFromRgb(rgb,width,height)};}
 finally{rgb.fill(0);}
}
function execute(executable,args,input,{signal,timeoutMs,maxBytes}){
 if(signal.aborted)reject();
 return new Promise((resolve,rejectPromise)=>{
  let child;try{child=spawn(executable,args,{cwd:'/',shell:false,env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',LC_ALL:'C',HOME:'/nonexistent',OMP_THREAD_LIMIT:'1'},stdio:['pipe','pipe','ignore']});}
  catch{rejectPromise(Error('PDF renderer unavailable'));return;}
  let buffers=[],size=0,failure=null,ended=false;
  const stop=error=>{failure??=error;child.kill('SIGKILL');};
  const abort=()=>stop(Error('PDF renderer cancelled')),timer=setTimeout(()=>stop(Error('PDF renderer deadline')),timeoutMs);timer.unref();
  signal.addEventListener('abort',abort,{once:true});if(signal.aborted)abort();
  child.stdout.on('data',part=>{size+=part.length;if(size>maxBytes){stop(Error('PDF renderer output exceeded'));return;}buffers.push(Buffer.from(part));});
  child.stdin.on('error',()=>stop(Error('PDF renderer input rejected')));
  child.once('error',()=>stop(Error('PDF renderer unavailable')));
  child.once('close',code=>{
   if(ended)return;ended=true;clearTimeout(timer);signal.removeEventListener('abort',abort);
   let out;try{if(!failure&&code===0&&size>0)out=Buffer.concat(buffers,size);}
   finally{for(const b of buffers)b.fill(0);buffers=[];}
   if(failure||code!==0||!out)rejectPromise(failure??Error('PDF renderer failed'));else resolve(out);
  });
  child.stdin.end(input);
 });
}
// Run this only as a non-root, network-isolated, resource-capped conversion worker.
// Passing arguments through a shell or running it in the application process is unsafe.
export function createOfflinePoppler({pdfinfoPath='/usr/bin/pdfinfo',pdftoppmPath='/usr/bin/pdftoppm',timeoutMs=6000}={}){
 if([pdfinfoPath,pdftoppmPath].some(p=>typeof p!=='string'||!isAbsolute(p)||p.length>256||/[\x00-\x1f]/.test(p))||!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>15000)reject();
 let occupied=false;
 const locked=async(fn)=>{
  if(occupied)reject();occupied=true;
  try{return await fn();}finally{occupied=false;}
 };
 return Object.freeze({
  async inspect(source,signal){return locked(()=>execute(pdfinfoPath,['-'],source,{signal,timeoutMs,maxBytes:8192}));},
  async render(source,page,signal){if(!Number.isInteger(page)||page<1||page>PDF_NORMALIZER_MAX_PAGES)reject();
   return locked(()=>execute(pdftoppmPath,['-f',String(page),'-l',String(page),'-singlefile','-r','150','-scale-to',String(PDF_NORMALIZER_MAX_RASTER),'-'],source,{signal,timeoutMs,maxBytes:maxOutput}));
  }
 });
}
// Normalisation is operator-assisted pre-admission processing, not evidence ingestion.
// The result is a *derived* raster PDF. Never describe it as the source original.
export async function normalizeExternalPdf(source,{renderer,signal}={}){
 if(!Buffer.isBuffer(source)||source.length<20||source.length>PDF_NORMALIZER_MAX_SOURCE||!header.test(source.subarray(0,12).toString('latin1'))||typeof renderer?.inspect!=='function'||typeof renderer?.render!=='function'||!signal)reject();
 signal.throwIfAborted();
 // Own a stable snapshot across all awaits; callers may reuse/mutate their buffer.
 const snapshot=Buffer.from(source),sourceDigest=hash(snapshot),scans=[],manifestPages=[];
 let pixels=0,canonical;
 try{
  let info,count;
  try{info=await renderer.inspect(snapshot,signal);signal.throwIfAborted();count=inspectPdfInfo(info);}
  finally{info?.fill?.(0);}
  for(let page=1;page<=count;page++){
   signal.throwIfAborted();
   const bytes=await renderer.render(snapshot,page,signal);let result;
   try{signal.throwIfAborted();result=ppmToCanonicalPng(bytes);}finally{bytes?.fill?.(0);}
   pixels+=result.width*result.height;
   if(pixels>2097152){result.png.fill(0);reject();}
   scans.push(result.png);
   manifestPages.push(Object.freeze({page,width:result.width,height:result.height,rasterSha256:hash(result.png)}));
  }
  canonical=count===1?canonicalScannedPdf(scans[0]):canonicalMultipageScannedPdf(scans);
  // Independently read *each* emitted page and verify every manifest anchor.
  for(let page=1;page<=count;page++){
   const verified=count===1?readCanonicalScannedPdf(canonical):readCanonicalMultipageScannedPdf(canonical,{page});
   try{
    const expected=manifestPages[page-1];
    if(verified.page!==page||(verified.pageCount??1)!==count||verified.width!==expected.width||verified.height!==expected.height||verified.rasterSha256!==expected.rasterSha256)reject();
   }finally{verified.png.fill(0);}
  }
  return {pdf:canonical,manifest:Object.freeze({version:1,sourceSha256:sourceDigest,sourceBytes:snapshot.length,derivedSha256:hash(canonical),derivedBytes:canonical.length,pageCount:count,pages:Object.freeze(manifestPages),originalRetained:false,reviewRequired:true,format:'offline-poppler-to-canonical-raster-v1',notice:'Derived copy; original source PDF is not retained by this transform. The converted file is not an original-document authenticity attestation. Text, links, forms and interactive content may be lost.'})};
 }finally{for(const b of scans)b.fill(0);snapshot.fill(0);}
}
