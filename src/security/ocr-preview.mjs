import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {isAbsolute} from 'node:path';
import {validateEvidence} from './evidence-objects.mjs';
import {ReleaseDenied,ReleaseConflict} from './evidence-release.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const fail=()=>{throw Error('invalid OCR output');};
const HEADER='level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext';
const num=(s,max)=>{if(!/^(?:0|[1-9][0-9]{0,8})$/.test(s)||Number(s)>max)fail();return Number(s);};
export const OCR_MAX_OUTPUT=128*1024;
export function parseOcrTsv(tsv,{width,height}){
 if(!Buffer.isBuffer(tsv)||tsv.length<HEADER.length||tsv.length>OCR_MAX_OUTPUT||!Number.isInteger(width)||!Number.isInteger(height)||width<1||height<1||width>2048||height>2048||width*height>1048576)fail();
 const text=new TextDecoder('utf-8',{fatal:true}).decode(tsv).replace(/\r\n/g,'\n'),rows=text.split('\n');
 if(rows.shift()!==HEADER||rows.pop()!==''||rows.length>4096)fail();
 const lines=new Map(),seen=new Set(),parents=new Set();let total=0,pageSeen=false;
 for(const row of rows){
  const fields=row.split('\t');if(fields.length!==12)fail();
  const [lv,pg,bl,pa,li,wo,x,y,w,h,cf,word]=fields;
  const level=num(lv,5),page=num(pg,1),block=num(bl,4096),paragraph=num(pa,4096),line=num(li,4096),ordinal=num(wo,4096);
  if(level<1||page!==1)fail();
  const ids=[block,paragraph,line,ordinal],depth=level-1;
  if(ids.some((n,i)=>i<depth?n<1:n!==0))fail();
  const left=num(x,width),top=num(y,height),bw=num(w,width),bh=num(h,height);
  if(left+bw>width||top+bh>height)fail();
  const addr=ids.slice(0,depth).join(':');
  if(seen.has(level+':'+addr)||level>1&&!parents.has(ids.slice(0,depth-1).join(':')))fail();
  seen.add(level+':'+addr);
  if(level===1){if(pageSeen||left!==0||top!==0||bw!==width||bh!==height)fail();pageSeen=true;}
  if(level<5){if(cf!=='-1'||word!=='')fail();parents.add(addr);continue;}
  if(!/^(?:0|[1-9][0-9]?|100)(?:\.[0-9]{1,6})?$/.test(cf)||Number(cf)>100||!bw||!bh||!word||word!==word.trim()||/[\s\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/u.test(word)||[...word].length>128)fail();
  const key=ids.slice(0,3).join(':');let entry=lines.get(key);
  if(!entry){if(lines.size>=512)fail();entry={block,paragraph,line,words:[],left,top,right:left+bw,bottom:top+bh,sum:0,min:100,last:0};lines.set(key,entry);}
  if(ordinal<=entry.last||entry.words.length>=128)fail();
  total+=Buffer.byteLength(word);if(total>32768)fail();
  const confidence=Number(cf);entry.last=ordinal;entry.words.push(word);entry.left=Math.min(entry.left,left);entry.top=Math.min(entry.top,top);entry.right=Math.max(entry.right,left+bw);entry.bottom=Math.max(entry.bottom,top+bh);entry.sum+=confidence;entry.min=Math.min(entry.min,confidence);
 }
 if(!pageSeen)fail();
 return Array.from(lines.values(),(e,i)=>{const quote=e.words.join(' ');return Object.freeze({ordinal:i+1,block:e.block,paragraph:e.paragraph,line:e.line,quote,quoteSha256:sha(quote),box:{left:e.left,top:e.top,width:e.right-e.left,height:e.bottom-e.top},confidence:Math.round(e.sum/e.words.length*100)/100,minWordConfidence:Math.round(e.min*100)/100,wordCount:e.words.length,reviewRequired:true});});
}
// Intended only for a dedicated restricted worker account, not the web process.
// No command shell, caller-controlled arguments, named plaintext input or output.
export function createTesseractEngine({binaryPath='/usr/bin/tesseract',tessdataPath='/usr/share/tesseract-ocr/5/tessdata',timeoutMs=8000}={}){
 if([binaryPath,tessdataPath].some(x=>typeof x!=='string'||!isAbsolute(x)||x.length>256||/[\x00-\x1f]/.test(x))||!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>15000)throw Error('invalid OCR configuration');
 let busy=false;
 return async function recognize(data,signal){
  if(busy)throw Error('OCR capacity');
  validateEvidence(data,'image/png');signal.throwIfAborted();busy=true;
  const chunks=[];let count=0;
  try{return await new Promise((resolve,reject)=>{
   const child=spawn(binaryPath,['stdin','stdout','--tessdata-dir',tessdataPath,'-l','eng','--psm','6','tsv'],{shell:false,cwd:'/',env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',OMP_THREAD_LIMIT:'1',HOME:'/nonexistent'},stdio:['pipe','pipe','ignore']});
   let failure=null,done=false;
   const stop=reason=>{failure??=reason;child.kill('SIGKILL');};
   const abort=()=>stop(Error('OCR cancelled'));
   const timer=setTimeout(()=>stop(Error('OCR timeout')),timeoutMs);timer.unref();
   signal.addEventListener('abort',abort,{once:true});if(signal.aborted)abort();
   child.stdout.on('data',chunk=>{if(failure){chunk.fill(0);return;}count+=chunk.length;if(count>OCR_MAX_OUTPUT){chunk.fill(0);stop(Error('OCR output limit'));return;}chunks.push(chunk);});
   child.stdin.on('error',()=>stop(Error('OCR input failed')));
   child.once('error',()=>stop(Error('OCR engine unavailable')));
   child.once('close',(code)=>{
    if(done)return;done=true;clearTimeout(timer);signal.removeEventListener('abort',abort);
    if(failure||code!==0)return reject(failure??Error('OCR engine failed'));
    resolve(Buffer.concat(chunks,count));
   });
   child.stdin.end(data);
  });}finally{for(const b of chunks)b.fill(0);busy=false;}
 };
}
// Preview is read-only by default. Explicit import derives the same region from authenticated original bytes again.
// The caller must supply a separately isolated, trusted recognition adapter.
export function createOcrPreview({retrieve,assessment,recognize,importSource}){
 if(typeof retrieve!=='function'||typeof assessment!=='function'||typeof recognize!=='function')throw Error('invalid OCR preview configuration');
 let active=false;
 return async(input,{signal,importRegion=false}={})=>{
  if(active)throw Error('OCR capacity');active=true;let source,output;
  try{
   signal.throwIfAborted();const initial=await assessment(input);if(!initial.canWrite||initial.archived)throw new ReleaseDenied('OCR denied');
   source=await retrieve(input);signal.throwIfAborted();
   if(source.mediaType!=='image/png'||source.sha256!==input.sha256||sha(source.data)!==input.sha256)throw new ReleaseConflict('OCR source mismatch');
   validateEvidence(source.data,'image/png');
   const width=source.data.readUInt32BE(16),height=source.data.readUInt32BE(20);
   output=await recognize(source.data,signal);signal.throwIfAborted();
   const regions=parseOcrTsv(output,{width,height}).map(r=>({...r,regionDigest:sha(JSON.stringify([input.sha256,width,height,r.ordinal,r.block,r.paragraph,r.line,r.quoteSha256,r.box.left,r.box.top,r.box.width,r.box.height,r.confidence,r.minWordConfidence,r.wordCount]))}));
   const final=await assessment(input);if(!final.canWrite||final.archived)throw new ReleaseDenied('OCR denied');
   signal.throwIfAborted();
   if(importRegion){
    if(typeof importSource!=='function'||input.confirm!==true)throw new ReleaseDenied('OCR import denied');
    const r=regions.find(r=>r.ordinal===input.ordinal&&r.regionDigest===input.regionDigest&&r.quoteSha256===input.quoteSha256);
    if(!r||[...r.quote].length>1024||Buffer.byteLength(r.quote)>4096||/[\x00-\x1f\x7f-\x9f]/u.test(r.quote))throw new ReleaseConflict('OCR region changed');
    return await importSource({...input,quote:r.quote,location:{algorithm:'tesseract-eng-psm6-tsv-v1',width,height,block:r.block,paragraph:r.paragraph,line:r.line,box:r.box,confidence:r.confidence,minWordConfidence:r.minWordConfidence,wordCount:r.wordCount,regionDigest:r.regionDigest}});
   }
   return {algorithm:'tesseract-eng-psm6-tsv-v1',sha256:input.sha256,width,height,regions,verified:false,reviewRequired:true,warning:'OCR may misread or omit text. Confidence is an engine score, not calibrated probability. Compare each region with the original. No requirement has been imported.'};
  }finally{source?.data?.fill(0);output?.fill?.(0);active=false;}
 };
}
