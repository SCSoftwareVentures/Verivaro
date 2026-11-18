import {spawn} from 'node:child_process';
import {mkdtemp,writeFile,rm,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const MAX_INPUT=10*1024*1024,MAX_TEXT=1024*1024,MAX_PAGES=20;
function run(bin,args,deadline,cwd,max=MAX_TEXT){
 return new Promise((resolve,reject)=>{
  const ms=Math.min(12000,deadline-Date.now());if(ms<=0){reject(Error('extraction deadline'));return;}
  const child=spawn(bin,args,{cwd,stdio:['ignore','pipe','ignore'],env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',LC_ALL:'C.UTF-8',HOME:cwd,OMP_THREAD_LIMIT:'1'},shell:false});
  let chunks=[],length=0,failed=false;const abort=()=>{failed=true;child.kill('SIGKILL');};
  const timer=setTimeout(abort,ms);
  child.stdout.on('data',b=>{length+=b.length;if(length>max){abort();return;}if(!failed)chunks.push(b);});
  child.on('error',()=>{clearTimeout(timer);reject(Error('extractor unavailable'));});
  child.on('close',code=>{clearTimeout(timer);if(failed||code!==0)reject(Error('extractor failed'));else try{resolve(new TextDecoder('utf8',{fatal:true}).decode(Buffer.concat(chunks)));}catch{reject(Error('invalid text'));}});
 });
}
/** Local adapter for a separately sandboxed parser worker. Fixed binaries and arguments.
 * Process time/output/input limits are not an OS sandbox; do not deploy unsandboxed.
 * Page numbers are original PDF pages or 1 for a standalone image; OCR is unverified.
 */
export function createNativeExtractor(){
 return async(bytes,mediaType)=>{
  if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>MAX_INPUT||!['application/pdf','image/png','image/jpeg'].includes(mediaType))throw Error('unsupported native input');
  const root=await mkdtemp(join(tmpdir(),'vv-native-'));const deadline=Date.now()+55000;
  const input=join(root,mediaType==='application/pdf'?'input.pdf':mediaType==='image/png'?'input.png':'input.jpg');
  const pages=[];let total=0;
  const accept=(page,text,method)=>{if(text.includes('\0'))throw Error('invalid extracted text');total+=Buffer.byteLength(text);if(total>MAX_TEXT)throw Error('text limit');pages.push({page,text,method});};
  try{
   await writeFile(input,bytes,{mode:0o600,flag:'wx'});
   if(mediaType==='application/pdf'){
    const info=await run('/usr/bin/pdfinfo',[input],deadline,root,65536);
    const count=Number(/^Pages:\s+(\d+)\s*$/m.exec(info)?.[1]);
    if(!Number.isSafeInteger(count)||count<1||count>MAX_PAGES||/^Encrypted:\s+yes/m.test(info))throw Error('PDF limits or encryption');
    for(let p=1;p<=count;p++){
     const s=await run('/usr/bin/pdftotext',['-f',String(p),'-l',String(p),'-enc','UTF-8','-nopgbrk',input,'-'],deadline,root);
     if(s.trim()){accept(p,s,'pdf-text');continue;}
     const prefix=join(root,'page-'+p);
     await run('/usr/bin/pdftoppm',['-f',String(p),'-l',String(p),'-singlefile','-scale-to','1800','-png',input,prefix],deadline,root,1024);
     const rendered=prefix+'.png';if((await stat(rendered)).size>MAX_INPUT)throw Error('render limit');
     accept(p,await run('/usr/bin/tesseract',[rendered,'stdout','-l','eng','--psm','6'],deadline,root),'ocr');
    }
   }else{
    // Native decoder must be sandboxed and resource-limited by the deployment supervisor.
    accept(1,await run('/usr/bin/tesseract',[input,'stdout','-l','eng','--psm','6'],deadline,root),'ocr');
   }
   if(!pages.some(p=>p.text.trim()))throw Error('no extractable text');
   return pages;
  }finally{await rm(root,{recursive:true,force:true});}
 };
}
