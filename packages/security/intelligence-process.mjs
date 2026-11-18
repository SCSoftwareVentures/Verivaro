import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {isAbsolute} from 'node:path';
const ENTRY=fileURLToPath(new URL('../worker/intelligence-local.mjs',import.meta.url));
const INPUT=262144,OUTPUT=262144;
/** Trusted local executable only; not a network sandbox or third-party adapter loader.
 * Node permissions restrict filesystem and subprocess access; external OS isolation still required.
 */
export function createLocalIntelligenceProvider({entry=ENTRY,timeoutMs=5000}={}){
 if(typeof entry!=='string'||!isAbsolute(entry)||!Number.isSafeInteger(timeoutMs)||timeoutMs<100||timeoutMs>7000)throw Error('invalid local intelligence configuration');
 let running=0;
 return ({pages,signal})=>{
 if(signal?.aborted||running>=2)return Promise.reject(Error('local provider unavailable'));
 const input=Buffer.from(JSON.stringify({pages}));if(input.length>INPUT)return Promise.reject(Error('local provider input limit'));
 running++;
 return new Promise((resolve,reject)=>{
 let child;
 try{child=spawn(process.execPath,['--permission','--allow-fs-read='+entry,'--max-old-space-size=32',entry],{stdio:['pipe','pipe','ignore'],env:{LANG:'C.UTF-8',LC_ALL:'C.UTF-8'},shell:false,windowsHide:true});}
 catch{running--;reject(Error('local provider unavailable'));return;}
 let failed=false,bytes=0,chunks=[];
 const stop=()=>{failed=true;child.kill('SIGKILL');};
 const timer=setTimeout(stop,timeoutMs);
 signal?.addEventListener('abort',stop,{once:true});if(signal?.aborted)stop();
 child.on('error',stop);child.stdin.on('error',stop);
 child.stdout.on('error',stop);
 child.stdout.on('data',b=>{if(failed)return;bytes+=b.length;if(bytes>OUTPUT){stop();return;}chunks.push(b);});
 child.once('close',code=>{
 clearTimeout(timer);signal?.removeEventListener('abort',stop);running--;
 if(failed||code!==0){reject(Error('local provider failed'));return;}
 try{const result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));if(!Array.isArray(result))throw Error();resolve(result);}catch{reject(Error('local provider protocol')); }
 });
 child.stdin.end(input);
 });
 };
}
