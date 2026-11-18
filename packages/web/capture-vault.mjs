const MAX=50*1024*1024,MAX_HEADER=16384,ITER=600000;
const enc=new TextEncoder(),dec=new TextDecoder('utf-8',{fatal:true});
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MIME=new Set(['application/pdf','image/jpeg','image/png','text/plain']);
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const digest=async b=>hex(await crypto.subtle.digest('SHA-256',b));
const random=n=>crypto.getRandomValues(new Uint8Array(n));
function checkScope(s){if(!Array.isArray(s)||s.length!==3||!s.every(x=>typeof x==='string'&&UUID.test(x)))throw Error('Authenticated actor and project required.');}
export async function vaultScope(s){checkScope(s);return digest(enc.encode('verivaro-offline-v1:'+s.join(':')));}
async function derive(pass,salt){
 if(typeof pass!=='string'||pass.length<16||pass.length>256)throw Error('Use a unique passphrase of at least 16 characters.');
 const raw=enc.encode(pass);
 try{const base=await crypto.subtle.importKey('raw',raw,'PBKDF2',false,['deriveKey']);return await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:ITER,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}finally{raw.fill(0);}
}
function meta(j){return {documentId:j.documentId,intentId:j.intentId,title:j.title,newDocument:j.newDocument,sha256:j.sha256,mediaType:j.mediaType,bytes:j.file.size};}
function validate(j){
 if(!j||!UUID.test(j.documentId)||!UUID.test(j.intentId)||typeof j.title!=='string'||j.title.length>250||(j.newDocument&&!j.title.trim())||typeof j.newDocument!=='boolean'||typeof j.sha256!=='string'||!/^[a-f0-9]{64}$/.test(j.sha256)||!MIME.has(j.mediaType)||!Number.isSafeInteger(j.bytes)||j.bytes<1||j.bytes>MAX)throw Error('Invalid capture metadata.');
}
async function pack(jobs){
 if(!Array.isArray(jobs)||jobs.length>5)throw Error('Capture count exceeded.');
 const m=jobs.map(meta);let total=0;const ids=new Set();
 for(const j of m){validate(j);if(ids.has(j.intentId))throw Error('Duplicate capture.');ids.add(j.intentId);total+=j.bytes;}
 const header=enc.encode(JSON.stringify(m));if(total>MAX||header.length>MAX_HEADER)throw Error('Capture capacity exceeded.');
 const out=new Uint8Array(4+header.length+total);new DataView(out.buffer).setUint32(0,header.length);out.set(header,4);
 let pos=4+header.length;for(const j of jobs){const b=new Uint8Array(await j.file.arrayBuffer());if(b.length!==j.file.size||await digest(b)!==j.sha256){out.fill(0);throw Error('Capture byte integrity failed.');}out.set(b,pos);pos+=b.length;b.fill(0);}
 return out;
}
async function unpack(raw){
 if(raw.length<6||raw.length>MAX+MAX_HEADER+4)throw Error('Invalid vault size.');
 const h=new DataView(raw.buffer,raw.byteOffset,raw.byteLength).getUint32(0);
 if(h<2||h>MAX_HEADER||h+4>raw.length)throw Error('Invalid vault header.');
 const items=JSON.parse(dec.decode(raw.subarray(4,4+h)));if(!Array.isArray(items)||items.length>5)throw Error('Invalid vault items.');
 let off=4+h;const result=[],ids=new Set();
 for(const j of items){validate(j);if(ids.has(j.intentId)||off+j.bytes>raw.length)throw Error('Invalid vault capture.');ids.add(j.intentId);
 const bytes=raw.subarray(off,off+j.bytes);if(await digest(bytes)!==j.sha256)throw Error('Capture digest mismatch.');
 const {bytes:_size,...metadata}=j;result.push({...metadata,file:new Blob([bytes],{type:j.mediaType})});off+=j.bytes;}
 if(off!==raw.length)throw Error('Unexpected vault bytes.');return result;
}
const aad=(scope,version)=>enc.encode('verivaro-offline-v1:'+scope+':'+version);
export async function createCipher(pass,scope,salt=random(16)){
 if(!/^[a-f0-9]{64}$/.test(scope)||!(salt instanceof Uint8Array)||salt.length!==16)throw Error('Invalid vault scope.');
 let key=await derive(pass,salt);
 return {
 async seal(jobs){if(!key)throw Error('Vault locked.');const version=crypto.randomUUID(),iv=random(12),raw=await pack(jobs);
 try{const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(scope,version)},key,raw);return {format:1,version,salt,iv,cipher};}finally{raw.fill(0);}},
 async open(record){if(!key)throw Error('Vault locked.');if(record?.format!==1||!UUID.test(record.version)||!(record.iv instanceof Uint8Array)||record.iv.length!==12||!(record.cipher instanceof ArrayBuffer)||record.cipher.byteLength>MAX+MAX_HEADER+20)throw Error('Invalid vault record.');
 const raw=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:record.iv,additionalData:aad(scope,record.version)},key,record.cipher));try{return await unpack(raw);}finally{raw.fill(0);}},
 close(){key=null;}
 };
}
async function database(){
 if(!globalThis.indexedDB)throw Error('Device storage unavailable.');
 return new Promise((resolve,reject)=>{const r=indexedDB.open('verivaro-capture-v1',1);r.onupgradeneeded=()=>r.result.createObjectStore('vaults');r.onsuccess=()=>{const d=r.result;d.onversionchange=()=>d.close();resolve(d);};r.onerror=()=>reject(Error('Device storage unavailable.'));r.onblocked=()=>reject(Error('Close other workspace tabs.'));});
}
async function read(scope){
 const d=await database();try{return await new Promise((resolve,reject)=>{const tx=d.transaction('vaults','readonly'),r=tx.objectStore('vaults').get(scope);tx.oncomplete=()=>resolve(r.result??null);tx.onerror=tx.onabort=()=>reject(Error('Vault read failed.'));});}finally{d.close();}
}
async function cas(scope,expect,next){
 const d=await database();try{return await new Promise((resolve,reject)=>{const tx=d.transaction('vaults','readwrite'),store=tx.objectStore('vaults'),r=store.get(scope);let conflict=false;
 r.onsuccess=()=>{if((r.result?.version??null)!==expect){conflict=true;tx.abort();return;}if(next)store.put(next,scope);else store.delete(scope);};
 tx.oncomplete=()=>resolve();tx.onerror=tx.onabort=()=>reject(Error(conflict?'Vault changed in another tab. Lock and reopen.':'Device storage write failed.'));});}finally{d.close();}
}
export async function unlockVault(scopeParts,pass){
 const scope=await vaultScope(scopeParts),record=await read(scope),cipher=await createCipher(pass,scope,record?.salt);
 let version=record?.version??null,closed=false,writing=false;
 let jobs;try{jobs=record?await cipher.open(record):[];if(!record){const next=await cipher.seal([]);await cas(scope,null,next);version=next.version;}}catch(e){cipher.close();throw Error('Cannot unlock capture vault. Check passphrase, storage availability or another open tab.');}
 return {jobs,async save(nextJobs){if(closed||writing)throw Error('Vault unavailable.');writing=true;try{const next=await cipher.seal(nextJobs);if(closed)throw Error('Vault locked.');await cas(scope,version,next);version=next.version;}finally{writing=false;}},close(){closed=true;cipher.close();}};
}
// Explicit destructive reset; cannot recover encrypted content without its passphrase.
export async function deleteVault(scopeParts){const scope=await vaultScope(scopeParts),r=await read(scope);if(r)await cas(scope,r.version,null);}
