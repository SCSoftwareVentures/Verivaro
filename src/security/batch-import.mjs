// Browser-safe deterministic selection validation; server still verifies all bytes.
export function safeImportPath(name,path){
 if(typeof name!=='string'||typeof path!=='string'||[...name].length<1||[...name].length>160||[...path].length>512||/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\\:\ud800-\udfff]/u.test(path))return false;
 const parts=path.split('/');return parts.length<=16&&parts.at(-1)===name&&parts.every(s=>s&&s!=='.'&&s!=='..'&&s===s.trim()&&[...s].length<=160);
}
export async function planBatchImport(files,{digest,randomId,validPath=safeImportPath}){
 if(!Array.isArray(files)||files.length<1||files.length>12||typeof digest!=='function'||typeof randomId!=='function')throw Error('Choose 1–12 files per batch.');
 const batchId=randomId(),rows=[],seen=new Set();
 for(let i=0;i<files.length;i++){
  const file=files[i],name=file.name,path=file.webkitRelativePath||name,mediaType=file.type==='image/png'?'image/png':file.type==='application/pdf'?'application/pdf':file.type==='text/plain'||/\.(?:txt|csv|md)$/i.test(name??'')?'text/plain; charset=utf-8':null;
  const row={file,name,path,ordinal:i+1,mediaType,state:'ready',requestId:randomId(),duplicate:false};
  if(!validPath(name,path)||!mediaType||!Number.isInteger(file.size)||file.size<1||file.size>262144){row.state='unsupported';rows.push(row);continue;}
  const bytes=new Uint8Array(await file.arrayBuffer());try{if(bytes.length!==file.size)throw Error('File size changed');row.sha256=await digest(bytes);if(!/^[a-f0-9]{64}$/.test(row.sha256))throw Error('Invalid digest');row.duplicate=seen.has(row.sha256);seen.add(row.sha256);}finally{bytes.fill(0);}rows.push(row);
 }
 return {batchId,rows};
}

// An encrypted batch retains the exact original request IDs and bytes.
// On resume every completed request may safely replay; no new IDs are minted.
export async function encodeBatchCheckpoint(plan,scope,digest){
 const id=x=>typeof x==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(x);
 if(!scope||![scope.actorId,scope.tenantId,scope.projectId,plan?.batchId].every(id)||!Array.isArray(plan.rows)||plan.rows.length<1||plan.rows.length>12)throw Error('Invalid batch scope');
 const rows=[],chunks=[],seen=new Set();
 try{
  for(let i=0;i<plan.rows.length;i++){const r=plan.rows[i];if(!id(r.requestId)||seen.has(r.requestId)||r.ordinal!==i+1)throw Error('Invalid batch identity');seen.add(r.requestId);
   if(r.state==='unsupported'){rows.push({ordinal:r.ordinal,requestId:r.requestId,state:'unsupported',name:'Unsupported item '+r.ordinal,path:'Unsupported item '+r.ordinal});continue;}
   if(!safeImportPath(r.name,r.path)||!['text/plain; charset=utf-8','image/png','application/pdf'].includes(r.mediaType)||!r.file||r.file.size<1||r.file.size>262144)throw Error('Invalid batch file');
   const bytes=new Uint8Array(await r.file.arrayBuffer());chunks.push(bytes);
   if(bytes.length!==r.file.size||await digest(bytes)!==r.sha256)throw Error('Original changed');
   rows.push({ordinal:r.ordinal,requestId:r.requestId,state:'ready',name:r.name,path:r.path,mediaType:r.mediaType,sha256:r.sha256,bytes:bytes.length,duplicate:r.duplicate===true});
  }
  const header=new TextEncoder().encode(JSON.stringify({version:1,...scope,batchId:plan.batchId,rows}));try{if(header.length>32768)throw Error('Batch metadata too large');const out=new Uint8Array(4+header.length+chunks.reduce((n,b)=>n+b.length,0));new DataView(out.buffer).setUint32(0,header.length);out.set(header,4);let pos=4+header.length;for(const b of chunks){out.set(b,pos);pos+=b.length;}return out;}finally{header.fill(0);}
 }finally{for(const b of chunks)b.fill(0);}
}
export async function decodeBatchCheckpoint(plain,scope,digest,batchId){
 const id=x=>typeof x==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(x);
 if(!(plain instanceof Uint8Array)||plain.length<5||plain.length>12*262144+32772)throw Error('Invalid batch checkpoint');
 const n=new DataView(plain.buffer,plain.byteOffset,plain.byteLength).getUint32(0);if(n<1||n>32768||4+n>plain.length)throw Error('Invalid batch checkpoint');
 const m=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain.subarray(4,4+n)));
 if(m.version!==1||m.batchId!==batchId||!id(batchId)||!scope||!['actorId','tenantId','projectId'].every(k=>id(scope[k])&&scope[k]===m[k])||!Array.isArray(m.rows)||m.rows.length<1||m.rows.length>12)throw Error('Batch belongs to another actor or project');
 let pos=4+n;const rows=[],seen=new Set();
 for(let i=0;i<m.rows.length;i++){const r=m.rows[i];if(!id(r.requestId)||seen.has(r.requestId)||r.ordinal!==i+1||!safeImportPath(r.name,r.path))throw Error('Invalid batch item');seen.add(r.requestId);
  if(r.state==='unsupported'){rows.push({ordinal:r.ordinal,requestId:r.requestId,state:'unsupported',name:r.name,path:r.path,duplicate:false});continue;}
  if(r.state!=='ready'||!Number.isInteger(r.bytes)||r.bytes<1||r.bytes>262144||pos+r.bytes>plain.length||!/^[a-f0-9]{64}$/.test(r.sha256)||!['text/plain; charset=utf-8','image/png','application/pdf'].includes(r.mediaType)||typeof r.duplicate!=='boolean')throw Error('Invalid batch item');
  const b=plain.subarray(pos,pos+r.bytes);if(await digest(b)!==r.sha256)throw Error('Batch original digest mismatch');pos+=r.bytes;
  rows.push({...r,file:new Blob([b],{type:r.mediaType})});
 }
 if(pos!==plain.length)throw Error('Unexpected batch bytes');
 return {batchId,rows};
}
