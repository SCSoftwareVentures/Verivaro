// Browser-safe deterministic selection validation; server still verifies all bytes.
export function safeImportPath(name,path){
 if(typeof name!=='string'||typeof path!=='string'||[...name].length<1||[...name].length>160||[...path].length>512||/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\\:\ud800-\udfff]/u.test(path))return false;
 const parts=path.split('/');return parts.length<=16&&parts.at(-1)===name&&parts.every(s=>s&&s!=='.'&&s!=='..'&&s===s.trim()&&[...s].length<=160);
}
export async function planBatchImport(files,{digest,randomId,validPath=safeImportPath}){
 if(!Array.isArray(files)||files.length<1||files.length>12||typeof digest!=='function'||typeof randomId!=='function')throw Error('Choose 1–12 files per batch.');
 const batchId=randomId(),rows=[],seen=new Set();
 for(let i=0;i<files.length;i++){
  const file=files[i],name=file.name,path=file.webkitRelativePath||name,mediaType=file.type==='image/png'?'image/png':file.type==='application/pdf'?'application/pdf':file.type==='text/plain'||name?.toLowerCase().endsWith('.txt')?'text/plain; charset=utf-8':null;
  const row={file,name,path,ordinal:i+1,mediaType,state:'ready',requestId:randomId(),duplicate:false};
  if(!validPath(name,path)||!mediaType||!Number.isInteger(file.size)||file.size<1||file.size>262144){row.state='unsupported';rows.push(row);continue;}
  const bytes=new Uint8Array(await file.arrayBuffer());try{if(bytes.length!==file.size)throw Error('File size changed');row.sha256=await digest(bytes);if(!/^[a-f0-9]{64}$/.test(row.sha256))throw Error('Invalid digest');row.duplicate=seen.has(row.sha256);seen.add(row.sha256);}finally{bytes.fill(0);}rows.push(row);
 }
 return {batchId,rows};
}
