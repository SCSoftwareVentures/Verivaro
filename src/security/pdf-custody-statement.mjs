// Independently verifiable Ed25519 statement linking a *retrieved, scanner-cleared*
// encrypted original PDF with a separately verified canonical raster derivative.
// Never interpreted as legal notarisation, faithful rendering, or proof of uptime.
import {createPrivateKey,createPublicKey,createHash,sign,verify} from 'node:crypto';
import {verifyPdfDerivative} from './pdf-worker-socket.mjs';
const fail=()=>{throw Error('PDF conversion custody attestation denied');};
const SHA=/^[a-f0-9]{64}$/;
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const hash=b=>createHash('sha256').update(b).digest('hex');
const iso=s=>typeof s==='string'&&Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s;
const keys='algorithm,conversionId,derivedBytes,derivedSha256,issuedAt,keyFingerprint,originalBytes,originalSha256,pageCount,pageRasterSha256,projectId,quarantineId,reviewRequired,sourceCustody,tenantId,version';
function identity(key){
 const publicKey=key?.type==='public'?key:createPublicKey(key);
 if(publicKey.asymmetricKeyType!=='ed25519')fail();
 return {publicKey,fingerprint:hash(publicKey.export({type:'spki',format:'der'}))};
}
function content(c){
 if(!c||typeof c!=='object'||Object.keys(c).sort().join(',')!==keys||c.version!==1||c.algorithm!=='Ed25519'||![c.tenantId,c.projectId,c.quarantineId,c.conversionId].every(v=>typeof v==='string'&&uuid.test(v))||![c.originalSha256,c.derivedSha256,c.keyFingerprint].every(v=>typeof v==='string'&&SHA.test(v))||!Number.isSafeInteger(c.originalBytes)||c.originalBytes<20||c.originalBytes>262144||!Number.isSafeInteger(c.derivedBytes)||c.derivedBytes<1||c.derivedBytes>262144||!Number.isInteger(c.pageCount)||c.pageCount<1||c.pageCount>4||!Array.isArray(c.pageRasterSha256)||c.pageRasterSha256.length!==c.pageCount||!c.pageRasterSha256.every(v=>typeof v==='string'&&SHA.test(v))||c.sourceCustody!=='encrypted-quarantine-retrieval-verified'||c.reviewRequired!==true||!iso(c.issuedAt))fail();
 return Buffer.from(JSON.stringify({version:1,algorithm:'Ed25519',tenantId:c.tenantId,projectId:c.projectId,quarantineId:c.quarantineId,conversionId:c.conversionId,originalSha256:c.originalSha256,originalBytes:c.originalBytes,derivedSha256:c.derivedSha256,derivedBytes:c.derivedBytes,pageCount:c.pageCount,pageRasterSha256:c.pageRasterSha256,sourceCustody:c.sourceCustody,reviewRequired:c.reviewRequired,keyFingerprint:c.keyFingerprint,issuedAt:c.issuedAt}),'utf8');
}
export function createPdfCustodySigner(privateKey){
 const key=privateKey?.type==='private'?privateKey:createPrivateKey(privateKey);
 if(key.asymmetricKeyType!=='ed25519')fail();
 const publicInfo=identity(key);
 return Object.freeze({fingerprint:publicInfo.fingerprint,
 async issue({quarantine,record,converted,conversionId,signal,clock=()=>new Date()}){
  if(typeof quarantine?.read!=='function'||!record||typeof conversionId!=='string'||!uuid.test(conversionId)||!signal||!converted?.pdf||!converted?.manifest)fail();
  signal.throwIfAborted();let original;
  try{
   // Signer retrieves the immutable encrypted original itself instead of
   // trusting a caller-supplied source hash or claim of retention.
   original=await quarantine.read(record,{signal});signal.throwIfAborted();
   verifyPdfDerivative(original,converted.pdf,converted.manifest);
   const c={version:1,algorithm:'Ed25519',tenantId:record.tenantId,projectId:record.projectId,quarantineId:record.quarantineId,conversionId,originalSha256:record.sha256,originalBytes:record.bytes,derivedSha256:converted.manifest.derivedSha256,derivedBytes:converted.manifest.derivedBytes,pageCount:converted.manifest.pageCount,pageRasterSha256:converted.manifest.pages.map(p=>p.rasterSha256),sourceCustody:'encrypted-quarantine-retrieval-verified',reviewRequired:true,keyFingerprint:publicInfo.fingerprint,issuedAt:clock().toISOString()};
   if(c.originalSha256!==converted.manifest.sourceSha256||c.originalBytes!==converted.manifest.sourceBytes)fail();
   const signature=sign(null,content(c),key).toString('base64url');
   signal.throwIfAborted();
   return {statement:c,signature,publicKey:publicInfo.publicKey.export({type:'spki',format:'pem'}),limitations:['Attestation of bytes checked at signing time, not an independent timestamp, legal signature or future retention guarantee.','Use an independently trusted signing key fingerprint and keep the original vault + receipt backed up separately.','Rendering may omit text, layers and attachments. An independent reviewer must verify content against the original.']};
  }finally{original?.fill(0);}
 }});
}
export function verifyPdfCustodyStatement(envelope,trustedKey,{original,derived}={}){
 const keyInfo=identity(trustedKey),statement=envelope?.statement,sig=envelope?.signature;
 if(statement?.keyFingerprint!==keyInfo.fingerprint||typeof sig!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(sig))fail();
 const bytes=Buffer.from(sig,'base64url');
 if(bytes.length!==64||bytes.toString('base64url')!==sig||!verify(null,content(statement),keyInfo.publicKey,bytes))fail();
 if(original!==undefined&&(!Buffer.isBuffer(original)||original.length!==statement.originalBytes||hash(original)!==statement.originalSha256))fail();
 if(derived!==undefined&&(!Buffer.isBuffer(derived)||derived.length!==statement.derivedBytes||hash(derived)!==statement.derivedSha256))fail();
 return {signatureVerified:true,originalBytesRechecked:original!==undefined,derivedBytesRechecked:derived!==undefined,statement};
}
