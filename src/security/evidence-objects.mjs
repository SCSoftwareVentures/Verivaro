import {createCipheriv,createDecipheriv,createHash,randomBytes,randomUUID,timingSafeEqual} from 'node:crypto';
import {TYPES,validatePng,validatePdf} from './evidence-formats.mjs';
import {readCanonicalScannedPdf} from './scanned-pdf.mjs';
import {readCanonicalMultipageScannedPdf} from './scanned-pdf-multipage.mjs';
import {extractOfficeSpans} from './office-extraction.mjs';
import {Readable} from 'node:stream';
import {createPrivateFileStore,isArtifactId} from './private-file-store.mjs';
export const MAX_EVIDENCE_UPLOAD=256*1024;
const hash=b=>createHash('sha256').update(b).digest('hex');
const keyId=/^[a-z][a-z0-9_-]{0,31}$/;
function metadata(m){if(!m||![m.id,m.tenantId,m.projectId].every(isArtifactId)||!/^[a-f0-9]{64}$/.test(m.sha256)||!Number.isInteger(m.bytes)||m.bytes<1||m.bytes>MAX_EVIDENCE_UPLOAD||!keyId.test(m.keyId))throw Error('invalid evidence metadata');const type=m.mediaType??TYPES[0];if(!TYPES.includes(type))throw Error('invalid evidence type');return Buffer.from(JSON.stringify(type===TYPES[0]?['vv-evidence-v1',m.id,m.tenantId,m.projectId,m.sha256,m.bytes,m.keyId]:['vv-evidence-v2',m.id,m.tenantId,m.projectId,m.sha256,m.bytes,m.keyId,type]));}
export function validateTextEvidence(data){
 if(!Buffer.isBuffer(data)||data.length<1||data.length>MAX_EVIDENCE_UPLOAD)throw Error('invalid evidence size');
 const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(data);
 if(!text.trim()||/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/u.test(text)||text.charCodeAt(0)===0xfeff)throw Error('invalid evidence text');
 return data;
}
export function validateEvidence(data,mediaType=TYPES[0]){
 if(!Buffer.isBuffer(data)||data.length<1||data.length>MAX_EVIDENCE_UPLOAD||!TYPES.includes(mediaType))throw Error('invalid evidence format');
 if(mediaType===TYPES[0])return validateTextEvidence(data);
 if(mediaType==='image/png')return validatePng(data);
 if(mediaType==='application/pdf'){try{return validatePdf(data);}catch{try{const raster=readCanonicalScannedPdf(data);raster.png.fill(0);return data;}catch{const raster=readCanonicalMultipageScannedPdf(data);raster.png.fill(0);return data;}}}
 extractOfficeSpans(data,mediaType==='application/vnd.openxmlformats-officedocument.wordprocessingml.document'?'docx':'xlsx');return data;
}
export function sealEvidence(data,{tenantId,projectId,id=randomUUID(),key,keyId,mediaType=TYPES[0]}){
 validateEvidence(data,mediaType);if(!Buffer.isBuffer(key)||key.length!==32)throw Error('invalid evidence key');
 const m={id,tenantId,projectId,sha256:hash(data),bytes:data.length,keyId,mediaType},nonce=randomBytes(12);
 const cipher=createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(metadata(m));
 const envelope=Buffer.concat([nonce,cipher.update(data),cipher.final(),cipher.getAuthTag()]);
 return {...m,envelope,cipherDigest:hash(envelope)};
}
export function openEvidence(m,key){
 if(!Buffer.isBuffer(key)||key.length!==32||!Buffer.isBuffer(m.envelope)||m.envelope.length!==m.bytes+28||hash(m.envelope)!==m.cipherDigest)throw Error('evidence integrity denied');
 const d=createDecipheriv('aes-256-gcm',key,m.envelope.subarray(0,12));d.setAAD(metadata(m));d.setAuthTag(m.envelope.subarray(-16));
 const clear=Buffer.concat([d.update(m.envelope.subarray(12,-16)),d.final()]);
 if(clear.length!==m.bytes||!timingSafeEqual(Buffer.from(hash(clear),'hex'),Buffer.from(m.sha256,'hex'))){clear.fill(0);throw Error('evidence integrity denied');}
 return clear;
}
// Trusted backup administrator only; no access to database object bytes is
// granted to the application runtime or scanner. Never fall back for db objects.
export function createEvidenceRecoverySource({client,sourceRoot,readKey}){
 const legacy=createPrivateFileStore(sourceRoot);
 if(typeof client?.query!=='function'||typeof readKey!=='function')throw Error('invalid recovery source');
 return async function source(id,{signal,maxBytes}){
  signal.throwIfAborted();
  if(!isArtifactId(id))throw Error('invalid evidence ID');
  const r=await client.query("SELECT e.storage_ref,e.tenant_id,e.project_id,e.sha256 AS expected_hash,o.evidence_id,o.tenant_id AS object_tenant,o.project_id AS object_project,o.sha256,o.bytes,o.key_id,o.media_type,o.envelope,encode(o.cipher_digest,'hex') AS cipher_digest FROM verivaro.evidence e LEFT JOIN verivaro_private.evidence_objects o ON o.evidence_id=e.id WHERE e.id=$1",[id]);
  const row=r.rows[0];
  if(!row||row.storage_ref!=='db-encrypted-v1'){if(row?.evidence_id)throw Error('inconsistent evidence storage');return legacy(id,{signal,maxBytes});}
  if(row.evidence_id!==id||row.tenant_id!==row.object_tenant||row.project_id!==row.object_project||row.sha256!==row.expected_hash||row.bytes>maxBytes)throw Error('inconsistent evidence storage');
  const clear=openEvidence({id,tenantId:row.tenant_id,projectId:row.project_id,sha256:row.sha256,bytes:row.bytes,keyId:row.key_id,mediaType:row.media_type,envelope:row.envelope,cipherDigest:row.cipher_digest},await readKey(row.key_id));
  // Stream the verified bytes directly into the encrypted backup writer.
  const stream=Readable.from([clear]);stream.once('close',()=>clear.fill(0));return stream;
 };
}
