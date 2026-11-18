import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {open,lstat,realpath,mkdir,writeFile,readFile,readdir,unlink,rm} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,dirname,basename} from 'node:path';
import {encryptBackup,decryptBackup} from './encrypted-backup.mjs';
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const storage=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const hex=/^[0-9a-f]{64}$/;
const mime=new Set(['application/pdf','image/jpeg','image/png','text/plain']);
const sha=b=>createHash('sha256').update(b).digest('hex');
const msg=b=>Buffer.concat([Buffer.from('verivaro-tenant-archive-v1\0'),b]);
const objectId=x=>x.projectId+'/'+x.intentId;
const same=(a,b)=>a.projectId===b.projectId&&a.intentId===b.intentId&&a.sha256===b.sha256&&a.bytes===b.bytes&&a.mediaType===b.mediaType;
const maxFile=52428800;
async function privateDir(path){const s=await lstat(path);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0)throw Error('private archive directory required');return realpath(path);}
async function newDir(path){const parent=await privateDir(dirname(path)),name=basename(path);if(!name||name==='.'||name==='..')throw Error('invalid archive name');const dir=join(parent,name);await mkdir(dir,{mode:0o700});return dir;}
async function syncDir(dir){const f=await open(dir,'r');try{await f.sync();}finally{await f.close();}}
async function durable(path,data){const f=await open(path,'wx',0o600);try{await f.writeFile(data);await f.sync();}finally{await f.close();}}
async function fileDigest(path,limit){const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);try{
 const s=await f.stat();if(!s.isFile()||s.uid!==process.getuid()||s.nlink!==1||(s.mode&0o077)!==0||s.size<1||s.size>limit)throw Error('invalid archive file');
 const h=createHash('sha256');let n=0;
 for await(const b of f.createReadStream({autoClose:false,highWaterMark:1048576})){n+=b.length;if(n>limit)throw Error('archive file limit');h.update(b);}
 const end=await f.stat();if(n!==s.size||end.size!==s.size||end.mtimeMs!==s.mtimeMs||end.ctimeMs!==s.ctimeMs)throw Error('archive file changed');return {bytes:n,sha256:h.digest('hex')};
 }finally{await f.close();}}
async function smallFile(path,limit){const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);try{const s=await f.stat();if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.size>limit||s.size<1)throw Error('invalid archive metadata');const b=await f.readFile();if(b.length!==s.size)throw Error('metadata changed');return b;}finally{await f.close();}}
function validObject(o){return uuid.test(o?.projectId)&&uuid.test(o?.intentId)&&hex.test(o?.sha256)&&Number.isSafeInteger(o?.bytes)&&o.bytes>=1&&o.bytes<=maxFile&&mime.has(o.mediaType);}
export function parseTenantRecords(row){
 if(typeof row?.json!=='string'||Buffer.byteLength(row.json)>16777216||sha(row.json)!==row.sha256)throw Error('tenant records digest mismatch');
 const x=JSON.parse(row.json);
 if(x.schema!=='verivaro-tenant-records-v1'||!uuid.test(x.tenantId)||!uuid.test(x.exportId)||x.allProjectRecordsIncluded!==true||x.containsOriginalBytes!==false||!Array.isArray(x.projects)||x.projects.length!==x.projectCount||x.projectCount<1||x.projectCount>20)throw Error('invalid tenant records');
 const projects=new Set(),objects=new Map();
 for(const p of x.projects){
 if(!uuid.test(p.projectId)||projects.has(p.projectId)||typeof p.json!=='string'||Buffer.byteLength(p.json)>8388608||sha(p.json)!==p.sha256)throw Error('project records digest mismatch');projects.add(p.projectId);
 const v=JSON.parse(p.json);if(v.schema!=='verivaro-project-records-v1'||v.projectId!==p.projectId||v.tenantId!==x.tenantId||v.exportId!==x.exportId||!Array.isArray(v.records?.quarantine_receipt))throw Error('project records scope mismatch');
 for(const q of v.records.quarantine_receipt){const o={projectId:q.project_id,intentId:q.intent_id,sha256:q.actual_sha256,bytes:Number(q.actual_bytes),mediaType:q.media_type};
 if(q.tenant_id!==x.tenantId||o.projectId!==p.projectId||!validObject(o)||objects.has(objectId(o)))throw Error('receipt scope or duplicate');objects.set(objectId(o),o);}
 }
 if(objects.size>4000)throw Error('object count limit');
 return {records:x,objects,expected:x.projects.map(p=>({projectId:p.projectId,sha256:p.sha256}))};
}
const context=(tenant,ticket,name)=>'tenant-archive:'+tenant+':'+ticket+':'+name;
/** Offline restricted operator. Records may contain customer data; encrypted copy
 * includes quarantined/rejected originals as opaque bytes, never safe-to-open files.
 * Caller must stop writes and verify permission, independent key custody and destination. */
export async function buildTenantArchive({pool,records,quarantineRoot,destination,key,keyId,privateKey,expectedTenantId,expectedExportId,expectedRecordsSha256,quiesced=false,maxTotalBytes=16*1024**3}){
 if(quiesced!==true||!uuid.test(expectedTenantId)||!uuid.test(expectedExportId)||!hex.test(expectedRecordsSha256)||records?.sha256!==expectedRecordsSha256||!Number.isSafeInteger(maxTotalBytes)||maxTotalBytes<1||maxTotalBytes>32*1024**3)throw Error('explicit archive authority required');
 const parsed=parseTenantRecords(records),x=parsed.records;if(x.tenantId!==expectedTenantId||x.exportId!==expectedExportId)throw Error('archive scope mismatch');
 const signing=privateKey?.type==='private'?privateKey:createPrivateKey(privateKey);if(signing.asymmetricKeyType!=='ed25519')throw Error('signing key required');
 const root=await privateDir(quarantineRoot),parent=await privateDir(dirname(destination));if(parent===root||parent.startsWith(root+'/'))throw Error('archive must be outside quarantine');
 const initial=(await pool.query('SELECT vv_api.portability_original_inventory($1,$2,$3::jsonb) AS inventory',[x.tenantId,x.exportId,JSON.stringify(parsed.expected)])).rows[0]?.inventory;
 if(initial?.tenantId!==x.tenantId||initial.exportId!==x.exportId||initial.projectCount!==x.projectCount||!Array.isArray(initial.objects)||initial.objects.length!==parsed.objects.size)throw Error('changed or incomplete inventory');
 const seen=new Set(),keys=new Set();let total=Buffer.byteLength(records.json);
 for(const o of initial.objects){if(!validObject(o)||!storage.test(o.objectKey)||keys.has(o.objectKey)||seen.has(objectId(o))||!parsed.objects.has(objectId(o))||!same(o,parsed.objects.get(objectId(o))))throw Error('original inventory mismatch');seen.add(objectId(o));keys.add(o.objectKey);total+=o.bytes;}
 if(total>maxTotalBytes)throw Error('archive total byte budget exceeded');
 const dir=await newDir(destination);let complete=false;
 try{
 const entries=[],plain=join(dir,'.records-stage'),name='records.vvb';
 await durable(plain,Buffer.from(records.json));const e=await encryptBackup(plain,join(dir,name),{key,keyId,context:context(x.tenantId,x.exportId,name),maxBytes:16777216});await unlink(plain);
 if(e.plaintextSha256!==records.sha256)throw Error('records hash changed');
 entries.push({name,kind:'records',plaintextSha256:e.plaintextSha256,plaintextBytes:e.plaintextBytes,ciphertext:await fileDigest(join(dir,name),16777216+76)});
 for(const [index,o] of initial.objects.entries()){
 const name='original-'+String(index+1).padStart(6,'0')+'.vvb';
 const result=await encryptBackup(join(root,o.objectKey),join(dir,name),{key,keyId,context:context(x.tenantId,x.exportId,name),maxBytes:maxFile});
 if(result.plaintextSha256!==o.sha256||result.plaintextBytes!==o.bytes)throw Error('original bytes mismatch');
 entries.push({name,kind:'original',projectId:o.projectId,intentId:o.intentId,mediaType:o.mediaType,plaintextSha256:o.sha256,plaintextBytes:o.bytes,ciphertext:await fileDigest(join(dir,name),maxFile+76)});
 }
 const latest=(await pool.query('SELECT vv_api.portability_original_inventory($1,$2,$3::jsonb) AS inventory',[x.tenantId,x.exportId,JSON.stringify(parsed.expected)])).rows[0]?.inventory;
 if(JSON.stringify(latest)!==JSON.stringify(initial))throw Error('archive inventory or authority changed');
 const manifest={schema:'verivaro-tenant-archive-v1',tenantId:x.tenantId,exportId:x.exportId,recordsSha256:records.sha256,keyId,projectCount:x.projectCount,originalCount:initial.objects.length,allReceiptedOriginalsIncluded:true,completeTenantExport:false,untrustedOriginals:true,entries};
 const bytes=Buffer.from(JSON.stringify(manifest,null,2)+'\n');if(bytes.length>4194304)throw Error('manifest budget');
 await durable(join(dir,'manifest.json'),bytes);await durable(join(dir,'manifest.sig'),sign(null,msg(bytes),signing));await syncDir(dir);complete=true;
 return {archive:dir,manifestSha256:sha(bytes),originalCount:manifest.originalCount,completeTenantExport:false};
 }finally{if(!complete)await rm(dir,{recursive:true,force:true});}
}
/** Verify independently trusted signer and exact archive identity before decrypting
 * into a fresh private directory. No automatic parsing/opening of original content. */
export async function unpackTenantArchive({archive,destination,key,keyId,publicKey,expectedTenantId,expectedExportId,expectedManifestSha256}){
 if(!uuid.test(expectedTenantId)||!uuid.test(expectedExportId)||!hex.test(expectedManifestSha256))throw Error('trusted archive identity required');
 const dir=await privateDir(archive),bytes=await smallFile(join(dir,'manifest.json'),4194304),sig=await smallFile(join(dir,'manifest.sig'),64),k=publicKey?.type==='public'?publicKey:createPublicKey(publicKey);
 if(sha(bytes)!==expectedManifestSha256||sig.length!==64||k.asymmetricKeyType!=='ed25519'||!verify(null,msg(bytes),k,sig))throw Error('archive signature mismatch');
 const m=JSON.parse(bytes);if(m.schema!=='verivaro-tenant-archive-v1'||m.tenantId!==expectedTenantId||m.exportId!==expectedExportId||m.keyId!==keyId||m.completeTenantExport!==false||m.untrustedOriginals!==true||m.allReceiptedOriginalsIncluded!==true||!hex.test(m.recordsSha256)||!Array.isArray(m.entries)||m.entries.length!==m.originalCount+1||m.entries.length>4001)throw Error('invalid manifest');
 const names=new Set(['manifest.json','manifest.sig']);let total=0;
 for(const [i,e] of m.entries.entries()){
 const expected=i===0?'records.vvb':'original-'+String(i).padStart(6,'0')+'.vvb',limit=i===0?16777216:maxFile;
 if(e.name!==expected||names.has(e.name)||e.kind!==(i===0?'records':'original')||!Number.isSafeInteger(e.plaintextBytes)||e.plaintextBytes<1||e.plaintextBytes>limit||!hex.test(e.plaintextSha256)||e.ciphertext?.bytes!==e.plaintextBytes+76||!hex.test(e.ciphertext?.sha256))throw Error('invalid manifest entry');
 names.add(e.name);total+=e.plaintextBytes;if(total>32*1024**3)throw Error('archive total byte limit');
 const checked=await fileDigest(join(dir,e.name),limit+76);if(checked.bytes!==e.ciphertext.bytes||checked.sha256!==e.ciphertext.sha256)throw Error('ciphertext integrity failure');
 }
 const actual=await readdir(dir);if(actual.length!==names.size||actual.some(n=>!names.has(n)))throw Error('archive contains unexpected files');
 const outParent=await privateDir(dirname(destination));if(outParent===dir||outParent.startsWith(dir+'/'))throw Error('output cannot be inside archive');
 const out=await newDir(destination);let done=false;
 try{
 let parsed;const restored=new Set();
 for(const [i,e] of m.entries.entries()){
 const name=i===0?'records.json':e.name.replace(/\.vvb$/,'.quarantined');
 const d=await decryptBackup(join(dir,e.name),join(out,name),{key,keyId,context:context(m.tenantId,m.exportId,e.name),maxBytes:i===0?16777216:maxFile});
 if(d.plaintextSha256!==e.plaintextSha256||d.plaintextBytes!==e.plaintextBytes)throw Error('plaintext integrity failure');
 if(i===0){parsed=parseTenantRecords({json:(await smallFile(join(out,name),16777216)).toString('utf8'),sha256:m.recordsSha256});if(parsed.records.tenantId!==m.tenantId||parsed.records.exportId!==m.exportId||parsed.records.projectCount!==m.projectCount||parsed.objects.size!==m.originalCount)throw Error('archive records mismatch');}
 else{const o={projectId:e.projectId,intentId:e.intentId,sha256:e.plaintextSha256,bytes:e.plaintextBytes,mediaType:e.mediaType},id=objectId(o);if(!validObject(o)||restored.has(id)||!parsed.objects.has(id)||!same(o,parsed.objects.get(id)))throw Error('manifest original mismatch');restored.add(id);}
 }
 await durable(join(out,'manifest.json'),bytes);await syncDir(out);done=true;return {directory:out,originalCount:restored.size,untrustedOriginals:true};
 }finally{if(!done)await rm(out,{recursive:true,force:true});}
}
