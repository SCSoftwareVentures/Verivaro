import {createHash} from 'node:crypto';
import {zip} from './verification-report-export.mjs';
import {buildHandoverDerivatives,HANDOVER_PROFILES} from './handover-templates.mjs';

const hash=b=>createHash('sha256').update(b).digest('hex');
const digest=s=>typeof s==='string'&&s.length===64&&/^[a-f0-9]{64}$/.test(s);
const uuid=s=>typeof s==='string'&&s.length===36&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(s);
const types=Object.freeze({'text/plain; charset=utf-8':'txt','application/pdf':'pdf','image/png':'png'});
export const MAX_SUBMISSION_ARCHIVE=20*1024*1024;
const fail=()=>{throw Error('submission verification failed');};
const json=b=>{try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b));}catch{fail();}};
const keys=(o,k)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));

// Both expected hashes must be obtained from a trusted channel independent
// of the archive. This verifies exact bytes, not identity, current permission,
// legal validity, malware status, delivery or recipient acceptance.
// No file extraction, decompression, external calls or archive execution.
export function verifySubmissionPackage(archive,{expectedPackageSha256,expectedManifestSha256}={}){
 if(!Buffer.isBuffer(archive)||archive.length<22||archive.length>MAX_SUBMISSION_ARCHIVE||
 !digest(expectedPackageSha256)||!digest(expectedManifestSha256)||hash(archive)!==expectedPackageSha256)fail();
 const files=[],names=new Set();let pos=0;
 while(pos+4<=archive.length&&archive.readUInt32LE(pos)===0x04034b50){
  if(files.length>=69||pos+30>archive.length)fail();
  const n=archive.readUInt16LE(pos+26),size=archive.readUInt32LE(pos+22);
  if(n<1||n>64||size<1||size>2097152||archive.readUInt16LE(pos+28)!==0||
   archive.readUInt16LE(pos+6)!==0||archive.readUInt16LE(pos+8)!==0||
   archive.readUInt32LE(pos+18)!==size||pos+30+n+size>archive.length)fail();
  const raw=archive.subarray(pos+30,pos+30+n),name=raw.toString('utf8');
  if(!Buffer.from(name,'ascii').equals(raw)||names.has(name)||
   !(/^(submission\.json|package-index\.json|handover-cover\.pdf|requirement-register\.csv|evidence-register\.csv|evidence-[a-f0-9-]{36}\.(txt|pdf|png))$/.test(name)))fail();
  names.add(name);files.push([name,archive.subarray(pos+30+n,pos+30+n+size)]);pos+=30+n+size;
 }
 if(files.length<3||files[0][0]!=='submission.json'||files.at(-1)[0]!=='package-index.json')fail();
 // Rebuild the single supported canonical STORE representation. This also
 // validates CRCs, central directory, local offsets, flags and end record.
 const canonical=zip(files);
 try{if(!canonical.equals(archive))fail();}finally{canonical.fill(0);}
 const manifestBytes=files[0][1];
 if(hash(manifestBytes)!==expectedManifestSha256)fail();
 const m=json(manifestBytes),index=json(files.at(-1)[1]);
 if(m?.version!==1||!uuid(m.tenantId)||!uuid(m.projectId)||m.summary?.status!=='criteria_satisfied'||
 !Array.isArray(m.evidence)||m.evidence.length<1||m.evidence.length>64)fail();
 const extended=index?.version===2,extra=extended?3:0;
 if(files.length!==m.evidence.length+2+extra||!(extended?keys(index,['version','profile','authorization','files'])&&HANDOVER_PROFILES.includes(index.profile):keys(index,['version','authorization','files'])&&index.version===1)||
 !uuid(index.authorization?.submissionId)||index.authorization.sha256!==expectedManifestSha256||
 index.authorization.authorization!=='internal owner-authorized download only'||
 !Array.isArray(index.files)||index.files.length!==files.length-1)fail();
 const ids=new Set();let total=0;
 for(let i=0;i<m.evidence.length;i++){
  const e=m.evidence[i],entry=files[i+1];
  if(!uuid(e?.id)||ids.has(e.id)||!digest(e.sha256)||!Object.hasOwn(types,e.mediaType)||
  !Number.isInteger(e.bytes)||e.bytes<1||e.bytes>262144||
  entry[0]!=='evidence-'+e.id+'.'+types[e.mediaType]||entry[1].length!==e.bytes||hash(entry[1])!==e.sha256)fail();
  ids.add(e.id);total+=e.bytes;
 }
 if(total>16777216)fail();
 if(extended){let derived;try{derived=buildHandoverDerivatives(m,expectedManifestSha256,index.profile);for(let i=0;i<derived.length;i++){const actual=files[m.evidence.length+1+i];if(actual[0]!==derived[i][0]||!actual[1].equals(derived[i][1]))fail();}}catch{fail();}finally{for(const [,b] of derived??[])b.fill(0);}}
 for(let i=0;i<index.files.length;i++){
  const e=index.files[i],entry=files[i];
  if(!keys(e,['name','bytes','sha256'])||e.name!==entry[0]||e.bytes!==entry[1].length||e.sha256!==hash(entry[1]))fail();
 }
 return Object.freeze({integrityVerified:true,packageSha256:expectedPackageSha256,
 manifestSha256:expectedManifestSha256,submissionId:index.authorization.submissionId,
 evidenceCount:ids.size,evidenceBytes:total,authenticityVerified:false});
}
