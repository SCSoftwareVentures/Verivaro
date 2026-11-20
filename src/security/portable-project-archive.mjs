import {createHash} from 'node:crypto';
import {zip} from './verification-report-export.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex'),id=x=>typeof x==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(x),sha=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x),types=Object.freeze({'text/plain; charset=utf-8':'txt','application/pdf':'pdf','image/png':'png','application/vnd.openxmlformats-officedocument.wordprocessingml.document':'docx','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':'xlsx'}),fail=()=>{throw Error('portable archive invalid');};
const LIMIT=20*1024*1024;
function inventory(m){
 if(!m||m.version!==1||!id(m.tenantId)||!id(m.projectId)||m.classification!=='internal preservation copy; not approval or full database backup'||m.report?.tenantId!==m.tenantId||m.report?.project?.id!==m.projectId||!m.report.project.archivedAt||m.assessment?.tenantId!==m.tenantId||m.assessment?.projectId!==m.projectId||m.assessment.archived!==true||m.lifecycle?.tenantId!==m.tenantId||m.lifecycle?.projectId!==m.projectId||m.lifecycle.archived!==true||m.lifecycle.executionEnabled!==false||!Array.isArray(m.report.evidence)||m.report.evidence.length>64)fail();
 let total=0;const seen=new Set();return m.report.evidence.map(e=>{if(!id(e.id)||seen.has(e.id)||!sha(e.sha256)||!Object.hasOwn(types,e.mediaType)||e.storage!=='encrypted'||!Number.isInteger(e.bytes)||e.bytes<1||e.bytes>262144)fail();seen.add(e.id);total+=e.bytes;if(total>16777216)fail();return {...e,name:'evidence-'+e.id+'.'+types[e.mediaType]};});
}
export function createPortableProjectArchive({workflow,retrieve}){
 if(typeof workflow?.portableArchiveInventory!=='function'||typeof retrieve!=='function')throw Error('invalid archive service');
 return async function assemble(input,{signal}){
  const files=[];let out;
  try{
   signal.throwIfAborted();const m=await workflow.portableArchiveInventory(input);if(m.tenantId!==input.tenantId||m.projectId!==input.projectId)fail();const entries=inventory(m),manifest=Buffer.from(JSON.stringify(m),'utf8');files.push(['project-inventory.json',manifest]);if(manifest.length>2097152)fail();
   for(const e of entries){signal.throwIfAborted();const r=await retrieve({...input,evidenceId:e.id});if(!Buffer.isBuffer(r.data)||r.mediaType!==e.mediaType||r.sha256!==e.sha256||r.data.length!==e.bytes||hash(r.data)!==e.sha256){r.data?.fill?.(0);fail();}files.push([e.name,r.data]);}
   const latest=await workflow.portableArchiveInventory(input);signal.throwIfAborted();if(JSON.stringify(latest)!==manifest.toString('utf8'))fail();
   files.push(['archive-index.json',Buffer.from(JSON.stringify({version:1,tenantId:m.tenantId,projectId:m.projectId,files:files.map(([name,b])=>({name,bytes:b.length,sha256:hash(b)}))}))]);
   out=zip(files);if(out.length>LIMIT)fail();return out;
  }catch(e){out?.fill(0);throw e;}finally{for(const [,b] of files)b.fill(0);}
 };
}
export function verifyPortableProjectArchive(archive,{expectedArchiveSha256,expectedTenantId,expectedProjectId}={}){
 if(!Buffer.isBuffer(archive)||archive.length<22||archive.length>LIMIT||!sha(expectedArchiveSha256)||hash(archive)!==expectedArchiveSha256||!id(expectedTenantId)||!id(expectedProjectId))fail();
 const files=[],seen=new Set();let pos=0;
 while(pos+4<=archive.length&&archive.readUInt32LE(pos)===0x04034b50){
  if(files.length>=66||pos+30>archive.length)fail();const n=archive.readUInt16LE(pos+26),size=archive.readUInt32LE(pos+22);
  if(n<1||n>64||size<1||size>2097152||archive.readUInt16LE(pos+28)!==0||archive.readUInt16LE(pos+6)!==0||archive.readUInt16LE(pos+8)!==0||archive.readUInt32LE(pos+18)!==size||pos+30+n+size>archive.length)fail();
  const raw=archive.subarray(pos+30,pos+30+n),name=raw.toString('utf8');if(!Buffer.from(name,'ascii').equals(raw)||seen.has(name)||!/^(project-inventory\.json|archive-index\.json|evidence-[a-f0-9-]{36}\.(txt|pdf|png|docx|xlsx))$/.test(name))fail();seen.add(name);files.push([name,archive.subarray(pos+30+n,pos+30+n+size)]);pos+=30+n+size;
 }
 if(files.length<2||files[0][0]!=='project-inventory.json'||files.at(-1)[0]!=='archive-index.json')fail();
 const canonical=zip(files);try{if(!canonical.equals(archive))fail();}finally{canonical.fill(0);}
 const parse=b=>JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b)),m=parse(files[0][1]),index=parse(files.at(-1)[1]),entries=inventory(m);
 if(m.tenantId!==expectedTenantId||m.projectId!==expectedProjectId||index?.version!==1||index.tenantId!==m.tenantId||index.projectId!==m.projectId||files.length!==entries.length+2||!Array.isArray(index.files)||index.files.length!==files.length-1)fail();
 for(let i=0;i<entries.length;i++){const e=entries[i],[name,b]=files[i+1];if(name!==e.name||b.length!==e.bytes||hash(b)!==e.sha256)fail();}
 for(let i=0;i<index.files.length;i++){const [name,b]=files[i],x=index.files[i];if(x.name!==name||x.bytes!==b.length||x.sha256!==hash(b))fail();}
 return {version:1,tenantId:m.tenantId,projectId:m.projectId,evidenceCount:entries.length,inventorySha256:hash(files[0][1]),integrityVerified:true,authenticityVerified:false,restorePerformed:false};
}
