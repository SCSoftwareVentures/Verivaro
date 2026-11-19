import {createHash} from 'node:crypto';
const digest=b=>createHash('sha256').update(b).digest('hex');
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const hash=/^[a-f0-9]{64}$/;
const MAX_JSON=2*1024*1024,MAX_PDF=8*1024*1024,MAX_PAGES=1000;
const states=['pending','approved','rejected','expired','released','revoked','closed'];
function invalid(){throw Error('invalid verification snapshot');}
function id(x){if(typeof x!=='string'||!uuid.test(x))invalid();return x;}
function sha(x){if(typeof x!=='string'||!hash.test(x))invalid();return x;}
function count(x,max=Number.MAX_SAFE_INTEGER){if(!Number.isSafeInteger(x)||x<0||x>max)invalid();return x;}
function date(x,nullable=false){if(nullable&&x===null)return '-';if(typeof x!=='string'||x.length>40||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/.test(x)||!Number.isFinite(Date.parse(x)))invalid();return new Date(x).toISOString();}
function label(x,max=256){if(typeof x!=='string'||[...x].length>max||/[\x00-\x1f\x7f-\x9f]/u.test(x))invalid();return x;}
// Preserve unsupported Unicode visibly as codepoints in the PDF. The exact
// original string remains in the companion JSON, without silent transliteration.
function display(x){return [...x].map(c=>{const n=c.codePointAt(0);return n>=32&&n<=126?c:'[U+'+n.toString(16).toUpperCase().padStart(4,'0')+']';}).join('');}
function literal(x){return '('+x.replace(/[\\()]/g,'\\$&')+')';}
function wrap(x,width){const a=[];for(let i=0;i<x.length;i+=width)a.push(x.slice(i,i+width));return a.length?a:[''];}
function inspect(report){
 if(!report||report.version!==1||!report.project||!report.summary||!Array.isArray(report.evidence)||!Array.isArray(report.reviews)||report.evidence.length>4096||report.reviews.length>2048||report.attestation!=='unsigned database snapshot; not an independently signed custody checkpoint')invalid();
 id(report.tenantId);id(report.project.id);label(report.project.name);count(report.project.revision,2147483647);date(report.generatedAt);date(report.project.archivedAt,true);
 const known=new Map(),reviews=new Set(),actual=Object.create(null);let bytes=0,encrypted=0;
 for(const e of report.evidence){
  id(e.id);sha(e.sha256);date(e.registeredAt);if(known.has(e.id))invalid();known.set(e.id,e.sha256);
  if(e.storage==='encrypted'){encrypted++;const n=count(e.bytes,262144);if(!n)invalid();bytes+=n;if(!['text/plain; charset=utf-8','application/pdf','image/png'].includes(e.mediaType)||!['clamd-instream-text-v1','clamd-instream-format-v2'].includes(e.scanPolicy))invalid();}
  else if(e.storage!=='legacy'||e.bytes!==null||e.mediaType!==null||e.scanPolicy!==null)invalid();
 }
 for(const r of report.reviews){
  id(r.id);id(r.evidenceId);sha(r.sha256);if(reviews.has(r.id)||known.get(r.evidenceId)!==r.sha256||!states.includes(r.state))invalid();reviews.add(r.id);
  date(r.submittedAt);date(r.reviewedAt,true);date(r.releasedAt,true);
  if(r.decision!==null&&!['approved','rejected'].includes(r.decision))invalid();
  if(r.reason!==null&&!['verified','integrity_concern','insufficient_evidence','policy_denied'].includes(r.reason))invalid();
  actual[r.state]=(actual[r.state]??0)+1;
 }
 const s=report.summary;
 if(s.evidence!==known.size||s.encrypted!==encrypted||s.bytes!==bytes||s.requests!==reviews.size||!s.states||Object.keys(s.states).length!==Object.keys(actual).length||Object.entries(actual).some(([k,n])=>s.states[k]!==n))invalid();
}
function text(x,y,size,value,font='F1',color='0.13 0.20 0.27'){return color+' rg BT /'+font+' '+size+' Tf 1 0 0 1 '+x+' '+y+' Tm '+literal(value)+' Tj ET\n';}
function pageFrame(n,total,report){
 return '0.08 0.18 0.27 rg 0 760 595 82 re f\n'+text(42,805,20,'VERIVARO','F2','1 1 1')+text(42,782,10,'VERIFICATION REPORT  /  CONFIDENTIAL','F1','0.83 0.90 0.94')+
 text(42,32,8,'Unsigned snapshot | '+report.project.id,'F1')+text(490,32,8,String(n)+' / '+String(total),'F2')+'0.78 0.84 0.88 RG 42 47 m 553 47 l S\n';
}
export function createVerificationPdf(report,jsonDigest){
 inspect(report);sha(jsonDigest);
 const pages=[];let commands='',y=730;
 function start(){if(commands)pages.push(commands);if(pages.length>=MAX_PAGES)throw Error('report page limit');commands='';y=730;}
 function need(height){if(y-height<63)start();}
 function heading(x){need(36);commands+='0.90 0.94 0.96 rg 42 '+(y-6)+' 511 24 re f\n'+text(50,y+1,13,x,'F2');y-=38;}
 function line(x,{bold=false,mono=false}={}){for(const w of wrap(display(String(x)),mono?92:50)){need(13);commands+=text(48,y,mono?8:10,w,mono?'F3':bold?'F2':'F1');y-=13;}}
 function gap(){y-=9;}
 heading('Project overview');
 line('Project: '+report.project.name,{bold:true});line('Project ID: '+report.project.id,{mono:true});line('Tenant ID: '+report.tenantId,{mono:true});
 line('Generated (UTC): '+date(report.generatedAt));line('Revision: '+report.project.revision+' | '+(report.project.archivedAt===null?'Active':'Archived '+date(report.project.archivedAt)));
 gap();heading('Verification summary');
 line('Registered evidence: '+report.summary.evidence+' | Encrypted: '+report.summary.encrypted+' | Legacy: '+(report.summary.evidence-report.summary.encrypted),{bold:true});
 line('Encrypted evidence bytes: '+report.summary.bytes);line('Review requests: '+report.summary.requests);
 for(const s of states)if(report.summary.states[s]!==undefined)line(s+': '+report.summary.states[s]);
 gap();heading('Integrity and interpretation');
 line('UNSIGNED DATABASE SNAPSHOT',{bold:true});line('This report records stored evidence metadata and review decisions.');line('It does not independently prove authorship, factual accuracy or delivery.');line('Legacy evidence lacks encrypted-object scan and size metadata.');line('Use a separately trusted signed custody checkpoint for historical attestation.');line('Non-ASCII characters are represented as Unicode codepoints here; see JSON.');
 line('SHA-256 of the exact companion JSON:',{bold:true});line(jsonDigest,{mono:true});
 start();heading('Evidence register');
 if(!report.evidence.length)line('No registered evidence.');
 for(const [i,e] of report.evidence.entries()){
  need(111);line(String(i+1)+'. '+e.id,{bold:true});line('SHA-256: '+e.sha256,{mono:true});
  line('Registered (UTC): '+date(e.registeredAt));line('Storage: '+e.storage+(e.bytes===null?' | Size unavailable':' | '+e.bytes+' bytes'));
  line('Media: '+(e.mediaType??'unavailable')+' | Scan policy: '+(e.scanPolicy??'unavailable'));gap();
 }
 start();heading('Review and release history');
 if(!report.reviews.length)line('No review requests.');
 for(const [i,r] of report.reviews.entries()){
  need(125);line(String(i+1)+'. '+r.id+' | '+r.state,{bold:true});line('Evidence: '+r.evidenceId,{mono:true});line('SHA-256: '+r.sha256,{mono:true});
  line('Submitted: '+date(r.submittedAt));line('Reviewed: '+date(r.reviewedAt,true));line('Decision: '+(r.decision??'-')+' | Reason: '+(r.reason??'-'));line('Released: '+date(r.releasedAt,true));gap();
 }
 if(commands)pages.push(commands);
 if(pages.length>MAX_PAGES)throw Error('report page limit');
 const objects=['<< /Type /Catalog /Pages 2 0 R >>','', '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>','<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>','<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>'];
 const ids=[];
 for(const [i,p] of pages.entries()){
  const pageId=objects.length+1,contentId=pageId+1;ids.push(pageId+' 0 R');
  const stream=pageFrame(i+1,pages.length,report)+p;
  objects.push('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents '+contentId+' 0 R >>','<< /Length '+Buffer.byteLength(stream)+' >>\nstream\n'+stream+'endstream');
 }
 objects[1]='<< /Type /Pages /Count '+pages.length+' /Kids ['+ids.join(' ')+'] >>';
 const parts=['%PDF-1.4\n'],offsets=[0];let offset=Buffer.byteLength(parts[0]);
 for(const [i,obj] of objects.entries()){offsets.push(offset);const part=(i+1)+' 0 obj\n'+obj+'\nendobj\n';parts.push(part);offset+=Buffer.byteLength(part);if(offset>MAX_PDF)throw Error('PDF capacity exceeded');}
 parts.push('xref\n0 '+offsets.length+'\n0000000000 65535 f \n'+offsets.slice(1).map(n=>String(n).padStart(10,'0')+' 00000 n \n').join('')+'trailer\n<< /Size '+offsets.length+' /Root 1 0 R >>\nstartxref\n'+offset+'\n%%EOF\n');
 const out=Buffer.from(parts.join(''),'ascii');if(out.length>MAX_PDF)throw Error('PDF capacity exceeded');return out;
}
// ZIP STORE only, fixed filenames, no paths, no compression or executable data.
const table=Array.from({length:256},(_,n)=>{let c=n;for(let i=0;i<8;i++)c=c&1?0xedb88320^(c>>>1):c>>>1;return c>>>0;});
function crc(b){let c=0xffffffff;for(const v of b)c=table[(c^v)&255]^(c>>>8);return (c^0xffffffff)>>>0;}
function zip(files){
 const local=[],central=[];let offset=0,centralSize=0;
 for(const [name,data] of files){
  const n=Buffer.from(name,'ascii'),sum=crc(data),h=Buffer.alloc(30),c=Buffer.alloc(46);
  h.writeUInt32LE(0x04034b50);h.writeUInt16LE(20,4);h.writeUInt16LE(33,12);h.writeUInt32LE(sum,14);h.writeUInt32LE(data.length,18);h.writeUInt32LE(data.length,22);h.writeUInt16LE(n.length,26);
  c.writeUInt32LE(0x02014b50);c.writeUInt16LE(20,4);c.writeUInt16LE(20,6);c.writeUInt16LE(33,14);c.writeUInt32LE(sum,16);c.writeUInt32LE(data.length,20);c.writeUInt32LE(data.length,24);c.writeUInt16LE(n.length,28);c.writeUInt32LE(offset,42);
  local.push(h,n,data);central.push(c,n);offset+=h.length+n.length+data.length;centralSize+=c.length+n.length;
 }
 const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(files.length,8);end.writeUInt16LE(files.length,10);end.writeUInt32LE(centralSize,12);end.writeUInt32LE(offset,16);
 return Buffer.concat([...local,...central,end]);
}
export function createVerificationExport(report,format){
 if(!['pdf','zip'].includes(format))invalid();
 inspect(report);const json=Buffer.from(JSON.stringify(report));if(json.length>MAX_JSON)throw Error('report capacity exceeded');
 const pdf=createVerificationPdf(report,digest(json));
 if(format==='pdf')return pdf;
 const files=[['verification.json',json],['verification.pdf',pdf]];
 const manifest=Buffer.from(JSON.stringify({version:1,projectId:report.project.id,tenantId:report.tenantId,generatedAt:report.generatedAt,attestation:report.attestation,files:files.map(([name,data])=>({name,bytes:data.length,sha256:digest(data)}))},null,2)+'\n');
 return zip([...files,['manifest.json',manifest]]);
}
