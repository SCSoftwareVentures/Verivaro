import {createHash} from 'node:crypto';
const hash=b=>createHash('sha256').update(b).digest('hex');
const limit=16*1024*1024;
const xml=s=>String(s).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]/g,'\ufffd').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;');
function crc32(b){let c=0xffffffff;for(const v of b){c^=v;for(let j=0;j<8;j++)c=(c>>>1)^((c&1)?0xedb88320:0);}return (c^0xffffffff)>>>0;}
/** Small deterministic STORE-only ZIP; canonical internal filenames, no path traversal or compression bombs. */
export function zipStore(entries){
 const chunks=[],central=[],seen=new Set();let offset=0;
 if(entries.length>100)throw Error('zip entry limit');
 for(const [name,value] of entries){
 if(typeof name!=='string'||!(name==='[Content_Types].xml'||/^[A-Za-z0-9_.\/-]+$/.test(name))||name.startsWith('/')||name.split('/').some(x=>!x||x==='.'||x==='..')||seen.has(name))throw Error('invalid archive name');
 seen.add(name);const n=Buffer.from(name),b=Buffer.from(value),crc=crc32(b);
 if(offset+b.length>limit)throw Error('archive limit');
 const l=Buffer.alloc(30);l.writeUInt32LE(0x04034b50);l.writeUInt16LE(20,4);l.writeUInt16LE(0x21,12);l.writeUInt32LE(crc,14);l.writeUInt32LE(b.length,18);l.writeUInt32LE(b.length,22);l.writeUInt16LE(n.length,26);
 const c=Buffer.alloc(46);c.writeUInt32LE(0x02014b50);c.writeUInt16LE(20,4);c.writeUInt16LE(20,6);c.writeUInt16LE(0x21,14);c.writeUInt32LE(crc,16);c.writeUInt32LE(b.length,20);c.writeUInt32LE(b.length,24);c.writeUInt16LE(n.length,28);c.writeUInt32LE(offset,42);
 chunks.push(l,n,b);central.push(c,n);offset+=l.length+n.length+b.length;
 }
 const directory=Buffer.concat(central),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(entries.length,8);end.writeUInt16LE(entries.length,10);end.writeUInt32LE(directory.length,12);end.writeUInt32LE(offset,16);
 return Buffer.concat([...chunks,directory,end]);
}
function xlsx(rows){
 const ns='http://schemas.openxmlformats.org/spreadsheetml/2006/main',rel='http://schemas.openxmlformats.org/package/2006/relationships',office='http://schemas.openxmlformats.org/officeDocument/2006/relationships';
 const sheet=rows.map((r,i)=>'<row r="'+(i+1)+'">'+r.map((v,j)=>'<c r="'+String.fromCharCode(65+j)+(i+1)+'" t="inlineStr"><is><t xml:space="preserve">'+xml(v)+'</t></is></c>').join('')+'</row>').join('');
 return zipStore([
 ['[Content_Types].xml','<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'],
 ['_rels/.rels','<Relationships xmlns="'+rel+'"><Relationship Id="rId1" Type="'+office+'/officeDocument" Target="xl/workbook.xml"/></Relationships>'],
 ['xl/workbook.xml','<workbook xmlns="'+ns+'" xmlns:r="'+office+'"><sheets><sheet name="Handover index" sheetId="1" r:id="rId1"/></sheets></workbook>'],
 ['xl/_rels/workbook.xml.rels','<Relationships xmlns="'+rel+'"><Relationship Id="rId1" Type="'+office+'/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'],
 ['xl/worksheets/sheet1.xml','<worksheet xmlns="'+ns+'"><sheetData>'+sheet+'</sheetData></worksheet>']
 ]);
}
// ASCII-only summary PDF; non-ASCII explicitly escaped as U+ codepoints (exact Unicode in JSON/XLSX).
const ascii=s=>[...String(s)].map(c=>c.charCodeAt(0)>=32&&c.charCodeAt(0)<=126?c:'[U+'+c.codePointAt(0).toString(16).toUpperCase()+']').join('');
const pdfEscape=s=>s.replace(/([\\()])/g,'\\$1');
function pdf(lines){
 const wrapped=lines.flatMap(s=>{const a=ascii(s);return a.match(/.{1,88}/g)??[''];});
 const pages=[];for(let i=0;i<wrapped.length;i+=48)pages.push(wrapped.slice(i,i+48));
 const objects=['<< /Type /Catalog /Pages 2 0 R >>','', '<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>'];
 const kids=[];
 for(const page of pages){const id=objects.length+1;kids.push(id+' 0 R');const stream='BT /F1 9 Tf 36 790 Td 15 TL '+page.map((s,i)=>(i?'T* ':'')+'('+pdfEscape(s)+') Tj').join('\n')+'\nET\n';
 objects.push('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents '+(id+1)+' 0 R >>','<< /Length '+Buffer.byteLength(stream)+' >>\nstream\n'+stream+'endstream');}
 objects[1]='<< /Type /Pages /Count '+kids.length+' /Kids ['+kids.join(' ')+'] >>';
 let out='%PDF-1.4\n',offsets=[];for(let i=0;i<objects.length;i++){offsets.push(Buffer.byteLength(out));out+=(i+1)+' 0 obj\n'+objects[i]+'\nendobj\n';}
 const start=Buffer.byteLength(out);out+='xref\n0 '+(objects.length+1)+'\n0000000000 65535 f \n'+offsets.map(x=>String(x).padStart(10,'0')+' 00000 n \n').join('')+'trailer\n<< /Size '+(objects.length+1)+' /Root 1 0 R >>\nstartxref\n'+start+'\n%%EOF\n';return Buffer.from(out);
}
export function renderDraft(manifest,kind){
 if(typeof manifest?.json!=='string'||hash(manifest.json)!==manifest.sha256||manifest.releaseAuthorised!==false||Buffer.byteLength(manifest.json)>8*1024*1024)throw Error('invalid draft manifest');
 const m=JSON.parse(manifest.json);
 const status=manifest.stale?'STALE - HISTORICAL DRAFT':'INTERNAL DRAFT - NOT RELEASED';
 const rows=[['Verivaro handover',status],['Draft',m.id],['Generation',m.generation],['As of',m.asOf],['Disposition at snapshot',m.disposition],['Manifest SHA256',manifest.sha256],['Notice','Configured checks only. No certification or release.'],['Document version','Revision','Original SHA256','Extracted text SHA256','Current']];
 for(const d of m.sources)rows.push([d.id,d.revision,d.originalSha256??'',d.textSha256,String(d.current)]);
 rows.push(['Requirement','Revision','Status','Blocker','Reason']);
 for(const f of m.report.findings)rows.push([f.requirementId,f.revision,f.status,String(f.blocker),f.reason]);
 const summary=pdf(rows.map(r=>r.join(' | ')));
 const workbook=xlsx(rows);
 if(kind==='pdf')return {bytes:summary,type:'application/pdf',filename:'handover-draft.pdf'};
 if(kind==='xlsx')return {bytes:workbook,type:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',filename:'handover-draft.xlsx'};
 if(kind==='zip'){
 const contents=[['manifest.json',Buffer.from(manifest.json)],['handover-draft.pdf',summary],['handover-draft.xlsx',workbook]];
 const checks=contents.map(([n,b])=>hash(b)+'  '+n).join('\n')+'\n';
 const bytes=zipStore([...contents,['SHA256SUMS.txt',Buffer.from(checks)],['NOTICE.txt',Buffer.from(status+'\nNo original documents, signatures or release authorisation included.\n')]]);
 return {bytes,type:'application/zip',filename:'handover-draft.zip'};
 }
 throw Error('unsupported format');
}

export function renderCorrectionCover(cover){
 if(cover?.releaseAuthorised!==false||cover.originalUnchanged!==true)throw Error('invalid correction cover');
 const lines=[cover.title,'Not a certificate, customer release or evidence modification.','Notice: '+cover.noticeId,'Plan revision: '+cover.planRevision,'Case revision: '+cover.caseRevision,'Target document version: '+cover.documentVersionId,'Original SHA256: '+cover.originalSha256,'Proposed submission filename: '+cover.proposedFilename,'Reviewer note: '+cover.reviewNote];
 return {bytes:pdf(lines),type:'application/pdf',filename:'correction-cover.pdf'};
}
