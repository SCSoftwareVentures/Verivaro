// Deterministic derived files. Original attachments are never rewritten.
import {createRegisterXlsx} from './xlsx-register.mjs';
export const HANDOVER_PROFILES=Object.freeze(['handover-v1','register-v1','workbook-v1']);
export function normalizeHandoverConfig(c){
 if(!c||typeof c!=='object'||Array.isArray(c)||Object.keys(c).sort().join(',')!=='heading,includeWorkbook,order,version'||c.version!==1||typeof c.heading!=='string'||c.heading.trim()!==c.heading||[...c.heading].length<1||[...c.heading].length>80||/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ud800-\udfff]/u.test(c.heading)||!['requirements_first','evidence_first'].includes(c.order)||typeof c.includeWorkbook!=='boolean')throw Error('invalid custom handover configuration');
 return {version:1,heading:c.heading,order:c.order,includeWorkbook:c.includeWorkbook};
}
const uuid=x=>typeof x==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(x);
const sha=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const ext={'text/plain; charset=utf-8':'txt','application/pdf':'pdf','image/png':'png'};
const invalid=()=>{throw Error('invalid handover source');};
const text=(s,n)=>typeof s==='string'&&[...s].length<=n&&!/[\x00-\x1f\x7f-\x9f]/u.test(s);
export function csvCell(value){
 let s=String(value??'');
 // Prevent formula invocation even after whitespace or Unicode BOM.
 if(/^[\s\uFEFF]*[=+\-@]/u.test(s)||/^[\t\r\n]/.test(s))s="'"+s;
 return '"'+s.replaceAll('"','""')+'"';
}
const csv=rows=>Buffer.from(rows.map(r=>r.map(csvCell).join(',')).join('\r\n')+'\r\n','utf8');
const ascii=s=>[...String(s)].map(c=>{const n=c.codePointAt(0);return n>=32&&n<=126?c:'[U+'+n.toString(16).toUpperCase()+']';}).join('');
const lit=s=>'('+ascii(s).replace(/[\\()]/g,'\\$&')+')';
function pdf(lines,profile){
 const wrapped=lines.flatMap(s=>{const a=ascii(s),parts=[];for(let i=0;i<Math.max(1,a.length);i+=88)parts.push(a.slice(i,i+88));return parts;});
 if(wrapped.length>2200)invalid();
 const pages=[];for(let i=0;i<wrapped.length;i+=46)pages.push(wrapped.slice(i,i+46));
 const objects=['<< /Type /Catalog /Pages 2 0 R >>','','<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>','<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>'],kids=[];
 for(const [i,p] of pages.entries()){
  const page=objects.length+1,streamId=page+1;kids.push(page+' 0 R');
  let stream='0.08 0.18 0.27 rg 0 760 595 82 re f\n1 1 1 rg BT /F1 18 Tf 42 802 Td (VERIVARO | HANDOVER) Tj ET\n1 1 1 rg BT /F1 10 Tf 42 780 Td '+lit(profile==='draft-v1'?'DRAFT - NOT APPROVED FOR RELEASE':profile+' | INTERNAL OWNER-AUTHORIZED SNAPSHOT')+' Tj ET\n0.12 0.19 0.25 rg\n';
  if(profile==='draft-v1')stream+='0.90 0.90 0.90 rg BT /F1 35 Tf 90 390 Td (DRAFT - NOT APPROVED) Tj ET\n0.12 0.19 0.25 rg\n';
  p.forEach((s,j)=>{stream+='BT /F2 9 Tf 42 '+(735-j*14)+' Td '+lit(s)+' Tj ET\n';});
  stream+='BT /F1 9 Tf 42 42 Td '+lit('Page '+(i+1)+' / '+pages.length+' | Not proof of delivery or acceptance')+' Tj ET\n';
  objects.push('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents '+streamId+' 0 R >>','<< /Length '+Buffer.byteLength(stream)+' >>\nstream\n'+stream+'endstream');
 }
 objects[1]='<< /Type /Pages /Count '+kids.length+' /Kids ['+kids.join(' ')+'] >>';
 let out='%PDF-1.4\n';const offsets=[0];objects.forEach((o,i)=>{offsets.push(Buffer.byteLength(out));out+=(i+1)+' 0 obj\n'+o+'\nendobj\n';});
 const x=Buffer.byteLength(out);out+='xref\n0 '+offsets.length+'\n0000000000 65535 f \n'+offsets.slice(1).map(n=>String(n).padStart(10,'0')+' 00000 n \n').join('')+'trailer\n<< /Size '+offsets.length+' /Root 1 0 R >>\nstartxref\n'+x+'\n%%EOF\n';
 const result=Buffer.from(out,'ascii');if(result.length>1048576)invalid();return result;
}
export function buildHandoverDerivatives(m,manifestSha256,profile){
 const custom=typeof profile==='object'&&profile!==null?normalizeHandoverConfig(profile):null;
 if(!custom&&!HANDOVER_PROFILES.includes(profile)||!sha(manifestSha256)||m?.version!==1||!uuid(m.tenantId)||!uuid(m.projectId)||!text(m.projectName,128)||m.summary?.status!=='criteria_satisfied'||!Array.isArray(m.requirements)||m.requirements.length<1||m.requirements.length>128||!Array.isArray(m.evidence)||m.evidence.length<1||m.evidence.length>64)invalid();
 const objects=new Map(),requirements=new Set(),links=new Map();
 for(const e of m.evidence){if(!uuid(e.id)||objects.has(e.id)||!sha(e.sha256)||!Object.hasOwn(ext,e.mediaType)||!Number.isInteger(e.bytes)||e.bytes<1||e.bytes>262144)invalid();objects.set(e.id,e);links.set(e.id,[]);}
 const rows=[['requirement_id','version_id','title','applicability','state','evidence_ids','source_id']];
 for(const q of m.requirements){
  if(!uuid(q.requirementId)||!uuid(q.versionId)||requirements.has(q.requirementId)||!text(q.title,128)||!['required','optional','not_applicable'].includes(q.applicability)||!['satisfied','not_applicable'].includes(q.state)||q.ruleDecision!=='approved'||!Array.isArray(q.links)||q.links.length>8)invalid();
  requirements.add(q.requirementId);
  const ids=new Set();
  for(const l of q.links){if(!objects.has(l.evidenceId)||objects.get(l.evidenceId).sha256!==l.sha256)invalid();ids.add(l.evidenceId);}
  const source=q.source?.evidenceId??null;
  if(source!==null&&!objects.has(source))invalid();
  for(const e of new Set([...ids,...(source?[source]:[])]))links.get(e).push(q.requirementId);
  rows.push([q.requirementId,q.versionId,q.title,q.applicability,q.state,[...ids].sort().join(';'),source]);
 }
 if([...links.values()].some(x=>!x.length))invalid();
 const ordered=[...objects.values()].sort((a,b)=>a.id.localeCompare(b.id)),inventory=[['evidence_id','attachment','bytes','sha256','media_type','requirement_ids']];
 for(const e of ordered)inventory.push([e.id,'evidence-'+e.id+'.'+ext[e.mediaType],e.bytes,e.sha256,e.mediaType,links.get(e.id).sort().join(';')]);
 const intro=[...(custom?['Presentation heading: '+custom.heading]:[]),'Project: '+m.projectName,'Project ID: '+m.projectId,'Manifest SHA-256: '+manifestSha256,'Reviewed documentary snapshot only. Not legal certification.','Originals are separate unmodified attachments.','See CSV registers and submission.json for exact Unicode and references.','Requirements: '+requirements.size+' | Evidence files: '+objects.size,''];
 const reqLines=['REQUIREMENT INDEX',...rows.slice(1).flatMap(r=>[r[2]+' | '+r[4],r[0]+' version '+r[1]])];
 const evidenceLines=['EVIDENCE INDEX',...inventory.slice(1).flatMap(r=>[r[1]+' | '+r[2]+' bytes','SHA-256: '+r[3]])];
 const generated=[['handover-cover.pdf',pdf([...intro,...((custom?custom.order==='requirements_first':profile==='handover-v1')?[...reqLines,'',...evidenceLines]:[...evidenceLines,'',...reqLines])],custom?'custom-v1':profile)],['requirement-register.csv',csv(rows)],['evidence-register.csv',csv(inventory)]];
 if(profile==='workbook-v1'||custom?.includeWorkbook)generated.push(['evidence-register.xlsx',createRegisterXlsx(rows,inventory)]);
 if(generated.some(([,b])=>b.length>1048576))invalid();return generated;
}

export function buildDraftHandoverPdf(g){
 if(!g||g.version!==1||!uuid(g.tenantId)||!uuid(g.projectId)||!g.summary||!['blocked','not_assessed','criteria_satisfied'].includes(g.summary.status)||!Array.isArray(g.requirements)||g.requirements.length>128)invalid();
 const lines=['DRAFT - NOT APPROVED FOR RELEASE','Project ID: '+g.projectId,'Assessment: '+g.summary.status,'This is an internal planning cover, not a frozen submission.','No original evidence files included. Independent review and authorization required.','Do not represent this draft as ready, delivered or accepted.',''];
 for(const q of g.requirements){if(!uuid(q.requirementId)||!uuid(q.versionId)||!text(q.title,128)||!text(q.state,64)||!text(q.applicability,64))invalid();lines.push(q.title+' | '+q.applicability+' | '+q.state,q.requirementId+' version '+q.versionId);}
 return pdf(lines,'draft-v1');
}
