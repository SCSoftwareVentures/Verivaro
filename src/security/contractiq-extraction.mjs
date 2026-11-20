import {createHash} from 'node:crypto';
import {validateEvidence} from './evidence-objects.mjs';
import {readCanonicalPdfPages} from './evidence-formats.mjs';
import {extractOfficeSpans} from './office-extraction.mjs';
import {ReleaseDenied,ReleaseConflict} from './evidence-release.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
export class UnsupportedExtraction extends Error{}
export function extractRequirementCandidates(data,mediaType,{afterLine=0,manual=false}={}){
 if(typeof manual!=='boolean')throw new RangeError('invalid source selection mode');
 if(!Number.isInteger(afterLine)||afterLine<0||afterLine>262144)throw new RangeError('invalid extraction cursor');
 validateEvidence(data,mediaType);
 const office=mediaType==='application/vnd.openxmlformats-officedocument.wordprocessingml.document'?'docx':mediaType==='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'?'xlsx':null;
 if(!office&&!['text/plain; charset=utf-8','application/pdf'].includes(mediaType))throw new UnsupportedExtraction('Source extraction not yet available for this evidence format');
 const pdf=mediaType==='application/pdf';
 let pages;
 if(pdf){try{pages=readCanonicalPdfPages(data);}catch{throw new UnsupportedExtraction('Scanned image-only PDF requires OCR review');}}
 const lines=office?extractOfficeSpans(data,office).spans.map(({quote,quoteSha256,...location})=>({quote,page:null,location})):pdf?pages.flatMap((lines,i)=>lines.map(quote=>({quote,page:i+1}))):new TextDecoder('utf-8',{fatal:true}).decode(data).split(/\r\n|\r|\n/).map(quote=>({quote,page:null}));
 let matched=0,skipped=0,remaining=0;const candidates=[];
 for(let i=0;i<lines.length;i++){
  const quote=lines[i].quote.trim();
  const legacy=/\b(?:shall|must|required\s+to|needs?\s+to)\b/i.test(quote);
  const extended=/\b(?:is|are)\s+(?:to\s+be|required|mandatory|prohibited|not\s+permitted)\b|\b(?:mandatory|prohibited)\b|\bno\s+[^.!?]{1,100}\b(?:permitted|allowed)\b|\b(?:undertakes|agrees)\s+to\b/i.test(quote);
  if(!quote||!manual&&!legacy&&!extended)continue;
  const algorithm=office?'office-source-span-v1':manual?'manual-source-line-v1':legacy?'modal-line-v1':'obligation-line-v2',category=manual?'manual_review':/\b(?:shall\s+not|must\s+not|prohibited|not\s+permitted|no\s+[^.!?]{1,100}\b(?:permitted|allowed))\b/i.test(quote)?'prohibition':/\b(?:before|after|within|by\s+\d)\b/i.test(quote)?'timing':'obligation_candidate';
  matched++;
  if([...quote].length>1024||Buffer.byteLength(quote)>4096||/[\x00-\x1f\x7f-\x9f]/u.test(quote)){skipped++;continue;}
  if(i+1<=afterLine)continue;
  remaining++;
  if(candidates.length<64)candidates.push({line:i+1,page:lines[i].page,...(office?{location:lines[i].location}:{}),quote,quoteSha256:hash(quote),algorithm,category});
 }
 return {algorithm:office?'office-source-span-v1':manual?'manual-source-line-v1':'obligation-line-v2',sha256:hash(data),mediaType,candidates,matched,skipped,truncated:remaining>candidates.length,nextAfterLine:remaining>candidates.length?candidates.at(-1).line:null,
  warning:manual?'Manually selected source lines are not interpreted obligations. Human review of the full original is required.':'Heuristic line candidates only; may miss obligations or include non-obligations. Human review of the full original is required.'};
}
export function createContractIQ({retrieve,workflow}){
 if(typeof retrieve!=='function'||typeof workflow?.assessment!=='function'||typeof workflow?.importSourceLine!=='function')throw Error('invalid extraction service');
 let active=0;
 return async function extract(input,{importLine=false,signal}){
  if(active>=4)throw Error('extraction capacity');active++;
  let source;
  try{
   signal.throwIfAborted();
   if(!(await workflow.assessment(input)).canWrite)throw new ReleaseDenied('extraction denied');
   source=await retrieve(input);signal.throwIfAborted();
   if(source.sha256!==input.sha256||hash(source.data)!==input.sha256)throw new ReleaseConflict('source changed');
   const result=extractRequirementCandidates(source.data,source.mediaType,{afterLine:importLine?input.line-1:input.afterLine??0,manual:input.manual??false});
   if(!importLine)return result;
   const line=result.candidates.find(c=>c.line===input.line&&c.quoteSha256===input.quoteSha256);
   if(!line)throw new ReleaseConflict('source candidate mismatch');
   signal.throwIfAborted();
   return await workflow.importSourceLine({...input,page:line.page,quote:line.quote,algorithm:line.algorithm,location:line.location});
  }finally{source?.data?.fill(0);active--;}
 };
}
