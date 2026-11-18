import {createHash} from 'node:crypto';
// Draft recommendations from untrusted exact notice text; no authority or document mutation.
const rules=[
 ['missing-evidence',/\b(missing|not (?:supplied|provided|attached)|omitted|absent)\b/i,'Locate the required current evidence, or request a replacement from its issuer.'],
 ['identifier-mismatch',/\b(serial|model|identifier|reference number)\b/i,'Compare the exact identifier with the approved criterion and request corrected evidence if needed.'],
 ['date-discrepancy',/\b(expir(?:y|ed|ation)|date|validity|outdated)\b/i,'Check the stated date, validity and current revision against the approved requirement.'],
 ['format-or-filename',/\b(file\s*name|naming|format|file type|layout)\b/i,'Confirm the submission convention. Draft a metadata-only filename or cover-sheet change; do not edit the issued file.'],
 ['signature-or-authority',/\b(signature|unsigned|signed|authoris(?:ed|ation)|authoriz(?:ed|ation))\b/i,'Request confirmation or a reissued document from the authorised issuer; do not add a signature.']
];
export function correctionDraft(notice){
 if(typeof notice?.quote!=='string'||!notice.quote.trim()||[...notice.quote].length>2000)throw Error('invalid rejection excerpt');
 const tasks=rules.filter(([,re])=>re.test(notice.quote)).map(([category,,recommendation])=>({category,recommendation}));
 if(!tasks.length)tasks.push({category:'unclear-feedback',recommendation:'Request clarification and identify the exact requirement before recording a resolution.'});
 return {state:'draft-review-required',tasks,source:{documentVersionId:notice.documentVersionId,page:notice.page,start:notice.start,end:notice.end,quote:notice.quote,textSha256:notice.textSha256},modifiesOriginal:false,authorisesRelease:false};
}
export function assessRejectionNotices(notices,cases){
 const byId=new Map(cases.map(c=>[c.id,c]));
 return notices.map(n=>{
 const c=byId.get(n.id);
 return {...n,caseId:c?.id??null,requiresAttention:!c||c.requiresAttention,status:!c?'mapping-required':c.requiresAttention?'correction-review-required':'resolution-documented',draft:correctionDraft(n)};
 }).sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
}

/** Explicitly selected reviewed notice only. Every nonblank line is a candidate, not a finding;
 * unknown lines are retained for clarification. Long lines are explicitly reported as incomplete. */
export function extractObjectionCandidates(pages){
 if(!Array.isArray(pages)||pages.length>20)throw Error('invalid pages');
 const candidates=[],seen=new Set();let total=0,truncated=false;
 for(const p of pages){
 if(!Number.isSafeInteger(p.page)||p.page<1||p.page>20||seen.has(p.page)||typeof p.text_value!=='string'||createHash('sha256').update(p.text_value).digest('hex')!==p.text_sha256)throw Error('invalid notice page');
 seen.add(p.page);total+=Buffer.byteLength(p.text_value);if(total>1048576)throw Error('notice budget');
 let start=0;
 for(const line of p.text_value.split('\n')){
 const quote=line.replace(/\r$/,''),length=[...quote].length;
 if(quote.trim()){
 if(length>2000||candidates.length>=200)truncated=true;
 else candidates.push({page:p.page,start,end:start+length,quote,textSha256:p.text_sha256,categories:correctionDraft({quote}).tasks.map(t=>t.category),state:'needs-review'});
 }
 start+=[...line].length+1;
 }
 }
 return {candidates,truncated,label:'Possible objections, including unknown feedback. Review and explicitly import each relevant excerpt; not exhaustive.'};
}
export function correctionCover(plan){
 if(!plan||plan.state!=='approved'||!plan.current)throw Error('current approved plan required');
 return {title:'Verivaro correction cover sheet — internal approved metadata draft',noticeId:plan.noticeId,planRevision:plan.revision,caseRevision:plan.caseRevision,documentVersionId:plan.documentVersionId,originalSha256:plan.originalSha256,proposedFilename:plan.filename,reviewNote:plan.coverNote,originalUnchanged:true,releaseAuthorised:false};
}
