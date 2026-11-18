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
