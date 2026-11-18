const SHA=/^[a-f0-9]{64}$/;
export function selectedSpan(page,start,end,max=2000){
 if(!page||typeof page.text_value!=='string'||!Number.isSafeInteger(page.page)||page.page<1||page.page>20||!SHA.test(page.text_sha256)||!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||start<0||end<=start||end>page.text_value.length)throw Error('Select exact source text.');
 const text=page.text_value;
 // Reject boundaries that split UTF-16 surrogate pairs.
 for(const i of [start,end])if(i>0&&i<text.length&&/[\uD800-\uDBFF]/.test(text[i-1])&&/[\uDC00-\uDFFF]/.test(text[i]))throw Error('Select complete characters.');
 const quote=text.slice(start,end),lo=[...text.slice(0,start)].length,hi=lo+[...quote].length;
 if(!quote.trim()||hi-lo>max)throw Error('Select a nonempty excerpt within the length limit.');
 return {page:page.page,start:lo,end:hi,quote,textSha256:page.text_sha256};
}
export function selectedAmount(span){
 const m=/^AUD ((?:0|[1-9]\d{0,11})\.\d{2})$/.exec(span?.quote??'');
 if(!m)throw Error('Select the exact AUD amount, for example AUD 1250.00.');
 return m[1];
}
export function currentSources(catalog){
 return catalog.documents.flatMap(d=>d.currentVersionId?d.uploads.filter(u=>u.state==='reviewed'&&u.versionId===d.currentVersionId).map(u=>({versionId:d.currentVersionId,documentId:d.id,title:d.title,uploadId:u.id})):[]);
}
