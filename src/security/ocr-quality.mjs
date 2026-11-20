// Bounded offline test metrics, not confidence calibration or a production claim.
const bad=()=>{throw new RangeError('invalid OCR benchmark data');};
const normalize=s=>s.normalize('NFKC').replace(/\s+/gu,' ').trim();
function distance(a,b){
 const aa=[...a],bb=[...b];if(bb.length>aa.length)return distance(b,a);
 const last=new Uint32Array(bb.length+1),next=new Uint32Array(bb.length+1);
 for(let j=0;j<last.length;j++)last[j]=j;
 for(let i=1;i<=aa.length;i++){
  next[0]=i;
  for(let j=1;j<=bb.length;j++)next[j]=Math.min(next[j-1]+1,last[j]+1,last[j-1]+(aa[i-1]===bb[j-1]?0:1));
  last.set(next);
 }
 return last[bb.length];
}
const tokens=s=>s?s.split(' '):[];
const numericIds=s=>s.match(/\b[A-Za-z]{1,6}-\d{1,8}\b|\b\d+(?:\.\d+)?\b/gu)??[];
const ratio=(n,d)=>d===0?null:Math.round(n/d*1000000)/1000000;
const percentile=(sorted,p)=>sorted[Math.max(0,Math.ceil(sorted.length*p)-1)];
export function scoreOcrCases(cases){
 if(!Array.isArray(cases)||cases.length<1||cases.length>32)bad();
 const durations=[],details=[],seen=new Set();
 let refChars=0,refWords=0,charErrors=0,wordErrors=0,exact=0,criticalTotal=0,criticalCorrect=0;
 for(const row of cases){
  if(!row||typeof row.id!=='string'||!/^[a-z0-9-]{1,40}$/.test(row.id)||seen.has(row.id)||typeof row.reference!=='string'||typeof row.observed!=='string'||!Number.isFinite(row.elapsedMs)||row.elapsedMs<0||row.elapsedMs>60000)bad();
  seen.add(row.id);
  const ref=normalize(row.reference),obs=normalize(row.observed),rc=[...ref],oc=[...obs],rw=tokens(ref),ow=tokens(obs);
  if(rc.length<1||rc.length>1024||oc.length>1024||rw.length>128||ow.length>128||/[\x00-\x1f\x7f-\x9f]/u.test(ref+obs))bad();
  const ce=distance(rc,oc),we=distance(rw,ow);refChars+=rc.length;refWords+=rw.length;charErrors+=ce;wordErrors+=we;
  if(ref===obs)exact++;
  const matching=new Map();for(const id of numericIds(obs))matching.set(id,(matching.get(id)||0)+1);
  let have=0;const refs=numericIds(ref);for(const id of refs){const n=matching.get(id)||0;if(n){matching.set(id,n-1);have++;}}
  criticalTotal+=refs.length;criticalCorrect+=have;durations.push(row.elapsedMs);
  details.push({id:row.id,reference:ref,observed:obs,referenceCharacters:rc.length,characterEdits:ce,referenceWords:rw.length,wordEdits:we,criticalIdentifiers:refs.length,criticalIdentifiersCorrect:have,elapsedMs:Math.round(row.elapsedMs*100)/100});
 }
 const sorted=durations.sort((a,b)=>a-b);
 return {version:1,scope:'synthetic deterministic fixtures only; no real-document accuracy claim',sampleCount:cases.length,totalReferenceCharacters:refChars,totalCharacterEdits:charErrors,totalReferenceWords:refWords,totalWordEdits:wordErrors,characterErrorRate:ratio(charErrors,refChars),wordErrorRate:ratio(wordErrors,refWords),exactLineRate:ratio(exact,cases.length),criticalIdentifierRecall:ratio(criticalCorrect,criticalTotal),criticalIdentifierCount:criticalTotal,elapsedMs:{p50:Math.round(percentile(sorted,0.50)*100)/100,p95:Math.round(percentile(sorted,0.95)*100)/100,max:Math.round(sorted.at(-1)*100)/100},cases:details};
}
