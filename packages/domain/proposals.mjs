/** Deliberately narrow lexical candidate extraction; never claims exhaustive obligations.
 * Offsets are Unicode code points to agree with PostgreSQL, not JS UTF-16.
 */
export function proposeRequirements(pages){
 const candidates=[];
 for(const p of pages){
  let offset=0;
  for(const line of p.text_value.split(/\n/)){
   const quote=line.replace(/\r$/,'');const len=[...quote].length;
   if(len>0&&len<=2000&&/\b(must|shall|required|mandatory)\b/i.test(quote)){
    candidates.push({page:p.page,start:offset,end:offset+len,quote,textSha256:p.text_sha256,method:p.method,state:'needs-review'});
    if(candidates.length>=200)return {candidates,truncated:true,label:'Possible obligations only; human review required.'};
   }
   offset+=[...line].length+1;
  }
 }
 return {candidates,truncated:false,label:'Possible obligations only; human review required.'};
}
/** Candidate match, never approved evidence. Literal occurrence, no inferred equivalence. */
export function suggestMatches(pages,expected){
 if(typeof expected!=='string'||!expected.trim()||expected.length>500)throw Error('invalid criterion');
 const needle=[...expected],matches=[];
 for(const p of pages){const hay=[...p.text_value];for(let i=0;i<=hay.length-needle.length;i++){
 if(hay[i]===needle[0]&&needle.every((x,j)=>hay[i+j]===x)){
 matches.push({page:p.page,start:i,end:i+needle.length,quote:expected,textSha256:p.text_sha256,state:'needs-review'});
 if(matches.length>=100)return {matches,truncated:true};i+=needle.length-1;
 }}}
 return {matches,truncated:false};
}
