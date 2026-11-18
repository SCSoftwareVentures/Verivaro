// Fixed offline worker. No tools, network clients, dynamic imports, or document commands.
import {createHash} from 'node:crypto';
const chunks=[];let n=0;
for await(const b of process.stdin){n+=b.length;if(n>262144)process.exit(2);chunks.push(b);}
const {pages}=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
if(!Array.isArray(pages)||pages.length>20)process.exit(2);
const result=[],seen=new Set();let total=0;
const rules=[
 ['obligation',/\b(?:responsible for|to be submitted|to be supplied|is required to|shall|must|mandatory|required)\b/i],
 ['exception',/\b(?:exempt|excluding|unless|except|subject to|notwithstanding)\b/i],
 ['amendment',/\b(?:revised clause|amendment|supersedes|replaces|variation|addendum)\b/i],
 ['deadline',/\b(?:not later than|prior to|within|before|deadline|due by)\b/i]
];
for(const p of pages){
 if(!Number.isSafeInteger(p.page)||p.page<1||p.page>20||seen.has(p.page)||typeof p.text_value!=='string'||createHash('sha256').update(p.text_value).digest('hex')!==p.text_sha256)process.exit(2);
 seen.add(p.page);total+=Buffer.byteLength(p.text_value);if(total>65536)process.exit(2);
 let start=0;for(const line of p.text_value.split('\n')){
 const quote=line.replace(/\r$/,''),length=[...quote].length,tags=rules.filter(([,re])=>re.test(quote)).map(([tag])=>tag);
 if(tags.length&&length<=2000&&result.length<100)result.push({page:p.page,start,end:start+length,quote,textSha256:p.text_sha256,tags});
 start+=[...line].length+1;
 }
}
process.stdout.write(JSON.stringify(result));
