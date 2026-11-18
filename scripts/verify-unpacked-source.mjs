// Run only after verifying signed archive bytes with a trusted signer.
import {readFileSync,readdirSync,lstatSync} from 'node:fs';
import {join} from 'node:path';
import {sha256} from '../packages/security/software-candidate.mjs';
const [root,index]=process.argv.slice(2);if(!root||!index)throw Error('source root and trusted file index required');
const listed=JSON.parse(readFileSync(index,'utf8')),map=new Map(listed.map(f=>[f.path,f]));
if(map.size!==listed.length)throw Error('duplicate source index');
function walk(dir,rel=''){for(const ent of readdirSync(dir,{withFileTypes:true})){const path=rel+ent.name,full=join(dir,ent.name);if(ent.isDirectory())walk(full,path+'/');else{
 const expected=map.get(path),stat=lstatSync(full);
 if(!ent.isFile()||!expected||stat.size!==expected.bytes||sha256(readFileSync(full))!==expected.sha256||Boolean(stat.mode&0o111)!==(expected.mode==='100755'))throw Error('unpacked mismatch: '+path);
 map.delete(path);
}}}
walk(root);if(map.size)throw Error('missing source files');console.log('Verified '+listed.length+' unpacked source files');
