// CI or buyer-owned offline signing of an INTERNAL candidate; never publishes a release.
import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdirSync,readdirSync,lstatSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {createPrivateKey,createPublicKey,generateKeyPairSync} from 'node:crypto';
import {sha256,publicFingerprint,signCandidate,verifyCandidate} from '../packages/security/software-candidate.mjs';
const die=s=>{throw Error(s);};
const git=(...args)=>execFileSync('git',args,{maxBuffer:64*1024*1024});
const revision=git('rev-parse','HEAD').toString().trim();
if(!/^[a-f0-9]{40}$/.test(revision))die('invalid revision');
git('diff','--exit-code','HEAD','--');
const [dest,mode,keyPath]=process.argv.slice(2);
if(!dest||!['ci-ephemeral','buyer-offline'].includes(mode)||(mode==='buyer-offline'?!keyPath:!!keyPath)||process.argv.length!==(mode==='buyer-offline'?5:4))die('usage: candidate-build.mjs NEW_DIRECTORY ci-ephemeral | buyer-offline PRIVATE_KEY_PATH');
const output=resolve(dest);
mkdirSync(output,{mode:0o700}); // Refuse pre-existing or reused directory.
const sourceFiles=[];
const entries=git('ls-tree','-r','-z',revision).toString('utf8').split('\0').filter(Boolean);
const allowedRoot=new Set(['README.md','.gitignore','.nvmrc','package.json','package-lock.json','demo.mjs']);
const allowedPrefix=['.github/workflows/','database/migrations/','docs/','packages/','scripts/','tests/','deploy/'];
const secretRules=[
 ['private-key',/-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/],
 ['github-token',/\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b/],
 ['aws-access-key',/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
 ['api-secret',/\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b/]
];
for(const item of entries){
 const m=/^(100644|100755) blob ([a-f0-9]{40})\t([A-Za-z0-9._/-]+)$/.exec(item);
 if(!m)die('non-regular or unsafe tracked object');
 const [,modeBits,blob,path]=m;
 if(path.split('/').some(x=>!x||x==='.'||x==='..')||(!allowedRoot.has(path)&&!allowedPrefix.some(p=>path.startsWith(p)))||/(?:^|\/)(?:\.env(?:\.|$)|node_modules(?:\/|$)|[^/]+\.(?:pem|key|p12|pfx|sqlite|dump)$)/i.test(path))die('unapproved tracked path: '+path);
 const bytes=git('cat-file','blob',blob);if(bytes.length>4*1024*1024)die('tracked file too large: '+path);
 // This public source package currently consists of text. Binary secrets cannot bypass text scanning.
 const content=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 if(content.includes('\0'))die('unexpected binary tracked content');
 for(const [rule,re] of secretRules)if(re.test(content))die('possible secret in '+path+' ('+rule+')');
 sourceFiles.push({path,mode:modeBits,bytes:bytes.length,sha256:sha256(bytes)});
}
const archive=git('archive','--format=tar','--prefix=verivaro/',revision);
if(!archive.equals(git('archive','--format=tar','--prefix=verivaro/',revision)))die('non-reproducible archive');
const lock=JSON.parse(readFileSync('package-lock.json','utf8')),pkg=JSON.parse(readFileSync('package.json','utf8'));
if(lock.lockfileVersion!==3||lock.packages[''].name!==pkg.name||JSON.stringify(lock.packages[''].dependencies)!==JSON.stringify(pkg.dependencies))die('lockfile mismatch');
const components=[],licenses=[],dependencies=[],byName=new Map(),allowedLicenses=new Set(['MIT','ISC','BSD-2-Clause','BSD-3-Clause','Apache-2.0']);
for(const [location,e] of Object.entries(lock.packages)){
 if(!location)continue;
 const name=location.slice('node_modules/'.length);
 if(location!=='node_modules/'+name||!/^(@[a-z0-9_-]+\/)?[a-z0-9_-]+$/.test(name)||!/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(e.version)||e.resolved!=='https://registry.npmjs.org/'+name+'/-/'+name.split('/').at(-1)+'-'+e.version+'.tgz'||!/^sha512-[A-Za-z0-9+/]{86}==$/.test(e.integrity)||!allowedLicenses.has(e.license)||e.hasInstallScript||e.link)die('unapproved dependency: '+location);
 const dir=resolve(location),installed=JSON.parse(readFileSync(join(dir,'package.json'),'utf8'));
 if(installed.name!==name||installed.version!==e.version||installed.license!==e.license)die('installed dependency mismatch '+name);
 const found=readdirSync(dir).filter(x=>/^(?:licen[cs]e|copying|notice)(?:\..*)?$/i.test(x)).sort();
 const texts=found.filter(x=>lstatSync(join(dir,x)).isFile()).map(x=>{const b=readFileSync(join(dir,x));if(b.length>131072)die('license too large');return {file:x,sha256:sha256(b),text:b.toString('utf8')};});
 if(!texts.some(x=>/^(?:licen[cs]e|copying)/i.test(x.file)&&x.text.trim()))die('dependency license text missing: '+name);
 const ref='pkg:npm/'+name+'@'+e.version;byName.set(name,ref);
 components.push({'bom-ref':ref,type:'library',name,version:e.version,purl:ref,licenses:[{license:{id:e.license}}],hashes:[{alg:'SHA-512',content:Buffer.from(e.integrity.slice(7),'base64').toString('hex')}]});
 licenses.push({name,version:e.version,declaredLicense:e.license,files:texts});
}
const rootRef='pkg:npm/'+pkg.name+'@'+pkg.version;
function refs(e){return [...new Set([...Object.keys(e.dependencies??{}),...Object.keys(e.optionalDependencies??{}),...Object.keys(e.peerDependencies??{}).filter(n=>!e.peerDependenciesMeta?.[n]?.optional)])].sort().map(n=>byName.get(n)??die('unlocked dependency edge '+n));}
dependencies.push({ref:rootRef,dependsOn:refs(lock.packages[''])});
for(const [location,e] of Object.entries(lock.packages))if(location)dependencies.push({ref:byName.get(location.slice(13)),dependsOn:refs(e)});
if(dependencies.some(x=>!x.ref))die('invalid SBOM references');
const sbom={bomFormat:'CycloneDX',specVersion:'1.5',version:1,metadata:{component:{type:'application','bom-ref':rootRef,name:pkg.name,version:pkg.version}},components,dependencies};
const audit=JSON.parse(readFileSync(process.env.VV_AUDIT_JSON??'npm-audit.json','utf8'));
const counts=audit.metadata?.vulnerabilities;if(!counts||audit.error||!['info','low','moderate','high','critical','total'].every(x=>Number.isSafeInteger(counts[x])&&counts[x]>=0)||counts.high!==0||counts.critical!==0)die('npm vulnerability gate not satisfied');
const evidence={schema:'verivaro-candidate-evidence-v1',revision,tree:git('rev-parse',revision+'^{tree}').toString().trim(),node:process.version,npm:execFileSync('npm',['--version']).toString().trim(),runId:process.env.GITHUB_RUN_ID??null,runAttempt:process.env.GITHUB_RUN_ATTEMPT??null,event:process.env.GITHUB_EVENT_NAME??null,workflowRef:process.env.GITHUB_WORKFLOW_REF??null,sourceFiles:sourceFiles.length,dependencyCount:components.length,sourceSecretScan:'limited-pattern-scan-passed',npmAudit:counts,productionApproved:false,limitations:['Self-generated evidence; CI key is ephemeral and not an independent attestation.','No container/OS CVE inventory or legal license opinion.','Release requires buyer-approved key, protected reviews and target environment validation.']};
const payloads=new Map([['source.tar',archive],['sbom.cdx.json',Buffer.from(JSON.stringify(sbom,null,2)+'\n')],['dependency-licenses.json',Buffer.from(JSON.stringify(licenses,null,2)+'\n')],['npm-audit.json',Buffer.from(JSON.stringify(audit,null,2)+'\n')],['source-files.json',Buffer.from(JSON.stringify(sourceFiles,null,2)+'\n')],['candidate-evidence.json',Buffer.from(JSON.stringify(evidence,null,2)+'\n')]]);
if(mode==='buyer-offline'){
 const root=resolve('.'),keyFile=resolve(keyPath),stat=lstatSync(keyFile);
 if(keyFile===root||keyFile.startsWith(root+'/')||!stat.isFile()||(stat.mode&0o077)!==0)die('offline key must be a private regular file outside the checkout');
}
const privateKey=mode==='ci-ephemeral'?generateKeyPairSync('ed25519').privateKey:createPrivateKey(readFileSync(keyPath));
const publicKey=createPublicKey(privateKey),fingerprint=publicFingerprint(publicKey);
const m={schema:'verivaro-software-candidate-v1',revision,signingMode:mode,signerFingerprint:fingerprint,productionApproved:false,artifacts:[...payloads].map(([name,b])=>({name,bytes:b.length,sha256:sha256(b)}))};
const {body,signature}=signCandidate(m,privateKey);
verifyCandidate({body,signature,publicKey,expectedRevision:revision,expectedFingerprint:fingerprint,expectedMode:mode,artifacts:payloads});
for(const [name,bytes] of payloads)writeFileSync(join(output,name),bytes,{flag:'wx',mode:0o600});
writeFileSync(join(output,'manifest.json'),body,{flag:'wx',mode:0o600});
writeFileSync(join(output,'manifest.sig'),signature,{flag:'wx',mode:0o600});
writeFileSync(join(output,'candidate-public.pem'),publicKey.export({format:'pem',type:'spki'}),{flag:'wx',mode:0o600});
console.log(JSON.stringify({revision,fingerprint,mode,sourceFiles:sourceFiles.length,dependencies:components.length,audit:counts,archiveSha256:sha256(archive),productionApproved:false}));
