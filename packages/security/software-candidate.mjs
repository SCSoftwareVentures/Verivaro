import {createHash,createPublicKey,createPrivateKey,sign,verify} from 'node:crypto';
const hex=/^[a-f0-9]{64}$/;
const sha1=/^[a-f0-9]{40}$/;
const domain='verivaro-software-candidate-v1\0';
export const sha256=b=>createHash('sha256').update(b).digest('hex');
export function validArtifactName(n){return typeof n==='string'&&/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,119}$/.test(n)&&n!=='.'&&n!=='..';}
const message=b=>Buffer.concat([Buffer.from(domain),b]);
function validate(m){
 if(!m||m.schema!=='verivaro-software-candidate-v1'||!sha1.test(m.revision)||!['ci-ephemeral','buyer-offline'].includes(m.signingMode)||!hex.test(m.signerFingerprint)||m.productionApproved!==false||!Array.isArray(m.artifacts)||m.artifacts.length<1||m.artifacts.length>30)throw Error('invalid candidate manifest');
 const names=new Set();
 for(const f of m.artifacts){if(!validArtifactName(f.name)||!Number.isSafeInteger(f.bytes)||f.bytes<1||f.bytes>64*1024*1024||!hex.test(f.sha256)||names.has(f.name))throw Error('invalid artifact entry');names.add(f.name);}
 for(const name of ['source.tar','sbom.cdx.json','dependency-licenses.json','npm-audit.json','source-files.json','candidate-evidence.json'])if(!names.has(name))throw Error('missing required artifact');
}
export function publicFingerprint(key){const k=key?.type==='public'?key:createPublicKey(key);if(k.asymmetricKeyType!=='ed25519')throw Error('Ed25519 required');return sha256(k.export({type:'spki',format:'der'}));}
export function signCandidate(manifest,privateKey){
 const key=privateKey?.type==='private'?privateKey:createPrivateKey(privateKey);
 if(key.asymmetricKeyType!=='ed25519'||publicFingerprint(createPublicKey(key))!==manifest.signerFingerprint)throw Error('wrong signing key');
 validate(manifest);const body=Buffer.from(JSON.stringify(manifest,null,2)+'\n');return {body,signature:sign(null,message(body),key)};
}
export function verifyCandidate({body,signature,publicKey,expectedRevision,expectedFingerprint,expectedMode,artifacts}){
 if(!Buffer.isBuffer(body)||body.length>131072||!Buffer.isBuffer(signature)||signature.length!==64||!sha1.test(expectedRevision)||!hex.test(expectedFingerprint)||!['ci-ephemeral','buyer-offline'].includes(expectedMode))throw Error('trusted revision, fingerprint and mode required');
 const key=publicKey?.type==='public'?publicKey:createPublicKey(publicKey);
 if(publicFingerprint(key)!==expectedFingerprint||!verify(null,message(body),key,signature))throw Error('candidate signature invalid');
 const m=JSON.parse(body.toString('utf8'));validate(m);
 if(m.revision!==expectedRevision||m.signerFingerprint!==expectedFingerprint||m.signingMode!==expectedMode)throw Error('candidate identity mismatch');
 if(!(artifacts instanceof Map)||artifacts.size!==m.artifacts.length)throw Error('unexpected artifact inventory');
 for(const f of m.artifacts){const b=artifacts.get(f.name);if(!Buffer.isBuffer(b)||b.length!==f.bytes||sha256(b)!==f.sha256)throw Error('artifact integrity failure: '+f.name);}
 return m;
}
