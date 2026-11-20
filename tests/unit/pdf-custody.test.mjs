import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,writeFile,chmod,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes,randomUUID,generateKeyPairSync,createHash} from 'node:crypto';
import {canonicalTextPdf} from '../../src/security/evidence-formats.mjs';
import {canonicalScannedPdf,readCanonicalScannedPdf} from '../../src/security/scanned-pdf.mjs';
import {fixturePng} from '../fixtures/evidence-formats-fixture.mjs';
import {createOriginalPdfQuarantine} from '../../src/security/pdf-quarantine.mjs';
import {createPdfCustodySigner,verifyPdfCustodyStatement} from '../../src/security/pdf-custody-statement.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex');
const source=canonicalTextPdf(['Equipment must carry ID.']);
const id=()=>randomUUID(),scope=()=>({tenantId:id(),projectId:id()});
function converted(original){
 const pdf=canonicalScannedPdf(fixturePng({width:16,height:12,pixels:Buffer.alloc(12*49)}));
 const r=readCanonicalScannedPdf(pdf);const rasterSha256=r.rasterSha256;r.png.fill(0);
 return {pdf,manifest:{version:1,sourceSha256:hash(original),sourceBytes:original.length,derivedSha256:hash(pdf),derivedBytes:pdf.length,pageCount:1,pages:[{page:1,width:16,height:12,rasterSha256}],originalRetained:false,reviewRequired:true,format:'offline-poppler-to-canonical-raster-v1',notice:'Derived copy; source authenticity is not guaranteed.'}};
}
test('scanner-cleared originals are stored encrypted and independently decrypted in exact scope',async()=>{
 const root=await mkdtemp(join(tmpdir(),'vv-rawpdf-')),key=randomBytes(32),sourceCopy=Buffer.from(source),ac=new AbortController();let scans=0;
 const vault=createOriginalPdfQuarantine({root,key,keyId:'pdf_original',scan:async x=>{scans++;assert.deepEqual(x,source);return 'clean';}});
 try{
  const m=await vault.put({...scope(),source:sourceCopy,signal:ac.signal});
  assert.equal(scans,1);assert.equal(m.sha256,hash(source));
  const path=join(root,m.quarantineId+'.vvq'),stored=await readFile(path);
  assert.equal(stored.length,source.length+28);assert.equal(stored.includes(source.subarray(0,20)),false);
  const recovered=await vault.read(m,{signal:ac.signal});assert.deepEqual(recovered,source);recovered.fill(0);
  await assert.rejects(vault.read({...m,tenantId:id()},{signal:ac.signal}));
  await assert.rejects(vault.read({...m,sha256:'a'.repeat(64)},{signal:ac.signal}));
  await chmod(path,0o644);await assert.rejects(vault.read(m,{signal:ac.signal}));await chmod(path,0o600);
  const bad=Buffer.from(stored);bad[bad.length-1]^=0xff;await writeFile(path,bad);await assert.rejects(vault.read(m,{signal:ac.signal}));
 }finally{vault.close();key.fill(0);sourceCopy.fill(0);await rm(root,{recursive:true,force:true});}
});
test('unknown malware verdict and mutable scanner input fail closed before file creation',async()=>{
 const root=await mkdtemp(join(tmpdir(),'vv-rawpdf-')),key=randomBytes(32),s=scope(),signal=new AbortController().signal;
 const deny=createOriginalPdfQuarantine({root,key,keyId:'pdf',scan:async()=> 'infected'});
 try{await assert.rejects(deny.put({...s,source,signal}));assert.deepEqual(await (await import('node:fs/promises')).readdir(root),[]);}finally{deny.close();}
 const changed=createOriginalPdfQuarantine({root,key,keyId:'pdf',scan:async b=>{b[20]^=1;return 'clean';}});
 try{await assert.rejects(changed.put({...s,source,signal}));assert.deepEqual(await (await import('node:fs/promises')).readdir(root),[]);}finally{changed.close();key.fill(0);await rm(root,{recursive:true,force:true});}
});
test('aborted scan and post-write cancellation leave no untracked original file',async()=>{
 const root=await mkdtemp(join(tmpdir(),'vv-rawpdf-')),key=randomBytes(32),s=scope(),controller=new AbortController();
 const aborted=createOriginalPdfQuarantine({root,key,keyId:'scan',scan:async()=>{controller.abort();return 'clean';}});
 try{
  await assert.rejects(aborted.put({...s,source,signal:controller.signal}));
  assert.deepEqual(await (await import('node:fs/promises')).readdir(root),[]);
 }finally{aborted.close();key.fill(0);await rm(root,{force:true,recursive:true});}
});
test('receipt binds retained original and derivative under an independent Ed25519 trust key',async()=>{
 const root=await mkdtemp(join(tmpdir(),'vv-rawpdf-')),key=randomBytes(32),pair=generateKeyPairSync('ed25519'),signal=new AbortController().signal;
 const vault=createOriginalPdfQuarantine({root,key,keyId:'original',scan:async()=> 'clean'});
 try{
  const record=await vault.put({...scope(),source,signal}),out=converted(source);
  const signer=createPdfCustodySigner(pair.privateKey),envelope=await signer.issue({quarantine:vault,record,converted:out,conversionId:id(),signal});
  const verified=verifyPdfCustodyStatement(envelope,pair.publicKey,{original:source,derived:out.pdf});
  assert.equal(verified.signatureVerified,true);assert.equal(verified.originalBytesRechecked,true);assert.equal(verified.derivedBytesRechecked,true);
  assert.throws(()=>verifyPdfCustodyStatement(envelope,generateKeyPairSync('ed25519').publicKey));
  assert.throws(()=>verifyPdfCustodyStatement({...envelope,statement:{...envelope.statement,tenantId:id()}},pair.publicKey));
  assert.throws(()=>verifyPdfCustodyStatement(envelope,pair.publicKey,{derived:Buffer.from('changed')}));
  const bad={...out,manifest:{...out.manifest,sourceSha256:'0'.repeat(64)}};
  await assert.rejects(signer.issue({quarantine:vault,record,converted:bad,conversionId:id(),signal}));
  out.pdf.fill(0);
 }finally{vault.close();key.fill(0);await rm(root,{recursive:true,force:true});}
});
