import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes,randomUUID} from 'node:crypto';
import {canonicalTextPdf} from '../../src/security/evidence-formats.mjs';
import {createClamdScanner} from '../../src/security/clamd-scanner.mjs';
import {createOriginalPdfQuarantine} from '../../src/security/pdf-quarantine.mjs';
if(!process.env.VV_REAL_CLAMD_SOCKET)throw Error('real antivirus integration required');
test('real ClamAV refuses marked PDF while clean original is retained encrypted',async()=>{
 const root=await mkdtemp(join(tmpdir(),'vv-clamd-quarantine-')),key=randomBytes(32),scan=createClamdScanner({socketPath:process.env.VV_REAL_CLAMD_SOCKET,timeoutMs:12000}),signal=new AbortController().signal;
 const vault=createOriginalPdfQuarantine({root,key,keyId:'test_original',scan});
 const meta={tenantId:randomUUID(),projectId:randomUUID()};
 const clean=canonicalTextPdf(['Equipment must carry ID.']),marked=canonicalTextPdf(['VV-QUARANTINE-TEST-SIGNATURE']);
 try{
  assert.equal(await scan(clean,signal),'clean');
  assert.equal(await scan(marked,signal),'infected');
  const stored=await vault.put({...meta,source:clean,signal});
  assert.equal((await readdir(root)).length,1);
  await assert.rejects(vault.put({...meta,source:marked,signal}));
  assert.equal((await readdir(root)).length,1,'rejected PDF must not be written to quarantine');
  const recovered=await vault.read(stored,{signal});
  try{assert.deepEqual(recovered,clean);}finally{recovered.fill(0);}
  console.log('real_clamd_original_pdf_quarantine_gate_passed');
 }finally{vault.close();key.fill(0);clean.fill(0);marked.fill(0);await rm(root,{force:true,recursive:true});}
});
