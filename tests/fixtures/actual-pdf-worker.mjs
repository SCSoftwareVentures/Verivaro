import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes,createHash} from 'node:crypto';
import {canonicalPagedTextPdf} from '../../src/security/evidence-formats.mjs';
import {createOfflinePoppler,normalizeExternalPdf} from '../../src/security/pdf-normalization.mjs';
import {startPdfWorker,createPdfWorkerClient} from '../../src/security/pdf-worker-socket.mjs';
import {validateEvidence} from '../../src/security/evidence-objects.mjs';
const input=canonicalPagedTextPdf([['Equipment must carry ID.'],['Valve V-204 must be checked.']]),dir=await mkdtemp(join(tmpdir(),'vv-pdf-real-')),socketPath=join(dir,'worker.sock'),key=randomBytes(32);
let worker,client;
try{
 const renderer=createOfflinePoppler();
 worker=await startPdfWorker({socketPath,key,convert:(source,signal)=>normalizeExternalPdf(source,{renderer,signal})});
 client=createPdfWorkerClient({socketPath,key});
 const result=await client(input,new AbortController().signal);
 assert.equal(result.manifest.pageCount,2);
 assert.equal(result.manifest.sourceSha256,createHash('sha256').update(input).digest('hex'));
 assert.equal(result.manifest.reviewRequired,true);
 validateEvidence(result.pdf,'application/pdf');
 console.log('AUTHENTICATED_PDF_WORKER_REAL_POPPLER_GATE '+JSON.stringify({pages:result.manifest.pageCount,originalDigest:result.manifest.sourceSha256,derivedDigest:result.manifest.derivedSha256,verified:true}));
 result.pdf.fill(0);
}finally{client?.close();await worker?.close();key.fill(0);input.fill(0);await rm(dir,{force:true,recursive:true});}
