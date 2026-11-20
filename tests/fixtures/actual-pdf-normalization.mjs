import assert from 'node:assert/strict';
import {canonicalPagedTextPdf} from '../../src/security/evidence-formats.mjs';
import {normalizeExternalPdf,createOfflinePoppler} from '../../src/security/pdf-normalization.mjs';
import {readCanonicalMultipageScannedPdf} from '../../src/security/scanned-pdf-multipage.mjs';
import {validateEvidence} from '../../src/security/evidence-objects.mjs';
const original=canonicalPagedTextPdf([['Equipment must carry ID.'],['Valve V-204 must be checked.']]);
const {pdf,manifest}=await normalizeExternalPdf(original,{renderer:createOfflinePoppler(),signal:new AbortController().signal});
assert.equal(manifest.pageCount,2);assert.equal(manifest.pages.length,2);assert.equal(manifest.originalRetained,false);
assert.equal(manifest.reviewRequired,true);assert.deepEqual(validateEvidence(pdf,'application/pdf'),pdf);
const second=readCanonicalMultipageScannedPdf(pdf,{page:2});try{assert.equal(second.page,2);assert.equal(second.pageCount,2);}finally{second.png.fill(0);}
console.log('OFFLINE_PDF_NORMALIZATION_GATE '+JSON.stringify({sourceBytes:manifest.sourceBytes,derivedBytes:manifest.derivedBytes,pageCount:manifest.pageCount,sourceSha256:manifest.sourceSha256,derivedSha256:manifest.derivedSha256,normalized:true,originalRetained:false}));
pdf.fill(0);original.fill(0);
