import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {performance} from 'node:perf_hooks';
import {createTesseractEngine,parseOcrTsv} from '../../src/security/ocr-preview.mjs';
import {canonicalPngFromRgb} from '../../src/security/scanned-pdf.mjs';
import {startOcrWorker,createOcrSocketClient} from '../../src/security/ocr-socket.mjs';
import {scoreOcrCases} from '../../src/security/ocr-quality.mjs';
import {stressRgbPpm,modes} from './ocr-stress-image.mjs';
const ppm=await readFile(process.argv[2]),reference='Valve V-204 must be checked.',dir=await mkdtemp(join(tmpdir(),'vv-ocr-stress-')),socketPath=join(dir,'worker.sock'),key=randomBytes(32),results=[];
let worker,recognize;
try{
 worker=await startOcrWorker({socketPath,key,recognize:createTesseractEngine()});
 recognize=createOcrSocketClient({socketPath,key});
 for(const mode of modes){
  const {width,height,pixels}=stressRgbPpm(ppm,mode);
  let png,tsv;
  try{
   png=canonicalPngFromRgb(pixels,width,height);
   const start=performance.now();tsv=await recognize(png,new AbortController().signal);const elapsedMs=performance.now()-start;
   const regions=parseOcrTsv(tsv,{width,height});
   assert.ok(regions.every(r=>r.reviewRequired));
   const score=scoreOcrCases([{id:mode,reference,observed:regions.map(r=>r.quote).join(' '),elapsedMs}]);
   results.push({condition:mode,characterErrorRate:score.characterErrorRate,wordErrorRate:score.wordErrorRate,exact:score.exactLineRate===1,criticalIdentifierRecall:score.criticalIdentifierRecall,elapsedMs:score.elapsedMs.p50,recognized:score.cases[0].observed});
  }finally{pixels.fill(0);png?.fill(0);tsv?.fill(0);}
 }
 assert.equal(results.length,modes.length);
 console.log('SYNTHETIC_OCR_STRESS_MATRIX '+JSON.stringify({engine:'Tesseract English PSM6 via authenticated Unix socket',conditions:results,reviewRequired:true,note:'Synthetic deterministic transformations. No consumer-document accuracy or throughput claim. No thresholds applied to degraded conditions.'}));
}finally{recognize?.close();await worker?.close();key.fill(0);ppm.fill(0);await rm(dir,{recursive:true,force:true});}
