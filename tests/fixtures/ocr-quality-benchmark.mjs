import assert from 'node:assert/strict';
import {mkdir,readFile,writeFile,mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomBytes,createHash} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {canonicalTextPdf} from '../../src/security/evidence-formats.mjs';
import {fixturePng} from './evidence-formats-fixture.mjs';
import {createTesseractEngine,parseOcrTsv} from '../../src/security/ocr-preview.mjs';
import {startOcrWorker,createOcrSocketClient} from '../../src/security/ocr-socket.mjs';
import {scoreOcrCases} from '../../src/security/ocr-quality.mjs';
const inputs=[
 ['equipment-id','Equipment must carry ID.'],
 ['valve-tag','Valve V-204 must be checked.'],
 ['zone-number','No vehicles are permitted in Zone 3.'],
 ['inspection-date','Inspection required by 30 June 2026.'],
 ['pressure-interval','Record pressure every 15 minutes.'],
 ['emergency-access','Emergency exit must remain clear.']
];
const root=process.argv[3],mode=process.argv[2];
if(!root||!['emit','evaluate'].includes(mode))throw Error('usage: ocr-quality-benchmark.mjs emit|evaluate <existing-directory>');
if(mode==='emit'){
 for(const [id,text] of inputs)await writeFile(join(root,id+'.pdf'),canonicalTextPdf([text]),{mode:0o600});
}else{
 const temp=await mkdtemp(join(tmpdir(),'vv-ocr-metrics-')),socketPath=join(temp,'ocr.sock'),key=randomBytes(32),hash=b=>createHash('sha256').update(b).digest('hex');
 let worker,client;const cases=[];
 try{
  worker=await startOcrWorker({socketPath,key,recognize:createTesseractEngine()});client=createOcrSocketClient({socketPath,key});
  for(const [id,reference] of inputs){
   const ppm=await readFile(join(root,id+'.ppm')),m=/^P6\n([1-9]\d*) ([1-9]\d*)\n255\n/.exec(ppm.subarray(0,64).toString('latin1'));
   assert.ok(m,'expected independently rendered P6 PPM');
   const width=Number(m[1]),height=Number(m[2]),start=m[0].length;assert.ok(width>0&&width<=2048&&height>0&&height<=2048&&width*height<=1048576);assert.equal(ppm.length-start,width*height*3);
   const pixels=Buffer.alloc(height*(width*3+1));for(let y=0;y<height;y++)ppm.copy(pixels,y*(width*3+1)+1,start+y*width*3,start+(y+1)*width*3);
   let png,out;try{
    png=fixturePng({width,height,pixels});
    const began=performance.now();out=await client(png,new AbortController().signal);const elapsedMs=performance.now()-began;
    const regions=parseOcrTsv(out,{width,height});
    cases.push({id,reference,observed:regions.map(r=>r.quote).join(' '),elapsedMs});
    assert.ok(regions.every(r=>r.reviewRequired)); // No score may bypass the review gate.
   }finally{png?.fill(0);out?.fill(0);pixels.fill(0);ppm.fill(0);}
  }
  const summary=scoreOcrCases(cases);
  console.log('OFFLINE_OCR_SYNTHETIC_BENCHMARK '+JSON.stringify({engine:'system-Tesseract-English-PSM6',fixture:'canonical PDF rendered separately by Poppler',summary}));
  assert.equal(summary.sampleCount,6);
  assert.ok(summary.characterErrorRate<=0.10,'synthetic character error rate regression');
  assert.ok(summary.wordErrorRate<=0.20,'synthetic word error rate regression');
  assert.ok(summary.exactLineRate>=0.66,'synthetic exact-line regression');
  assert.ok(summary.criticalIdentifierRecall!==null&&summary.criticalIdentifierRecall>=0.8,'synthetic critical identifier regression');
 }finally{client?.close();await worker?.close();key.fill(0);await rm(temp,{recursive:true,force:true});}
}
