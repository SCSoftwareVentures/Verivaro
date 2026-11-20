import test from 'node:test';
import assert from 'node:assert/strict';
import {stressRgbPpm,modes} from '../fixtures/ocr-stress-image.mjs';
const ppm=(w,h,p)=>Buffer.concat([Buffer.from('P6\n'+w+' '+h+'\n255\n'),p]);
test('all synthetic OCR conditions keep size, enforce deterministic pixel transforms',()=>{
 const data=ppm(4,3,Buffer.from(Array.from({length:36},(_,i)=>(i*7)%256)));
 const baseline=stressRgbPpm(data,'clean');
 assert.deepEqual(baseline.pixels,data.subarray(data.length-36));
 const a=stressRgbPpm(data,'speckle'),b=stressRgbPpm(data,'speckle');assert.deepEqual(a.pixels,b.pixels);
 for(const mode of modes){const x=stressRgbPpm(data,mode);assert.equal(x.width,4);assert.equal(x.height,3);assert.equal(x.pixels.length,36);x.pixels.fill(0);}
 baseline.pixels.fill(0);a.pixels.fill(0);b.pixels.fill(0);
});
test('stress input validates dimensions, PPM header, exact bytes and modes',()=>{
 const valid=ppm(1,1,Buffer.from([10,20,30]));
 for(const source of [ppm(0,1,Buffer.from([0])),Buffer.from('P3\n1 1\n255\nabc'),Buffer.concat([valid,Buffer.from('extra')]),valid.subarray(0,-1),Buffer.alloc(0)])assert.throws(()=>stressRgbPpm(source,'clean'));
 assert.throws(()=>stressRgbPpm(valid,'unknown'));
});
