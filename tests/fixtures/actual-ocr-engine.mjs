import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createTesseractEngine,parseOcrTsv} from '../../src/security/ocr-preview.mjs';
import {fixturePng} from './evidence-formats-fixture.mjs';
// Poppler emits P6 PPM; transform an independently rendered synthetic PDF
// into the existing strict RGB PNG format (no ancillary chunks).
const ppm=await readFile(process.argv[2]),header=/^P6\n([1-9]\d*) ([1-9]\d*)\n255\n/.exec(ppm.subarray(0,64).toString('latin1'));
assert.ok(header);const width=Number(header[1]),height=Number(header[2]),start=header[0].length;assert.equal(ppm.length-start,width*height*3);
const pixels=Buffer.alloc(height*(width*3+1));for(let y=0;y<height;y++)ppm.copy(pixels,y*(width*3+1)+1,start+y*width*3,start+(y+1)*width*3);
const png=fixturePng({width,height,pixels}),recognize=createTesseractEngine(),out=await recognize(png,new AbortController().signal);
try{const rows=parseOcrTsv(out,{width,height});assert.match(rows.map(r=>r.quote).join(' '),/Equipment must carry ID/i);assert.ok(rows.every(r=>r.reviewRequired));console.log('actual_tesseract_synthetic_image_gate_passed');}finally{out.fill(0);png.fill(0);pixels.fill(0);ppm.fill(0);}
