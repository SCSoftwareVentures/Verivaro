import {writeFileSync} from 'node:fs';
import {canonicalScannedPdf} from '../../src/security/scanned-pdf.mjs';
import {fixturePng} from './evidence-formats-fixture.mjs';
const w=200,h=80,pixels=Buffer.alloc(h*(w*3+1),255);
for(let y=0;y<h;y++){pixels[y*(w*3+1)]=0;for(let x=0;x<w;x++){const o=y*(w*3+1)+1+x*3;const c=(x+y)%6===0?0:255;pixels[o]=c;pixels[o+1]=c;pixels[o+2]=c;}}
if(process.argv[3]==='multipage'){
 const {canonicalMultipageScannedPdf}=await import('../../src/security/scanned-pdf-multipage.mjs');
 const second=Buffer.from(pixels);second[7]=0;
 writeFileSync(process.argv[2],canonicalMultipageScannedPdf([fixturePng({width:w,height:h,pixels}),fixturePng({width:w,height:h,pixels:second})]));second.fill(0);
}else writeFileSync(process.argv[2],canonicalScannedPdf(fixturePng({width:w,height:h,pixels})));
pixels.fill(0);
