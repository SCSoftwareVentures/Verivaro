import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createNativeExtractor} from '../../packages/worker/native-extract.mjs';
function pdf(){
 const stream='BT /F1 24 Tf 40 700 Td (Serial MUST be ABC-123) Tj ET';
 const objs=['<< /Type /Catalog /Pages 2 0 R >>','<< /Type /Pages /Kids [3 0 R] /Count 1 >>','<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>','<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>','<< /Length '+Buffer.byteLength(stream)+' >>\nstream\n'+stream+'\nendstream'];
 let out='%PDF-1.4\n',offsets=[];for(let i=0;i<objs.length;i++){offsets.push(Buffer.byteLength(out));out+=(i+1)+' 0 obj\n'+objs[i]+'\nendobj\n';}
 const x=Buffer.byteLength(out);out+='xref\n0 6\n0000000000 65535 f \n'+offsets.map(n=>String(n).padStart(10,'0')+' 00000 n \n').join('')+'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n'+x+'\n%%EOF\n';return Buffer.from(out);
}
test('real Poppler extraction preserves page and literal text',async()=>{const p=await createNativeExtractor()(pdf(),'application/pdf');assert.equal(p.length,1);assert.equal(p[0].method,'pdf-text');assert.match(p[0].text,/Serial MUST be ABC-123/);});
test('real Tesseract image OCR returns an explicitly unverified page',async t=>{const root=await mkdtemp(join(tmpdir(),'vv-ocr-test-'));t.after(()=>rm(root,{recursive:true,force:true}));const path=join(root,'fixture.png');execFileSync('/usr/bin/convert',['-size','1200x240','xc:white','-font','DejaVu-Sans','-pointsize','56','-fill','black','-gravity','center','-annotate','0','SERIAL MUST BE ABC123',path]);const p=await createNativeExtractor()(await readFile(path),'image/png');assert.equal(p[0].method,'ocr');assert.match(p[0].text,/ABC123/i);});
test('damaged PDF rejected',async()=>assert.rejects(createNativeExtractor()(Buffer.from('%PDF-1.7\ninvalid'),'application/pdf')));
