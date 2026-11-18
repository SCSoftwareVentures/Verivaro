import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {labelFor,qrMatrix} from '../../packages/web/qr-label.mjs';
test('independent ZBar decoder recognises generated milestone labels',async()=>{const root=await mkdtemp(join(tmpdir(),'vv-qr-'));try{for(const rev of [1,123,2147483647]){const label=labelFor('12345678-1234-1234-1234-123456789abc',rev),m=qrMatrix(label),size=296,b=Buffer.alloc(size*size,255);for(let y=0;y<29;y++)for(let x=0;x<29;x++)if(m[y][x])for(let j=0;j<8;j++)for(let i=0;i<8;i++)b[((y+4)*8+j)*size+(x+4)*8+i]=0;const fn=join(root,'qr.pgm');await writeFile(fn,Buffer.concat([Buffer.from('P5\n'+size+' '+size+'\n255\n'),b]));assert.equal(execFileSync('zbarimg',['--quiet','--raw',fn],{encoding:'utf8'}).trim(),label);}}finally{await rm(root,{recursive:true,force:true});}});
