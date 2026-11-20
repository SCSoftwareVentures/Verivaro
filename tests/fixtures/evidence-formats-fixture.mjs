import {deflateSync} from 'node:zlib';
import {crc32} from '../../src/security/evidence-formats.mjs';
export function fixturePng({width=1,height=1,pixels=Buffer.from([0,125,60,20]),extra}={}){
 function chunk(type,data){
  const len=Buffer.alloc(4),t=Buffer.from(type),crc=Buffer.alloc(4);len.writeUInt32BE(data.length);crc.writeUInt32BE(crc32(Buffer.concat([t,data])));return Buffer.concat([len,t,data,crc]);
 }
 const h=Buffer.alloc(13);h.writeUInt32BE(width,0);h.writeUInt32BE(height,4);h[8]=8;h[9]=2;
 return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',h),...(extra?[chunk('tEXt',Buffer.from('comment'))]:[]),chunk('IDAT',deflateSync(pixels)),chunk('IEND',Buffer.alloc(0))]);
}
