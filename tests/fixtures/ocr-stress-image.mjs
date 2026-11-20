// Deterministic synthetic artefacts for OCR regression only; not photographs.
const fail=()=>{throw Error('invalid OCR stress fixture');};
export const modes=Object.freeze(['clean','washed','motion-blur','speckle','shear']);
export function stressRgbPpm(source,mode){
 if(!Buffer.isBuffer(source)||source.length<16||source.length>3*1048576+64||!modes.includes(mode))fail();
 const m=/^P6\n([1-9]\d{0,3}) ([1-9]\d{0,3})\n255\n/.exec(source.subarray(0,64).toString('latin1'));
 if(!m)fail();const width=Number(m[1]),height=Number(m[2]),start=m[0].length;
 if(width>2048||height>2048||width*height>1048576||source.length-start!==width*height*3)fail();
 const original=source.subarray(start),pixels=Buffer.alloc(width*height*3,255);
 const index=(x,y)=>3*(y*width+x);
 for(let y=0;y<height;y++)for(let x=0;x<width;x++){
  const dst=index(x,y),shift=mode==='shear'?Math.floor((y-height/2)*0.075):0,at=x-shift;
  for(let c=0;c<3;c++){
   const sample=at>=0&&at<width?original[index(at,y)+c]:255;
   if(mode==='washed')pixels[dst+c]=Math.round(200+sample*0.21);
   else if(mode==='motion-blur'){
    let n=0,sum=0;for(let dx=-2;dx<=2;dx++){const xx=x+dx;if(xx>=0&&xx<width){sum+=original[index(xx,y)+c];n++;}}
    pixels[dst+c]=Math.round(sum/n);
   }else if(mode==='speckle')pixels[dst+c]=((x*13+y*19+7)%37===0)?0:sample;
   else pixels[dst+c]=sample;
  }
 }
 return Object.freeze({width,height,pixels});
}
