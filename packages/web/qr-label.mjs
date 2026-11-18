// Fixed QR version 3-L, byte mode, mask 0. Only non-secret ProofLock labels.
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export function labelFor(id,rev){if(!UUID.test(id)||!Number.isSafeInteger(rev)||rev<1||rev>2147483647)throw Error('Invalid milestone label.');return 'VV1:'+id+':'+rev;}
export function parseLabel(s){const m=/^VV1:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):([1-9][0-9]{0,9})$/.exec(s);if(!m||Number(m[2])>2147483647)throw Error('Invalid ProofLock label.');return {milestoneId:m[1],milestoneRevision:Number(m[2])};}
function mul(x,y){let z=0;while(y){if(y&1)z^=x;y>>=1;x<<=1;if(x&256)x^=0x11d;}return z;}
function ecc(data){
 let g=[1],r=1;for(let i=0;i<15;i++){const n=Array(g.length+1).fill(0);for(let j=0;j<g.length;j++){n[j]^=g[j];n[j+1]^=mul(g[j],r);}g=n;r=mul(r,2);}
 const out=[...data,...Array(15).fill(0)];for(let i=0;i<data.length;i++){const k=out[i];for(let j=0;j<g.length;j++)out[i+j]^=mul(g[j],k);}return out.slice(data.length);
}
export function qrMatrix(label){
 parseLabel(label);const bytes=new TextEncoder().encode(label),bits=[];
 const push=(x,n)=>{for(let i=n-1;i>=0;i--)bits.push((x>>>i)&1);};
 push(4,4);push(bytes.length,8);for(const b of bytes)push(b,8);push(0,Math.min(4,440-bits.length));while(bits.length%8)bits.push(0);
 const data=[];for(let i=0;i<bits.length;i+=8)data.push(bits.slice(i,i+8).reduce((n,b)=>n*2+b,0));while(data.length<55)data.push(data.length%2===Math.ceil(bits.length/8)%2?0xec:0x11);
 const words=[...data,...ecc(data)],size=29,grid=Array.from({length:size},()=>Array(size).fill(false)),fixed=Array.from({length:size},()=>Array(size).fill(false));
 const set=(x,y,v)=>{if(x>=0&&x<size&&y>=0&&y<size){grid[y][x]=!!v;fixed[y][x]=true;}};
 for(let i=0;i<size;i++){set(6,i,i%2===0);set(i,6,i%2===0);}
 for(const [cx,cy] of [[3,3],[25,3],[3,25]])for(let y=-4;y<=4;y++)for(let x=-4;x<=4;x++){const d=Math.max(Math.abs(x),Math.abs(y));set(cx+x,cy+y,d!==2&&d!==4);}
 for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(22+x,22+y,Math.max(Math.abs(x),Math.abs(y))!==1);
 const fmt=0x77c4,bit=i=>(fmt>>>i)&1;
 for(let i=0;i<=5;i++)set(8,i,bit(i));set(8,7,bit(6));set(8,8,bit(7));set(7,8,bit(8));
 for(let i=9;i<15;i++)set(14-i,8,bit(i));
 for(let i=0;i<8;i++)set(size-1-i,8,bit(i));for(let i=8;i<15;i++)set(8,size-15+i,bit(i));set(8,size-8,true);
 let k=0,up=true;for(let right=size-1;right>=1;right-=2){if(right===6)right=5;for(let step=0;step<size;step++){const y=up?size-1-step:step;for(let x=right;x>=right-1;x--)if(!fixed[y][x]){const b=k<words.length*8?(words[k>>>3]>>>(7-(k&7)))&1:0;grid[y][x]=Boolean(b^((x+y)%2===0?1:0));k++;}}up=!up;}
 if(k!==567)throw Error('QR module count');return grid;
}
