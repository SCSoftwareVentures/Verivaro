import {createServer} from 'node:net';
import {join} from 'node:path';
// Protocol fixture, not a malware engine. The tests explicitly select verdicts.
export async function scannerFixture(directory){
 const socketPath=join(directory,'clamd.sock');let verdict='clean',calls=0;
 const server=createServer(socket=>{
  let bytes=Buffer.alloc(0);
  socket.on('error',()=>{});
  socket.on('data',chunk=>{
   bytes=Buffer.concat([bytes,chunk]);
   if(bytes.length<14)return;
   if(bytes.subarray(0,10).toString()!=='zINSTREAM\0'){socket.destroy();return;}
   const len=bytes.readUInt32BE(10);
   if(bytes.length<18+len)return;
   if(bytes.length!==18+len||bytes.readUInt32BE(14+len)!==0){socket.destroy();return;}
   calls++;
   if(verdict==='clean')socket.end('stream: OK\0');
   else if(verdict==='infected')socket.end('stream: Fixture.Test FOUND\0');
   else if(verdict==='error')socket.end('stream: scanner unavailable ERROR\0');
   else socket.destroy();
  });
 });
 await new Promise((r,j)=>{server.once('error',j);server.listen(socketPath,r);});
 return {socketPath,get calls(){return calls;},setVerdict(x){verdict=x;},close:()=>new Promise(r=>server.close(r))};
}
