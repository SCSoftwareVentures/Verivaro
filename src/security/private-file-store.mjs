import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { isAbsolute, join } from 'node:path';
const idPattern=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export function isArtifactId(value){return typeof value==='string'&&idPattern.test(value);}
// Trusted, dedicated private directory. No user-controlled ancestor paths.
// File names are internal UUIDs, not supplied filenames. Linux/POSIX adapter.
export function createPrivateFileStore(root){
 if(typeof root!=='string'||!isAbsolute(root)||!constants.O_NOFOLLOW)throw new TypeError('unsupported private file store');
 return async function openArtifact(id,{signal,maxBytes}){
  if(!isArtifactId(id)||!Number.isSafeInteger(maxBytes)||maxBytes<1)throw Error('invalid artifact');
  signal.throwIfAborted();
  const handle=await open(join(root,id),constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
   const stats=await handle.stat();
   if(!stats.isFile()||stats.size<1||stats.size>maxBytes)throw Error('invalid artifact');
   signal.throwIfAborted();
   return handle.createReadStream({autoClose:true,signal});
  }catch(e){await handle.close();throw e;}
 };
}
