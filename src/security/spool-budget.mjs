import {statfs} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
const BLOCK=256*1024,TAG=16,ALIGN=4096;
export const MAX_AGGREGATE_SPOOL_BYTES=2*1024*1024*1024;
export function encryptedReservation(bytes){
 if(!Number.isSafeInteger(bytes)||bytes<1||bytes>512*1024*1024)throw Error('invalid reservation size');
 // Round the encrypted file to filesystem blocks; reserve extra metadata space.
 return Math.ceil((bytes+Math.ceil(bytes/BLOCK)*TAG)/ALIGN)*ALIGN+ALIGN*8;
}
// Shared by all handlers using the same filesystem in this process.
// An independently enforced filesystem quota is still required across processes.
export function createSpoolBudget({directory,capacityBytes=MAX_AGGREGATE_SPOOL_BYTES,minimumFreeBytes=64*1024*1024,inspect=statfs}){
 if(typeof directory!=='string'||!isAbsolute(directory)||!Number.isSafeInteger(capacityBytes)||capacityBytes<1||capacityBytes>MAX_AGGREGATE_SPOOL_BYTES||
 !Number.isSafeInteger(minimumFreeBytes)||minimumFreeBytes<0||typeof inspect!=='function')throw Error('invalid spool budget');
 let reserved=0,peak=0,active=0;
 return Object.freeze({
  directory,
  async reserve(bytes,signal){
   const need=encryptedReservation(bytes);
   signal.throwIfAborted();
   // Reserve synchronously before statfs so concurrent admissions cannot oversubscribe.
   if(need>capacityBytes-reserved)return null;
   reserved+=need;active++;peak=Math.max(peak,reserved);
   let released=false;
   const release=()=>{if(released)return;released=true;reserved-=need;active--;};
   try{
    const info=await inspect(directory,{bigint:true});
    signal.throwIfAborted();
    if(typeof info.bavail!=='bigint'||typeof info.bsize!=='bigint'||info.bavail<0n||info.bsize<1n)throw Error('invalid filesystem status');
    // Deliberately conservative: already consumed staging bytes are also covered
    // by reservations. External writers can still consume free space later.
    if(info.bavail*info.bsize<BigInt(minimumFreeBytes+reserved)){release();return null;}
    return Object.freeze({release});
   }catch(e){release();throw e;}
  },
  snapshot(){return Object.freeze({reservedBytes:reserved,peakReservedBytes:peak,active,capacityBytes});}
 });
}
