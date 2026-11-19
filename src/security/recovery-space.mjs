import {statfs} from 'node:fs/promises';
// Advisory storage headroom; dedicated volume quotas remain mandatory.
export async function requireRecoverySpace(directory,bytes,{minimumFreeBytes=64*1024*1024,inspect=statfs}={}){
 if(!Number.isSafeInteger(bytes)||bytes<0||!Number.isSafeInteger(minimumFreeBytes)||minimumFreeBytes<0)throw Error('invalid recovery allocation');
 const s=await inspect(directory,{bigint:true});
 if(typeof s.bavail!=='bigint'||typeof s.bsize!=='bigint'||s.bavail<0n||s.bsize<1n)throw Error('invalid recovery filesystem');
 if(s.bavail*s.bsize<BigInt(bytes)+BigInt(minimumFreeBytes))throw Error('insufficient recovery storage');
}
