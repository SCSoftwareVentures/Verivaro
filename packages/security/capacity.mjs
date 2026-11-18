/** Per-process capacity boundary. Distributed ingress enforcement remains a deployment requirement. */
export class CapacityError extends Error {}
export function createCapabilityGate({maxConcurrent=4,maxPerMinute=120,clock=()=>performance.now()}={}){
 if(!Number.isSafeInteger(maxConcurrent)||maxConcurrent<1||!Number.isSafeInteger(maxPerMinute)||maxPerMinute<1)throw Error('invalid capability budget');
 let active=0,used=0,start=clock();
 return async function run(operation){
 const t=clock();if(t-start>=60000){start=t;used=0;}
 if(active>=maxConcurrent||used>=maxPerMinute)throw new CapacityError('capability capacity');
 active++;used++;
 try{return await operation();}finally{active--;}
 };
}
