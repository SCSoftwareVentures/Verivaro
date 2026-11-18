/** Explicit confirmed UTC instants only. No inference that work has occurred. */
export function evidenceWindow(input:{milestone:string|null;confirmed:boolean;leadMinutes:number;now:string;irreversibility:'reversible'|'costly'|'irreversible'}){
 const parse=(s:string)=>{if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(s))throw new Error('canonical UTC timestamp required');const n=Date.parse(s);if(!Number.isFinite(n)||new Date(n).toISOString()!==s)throw new Error('invalid timestamp');return n;};
 const now=parse(input.now);if(!Number.isSafeInteger(input.leadMinutes)||input.leadMinutes<0||input.leadMinutes>525600||!['reversible','costly','irreversible'].includes(input.irreversibility)||typeof input.confirmed!=='boolean')throw new Error('invalid evidence window');
 if(!input.confirmed||input.milestone===null)return {due:null,status:'unknown',risk:input.irreversibility};const due=parse(input.milestone)-input.leadMinutes*60000;return {due:new Date(due).toISOString(),status:now>=due?'due-or-overdue':'upcoming',risk:input.irreversibility};
}
