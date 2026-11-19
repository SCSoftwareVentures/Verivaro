import {createHash,timingSafeEqual} from 'node:crypto';
const esc=x=>String(x??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const date=x=>{if(x===null||x===undefined)return '—';const d=new Date(x);if(!Number.isFinite(d.getTime()))throw Error('invalid timestamp');return d.toISOString();};
const integer=x=>{const n=Number(x);if(!Number.isSafeInteger(n)||n<0)throw Error('invalid metric');return n;};
const kinds={access_denials:'Access denials',integrity_failure:'Integrity failure',resource_pressure:'Resource pressure',stranded_reservation:'Stranded reservation',delivery_failures:'Delivery failures'};
const headers={'Cache-Control':'no-store, private','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",'Cross-Origin-Resource-Policy':'same-origin','Content-Type':'text/html; charset=utf-8'};
function send(res,status,body,extra={}){if(res.destroyed||res.writableEnded)return;res.writeHead(status,{...headers,'Content-Length':Buffer.byteLength(body),...extra});res.end(body);}
function label(x){if(!Object.hasOwn(kinds,x))throw Error('invalid kind');return kinds[x];}
function render(snapshot,now){
 const h=snapshot.health;
 const stamp=h.evaluated_at===null?NaN:new Date(h.evaluated_at).getTime();
 const stale=!Number.isFinite(stamp)||now-stamp>180000||stamp>now+5000;
 const active=integer(h.active_leases),reserved=integer(h.reserved_bytes),open=integer(h.open_incidents),critical=integer(h.critical_incidents);
 const incidents=snapshot.incidents.map(i=>'<tr><td>'+esc(label(i.kind))+'</td><td>'+esc(i.severity)+'</td><td>'+esc(date(i.opened_at))+'</td><td>'+esc(date(i.last_seen))+'</td><td>'+esc(date(i.acknowledged_at))+'</td><td>'+esc(date(i.escalated_at))+'</td></tr>').join('');
 const alerts=snapshot.alerts.map(a=>'<tr><td>'+esc(integer(a.event_id))+'</td><td>'+esc(label(a.kind))+'</td><td>'+esc(a.severity)+'</td><td>'+esc(a.action)+'</td><td>'+esc(date(a.occurred_at))+'</td></tr>').join('');
 return {status:stale?503:200,body:'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="30"><title>Verivaro security operations</title><style>body{font:16px system-ui;margin:2rem;max-width:1000px;color:#182331;background:#f4f6f9}h1{font-size:1.65rem}section{background:white;padding:1rem;margin:1rem 0;border:1px solid #cad3dd;border-radius:8px;overflow:auto}table{border-collapse:collapse;width:100%;font-size:.9rem}td,th{text-align:left;padding:.65rem;border-bottom:1px solid #d9e0e7}strong{font-size:1.1rem}p{line-height:1.5}</style></head><body><h1>Verivaro security operations</h1><p><strong>'+ (stale?'MONITOR STALE / UNAVAILABLE':critical?'CRITICAL INCIDENTS OPEN':open?'INCIDENTS OPEN':'MONITOR CURRENT')+'</strong> · Last evaluation '+esc(date(h.evaluated_at))+'</p><section><h2>Resource and incident status</h2><p>Active reservations: '+active+' · Reserved MiB: '+(reserved/1048576).toFixed(1)+' · Open incidents: '+open+' · Critical: '+critical+'</p></section><section><h2>Open incidents</h2><table><thead><tr><th>Signal</th><th>Severity</th><th>Opened</th><th>Last seen</th><th>Acknowledged</th><th>Escalated</th></tr></thead><tbody>'+(incidents||'<tr><td colspan="6">No open incidents</td></tr>')+'</tbody></table></section><section><h2>Internal alert inbox</h2><p>Latest 50 opened/escalated events; event IDs are stable. This is not external delivery confirmation.</p><table><thead><tr><th>Event</th><th>Signal</th><th>Severity</th><th>Action</th><th>Time (UTC)</th></tr></thead><tbody>'+(alerts||'<tr><td colspan="5">No alerts</td></tr>')+'</tbody></table></section><p>Read only · Refreshes every 30 seconds · Restricted operator access</p></body></html>'};
}
// Loopback-only admin listener, protected by a dedicated high-entropy credential.
export function createMonitorDashboard({snapshot,password,now=Date.now,maxConcurrent=2}){
 if(typeof snapshot!=='function'||typeof password!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(password)||Buffer.from(password,'base64url').toString('base64url')!==password||!Number.isInteger(maxConcurrent)||maxConcurrent<1||maxConcurrent>8)throw Error('invalid dashboard settings');
 const expected=createHash('sha256').update('Basic '+Buffer.from('operator:'+password).toString('base64')).digest();
 let active=0;
 return async(req,res)=>{
  if(!['127.0.0.1','::1','::ffff:127.0.0.1'].includes(req.socket.remoteAddress)){send(res,404,'Not available');return;}
  const auth=req.headers.authorization;
  if(typeof auth!=='string'||auth.length>256||req.rawHeaders.filter((x,i)=>i%2===0&&x.toLowerCase()==='authorization').length!==1||!timingSafeEqual(createHash('sha256').update(auth).digest(),expected)){
   send(res,401,'Authorization required',{'WWW-Authenticate':'Basic realm="Verivaro operations", charset="UTF-8"','Connection':'close'});return;
  }
  if(req.method!=='GET'||req.url!=='/'||req.headers['transfer-encoding']!==undefined||(req.headers['content-length']!==undefined&&req.headers['content-length']!=='0')){send(res,404,'Not available',{'Connection':'close'});return;}
  if(active>=maxConcurrent){send(res,429,'Not available',{'Retry-After':'5'});return;}
  active++;
  try{const view=render(await snapshot(),now());send(res,view.status,view.body);}
  catch{send(res,503,'Monitor unavailable');}
  finally{active--;}
 };
}
