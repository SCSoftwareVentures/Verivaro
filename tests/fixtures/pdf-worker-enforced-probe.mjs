import assert from 'node:assert/strict';
import {existsSync,readFileSync,readlinkSync,writeFileSync} from 'node:fs';
import {createServer} from 'node:net';
const [hostTmp,hostNet]=process.argv.slice(2);
assert.ok(typeof process.getuid==='function'&&process.getuid()!==0,'non-root identity required');
assert.equal(existsSync(hostTmp),false,'PrivateTmp must hide host tmp');
assert.notEqual(readlinkSync('/proc/self/ns/net'),hostNet,'PrivateNetwork must isolate namespace');
const status=readFileSync('/proc/self/status','utf8');
assert.match(status,/^NoNewPrivs:\s+1$/m);
assert.match(status,/^CapEff:\s+0+$/m);
assert.throws(()=>writeFileSync('/etc/vv-pdf-worker-probe','forbidden'),'ProtectSystem must block writes');
await new Promise((resolve,reject)=>{
 const listener=createServer(),timer=setTimeout(()=>{listener.close();reject(Error('network family probe deadline'));},2500);
 listener.once('error',e=>{clearTimeout(timer);['EAFNOSUPPORT','EPERM','EACCES'].includes(e.code)?resolve():reject(e);});
 listener.listen(0,'127.0.0.1',()=>{clearTimeout(timer);listener.close();reject(Error('AF_INET unexpectedly available'));});
});
console.log('PDF_ISOLATION_ENFORCED '+JSON.stringify({nonRoot:true,networkNamespace:true,privateTmp:true,noNewPrivileges:true,capsEmpty:true,systemWritesBlocked:true,inetDenied:true}));
