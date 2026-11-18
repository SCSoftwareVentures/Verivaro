import test from 'node:test';
import assert from 'node:assert/strict';
import {request} from 'node:http';
import {createHttpServer} from '../../packages/api/http.mjs';
const u='00000000-0000-0000-0000-000000000001',prefix='/v1/tenants/'+u+'/projects/'+u;
test('adversarial HTTP boundaries reject malformed or cross-origin requests before dispatch',async t=>{
 let invoked=0;const service={project:()=>{invoked++;return {ok:true};},createDocument:()=>{invoked++;return {};},upload:()=>{invoked++;return {};}};
 const server=createHttpServer(service);await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
 const call=(path,method,headers,body)=>new Promise((resolve,reject)=>{const req=request({host:'127.0.0.1',port:server.address().port,path,method,headers},res=>{let s='';res.on('data',b=>s+=b);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:JSON.parse(s)}));});req.on('error',reject);req.end(body);});
 const h={'authorization':'Bearer synthetic','content-type':'application/json'};
 const bad=[
 [prefix,'GET',{'sec-fetch-site':'cross-site'},undefined,403],
 [prefix,'GET',{'sec-fetch-site':'same-site'},undefined,403],
 [prefix,'GET',{'content-length':'1'},'x',400],
 [prefix+'/documents','POST',{...h,'content-encoding':'gzip'},'{}',415],
 [prefix+'/documents','POST',{...h,'content-type':['application/json','text/plain']},'{}',400],
 [prefix+'/documents','POST',{...h,'authorization':['Bearer a','Bearer b']},'{}',400],
 [prefix+'/documents','POST',{...h,'content-length':'20000'},' '.repeat(20000),413],
 [prefix+'/documents','POST',h,Buffer.from([0xff]),400],
 [prefix+'/documents','POST',h,'{"invalid":',400],
 [prefix+'/uploads/'+u,'PUT',{'content-type':'application/octet-stream','content-length':'52428801'},undefined,413],
 [prefix+'%2f..%2f','GET',{},undefined,404]
 ];
 for(const [path,method,headers,body,status] of bad){const r=await call(path,method,headers,body);assert.equal(r.status,status,path+' '+JSON.stringify(headers));assert.equal(r.headers['cache-control'],'no-store');assert.equal(r.headers['x-frame-options'],'DENY');assert.equal(r.headers['access-control-allow-origin'],undefined);}
 assert.equal(invoked,0);const r=await call(prefix,'GET',{'sec-fetch-site':'same-origin'});assert.equal(r.status,200);assert.equal(invoked,1);
});
