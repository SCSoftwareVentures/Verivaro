import {createServer} from 'node:http';
import {randomUUID} from 'node:crypto';
import {ServiceError} from './service.mjs';
const UUID='([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})';
const prefix='/v1/tenants/'+UUID+'/projects/'+UUID;
const project=new RegExp('^'+prefix+'$'),doc=new RegExp('^'+prefix+'/documents$'),intent=new RegExp('^'+prefix+'/documents/'+UUID+'/uploads$'),upload=new RegExp('^'+prefix+'/uploads/'+UUID+'$');
const review=new RegExp('^'+prefix+'/uploads/'+UUID+'/review$'),match=new RegExp('^'+prefix+'/uploads/'+UUID+'/matches$');
async function json(req){
 if(req.headers['content-type']!=='application/json')throw new ServiceError(415,'unsupported_media_type');
 let n=0,parts=[];for await(const b of req){n+=b.length;if(n>16384)throw new ServiceError(413,'payload_too_large');parts.push(b);}
 try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts)));}catch{throw new ServiceError(400,'invalid_json');}
}
function send(res,status,data,id){
 if(res.destroyed)return;
 const body=JSON.stringify(data);res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','x-request-id':id,'content-length':Buffer.byteLength(body),'connection':'close'});res.end(body);
}
/** Internal/demo HTTP server. Caller controls bind address; no implicit public listening.
 * TLS reverse proxy, distributed rate limits, trusted IdP and worker process separation are required before release.
 */
export function createHttpServer(service){
 const server=createServer({maxHeaderSize:8192,requestTimeout:30000,headersTimeout:10000},async(req,res)=>{
 const id=randomUUID(),path=req.url??'',b=req.headers.authorization;
 try{
 if(req.headersDistinct.authorization?.length>1)throw new ServiceError(400,'duplicate_authorization');
 let m,out,status=200;
 if(req.method==='GET'&&path==='/health/live'){out={status:'ok'};}
 else if(req.method==='GET'&&(m=project.exec(path)))out=await service.project(b,m[1],m[2]);
 else if(req.method==='POST'&&(m=doc.exec(path))){out=await service.createDocument(b,m[1],m[2],await json(req));status=201;}
 else if(req.method==='POST'&&(m=intent.exec(path))){out=await service.requestUpload(b,m[1],m[2],m[3],await json(req));status=202;}
 else if(req.method==='GET'&&(m=review.exec(path)))out=await service.reviewDraft(b,m[1],m[2],m[3]);
 else if(req.method==='POST'&&(m=review.exec(path))){out=await service.decideRequirement(b,m[1],m[2],m[3],await json(req));status=201;}
 else if(req.method==='POST'&&(m=match.exec(path)))out=await service.matchDraft(b,m[1],m[2],m[3],await json(req));
 else if(req.method==='GET'&&(m=upload.exec(path)))out=await service.status(b,m[1],m[2],m[3]);
 else if(req.method==='PUT'&&(m=upload.exec(path))){
 if(req.headers['content-type']!=='application/octet-stream')throw new ServiceError(415,'unsupported_media_type');
 out=await service.upload(b,m[1],m[2],m[3],req);status=202;
 }else throw new ServiceError(404,'resource_unavailable');
 send(res,status,out,id);
 }catch(e){const safe=e instanceof ServiceError?e:new ServiceError(503,'service_unavailable');send(res,safe.status,{status:safe.status,code:safe.code,request_id:id},id);}
 });
 server.maxRequestsPerSocket=1;server.setTimeout(35000,socket=>socket.destroy());
 return server;
}
