import {createServer} from 'node:http';
import {randomUUID} from 'node:crypto';
import {serveApp} from './static.mjs';
import {ServiceError} from './service.mjs';
const UUID='([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})';
const prefix='/v1/tenants/'+UUID+'/projects/'+UUID;
const project=new RegExp('^'+prefix+'$'),doc=new RegExp('^'+prefix+'/documents$'),intent=new RegExp('^'+prefix+'/documents/'+UUID+'/uploads$'),upload=new RegExp('^'+prefix+'/uploads/'+UUID+'$');
const review=new RegExp('^'+prefix+'/uploads/'+UUID+'/review$'),match=new RegExp('^'+prefix+'/uploads/'+UUID+'/matches$');
const promoteDoc=new RegExp('^'+prefix+'/uploads/'+UUID+'/promote$'),promoteReq=new RegExp('^'+prefix+'/decisions/'+UUID+'/promote$'),evidence=new RegExp('^'+prefix+'/evidence$'),retire=new RegExp('^'+prefix+'/evidence/'+UUID+'/retire$'),readiness=new RegExp('^'+prefix+'/readiness$'),confirm=new RegExp('^'+prefix+'/scope/confirm$');
const milestone=new RegExp('^'+prefix+'/prooflock$'),rejection=new RegExp('^'+prefix+'/rejections$'),handover=new RegExp('^'+prefix+'/handover$'),draft=new RegExp('^'+prefix+'/handover/'+UUID+'$');
const financial=new RegExp('^'+prefix+'/finance$'),dispute=new RegExp('^'+prefix+'/finance/events$'),pack=new RegExp('^'+prefix+'/finance/'+UUID+'/dispute-pack$');
const exportDraft=new RegExp('^'+prefix+'/handover/'+UUID+'/export/(pdf|xlsx|zip)$'),approveIndex=new RegExp('^'+prefix+'/handover/'+UUID+'/approve-index$'),grantIndex=new RegExp('^'+prefix+'/index-releases/'+UUID+'/grants$'),revokeIndex=new RegExp('^'+prefix+'/index-grants/'+UUID+'/revoke$'),sharedIndex=new RegExp('^/v1/shared-index/'+UUID+'$');
const approveOriginals=new RegExp('^'+prefix+'/index-releases/'+UUID+'/approve-originals$'),grantOriginals=new RegExp('^'+prefix+'/index-releases/'+UUID+'/original-grants$'),bundleIndex=new RegExp('^/v1/shared-index/'+UUID+'/bundle$'),downloadOriginal=new RegExp('^/v1/shared-index/'+UUID+'/originals/'+UUID+'$');
const intelligence=new RegExp('^'+prefix+'/uploads/'+UUID+'/intelligence$'),suggestions=new RegExp('^'+prefix+'/requirements/'+UUID+'/suggestions$'),relation=new RegExp('^'+prefix+'/contract-relations$');
const catalog=new RegExp('^'+prefix+'/catalog$');
const milestoneUpload=new RegExp('^'+prefix+'/documents/'+UUID+'/milestone-uploads$'),reviewerOriginal=new RegExp('^'+prefix+'/uploads/'+UUID+'/original$');
function rejectAmbiguity(req,path){
 const h=req.headersDistinct;
 for(const name of ['authorization','content-type','content-length','host','content-encoding'])if(h[name]?.length>1)throw new ServiceError(400,'duplicate_header');
 // Explicit bearer/capability API, no cookie auth or cross-origin browser access.
 if(path.startsWith('/v1/')&&['cross-site','same-site'].includes(req.headers['sec-fetch-site']))throw new ServiceError(403,'cross_origin_denied');
 if(req.headers['content-encoding']&&req.headers['content-encoding']!=='identity')throw new ServiceError(415,'unsupported_content_encoding');
 if(['GET','HEAD'].includes(req.method)&&(req.headers['transfer-encoding']||Number(req.headers['content-length']??0)>0))throw new ServiceError(400,'unexpected_body');
}
function boundLength(req,limit){if(Number(req.headers['content-length']??0)>limit)throw new ServiceError(413,'payload_too_large');}
async function json(req){boundLength(req,16384);
 if(req.headers['content-type']!=='application/json')throw new ServiceError(415,'unsupported_media_type');
 let n=0,parts=[];for await(const b of req){n+=b.length;if(n>16384)throw new ServiceError(413,'payload_too_large');parts.push(b);}
 try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts)));}catch{throw new ServiceError(400,'invalid_json');}
}
function send(res,status,data,id){
 if(res.destroyed)return;
 const body=JSON.stringify(data);res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer','x-frame-options':'DENY','content-security-policy':"default-src 'none'; frame-ancestors 'none'",'x-request-id':id,'content-length':Buffer.byteLength(body),'connection':'close'});res.end(body);
}
/** Internal/demo HTTP server. Caller controls bind address; no implicit public listening.
 * TLS reverse proxy, distributed rate limits, trusted IdP and worker process separation are required before release.
 */
export function createHttpServer(service){
 const server=createServer({maxHeaderSize:8192,requestTimeout:30000,headersTimeout:10000},async(req,res)=>{
 const id=randomUUID(),path=req.url??'',b=req.headers.authorization;
 try{
 if(req.headersDistinct.authorization?.length>1)throw new ServiceError(400,'duplicate_authorization');
 rejectAmbiguity(req,path);
 if(serveApp(req,res))return;
 let m,out,status=200;
 if(req.method==='GET'&&path==='/health/live'){out={status:'ok'};}
 else if(req.method==='GET'&&(m=project.exec(path)))out=await service.project(b,m[1],m[2]);
 else if(req.method==='POST'&&(m=doc.exec(path))){out=await service.createDocument(b,m[1],m[2],await json(req));status=201;}
 else if(req.method==='POST'&&(m=milestoneUpload.exec(path))){out=await service.requestMilestoneUpload(b,m[1],m[2],m[3],await json(req));status=202;}
 else if(req.method==='GET'&&(m=reviewerOriginal.exec(path))){const file=await service.reviewerOriginal(b,m[1],m[2],m[3]);if(!res.destroyed){res.writeHead(200,{'content-type':file.type,'content-disposition':'attachment; filename="'+file.filename+'"','cache-control':'no-store','x-content-type-options':'nosniff','content-security-policy':"default-src 'none'; sandbox",'x-content-sha256':file.sha256,'x-request-id':id,'content-length':file.bytes.length,'connection':'close'});res.end(file.bytes);}return;}
 else if(req.method==='POST'&&(m=intent.exec(path))){out=await service.requestUpload(b,m[1],m[2],m[3],await json(req));status=202;}
 else if(req.method==='POST'&&(m=promoteDoc.exec(path))){out=await service.promoteDocument(b,m[1],m[2],m[3],await json(req));status=201;}
 else if(req.method==='POST'&&(m=promoteReq.exec(path))){out=await service.promoteRequirement(b,m[1],m[2],m[3],await json(req));status=201;}
 else if(req.method==='POST'&&(m=evidence.exec(path))){out=await service.linkEvidence(b,m[1],m[2],await json(req));status=201;}
 else if(req.method==='POST'&&(m=retire.exec(path)))out=await service.retireEvidence(b,m[1],m[2],m[3],await json(req));
 else if(req.method==='POST'&&(m=milestone.exec(path))){out=await service.saveMilestone(b,m[1],m[2],await json(req));status=201;}
 else if(req.method==='POST'&&(m=rejection.exec(path))){out=await service.saveRejection(b,m[1],m[2],await json(req));status=201;}
 else if(req.method==='POST'&&(m=handover.exec(path))){out=await service.createHandover(b,m[1],m[2],await json(req));status=201;}
 else if(req.method==='GET'&&(m=exportDraft.exec(path))){
 const file=await service.exportDraft(b,m[1],m[2],m[3],m[4]);
 if(!res.destroyed){res.writeHead(200,{'content-type':file.type,'content-disposition':'attachment; filename="'+file.filename+'"','cache-control':'no-store','x-content-type-options':'nosniff','x-request-id':id,'content-length':file.bytes.length,'connection':'close'});res.end(file.bytes);}return;
 }
 else if(req.method==='POST'&&(m=approveIndex.exec(path))){out=await service.approveIndex(b,m[1],m[2],m[3],await json(req));status=201;}
 else if(req.method==='POST'&&(m=grantIndex.exec(path))){out=await service.grantIndex(b,m[1],m[2],m[3],await json(req));status=201;}
 else if(req.method==='POST'&&(m=revokeIndex.exec(path)))out=await service.revokeIndex(b,m[1],m[2],m[3]);
 else if(req.method==='POST'&&(m=approveOriginals.exec(path))){out=await service.approveOriginals(b,m[1],m[2],m[3],await json(req));status=201;}
 else if(req.method==='POST'&&(m=grantOriginals.exec(path))){out=await service.grantOriginals(b,m[1],m[2],m[3],await json(req));status=201;}
 else if(req.method==='GET'&&(m=bundleIndex.exec(path)))out=await service.readBundleIndex(b,m[1]);
 else if(req.method==='GET'&&(m=downloadOriginal.exec(path))){
 const file=await service.downloadOriginal(b,m[1],m[2]);if(!res.destroyed){res.writeHead(200,{'content-type':file.type,'content-disposition':'attachment; filename="'+file.filename+'"','cache-control':'no-store','x-content-type-options':'nosniff','content-security-policy':"default-src 'none'; sandbox",'x-content-sha256':file.sha256,'x-request-id':id,'content-length':file.bytes.length,'connection':'close'});res.end(file.bytes);}return;
 }
 else if(req.method==='GET'&&(m=sharedIndex.exec(path)))out=await service.readSharedIndex(b,m[1]);
 else if(req.method==='GET'&&(m=draft.exec(path)))out=await service.readHandover(b,m[1],m[2],m[3]);
 else if(req.method==='POST'&&(m=intelligence.exec(path)))out=await service.analyseDraft(b,m[1],m[2],m[3],await json(req));
 else if(req.method==='GET'&&(m=suggestions.exec(path)))out=await service.evidenceSuggestions(b,m[1],m[2],m[3]);
 else if(req.method==='POST'&&(m=relation.exec(path))){out=await service.saveRelation(b,m[1],m[2],await json(req));status=201;}
 else if(req.method==='GET'&&(m=financial.exec(path)))out=await service.financial(b,m[1],m[2]);
 else if(req.method==='POST'&&(m=financial.exec(path))){out=await service.saveFinance(b,m[1],m[2],await json(req));status=201;}
 else if(req.method==='POST'&&(m=dispute.exec(path))){out=await service.recordDispute(b,m[1],m[2],await json(req));status=201;}
 else if(req.method==='GET'&&(m=pack.exec(path)))out=await service.disputePack(b,m[1],m[2],m[3]);
 else if(req.method==='GET'&&(m=catalog.exec(path)))out=await service.catalog(b,m[1],m[2]);
 else if(req.method==='GET'&&(m=readiness.exec(path)))out=await service.readiness(b,m[1],m[2]);
 else if(req.method==='POST'&&(m=confirm.exec(path)))out=await service.confirmScope(b,m[1],m[2],await json(req));
 else if(req.method==='GET'&&(m=review.exec(path)))out=await service.reviewDraft(b,m[1],m[2],m[3]);
 else if(req.method==='POST'&&(m=review.exec(path))){out=await service.decideRequirement(b,m[1],m[2],m[3],await json(req));status=201;}
 else if(req.method==='POST'&&(m=match.exec(path)))out=await service.matchDraft(b,m[1],m[2],m[3],await json(req));
 else if(req.method==='GET'&&(m=upload.exec(path)))out=await service.status(b,m[1],m[2],m[3]);
 else if(req.method==='PUT'&&(m=upload.exec(path))){
 boundLength(req,52428800);
 if(req.headers['content-type']!=='application/octet-stream')throw new ServiceError(415,'unsupported_media_type');
 out=await service.upload(b,m[1],m[2],m[3],req);status=202;
 }else throw new ServiceError(404,'resource_unavailable');
 send(res,status,out,id);
 }catch(e){const safe=e instanceof ServiceError?e:new ServiceError(503,'service_unavailable');send(res,safe.status,{status:safe.status,code:safe.code,request_id:id},id);}
 });
 server.maxRequestsPerSocket=1;server.setTimeout(35000,socket=>socket.destroy());
 return server;
}
