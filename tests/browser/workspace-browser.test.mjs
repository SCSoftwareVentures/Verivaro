import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {once} from 'node:events';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {buildRejectionPreflight} from '../../src/security/rejection-preflight.mjs';
import {workspacePage,workspaceScript,workspaceCss} from '../../src/security/workspace-assets.mjs';
if(!process.env.VV_BROWSER_DIR||!['chromium','webkit'].includes(process.env.VV_BROWSER_ENGINE))throw Error('explicit browser fixture required');
const engine=process.env.VV_BROWSER_ENGINE,driver=createRequire(resolve(process.env.VV_BROWSER_DIR,'package.json'))('playwright');
const tenant='11111111-1111-4111-8111-111111111111',project='22222222-2222-4222-8222-222222222222',requestId='33333333-3333-4333-8333-333333333333',evidenceId='44444444-4444-4444-8444-444444444444';
const name='<img src=x onerror=alert(1)> '+ 'W'.repeat(92),code=Buffer.alloc(32,7).toString('base64url'),base='/api/v1/tenants/'+tenant,projectBase=base+'/projects/'+project;
const csp="default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
test('real browser renders signed-out, invited, owner and archived states; role controls and refresh',{timeout:120000},async()=>{
 const server=createServer((req,res)=>{
  const assets={'/': ['text/html; charset=utf-8',workspacePage],'/assets/workspace.js':['text/javascript; charset=utf-8',workspaceScript],'/assets/workspace.css':['text/css; charset=utf-8',workspaceCss]};
  const v=assets[req.url];if(!v){res.writeHead(404);return res.end();}
  res.writeHead(200,{'Content-Type':v[0],'Content-Security-Policy':csp,'Cache-Control':'no-store'});res.end(v[1]);
 });
 server.listen(0,'127.0.0.1');await once(server,'listening');
 const origin='http://127.0.0.1:'+server.address().port;let browser;
 try{
  browser=await driver[engine].launch({headless:true});
  for(const width of [320,390,1280]){
   const context=await browser.newContext({viewport:{width,height:900},isMobile:width<500,hasTouch:width<500});
   const page=await context.newPage(),errors=[],calls=[];let role='guest',archived=false,renameCount=0,graphWrites=[];
   page.on('pageerror',e=>errors.push(e.message));page.on('dialog',d=>d.accept());
   await page.route('**/api/**',async route=>{
    const req=route.request(),path=new URL(req.url()).pathname,method=req.method();calls.push({path,method});let payload,status=200;
    if(path==='/api/v1/workspaces'){if(role==='guest')status=401;payload={items:['owner','viewer'].includes(role)?[{id:tenant,name,role}]:[]};}
    else if(path===base+'/administration/invite-redeem'&&method==='POST'){
     const input=req.postDataJSON();assert.deepEqual(input,{requestId,code});assert.equal(role,'invited');role='viewer';payload={generation:requestId};
    }else if(path===base+'/administration/transfers')payload={items:[]};
    else if(path===base+'/administration/enrollments'||path===base+'/administration/directory'){assert.equal(role,'owner');payload={items:[]};}
    else if(path===base+'/projects')payload={items:role==='owner'?[{id:project,name}]:[]};
    else if(path===projectBase+'/releases')payload={tenantRole:role,projectRole:role,publishEnabled:true,uploadsEnabled:true,evidence:[{id:evidenceId,sha256:'b'.repeat(64),bytes:5,mediaType:'text/plain; charset=utf-8',canSubmit:true}],requests:[]};
    else if(path===projectBase&&method==='GET')payload={project:{id:project,name,revision:0,archivedAt:archived?'2026-11-19T00:00:00Z':null}};
    else if(path===projectBase&&method==='PATCH'){assert.equal(role,'owner');assert.ok(req.headers()['idempotency-key']);renameCount++;payload={revision:1};}
    else if(path===projectBase+'/directory'||path===projectBase+'/shares')payload={items:[]};
    else if(path===projectBase+'/verification/submission-list')payload={items:[],downloadEnabled:true};
    else if(path===projectBase+'/verification'&&method==='GET'){payload={version:1,canWrite:role==='owner'&&!archived,extractionEnabled:true,archived,summary:{requirements:graphWrites.length,required:graphWrites.filter(x=>x.applicability==='required').length,verifiedRequired:0,blockers:graphWrites.length,status:graphWrites.length?'blocked':'not_assessed'},requirements:graphWrites.map(x=>({...x,revision:1,ruleDecision:'pending',ruleReason:null,state:'awaiting_rule_review',links:[],canRevise:!archived,canReview:false,canLink:false}))};payload.preflight=buildRejectionPreflight(payload);}
    else if(path===projectBase+'/verification/extract'&&method==='POST'){assert.equal(role,'owner');assert.deepEqual(req.postDataJSON(),{evidenceId,sha256:'b'.repeat(64)});payload={candidates:[{line:2,page:null,quote:'Equipment must carry an identifier.',quoteSha256:'a'.repeat(64)}],skipped:0,truncated:false,warning:'Review the original.'};}
    else if(path===projectBase+'/verification/import-source'&&method==='POST'){const x=req.postDataJSON();assert.equal(x.evidenceId,evidenceId);assert.equal(x.line,2);assert.equal(x.quote,undefined);graphWrites.push({...x,title:'Source line 2',criterion:'Equipment must carry an identifier.',source:{evidenceId,sha256:x.sha256,line:2,page:null,quoteSha256:x.quoteSha256}});payload={requirementId:x.requirementId,versionId:x.versionId,revision:1};}
    else if(path===projectBase+'/verification/requirement'&&method==='POST'){assert.equal(role,'owner');const x=req.postDataJSON();assert.equal(x.expectedRevision,0);graphWrites.push(x);payload={requirementId:x.requirementId,versionId:x.versionId,revision:1};}
    else if(path===projectBase+'/report')payload={summary:{evidence:1,encrypted:1,bytes:5,requests:0,states:{}}};
    else{status=404;payload={error:'not_found'};}
    await route.fulfill({status,contentType:'application/json',body:JSON.stringify(payload)});
   });
   async function notice(value){await page.waitForFunction(v=>document.getElementById('notice').textContent===v,value);}
   async function fits(){const size=await page.evaluate(()=>{const viewport=document.documentElement.clientWidth,scroll=document.documentElement.scrollWidth;return {viewport,scroll,internalOverflow:[...document.querySelectorAll('body *')].filter(e=>e.clientWidth>0&&e.scrollWidth>e.clientWidth+1).slice(0,12).map(e=>({tag:e.tagName,id:e.id,client:e.clientWidth,scroll:e.scrollWidth})),offenders:[...document.querySelectorAll('body *')].filter(e=>{const b=e.getBoundingClientRect();return b.width>0&&b.right>viewport+1;}).slice(0,12).map(e=>({tag:e.tagName,id:e.id,cls:e.className,right:Math.round(e.getBoundingClientRect().right),width:Math.round(e.getBoundingClientRect().width),scroll:e.scrollWidth}))};});assert.ok(size.scroll<=size.viewport+1,JSON.stringify({engine,width,...size}));assert.deepEqual(size.offenders,[],JSON.stringify({engine,width,...size}));}
   await page.goto(origin);await notice('Sign in again.');assert.equal(await page.locator('#workspace').isVisible(),false);assert.equal(await page.locator('#invitationPanel').isVisible(),false);
   role='invited';await page.reload();await notice('No accessible workspaces.');assert.equal(await page.locator('#invitationPanel').isVisible(),true);assert.equal(await page.locator('#projectContent').isVisible(),false);await fits();
   await page.locator('#inviteTenant').fill(tenant);await page.locator('#inviteRequest').fill(requestId);await page.locator('#inviteCode').fill('bad');
   await page.getByRole('button',{name:'Accept invitation',exact:true}).click();await notice('Enter the supplied invitation details.');assert.equal(calls.filter(x=>x.path.endsWith('/invite-redeem')).length,0);
   await page.locator('#inviteCode').fill(code);await page.getByRole('button',{name:'Accept invitation',exact:true}).click();await notice('Invitation accepted.');
   assert.equal(await page.locator('#inviteCode').inputValue(),'');assert.equal(await page.locator('#tenant').inputValue(),tenant);assert.equal(await page.locator('#tenantOwnerControls').isVisible(),false);assert.equal(await page.locator('#projectContent').isVisible(),false);await fits();
   role='owner';await page.reload();await notice('Workspace ready.');assert.equal(await page.locator('#projectContent').isVisible(),true);assert.equal(await page.locator('#tenantOwnerControls').isVisible(),true);assert.equal(await page.locator('#archive').isVisible(),true);
   assert.equal(await page.locator('#name').inputValue(),name);assert.equal(await page.locator('#selectedTenantName').textContent(),name);assert.equal(await page.locator('#selectedProjectName').textContent(),name);assert.ok((await page.locator('#tenant option').textContent()).length<22);assert.equal(await page.locator('img').count(),0);assert.equal(await page.locator('#reportPdf').getAttribute('href'),projectBase+'/report-pdf');await fits();
   assert.equal(await page.locator('#graphStatus').textContent(),'Not assessed — no mandatory criteria');assert.match(await page.locator('#preflightSummary').textContent(),/Not assessed/);assert.equal(await page.locator('#prepareSubmission').isVisible(),false);assert.match(await page.locator('#submissionItems').textContent(),/No submission snapshots/);
   await page.locator('#ruleTitle').fill('Serial number');await page.locator('#ruleCriterion').fill('Match approved register.');await page.locator('#ruleApplicability').selectOption('required');
   await page.getByRole('button',{name:'Create requirement',exact:true}).click();await notice('Requirement drafted.');assert.equal(graphWrites.length,1);
   assert.match(await page.locator('#graphStatus').textContent(),/Blocked/);assert.match(await page.locator('#graphItems').textContent(),/Serial number/);assert.match(await page.locator('#preflightSummary').textContent(),/0%.*1 blockers/);assert.match(await page.locator('#preflightActions').textContent(),/independent reviewer/);await fits();
   await page.getByRole('button',{name:'Find candidate requirements',exact:true}).click();await page.locator('#extractCandidates article').waitFor();assert.match(await page.locator('#extractCandidates').textContent(),/Equipment must carry an identifier/);
   await page.getByRole('button',{name:'Draft from source',exact:true}).click();await notice('Source-linked requirement drafted.');assert.equal(graphWrites.length,2);assert.match(await page.locator('#graphItems').textContent(),/Source SHA-256/);await fits();
   await page.locator('#name').fill('Updated project');await page.getByRole('button',{name:'Save name',exact:true}).click();await notice('Project name saved.');assert.equal(renameCount,1);
   archived=true;await page.getByRole('button',{name:'Refresh',exact:true}).click();await notice('Workspace ready.');assert.equal(await page.locator('#archive').isVisible(),false);assert.equal(await page.locator('#rename').isVisible(),false);assert.equal(await page.locator('#upload').isVisible(),false);assert.equal(await page.getByRole('button',{name:'Submit for review',exact:true}).count(),0);assert.equal(await page.locator('#reportPanel').isVisible(),true);assert.equal(await page.locator('#requirementForm').isVisible(),false);assert.equal(await page.locator('#contractIQ').isVisible(),false);assert.equal(await page.getByRole('button',{name:'Save new revision'}).count(),0);await fits();
   role='viewer';await page.getByRole('button',{name:'Refresh',exact:true}).click();await notice('No accessible projects.');assert.equal(await page.locator('#tenantOwnerControls').isVisible(),false);assert.equal(await page.locator('#projectContent').isVisible(),false);assert.equal(await page.locator('#creation').isVisible(),false);
   role='guest';await page.getByRole('button',{name:'Refresh',exact:true}).click();await notice('Sign in again.');assert.equal(await page.locator('#workspace').isVisible(),false);assert.equal(await page.locator('#invitationPanel').isVisible(),false);
   assert.deepEqual(errors,[]);await context.close();console.log('workspace_browser_gate_passed engine='+engine+' viewport='+width);
  }
 }finally{await browser?.close();server.closeAllConnections();await new Promise(r=>server.close(r));}
});
