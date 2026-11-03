'use strict';
// New actual-app capture only. Never reuse a payment harness or old media job.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {spawn}=require('node:child_process'),assert=require('node:assert/strict');
const {chromium}=require('playwright');
const out=path.resolve('media264');fs.mkdirSync(out,{recursive:false});
const receipt={schema:'PAYPROOF_VIDEO264_CAPTURE',state:'STARTED',scenes:[],requests:[],page_errors:[],provider_calls:0,source:process.env.GITHUB_SHA};
const save=()=>fs.writeFileSync(path.join(out,'capture.json'),JSON.stringify(receipt,null,2));
const wait=ms=>new Promise(r=>setTimeout(r,ms));let server,browser,context,video,logs='',exit;
const deadline=setTimeout(()=>{if(server)server.kill('SIGTERM');process.exit(2)},230000);
(async()=>{try{
 fs.writeFileSync(path.join(out,'once.json'),JSON.stringify({source:process.env.GITHUB_SHA,run:process.env.GITHUB_RUN_ID}),{flag:'wx'});save();
 server=spawn('python3',['-u','-B','-m','payproof.server','--mode','fixture','--db',path.join(out,'fixture.sqlite3'),'--port','0'],{env:{PATH:process.env.PATH,LANG:'C.UTF-8'},stdio:['ignore','pipe','pipe']});
 server.stdout.on('data',b=>logs+=b);server.stderr.on('data',b=>logs+=b);const closed=new Promise(r=>server.on('close',(code,signal)=>{exit={code,signal};r();}));
 let origin;for(let i=0;i<100;i++){origin=logs.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];if(origin)break;if(exit)throw Error('Fixture exited');await wait(100);}assert(origin,'Fixture startup');
 const executable=chromium.executablePath();
 assert.equal(crypto.createHash('sha256').update(fs.readFileSync(executable)).digest('hex'),'377a9fc07b495c3b8d0ab8ec1fdfd153641759f9756fea34d8dfce4de82f5025');
 browser=await chromium.launch({headless:true,executablePath:executable});
 context=await browser.newContext({viewport:{width:1280,height:720},recordVideo:{dir:out,size:{width:1280,height:720}},serviceWorkers:'block'});
 await context.route('**/*',route=>{const q=route.request(),u=new URL(q.url());const ok=u.origin===origin&&((q.method()==='GET'&&['/','/app.js','/style.css','/api/state','/favicon.ico'].includes(u.pathname))||(q.method()==='POST'&&u.pathname==='/api/fixture'));receipt.requests.push({path:u.origin===origin?u.pathname:'BLOCKED_EXTERNAL',method:q.method(),allowed:ok});return ok?route.continue():route.abort();});
 const opened=performance.now(),page=await context.newPage();video=page.video();page.on('pageerror',e=>receipt.page_errors.push(e.message));page.setDefaultTimeout(6000);
 await page.goto(origin,{waitUntil:'networkidle'});await page.locator('#proof244-content').waitFor({state:'visible'});
 assert.equal(await page.locator('#proof244-status').textContent(),'COMPLETED · recorded');assert.equal(await page.locator('#recorded-run-status').textContent(),'CONFLICT · recorded');
 receipt.renderer={chromium:browser.version(),playwright:require('playwright/package.json').version,viewport:{width:1280,height:720}};
 const began=performance.now();receipt.lead_seconds=(began-opened)/1000;
 const until=async seconds=>{const remaining=began+seconds*1000-performance.now();if(remaining>0)await wait(remaining);};
 const scene=async(name,fn)=>{await fn();receipt.scenes.push({name,seconds:(performance.now()-began)/1000});save();};
 const scroll=selector=>page.locator(selector).evaluate(el=>el.scrollIntoView({block:'start',behavior:'smooth'}));
 async function select(value,state){await page.locator('#scenario').selectOption(value);await page.locator('#observe').click();await page.locator('#state').filter({hasText:state}).waitFor();}
 await scene('actual application introduction',()=>page.evaluate(()=>scrollTo(0,0)));await until(15);
 await scene('synthetic approved not paid',async()=>{await scroll('.workspace');await select('approved','APPROVED');});await until(32);
 await scene('synthetic completed',()=>select('completed','COMPLETED'));await until(40);
 await scene('synthetic conflict',()=>select('conflict','CONFLICT'));await until(47);
 await scene('synthetic unknown',()=>select('unknown','UNKNOWN'));await until(55);
 await scene('recorded real C244, not live',()=>scroll('#proof244'));await until(78);
 await scene('recorded approval capture finalread webhook',async()=>{await page.locator('#proof244 .facts').hover();});await until(103);
 await scene('recorded learned advice',()=>scroll('#proof244-ai'));await until(128);
 await scene('recorded cleanup custody and limits',()=>scroll('#proof244-cleanup'));await until(150);
 await scene('scoped evidence and source',()=>scroll('#proof244'));await until(172);
 receipt.timeline_seconds=(performance.now()-began)/1000;assert.equal(receipt.page_errors.length,0);assert(receipt.requests.every(r=>r.allowed));receipt.state='CAPTURED';save();
 await context.close();context=null;await browser.close();browser=null;
 const file=await video.path();receipt.video={file:path.basename(file),sha256:crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')};
 server.kill('SIGINT');await Promise.race([closed,wait(5000)]);assert(exit,'Fixture closure');receipt.server_closed=exit;save();
 }catch(e){receipt.state='FAILED';receipt.error=String(e);save();process.exitCode=1;}
 finally{if(context)await context.close();if(browser)await browser.close();if(server&&!exit)server.kill('SIGTERM');clearTimeout(deadline);save();}
})();
