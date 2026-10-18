'use strict';
// One new private real-time media capture; no historical QA or provider replay.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const assert=require('node:assert/strict'),{spawn}=require('node:child_process'),{chromium}=require('playwright');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const env=process.env,product=env.DEMO122_PRODUCT,out=env.DEMO122_MEDIA,reportPath=env.DEMO122_REPORT;
const report={schema:'PAYPROOF_DEMO122_CAPTURE',nonce:'PAYPROOF-DEMO122-PRIVATE-ONCE',status:'NOT_STARTED',scenes:[],requests:[],page_errors:[],cleanup:[],first_error:null,provider_calls:0,model_fit:0,captures:1,new_DB:1};
let browser,context,child,closed,terminal,video,portOrigin,dbdir,stdout='',stderr='';
const deadline=performance.now()+205000;let stopping=false,stdoutEOF=false,stderrEOF=false;
function save(){fs.writeFileSync(reportPath,JSON.stringify(report,null,2)+'\n');}
async function bounded(p,ms,label){let timer;try{return await Promise.race([p,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error(label)),Math.max(1,ms));})]);}finally{clearTimeout(timer);}}
async function scene(label,fn){assert(!stopping&&performance.now()<deadline);await fn();report.scenes.push({label,utc:new Date().toISOString()});save();}
async function run(){try{
 assert.equal(env.DEMO122_NONCE,report.nonce);assert(product&&out&&reportPath);
 assert.equal(process.version,'v22.23.3');assert.equal(require('playwright/package.json').version,'1.64.1');
 const executable=chromium.executablePath(),bin=fs.readFileSync(executable);assert.equal(bin.length,301186376);assert.equal(sha(bin),'377a9fc07b495c3b8d0ab8ec1fdfd153641759f9756fea34d8dfce4de82f5025');
 fs.mkdirSync(out,{mode:0o700,recursive:false});fs.writeFileSync(path.join(out,'once.json'),JSON.stringify({nonce:report.nonce,expected_head:env.DEMO122_EXPECTED_HEAD}),{flag:'wx',mode:0o600});
 dbdir=fs.mkdtempSync(path.join(os.tmpdir(),'payproof-demo122-'));fs.chmodSync(dbdir,0o700);
 child=spawn('python3',['-I','-S','-B',path.join(product,'tools/contest_launcher84.py'),'--data-dir',dbdir,'--port','0'],{cwd:product,stdio:['ignore','pipe','pipe'],env:{PATH:env.PATH,LANG:'C.UTF-8'}});
 for(const [key,pipe]of [['stdout',child.stdout],['stderr',child.stderr]]){pipe.on('data',b=>{if(key==='stdout')stdout+=b.toString();else stderr+=b.toString();if(Buffer.byteLength(stdout)+Buffer.byteLength(stderr)>65536){stopping=true;child.kill('SIGKILL');}});pipe.on('end',()=>{if(key==='stdout')stdoutEOF=true;else stderrEOF=true;});}
 closed=new Promise(resolve=>child.once('close',(code,signal)=>{terminal={code,signal,reaped:true,stdout_eof:stdoutEOF,stderr_eof:stderrEOF};resolve(terminal);}));
 portOrigin=await bounded(new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',()=>reject(new Error('Fixture exited before startup')));child.stdout.on('data',()=>{const m=stdout.match(/PayProof running at (http:\/\/127\.0\.0\.1:\d+) — SYNTHETIC ONLY/);if(m)resolve(m[1]);});}),10000,'Fixture startup UNKNOWN');
 browser=await chromium.launch({headless:true,executablePath:executable,timeout:10000});assert.equal(browser.version(),'156.0.8078.4');
 context=await browser.newContext({viewport:{width:1280,height:720},recordVideo:{dir:out,size:{width:1280,height:720}},acceptDownloads:false,serviceWorkers:'block'});
 await context.route('**/*',async route=>{const q=route.request(),u=new URL(q.url());const allowed=!stopping&&u.origin===portOrigin&&((q.method()==='GET'&&['/','/app.js','/style.css','/api/state','/favicon.ico'].includes(u.pathname))||(q.method()==='POST'&&u.pathname==='/api/fixture'));report.requests.push({method:q.method(),path:u.origin===portOrigin?u.pathname:'EXTERNAL_BLOCKED',allowed});if(allowed)return route.continue();save();return route.abort();});
 const tPage=performance.now(),page=await context.newPage();video=page.video();page.setDefaultTimeout(6000);page.on('pageerror',e=>{report.page_errors.push(e.message);save();});
 await page.goto(portOrigin,{waitUntil:'networkidle'});await page.locator('#recorded-run-status[data-evidence="reviewed-recording"]').waitFor({state:'visible'});
 assert.equal(await page.locator('#recorded-run-status').textContent(),'CONFLICT · recorded');assert.equal(await page.getByRole('heading',{name:'No payment verified',exact:true}).count(),1);
 const initial=await(await page.request.get(portOrigin+'/api/state')).json();assert.equal(initial.local_model.enabled,false);assert.equal(initial.contest_ready,false);report.initial_state=initial;
 const begin=performance.now();report.lead_seconds=(begin-tPage)/1000;report.actual_renderer={node:process.version,playwright:'1.64.1',chromium:browser.version(),binary_sha256:sha(bin),width:1280,height:720};report.status='CAPTURING';save();
 async function until(seconds){const remaining=begin+seconds*1000-performance.now();if(remaining>0)await bounded(new Promise(resolve=>setTimeout(resolve,remaining)),Math.min(remaining+1000,deadline-performance.now()),'Capture timeline deadline');}
 async function select(value){await page.locator('#scenario').selectOption(value);await page.locator('#observe').focus();const pending=page.waitForResponse(r=>r.url()===portOrigin+'/api/fixture'&&r.request().method()==='POST');await page.locator('#observe').press('Enter');const response=await pending;assert.equal(response.status(),200);await page.waitForFunction(()=>document.querySelectorAll('button:disabled').length<=1);}
 await scene('0-25 freelancer decision',()=>page.evaluate(()=>scrollTo({top:0,behavior:'instant'})));await until(25);
 await scene('25-40 synthetic approval, not captured',async()=>{await select('approved');await page.locator('#state').scrollIntoViewIfNeeded();});await until(40);
 await scene('40-55 synthetic completed capture',async()=>{await page.locator('#scenario').scrollIntoViewIfNeeded();await select('completed');await page.locator('#state').scrollIntoViewIfNeeded();});await until(55);
 await scene('55-68 synthetic conflict',async()=>{await page.locator('#scenario').scrollIntoViewIfNeeded();await select('conflict');await page.locator('#summary').scrollIntoViewIfNeeded();});await until(68);
 await scene('68-80 synthetic unavailable',async()=>{await page.locator('#scenario').scrollIntoViewIfNeeded();await select('unknown');await page.locator('#summary').scrollIntoViewIfNeeded();});await until(80);
 await scene('80-120 recorded real117, no current request',async()=>{await page.locator('[aria-labelledby="recorded-run-title"]').scrollIntoViewIfNeeded();await page.locator('#recorded-run-title').scrollIntoViewIfNeeded();});await until(120);
 await scene('120-145 recorded advisory READY yet unknown',()=>page.locator('#recorded-run-model').scrollIntoViewIfNeeded());await until(145);
 await scene('145-160 value and actual limits',()=>page.evaluate(()=>scrollTo({top:0,behavior:'instant'})));await until(160);
 report.timeline_seconds=(performance.now()-begin)/1000;report.final_state=await(await page.request.get(portOrigin+'/api/state')).json();assert.equal(report.final_state.local_model.enabled,false);assert.equal(report.final_state.contest_ready,false);
 const record=JSON.parse(await page.locator('#recorded-run117-data').textContent());assert.equal(record.state,'CONFLICT');assert.equal(record.local_assistance.priority,'unknown');assert.equal(record.local_assistance.financial_authority,false);assert.deepEqual(record.payment_actions,[]);
 assert.equal(report.page_errors.length,0);assert(!report.requests.some(x=>!x.allowed));report.status='CAPTURED';save();
 }catch(e){report.first_error={type:e.name,message:e.message,stack:String(e.stack).slice(0,2500),utc:new Date().toISOString()};report.status='FAIL_UNKNOWN_NO_RETRY';save();}
 finally{stopping=true;
  for(const [label,fn]of [['context',()=>context&&context.close()],['browser',()=>browser&&browser.close()]]){try{await bounded(fn(),10000,label+' cleanup UNKNOWN');report.cleanup.push({label,status:'CLOSED'});}catch(e){report.cleanup.push({label,error:e.message});}}
  if(video){try{const file=await bounded(video.path(),3000,'Video path UNKNOWN');const bytes=fs.readFileSync(file);report.raw_video={path:file,bytes:bytes.length,sha256:sha(bytes),partial:report.status!=='CAPTURED'};}catch(e){report.cleanup.push({label:'raw-video',error:e.message});}}
  if(child){try{if(!terminal)child.kill('SIGINT');await bounded(closed,4000,'Fixture reap UNKNOWN');report.server={terminal,stdout,stderr,private_db_retained_on_ephemeral_runner:dbdir};if(!terminal||!terminal.reaped||!terminal.stdout_eof||!terminal.stderr_eof||terminal.code!==0||stderr)throw new Error('Fixture terminal not clean');}catch(e){report.cleanup.push({label:'fixture',error:e.message});}}
  if(report.cleanup.some(x=>x.error))report.status='FAIL_UNKNOWN_NO_RETRY';save();console.log(JSON.stringify(report));
 }
 if(report.status!=='CAPTURED')process.exitCode=1;
}
run().catch(e=>{report.first_error=report.first_error||{message:e.message};report.status='FAIL_UNKNOWN_NO_RETRY';save();process.exitCode=1;});
