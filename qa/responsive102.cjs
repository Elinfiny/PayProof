'use strict';
// SOURCE ONLY102. No browser/server/install/dispatch was executed for this file.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const crypto=require('node:crypto'),assert=require('node:assert/strict');
const {spawn,execFileSync}=require('node:child_process');
const ROOT=path.resolve(__dirname,'..'),OLD_ONCE='PAYPROOF-LOCAL-AI-UI95-20261018-ONCE';
const BINARY='377a9fc07b495c3b8d0ab8ec1fdfd153641759f9756fea34d8dfce4de82f5025';
const LOCK='4c5980b6227cd6d180285ea681b30c271cece60651ce9d7c73f8d3273073832d';
const MODEL='0513952a8592ad96858b70d87da5cf3d8079b2c5e53e4e38b8dbed2e90d30662';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const stamp=()=>({utc:new Date().toISOString(),monotonic_ns:process.hrtime.bigint().toString()});
const report={schema:'PAYPROOF_RESPONSIVE102_V1',status:'NOT_STARTED',pre_invoke:stamp(),
  group_invocations:1,retries:0,actual_renderer:false,viewports:[],cleanup:[],first_error:null,
  external_requests:[],provider_calls:0,external_model_calls:0,spend_usd:0,screenshots:0};
const servers=[];let browser,out,stopping=false;const contexts=[];
const deadline=performance.now()+170000;report.work_deadline_ms=170000;report.steps=[];report.cleanup_errors=[];
function check(){if(stopping||performance.now()>=deadline){stopping=true;const e=new Error('Absolute work deadline; no new effect');fail(e);throw e;}}
async function step(label,fn,retain){check();let v;try{v=await fn();if(retain)retain(v);report.steps.push({label,returned:stamp()});save();}catch(e){report.steps.push({label,error:String(e.message),at:stamp()});save();throw e;}
 if(stopping||performance.now()>=deadline){if(label==='browser'&&v){try{await bounded(v.close(),cleanupBudget(2000),'Late browser close UNKNOWN');report.cleanup.push({browser:'late-return-closed'});}catch(e){report.cleanup_errors.push({step:label,error:String(e.message)});}}check();}return v;}
function cleanupBudget(ms){return Math.max(1,Math.min(ms,deadline+10000-performance.now()));}
function fail(e){if(!report.first_error)report.first_error={message:String(e.message||e).slice(0,1500),
  stack:String(e.stack||'').split('\n').slice(0,5).join('\n').slice(0,2000),at:stamp()};report.status='FAIL';}
function save(){if(out)fs.writeFileSync(path.join(out,'report.json'),JSON.stringify(report,null,2)+'\n');}
async function bounded(p,ms,label,onTimeout){let t;try{return await Promise.race([p,new Promise((_,reject)=>{
  t=setTimeout(()=>{if(onTimeout)onTimeout();reject(new Error(label));},ms);})]);}finally{clearTimeout(t);}}
async function stop(s){
  if(!s.terminal){s.child.kill('SIGINT');try{await bounded(s.closed,cleanupBudget(1500),'SIGINT grace');}
    catch{if(!s.terminal)s.child.kill('SIGKILL');await bounded(s.closed,cleanupBudget(1500),'Child terminal UNKNOWN');}}
  const rec={width:s.width,terminal:s.terminal||'UNKNOWN',stdout:s.stdout,stderr:s.stderr,private_db_removed:false};
  report.cleanup.push(rec);save();assert(s.terminal&&s.terminal.reaped&&s.terminal.stdout_eof&&s.terminal.stderr_eof,'Child not reaped/EOF');
  assert.equal(s.terminal.code,0,'Server forced/failed exit');assert.equal(s.terminal.signal,null);
  assert.equal(s.stderr,'');assert(!s.output_overflow);
  fs.rmSync(s.dir,{recursive:true,force:true});s.removed=true;rec.private_db_removed=true;save();
}
async function diagnose(page,v,stage){
  check();const geometry=await page.evaluate(()=>{
    const width=innerWidth,root=document.documentElement;
    const offenders=[];let offenderCount=0;
    for(const e of document.querySelectorAll('body *')){
      if(!e.getClientRects().length)continue;const r=e.getBoundingClientRect();
      if(r.width<=0||!(r.right>width||r.left<0))continue;
      offenderCount++;if(offenders.length>=24)continue;
      const c=getComputedStyle(e),selector=e.id?'#'+e.id:
        e.tagName.toLowerCase()+Array.from(e.classList).slice(0,3).map(n=>'.'+n).join('');
      offenders.push({selector,rect:{x:r.x,y:r.y,width:r.width,left:r.left,right:r.right},
        minWidth:c.minWidth,maxWidth:c.maxWidth,overflowWrap:c.overflowWrap,wordBreak:c.wordBreak,
        whiteSpace:c.whiteSpace,overflowX:c.overflowX,gridTemplateColumns:c.gridTemplateColumns,
        display:c.display,position:c.position});
    }
    const d=document.querySelector('details');
    return {viewportWidth:width,documentWidth:root.scrollWidth,clientWidth:root.clientWidth,
      overflowDelta:Math.max(0,root.scrollWidth-width),overflow:root.scrollWidth>width,
      detailsOpen:!!d?.open,offenderCount,offenders};
  });
  v.measurements.push({stage,at:stamp(),...geometry});save(); // Original geometry retained before deadline conversion or strict assertion.
  check();
  assert.equal(geometry.overflow,false,stage+': document.scrollWidth > innerWidth');
  return geometry;
}
async function run(){
  try{
    const env=process.env;
    assert(env.QA102_ADMISSION_REF,'Separate current runtime admission required');
    assert.match(env.QA102_EXPECTED_HEAD||'',/^[a-f0-9]{40}$/);
    assert.match(env.QA102_INVOCATION_ID||'',/^[A-Za-z0-9_-]{1,120}$/);
    assert.notEqual(env.QA102_INVOCATION_ID,OLD_ONCE,'Consumed101 key cannot be reused');
    assert.equal(process.version,'v22.23.3');assert.equal(env.QA102_BINARY_SHA256,BINARY);
    assert.equal(execFileSync('git',['rev-parse','HEAD'],{cwd:ROOT,encoding:'utf8',timeout:5000}).trim(),env.QA102_EXPECTED_HEAD);
    assert.equal(sha(fs.readFileSync(path.join(ROOT,'qa/package-lock.json'))),LOCK);
    const {chromium}=require('playwright');assert.equal(require('playwright/package.json').version,'1.64.1');
    assert.equal(require('playwright-core/package.json').version,'1.64.1');
    const executable=chromium.executablePath(),bytes=fs.readFileSync(executable);
    assert.equal(bytes.length,301186376);assert.equal(sha(bytes),BINARY);
    report.renderer={node:process.version,playwright:'1.64.1',bytes:bytes.length,sha256:BINARY};
    assert(path.isAbsolute(env.QA102_EVIDENCE_DIR||''));out=env.QA102_EVIDENCE_DIR;
    fs.mkdirSync(out,{mode:0o700,recursive:false});fs.writeFileSync(path.join(out,'once.json'),
      JSON.stringify({head:env.QA102_EXPECTED_HEAD,admission:env.QA102_ADMISSION_REF,
        invocation:env.QA102_INVOCATION_ID,pre_invoke:report.pre_invoke}),{flag:'wx',mode:0o600});
    report.status='RUNNING';save();
    await bounded((async()=>{
      await step('browser',()=>chromium.launch({headless:true,executablePath:executable,timeout:10000}),b=>{browser=b;});
      assert.equal(browser.version(),'156.0.8078.4');report.actual_renderer=true;
      for(const width of [390,1440]){
        check();
        const v={width,height:1000,status:'RUNNING',measurements:[],page_errors:[],posts:[]};
        report.viewports.push(v);save();
        check();const dir=fs.mkdtempSync(path.join(os.tmpdir(),'payproof-responsive102-')),db=path.join(dir,'synthetic.sqlite3');
        assert(!fs.existsSync(db));check();const child=spawn('python3',['-B','-m','payproof.server','--port','0','--mode','fixture','--db',db,'--local-ai'],
          {cwd:ROOT,stdio:['ignore','pipe','pipe'],env:{PATH:env.PATH,LANG:'C.UTF-8',PYTHONDONTWRITEBYTECODE:'1'}});
        const s={child,width,dir,stdout:'',stderr:'',terminal:null,removed:false,stdout_eof:false,stderr_eof:false};
        servers.push(s);for(const k of ['stdout','stderr']){
          child[k].on('data',b=>{s[k]+=b.toString('utf8');if(Buffer.byteLength(s[k])>32768){s.output_overflow=true;child.kill('SIGKILL');}});
          child[k].on('end',()=>{s[k+'_eof']=true;});
        }
        s.closed=new Promise(resolve=>child.once('close',(code,signal)=>{
          s.terminal={code,signal,stdout_eof:s.stdout_eof,stderr_eof:s.stderr_eof,reaped:true};resolve(s.terminal);}));
        const origin=await bounded(new Promise((resolve,reject)=>{
          child.once('error',reject);child.once('close',()=>reject(new Error('Server exited before startup')));
          child.stdout.on('data',()=>{const m=s.stdout.match(/PayProof running at (http:\/\/127\.0\.0\.1:\d+) — SYNTHETIC ONLY/);
            if(m)resolve(m[1]);});
        }),Math.min(10000,deadline-performance.now()),'Authentic startup missing');check();
        v.target={origin,fresh_db:true};const context=await step('context',()=>browser.newContext({viewport:{width,height:1000},acceptDownloads:true,serviceWorkers:'block'}),c=>contexts.push(c));
        await step('route-binding',()=>context.route('**/*',async route=>{
          if(stopping||performance.now()>=deadline)return route.abort();
          const q=route.request(),u=new URL(q.url());
          const ok=u.origin===origin&&(q.method()==='GET'&&['/','/app.js','/style.css','/api/state','/favicon.ico'].includes(u.pathname)
            ||q.method()==='POST'&&u.pathname==='/api/fixture');
          if(!ok){report.external_requests.push(u.origin===origin?u.pathname:u.origin);return route.abort();}
          if(q.method()==='POST')v.posts.push({path:u.pathname,body:JSON.parse(q.postData())});check();return route.continue();
        }));
        const page=await step('page',()=>context.newPage());page.setDefaultTimeout(5000);page.on('pageerror',e=>v.page_errors.push(String(e.message)));
        const fresh=()=>page.waitForResponse(r=>r.url()===origin+'/api/state'&&r.request().method()==='GET');
        check();const initial=fresh();await step('navigation',()=>page.goto(origin,{waitUntil:'networkidle'}));let state=await step('initial-state',async()=>await (await initial).json(),value=>{v.initial_state=value;});
        assert.equal(state.mode,'SYNTHETIC FIXTURES — NO PAYPAL CONNECTION');assert.equal(state.contest_ready,false);
        await step('initial-ready',()=>page.waitForFunction(model=>!document.querySelector('#observe').disabled&&document.querySelector('#local-model-id').textContent===model,MODEL));
        const details=page.locator('details').filter({has:page.locator('#local-model-id')}),summary=details.locator('summary');
        assert.equal(await details.evaluate(e=>e.open),false);await diagnose(page,v,'initial-closed');
        await step('details-toggle',()=>summary.click());assert.equal(await page.locator('#local-model-id').textContent(),MODEL);
        await diagnose(page,v,'initial-open');await step('details-toggle',()=>summary.click());
        await step('scenario',()=>page.selectOption('#scenario','completed'));check();const post=page.waitForResponse(r=>r.url()===origin+'/api/fixture'&&r.request().method()==='POST'),get=fresh();
        await step('focus',()=>page.focus('#scenario'));await step('keyboard-tab',()=>page.keyboard.press('Tab'));
        assert.equal(await page.evaluate(()=>document.activeElement.id),'observe');await step('fixture-post-keyboard',()=>page.keyboard.press('Enter'));
        const pr=await post;v.post_response_status=pr.status();save();check();const gr=await get;v.get_response_status=gr.status();save();check();assert.equal(pr.status(),200);assert.equal(gr.status(),200);state=await step('completed-state',()=>gr.json(),value=>{v.completed_state=value;});
        const order=state.orders[0],{local_assistance:advice,...financial}=order;
        assert.equal(order.state,'COMPLETED');assert.equal(advice.priority,'capture_context');assert.equal(advice.financial_authority,false);
        assert.deepEqual(await step('fixture-response',()=>pr.json(),value=>{v.fixture_response=value;}),financial);
        await step('completed-ready',()=>page.waitForFunction(()=>document.querySelector('#state').textContent==='COMPLETED'&&!document.querySelector('#observe').disabled));
        await diagnose(page,v,'completed-closed');await step('details-toggle',()=>summary.click());await diagnose(page,v,'completed-open');
        check();const pending=page.waitForEvent('download');await step('export-click',()=>page.click('#export'));const download=await pending;v.download_return={suggestedFilename:download.suggestedFilename(),at:stamp()};save();check();
        assert.equal(download.suggestedFilename(),'payproof-synthetic-evidence.json');
        const file=path.join(out,'export-'+width+'.json');await step('download-save',()=>download.saveAs(file),()=>{v.partial_export={file,bytes:fs.existsSync(file)?fs.statSync(file).size:null};});assert.equal(await step('download-status',()=>download.failure()),null);check();
        const raw=fs.readFileSync(file);assert(raw.length<=65536);const exported=JSON.parse(raw);
        assert.equal(exported.schema,'PAYPROOF_EVIDENCE_V1');assert.equal(exported.mode,'SYNTHETIC_ONLY');
        assert.equal(exported.ai_mode,state.ai_mode);assert.deepEqual(exported.order,order);
        v.export={bytes:raw.length,sha256:sha(raw)};await diagnose(page,v,'after-export-open');
        assert.deepEqual(v.page_errors,[]);assert.deepEqual(report.external_requests,[]);
        await step('context-close',()=>context.close());check();await stop(s);check();v.status='PASS';save();
      }
    })(),Math.max(1,deadline-performance.now()),'Absolute170s work deadline; cleanup reserve10s',()=>{stopping=true;});
    check();report.status='PASS';
  }catch(e){stopping=true;fail(e);}
  finally{
    stopping=true;for(const s of servers)if(!s.removed){try{await stop(s);}catch(e){report.cleanup_errors.push({width:s.width,error:String(e.message)});fail(e);report.cleanup.push({width:s.width,terminal:s.terminal||'UNKNOWN',cleanup_error:String(e.message)});}}
    if(browser){try{await bounded(browser.close(),cleanupBudget(3000),'Browser close UNKNOWN');report.cleanup.push({browser:'closed'});}
      catch(e){report.cleanup_errors.push({browser:'UNKNOWN',error:String(e.message)});fail(e);report.cleanup.push({browser:'UNKNOWN',error:String(e.message)});}}
    report.post_return=stamp();save();console.log(JSON.stringify(report));if(report.status!=='PASS')process.exitCode=1;
  }
}
run().catch(e=>{fail(e);report.post_return=stamp();save();console.log(JSON.stringify(report));process.exitCode=1;});
