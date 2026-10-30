'use strict';
// Private UI151 candidate; no live browser/job execution is granted by this source.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const crypto=require('node:crypto'),assert=require('node:assert/strict');
const {spawn,execFileSync}=require('node:child_process');
const ROOT=path.resolve(__dirname,'..'),OLD_ONCE='PAYPROOF-RESPONSIVE104-20261018-ONCE';
const BINARY='377a9fc07b495c3b8d0ab8ec1fdfd153641759f9756fea34d8dfce4de82f5025';
const LOCK='4c5980b6227cd6d180285ea681b30c271cece60651ce9d7c73f8d3273073832d';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const stamp=()=>({utc:new Date().toISOString(),monotonic_ns:process.hrtime.bigint().toString()});
const report={schema:'PAYPROOF_CURRENT_UI151_V1',status:'NOT_STARTED',pre_invoke:stamp(),
  group_invocations:1,retries:0,actual_renderer:false,viewports:[],cleanup:[],first_error:null,
  external_requests:[],provider_calls:0,external_model_calls:0,model_fit_calls:0,spend_usd:0,screenshots:0,first_unknown:null};
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
  check();
  const measurement=await page.evaluate(()=>{
    const panel=document.querySelector('[aria-labelledby="recorded-run-title"]');
    const proof=panel.querySelector('#recorded-run-proof'),details=panel.querySelector('details');
    const selected=[panel,panel.querySelector('#recorded-run-time'),proof];
    return {viewport:{width:innerWidth,height:innerHeight},documentWidth:document.documentElement.scrollWidth,
      clientWidth:document.documentElement.clientWidth,overflow:document.documentElement.scrollWidth>innerWidth,
      detailsOpen:details.open,proofCharacters:proof.textContent.length,
      geometry:selected.map(e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return {
        id:e.id||'recorded-panel',visible:!!e.getClientRects().length,left:r.left,right:r.right,width:r.width,
        overflowWrap:s.overflowWrap,whiteSpace:s.whiteSpace};})};
  });
  v.measurements.push({stage,at:stamp(),...measurement});save();check();
  assert.equal(measurement.overflow,false,stage+': actual document overflow');
  assert.equal(measurement.viewport.width,v.width);assert.equal(measurement.viewport.height,v.height);
  for(const row of measurement.geometry)if(row.visible)assert(row.left>=0&&row.right<=v.width,stage+': panel child outside viewport');
  if(measurement.detailsOpen)assert(measurement.proofCharacters>=1291,'Long real proof must actually be visible');
  return measurement;
}
async function run(){
  try{
    const env=process.env;
    assert(env.QA151_ADMISSION_REF,'Separate reviewed runtime/minutes admission required');
    assert.match(env.QA151_EXPECTED_HEAD||'',/^[a-f0-9]{40}$/);
    assert.equal(env.QA151_INVOCATION_ID,'PAYPROOF-CURRENT-UI151-ONCE');
    assert.notEqual(env.QA151_INVOCATION_ID,OLD_ONCE);assert.notEqual(env.QA151_INVOCATION_ID,'PAYPROOF-RECORDED-PANEL120-ONCE');
    assert.equal(process.version,'v22.23.3');assert.equal(env.QA151_BINARY_SHA256,BINARY);
    assert.equal(execFileSync('git',['rev-parse','HEAD'],{cwd:ROOT,encoding:'utf8',timeout:5000}).trim(),env.QA151_EXPECTED_HEAD);
    assert.equal(sha(fs.readFileSync(path.join(ROOT,'qa/package-lock.json'))),LOCK);
    const currentAssets={
      'payproof/web/index.html':'65ea835aeb1e236bb1f623e090e2859b85b2f8b3a5143e09ade73a84e20b847e',
      'payproof/web/app.js':'4ea8b2c3b896698a984d4e2f34d789a15656fed2700b84411249d0a6f6658fb9',
      'payproof/web/style.css':'42d457e036fd5779786f53312bfc2805d64e3c6d2417ab85006dfdb10df68035',
      'payproof/server.py':'ad12ef892df61b9d1f8d61adf1416c6e14d55d5a10cfcf7d30a7ca4dcc175a33'};
    for(const [file,expected] of Object.entries(currentAssets))assert.equal(sha(fs.readFileSync(path.join(ROOT,file))),expected);
    report.source_assets=currentAssets;

    const {chromium}=require('playwright');assert.equal(require('playwright/package.json').version,'1.64.1');
    assert.equal(require('playwright-core/package.json').version,'1.64.1');
    const executable=chromium.executablePath(),bytes=fs.readFileSync(executable);
    assert.equal(bytes.length,301186376);assert.equal(sha(bytes),BINARY);
    report.renderer={node:process.version,playwright:'1.64.1',bytes:bytes.length,sha256:BINARY};
    assert(path.isAbsolute(env.QA151_EVIDENCE_DIR||''));out=env.QA151_EVIDENCE_DIR;
    fs.mkdirSync(out,{mode:0o700,recursive:false});
    fs.writeFileSync(path.join(out,'once.json'),JSON.stringify({head:env.QA151_EXPECTED_HEAD,
      admission:env.QA151_ADMISSION_REF,invocation:env.QA151_INVOCATION_ID,pre_invoke:report.pre_invoke}),{flag:'wx',mode:0o600});
    // The external owned consumed record is required before dispatch; this local
    // create-only journal is supplementary, not a provider lease or authority.
    report.status='RUNNING';save();
    await bounded((async()=>{
      await step('browser',()=>chromium.launch({headless:true,executablePath:executable,timeout:10000}),b=>{browser=b;});
      assert.equal(browser.version(),'156.0.8078.4');report.actual_renderer=true;
      for(const [width,height] of [[390,844],[1440,900]]){
        check();
        const v={width,height,status:'RUNNING',measurements:[],page_errors:[],requests:[],posts:[]};
        report.viewports.push(v);save();
        const dir=fs.mkdtempSync(path.join(os.tmpdir(),'payproof-ui151-')),db=path.join(dir,'synthetic.sqlite3');
        assert(!fs.existsSync(db));check();
        const child=spawn('python3',['-B','-m','payproof.server','--port','0','--mode','fixture','--db',db],
          {cwd:ROOT,stdio:['ignore','pipe','pipe'],env:{PATH:env.PATH,LANG:'C.UTF-8',PYTHONDONTWRITEBYTECODE:'1'}});
        const s={child,width,dir,stdout:'',stderr:'',terminal:null,removed:false,stdout_eof:false,stderr_eof:false};
        servers.push(s);
        for(const k of ['stdout','stderr']){
          child[k].on('data',b=>{s[k]+=b.toString('utf8');if(Buffer.byteLength(s[k])>32768){s.output_overflow=true;child.kill('SIGKILL');}});
          child[k].on('end',()=>{s[k+'_eof']=true;});
        }
        s.closed=new Promise(resolve=>child.once('close',(code,signal)=>{
          s.terminal={code,signal,stdout_eof:s.stdout_eof,stderr_eof:s.stderr_eof,reaped:true};resolve(s.terminal);
        }));
        const origin=await bounded(new Promise((resolve,reject)=>{
          child.once('error',reject);child.once('close',()=>reject(new Error('Server exited before startup')));
          child.stdout.on('data',()=>{const m=s.stdout.match(/PayProof running at (http:\/\/127\.0\.0\.1:\d+) — SYNTHETIC ONLY/);if(m)resolve(m[1]);});
        }),Math.min(10000,deadline-performance.now()),'Authentic fixture startup missing');check();
        v.target={origin,fresh_db:true,local_ai_enabled:false};
        const context=await step('context',()=>browser.newContext({viewport:{width,height},acceptDownloads:false,serviceWorkers:'block'}),c=>contexts.push(c));
        await step('route-binding',()=>context.route('**/*',async route=>{
          const q=route.request(),u=new URL(q.url());
          if(stopping||performance.now()>=deadline)return route.abort();
          const allowed=u.origin===origin&&q.method()==='GET'&&['/','/app.js','/style.css','/api/state','/favicon.ico'].includes(u.pathname);
          v.requests.push({method:q.method(),path:u.origin===origin?u.pathname:u.origin,allowed});
          if(q.method()!=='GET')v.posts.push({method:q.method(),path:u.pathname});
          if(!allowed){report.external_requests.push(u.origin===origin?u.pathname:u.origin);save();return route.abort();}
          check();return route.continue();
        }));
        const page=await step('page',()=>context.newPage());page.setDefaultTimeout(5000);
        page.on('pageerror',e=>v.page_errors.push(String(e.message)));
        const initial=page.waitForResponse(r=>r.url()===origin+'/api/state'&&r.request().method()==='GET');
        await step('navigation',()=>page.goto(origin,{waitUntil:'networkidle'}));
        const before=await step('initial-fixture-state',async()=>await(await initial).json(),r=>{v.initial_state=r;});
        assert.equal(before.mode,'SYNTHETIC FIXTURES — NO PAYPAL CONNECTION');
        assert.equal(await page.locator('.private').textContent(),'Research prototype');
        assert.match(await page.locator('.notice').innerText(),/Offline walkthrough — no real payments/);
        assert.equal(before.local_model.enabled,false);assert.equal(before.contest_ready,false);
        await step('recorded-ready',()=>page.locator('#recorded-run-status[data-evidence="reviewed-recording"]').waitFor({state:'visible'}));
        const panel=page.locator('[aria-labelledby="recorded-run-title"]');
        assert.equal(await panel.getByRole('heading',{name:'Recorded Sandbox run',exact:true}).count(),1);
        assert.equal(await panel.getByRole('heading',{name:'No payment verified',exact:true}).count(),1);
        assert.equal(await panel.locator('#recorded-run-status').textContent(),'CONFLICT · recorded');
        assert.equal(await panel.locator('#recorded-run-time').getAttribute('datetime'),'2026-10-18T19:36:29.277776Z');
        assert.match(await panel.locator('#recorded-run-model').textContent(),/Local model READY.*unknown.*abstained/);
        assert.match(await panel.locator('#recorded-run-context').textContent(),/internal cause was not retained/);
        assert.equal(await panel.locator('#recorded-run-link').getAttribute('href'),'https://github.com/Elinfiny/PayProof/actions/runs/39159527253');
        const saved=JSON.parse(await panel.locator('#recorded-run-proof').textContent());
        assert.equal(saved.state,'CONFLICT');assert.equal(saved.local_assistance.priority,'unknown');
        assert.equal(saved.local_assistance.reason,'INVALID_OR_UNVERIFIED_EVIDENCE');
        assert.equal(saved.local_assistance.financial_authority,false);assert.deepEqual(saved.payment_actions,[]);
        v.recorded_evidence={run_id:saved.run_id,job_id:saved.job_id,observed_at:saved.observed_at,state:saved.state,
          model_ready:saved.local_assistance.model_ready,priority:saved.local_assistance.priority,reason:saved.local_assistance.reason,
          no_payment_verified:true,link_clicked:false};
        const uiBefore=await page.evaluate(()=>({state:document.querySelector('#state').textContent,
          order:document.querySelector('#order-id').textContent,total:document.querySelector('#total').textContent}));
        assert.equal(uiBefore.state,before.orders[0].state);assert.equal(uiBefore.order,before.orders[0].id);
        const dbBefore=fs.readFileSync(db);assert(dbBefore.length<=1048576);
        const details=panel.locator('details'),summary=details.locator('summary');
        assert.equal(await details.evaluate(e=>e.open),false);await diagnose(page,v,'recorded-closed');
        await step('summary-focus',()=>summary.focus());assert.equal(await summary.evaluate(e=>document.activeElement===e),true);
        await step('keyboard-open',()=>page.keyboard.press('Enter'));
        await step('open-observed',()=>page.waitForFunction(()=>document.querySelector('[aria-labelledby="recorded-run-title"] details').open));
        await diagnose(page,v,'recorded-keyboard-open-long-proof');
        await step('keyboard-close',()=>page.keyboard.press('Enter'));
        await step('closed-observed',()=>page.waitForFunction(()=>!document.querySelector('[aria-labelledby="recorded-run-title"] details').open));
        await diagnose(page,v,'recorded-keyboard-closed');
        const after=await step('final-fixture-state',()=>page.evaluate(async()=>{
          const r=await fetch('/api/state');if(!r.ok)throw new Error('Fixture state read failed');return await r.json();
        }),r=>{v.final_state=r;});
        assert.deepEqual(after,before,'Recorded panel must not overwrite synthetic state/order');
        const uiAfter=await page.evaluate(()=>({state:document.querySelector('#state').textContent,
          order:document.querySelector('#order-id').textContent,total:document.querySelector('#total').textContent}));
        assert.deepEqual(uiAfter,uiBefore);
        const dbAfter=fs.readFileSync(db);assert.equal(sha(dbAfter),sha(dbBefore),'Read-only panel must preserve fixture Store bytes');
        v.fixture_preservation={state_equal:true,order_equal:true,store_bytes:dbAfter.length,store_sha256:sha(dbAfter),store_unchanged:true};
        assert.deepEqual(v.posts,[]);assert.deepEqual(v.page_errors,[]);assert.deepEqual(report.external_requests,[]);
        await step('context-close',()=>context.close());check();await stop(s);check();v.status='PASS';save();
      }
    })(),Math.max(1,deadline-performance.now()),'Absolute170s work deadline; cleanup reserve10s',()=>{stopping=true;});
    check();report.status='PASS';
  }catch(e){stopping=true;fail(e);if(/UNKNOWN|timeout|deadline/i.test(String(e.message)))report.first_unknown=report.first_error;}
  finally{
    stopping=true;
    for(const s of servers)if(!s.removed){try{await stop(s);}catch(e){
      report.cleanup_errors.push({width:s.width,error:String(e.message)});fail(e);
      if(!report.first_unknown)report.first_unknown={message:String(e.message),at:stamp()};
      report.cleanup.push({width:s.width,terminal:s.terminal||'UNKNOWN',cleanup_error:String(e.message)});
    }}
    if(browser){try{await bounded(browser.close(),cleanupBudget(3000),'Browser close UNKNOWN');report.cleanup.push({browser:'closed'});}
      catch(e){report.cleanup_errors.push({browser:'UNKNOWN',error:String(e.message)});fail(e);if(!report.first_unknown)report.first_unknown={message:String(e.message),at:stamp()};}}
    report.post_return=stamp();save();console.log(JSON.stringify(report));if(report.status!=='PASS')process.exitCode=1;
  }
}
run().catch(e=>{fail(e);report.post_return=stamp();save();console.log(JSON.stringify(report));process.exitCode=1;});

