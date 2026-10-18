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
const servers=[];let browser,out,stopping=false;
function fail(e){if(!report.first_error)report.first_error={message:String(e.message||e).slice(0,1500),
  stack:String(e.stack||'').split('\n').slice(0,5).join('\n').slice(0,2000),at:stamp()};report.status='FAIL';}
function save(){if(out)fs.writeFileSync(path.join(out,'report.json'),JSON.stringify(report,null,2)+'\n');}
async function bounded(p,ms,label){let t;try{return await Promise.race([p,new Promise((_,reject)=>{
  t=setTimeout(()=>reject(new Error(label)),ms);})]);}finally{clearTimeout(t);}}
async function stop(s){
  if(!s.terminal){s.child.kill('SIGINT');try{await bounded(s.closed,1500,'SIGINT grace');}
    catch{if(!s.terminal)s.child.kill('SIGKILL');await bounded(s.closed,1500,'Child terminal UNKNOWN');}}
  const rec={width:s.width,terminal:s.terminal||'UNKNOWN',stdout:s.stdout,stderr:s.stderr,private_db_removed:false};
  report.cleanup.push(rec);save();assert(s.terminal&&s.terminal.reaped&&s.terminal.stdout_eof&&s.terminal.stderr_eof,'Child not reaped/EOF');
  assert.equal(s.terminal.code,0,'Server forced/failed exit');assert.equal(s.terminal.signal,null);
  assert.equal(s.stderr,'');assert(!s.output_overflow);
  fs.rmSync(s.dir,{recursive:true,force:true});s.removed=true;rec.private_db_removed=true;save();
}
async function diagnose(page,v,stage){
  const geometry=await page.evaluate(()=>{
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
  v.measurements.push({stage,at:stamp(),...geometry});save(); // Evidence before assertion.
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
      browser=await chromium.launch({headless:true,executablePath:executable,timeout:10000});
      assert.equal(browser.version(),'156.0.8078.4');report.actual_renderer=true;
      for(const width of [390,1440]){
        assert(!stopping,'Work deadline reached; no new viewport/server');
        const v={width,height:1000,status:'RUNNING',measurements:[],page_errors:[],posts:[]};
        report.viewports.push(v);save();
        const dir=fs.mkdtempSync(path.join(os.tmpdir(),'payproof-responsive102-')),db=path.join(dir,'synthetic.sqlite3');
        assert(!fs.existsSync(db));const child=spawn('python3',['-B','-m','payproof.server','--port','0','--mode','fixture','--db',db,'--local-ai'],
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
        }),10000,'Authentic startup missing');
        v.target={origin,fresh_db:true};const context=await browser.newContext({viewport:{width,height:1000},acceptDownloads:true,serviceWorkers:'block'});
        await context.route('**/*',async route=>{
          const q=route.request(),u=new URL(q.url());
          const ok=u.origin===origin&&(q.method()==='GET'&&['/','/app.js','/style.css','/api/state','/favicon.ico'].includes(u.pathname)
            ||q.method()==='POST'&&u.pathname==='/api/fixture');
          if(!ok){report.external_requests.push(u.origin===origin?u.pathname:u.origin);return route.abort();}
          if(q.method()==='POST')v.posts.push({path:u.pathname,body:JSON.parse(q.postData())});return route.continue();
        });
        const page=await context.newPage();page.setDefaultTimeout(5000);page.on('pageerror',e=>v.page_errors.push(String(e.message)));
        const fresh=()=>page.waitForResponse(r=>r.url()===origin+'/api/state'&&r.request().method()==='GET');
        const initial=fresh();await page.goto(origin,{waitUntil:'networkidle'});let state=await (await initial).json();
        assert.equal(state.mode,'SYNTHETIC FIXTURES — NO PAYPAL CONNECTION');assert.equal(state.contest_ready,false);
        await page.waitForFunction(model=>!document.querySelector('#observe').disabled&&document.querySelector('#local-model-id').textContent===model,MODEL);
        const details=page.locator('details').filter({has:page.locator('#local-model-id')}),summary=details.locator('summary');
        assert.equal(await details.evaluate(e=>e.open),false);await diagnose(page,v,'initial-closed');
        await summary.click();assert.equal(await page.locator('#local-model-id').textContent(),MODEL);
        await diagnose(page,v,'initial-open');await summary.click();
        await page.selectOption('#scenario','completed');const post=page.waitForResponse(r=>r.url()===origin+'/api/fixture'&&r.request().method()==='POST'),get=fresh();
        await page.focus('#scenario');await page.keyboard.press('Tab');
        assert.equal(await page.evaluate(()=>document.activeElement.id),'observe');await page.keyboard.press('Enter');
        const pr=await post,gr=await get;assert.equal(pr.status(),200);assert.equal(gr.status(),200);state=await gr.json();
        const order=state.orders[0],{local_assistance:advice,...financial}=order;
        assert.equal(order.state,'COMPLETED');assert.equal(advice.priority,'capture_context');assert.equal(advice.financial_authority,false);
        assert.deepEqual(await pr.json(),financial);
        await page.waitForFunction(()=>document.querySelector('#state').textContent==='COMPLETED'&&!document.querySelector('#observe').disabled);
        await diagnose(page,v,'completed-closed');await summary.click();await diagnose(page,v,'completed-open');
        const pending=page.waitForEvent('download');await page.click('#export');const download=await pending;
        assert.equal(download.suggestedFilename(),'payproof-synthetic-evidence.json');
        const file=path.join(out,'export-'+width+'.json');await download.saveAs(file);assert.equal(await download.failure(),null);
        const raw=fs.readFileSync(file);assert(raw.length<=65536);const exported=JSON.parse(raw);
        assert.equal(exported.schema,'PAYPROOF_EVIDENCE_V1');assert.equal(exported.mode,'SYNTHETIC_ONLY');
        assert.equal(exported.ai_mode,state.ai_mode);assert.deepEqual(exported.order,order);
        v.export={bytes:raw.length,sha256:sha(raw)};await diagnose(page,v,'after-export-open');
        assert.deepEqual(v.page_errors,[]);assert.deepEqual(report.external_requests,[]);
        await context.close();await stop(s);v.status='PASS';save();
      }
    })(),170000,'170s work deadline; cleanup reserve10s');
    report.status='PASS';
  }catch(e){stopping=true;fail(e);}
  finally{
    for(const s of servers)if(!s.removed){try{await stop(s);}catch(e){fail(e);report.cleanup.push({width:s.width,terminal:s.terminal||'UNKNOWN',cleanup_error:String(e.message)});}}
    if(browser){try{await bounded(browser.close(),3000,'Browser close UNKNOWN');report.cleanup.push({browser:'closed'});}
      catch(e){fail(e);report.cleanup.push({browser:'UNKNOWN',error:String(e.message)});}}
    report.post_return=stamp();save();console.log(JSON.stringify(report));if(report.status!=='PASS')process.exitCode=1;
  }
}
run().catch(e=>{fail(e);report.post_return=stamp();save();console.log(JSON.stringify(report));process.exitCode=1;});
