'use strict';
// NEW UI93 candidate only. Source review and fresh renderer admission precede use.
// No install, CI dispatch, browser download, credential or provider operation.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {spawn, execFileSync} = require('node:child_process');
const ROOT = path.resolve(__dirname, '..');
const EXPECTED_TREE = '966fc0f91169981246c1bf059c4a8d10f50f4890';
const EXPECTED_MODEL = '0513952a8592ad96858b70d87da5cf3d8079b2c5e53e4e38b8dbed2e90d30662';
const EXPECTED_CORPUS = '4a29e86e87abf252972f05e034a60f589550de95df7dc4a288369b1c0a61c283';
const PACKAGE_LOCK_SHA = '4c5980b6227cd6d180285ea681b30c271cece60651ce9d7c73f8d3273073832d';
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const stamp = () => ({utc:new Date().toISOString(),monotonic_ns:process.hrtime.bigint().toString()});
const report = {schema:'PAYPROOF_NEW_UI93_V1',status:'RUNNING',pre_invoke:stamp(),
  candidate_tree:EXPECTED_TREE,group_invocations:1,retries:0,limits:{seconds:180,widths:[1440,390]},
  mode:'SYNTHETIC_ONLY',actual_renderer:false,viewports:[],cleanup:[],first_error:null,
  external_requests:[],provider_calls:0,external_model_calls:0,spend_usd:0,
  native_paypal_qualified:false,human_visual_review:'NOT_PERFORMED',screenshots:0};
let out, browser, timer;
const servers = [];
const fail = e => {if(!report.first_error)report.first_error={message:String(e.message||e).slice(0,1500),at:stamp()};report.status='FAIL';};
function save(){if(out)fs.writeFileSync(path.join(out,'report.json'),JSON.stringify(report,null,2)+'\n');}
function boundedCapture(stream, record, key){
  stream.on('data',chunk=>{
    record[key]+=chunk.toString('utf8');
    if(Buffer.byteLength(record[key])>32768){record.capture_overflow=true;record.child.kill('SIGKILL');}
  });
}
function safeExport(value){
  if(Array.isArray(value))return value.forEach(safeExport);
  if(value && typeof value==='object'){
    for(const [key,entry] of Object.entries(value)){
      assert(!/payer|email|secret|token|authorization|credential|password/i.test(key),'Export key outside privacy boundary');
      safeExport(entry);
    }
  }else if(typeof value==='string')assert(!/@|synthetic-private-field|Bearer\s/i.test(value),'Export value outside privacy boundary');
}
async function stop(s){
  if(!s.terminal){
    s.child.kill('SIGINT');
    const closed=await Promise.race([s.closed,delay(5000).then(()=>null)]);
    if(!closed){s.child.kill('SIGKILL');await s.closed;throw new Error('Server required forced shutdown');}
  }
  assert(!s.capture_overflow,'Server output overflow');
  assert.deepEqual(s.terminal,{code:0,signal:null,stdout_eof:true,stderr_eof:true,reaped:true});
  assert.equal(s.stderr,'');
  report.cleanup.push({width:s.width,terminal:s.terminal,stdout:s.stdout,stderr:s.stderr,private_db_removed:true});
  fs.rmSync(s.dir,{recursive:true,force:true});s.removed=true;save();
}
async function main(){
  try{
    // This caller-supplied reference binds an independently issued admission;
    // it is evidence metadata, never a native/payment authorization token.
    assert(process.env.QA93_CURRENT_ADMISSION_REF,'Fresh independently reviewed renderer admission reference required');
    assert.equal(process.env.QA93_EXPECTED_TREE,EXPECTED_TREE);
    assert.match(process.env.QA93_BINARY_SHA256||'',/^[a-f0-9]{64}$/);
    assert.match(process.version,/^v22\./);
    assert.equal(sha(fs.readFileSync(path.join(ROOT,'qa/package-lock.json'))),PACKAGE_LOCK_SHA);
    const playwright=require('playwright');
    assert.equal(require('playwright/package.json').version,'1.64.1');
    const core=path.dirname(require.resolve('playwright-core/package.json'));
    assert.equal(require('playwright-core/package.json').version,'1.64.1');
    const metadata=JSON.parse(fs.readFileSync(path.join(core,'browsers.json'))).browsers;
    const chromium=metadata.find(b=>b.name==='chromium');
    assert.equal(String(chromium.revision),'1248');assert.equal(chromium.browserVersion,'156.0.8078.4');
    const executable=playwright.chromium.executablePath();
    assert(fs.statSync(executable).isFile(),'Existing pinned executable required');
    const binary=fs.readFileSync(executable);
    assert.equal(sha(binary),process.env.QA93_BINARY_SHA256,'Admitted binary identity mismatch');
    const version=execFileSync(executable,['--version'],{encoding:'utf8',timeout:5000}).trim();
    assert(version.includes('156.0.8078.4'));
    report.renderer={node:process.version,playwright:'1.64.1',revision:'1248',version,executable,
      bytes:binary.length,sha256:sha(binary),admission_ref:process.env.QA93_CURRENT_ADMISSION_REF};
    // Exclusive output directory and replay reservation: a failed/unknown
    // invocation cannot be repeated against the same evidence identity.
    assert(path.isAbsolute(process.env.QA93_EVIDENCE_DIR||''),'New absolute evidence directory required');
    out=process.env.QA93_EVIDENCE_DIR;fs.mkdirSync(out,{recursive:false,mode:0o700});
    fs.writeFileSync(path.join(out,'once.json'),JSON.stringify({pre_invoke:report.pre_invoke,admission_ref:report.renderer.admission_ref,candidate_tree:EXPECTED_TREE}),{flag:'wx',mode:0o600});
    timer=setTimeout(()=>{
      report.status='UNKNOWN_AT_DEADLINE';if(!report.first_error)report.first_error={message:'180s hard deadline',at:stamp()};
      for(const s of servers)if(!s.terminal)s.child.kill('SIGKILL');
      report.post_return=stamp();save();console.log(JSON.stringify(report));process.exit(1);
    },180000);
    save();
    browser=await playwright.chromium.launch({headless:true,executablePath:executable,timeout:10000});
    assert.equal(browser.version(),'156.0.8078.4');report.actual_renderer=true;
    for(const width of [1440,390]){
      const v={id:'NEW-UI93-'+width,width,height:1000,status:'RUNNING',cases:[],console_errors:[],page_errors:[],failed_requests:[],http_errors:[],posts:[]};
      report.viewports.push(v);save();
      const dir=fs.mkdtempSync(path.join(os.tmpdir(),'payproof-new-ui93-'));
      const db=path.join(dir,'synthetic93.sqlite3');assert(!fs.existsSync(db));
      const child=spawn('python3',['-B','-m','payproof.server','--port','0','--mode','fixture','--db',db,'--local-ai'],
        {cwd:ROOT,stdio:['ignore','pipe','pipe'],env:{PATH:process.env.PATH,LANG:'C.UTF-8',PYTHONDONTWRITEBYTECODE:'1'}});
      const s={child,width,dir,stdout:'',stderr:'',terminal:null,removed:false,stdout_eof:false,stderr_eof:false};servers.push(s);
      child.stdout.on('end',()=>{s.stdout_eof=true;});child.stderr.on('end',()=>{s.stderr_eof=true;});
      boundedCapture(child.stdout,s,'stdout');boundedCapture(child.stderr,s,'stderr');
      s.closed=new Promise(resolve=>child.once('close',(code,signal)=>{s.terminal={code,signal,stdout_eof:s.stdout_eof,stderr_eof:s.stderr_eof,reaped:true};resolve(s.terminal);}));
      const origin=await new Promise((resolve,reject)=>{
        const startup=setTimeout(()=>reject(new Error('No authentic startup binding within10s')),10000);
        child.once('error',e=>{clearTimeout(startup);reject(e);});
        child.once('close',()=>{clearTimeout(startup);reject(new Error('Server exited before startup binding'));});
        child.stdout.on('data',()=>{
          const match=s.stdout.match(/PayProof running at (http:\/\/127\.0\.0\.1:\d+) — SYNTHETIC ONLY/);
          if(match){clearTimeout(startup);resolve(match[1]);}
        });
      });
      v.target={origin,binding:'Actual fresh synthetic server stdout, ephemeral port; not guessed URL',db_new:true,db_isolated:true};save();
      const context=await browser.newContext({viewport:{width,height:1000},acceptDownloads:true,serviceWorkers:'block'});
      // Only this specific ephemeral synthetic origin is ever continued.
      await context.route('**/*',async route=>{
        const request=route.request(),url=new URL(request.url());
        if(url.origin!==origin){report.external_requests.push(request.url());await route.abort();return;}
        const permitted=request.method()==='GET'&&['/','/app.js','/style.css','/api/state','/favicon.ico'].includes(url.pathname)
          || request.method()==='POST'&&url.pathname==='/api/fixture';
        if(!permitted){report.external_requests.push('UNADMITTED_SYNTHETIC_PATH:'+url.pathname);await route.abort();return;}
        if(request.method()==='POST')v.posts.push({path:url.pathname,body:JSON.parse(request.postData())});
        await route.continue();
      });
      const page=await context.newPage();page.setDefaultTimeout(5000);
      page.on('pageerror',e=>v.page_errors.push(String(e.message)));
      page.on('console',m=>{if(m.type()==='error')v.console_errors.push({text:m.text(),url:m.location().url});});
      page.on('requestfailed',r=>v.failed_requests.push({url:r.url(),failure:r.failure()}));
      page.on('response',r=>{if(r.status()>=400)v.http_errors.push({url:r.url(),status:r.status()});});
      const stateResponse=()=>page.waitForResponse(r=>r.url()===origin+'/api/state'&&r.request().method()==='GET');
      const first=stateResponse();await page.goto(origin,{waitUntil:'networkidle'});
      const firstResponse=await first;assert.equal(firstResponse.status(),200);let state=await firstResponse.json();
      async function visible(current){
        assert.equal(current.mode,'SYNTHETIC FIXTURES — NO PAYPAL CONNECTION');
        assert.equal(current.ai_mode,'LOCAL MODEL ASSISTANCE — SYNTHETIC DEMO');assert.equal(current.contest_ready,false);
        assert.equal(current.orders.length,1);const order=current.orders[0],advice=order.local_assistance;
        assert.equal(advice.financial_authority,false);assert.equal(advice.live_paypal_verified,false);assert.deepEqual(advice.payment_actions,[]);
        assert.equal(advice.model_fingerprint,EXPECTED_MODEL);assert.equal(advice.corpus_sha256,EXPECTED_CORPUS);
        assert(!Object.hasOwn(advice,'confidence'),'No payment certainty percentage');
        await page.waitForFunction(({state,priority,text,mode})=>document.getElementById('state').textContent===state
          &&document.getElementById('local-priority').textContent===priority
          &&document.getElementById('local-explanation').textContent===text
          &&document.getElementById('ai-mode').textContent===mode&&!document.getElementById('observe').disabled,
          {state:order.state,priority:advice.priority,text:advice.text,mode:current.ai_mode});
        assert(await page.locator('#local-priority').isVisible());assert(await page.locator('#local-explanation').isVisible());
        assert.equal(await page.locator('#summary').textContent(),order.explanation.text);
        assert.equal(await page.locator('#next').textContent(),order.explanation.next_step);
        assert.equal(await page.locator('#source').textContent(),order.source);
        assert.equal(await page.locator('#raw').textContent(),JSON.stringify(order.facts||{state:order.state,evidence:'No usable current provider facts'},null,2));
        assert.equal(await page.locator('#message').textContent(),'');
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
        if(advice.uncertainty)assert((await page.locator('#local-uncertainty').textContent()).includes('UNKNOWN'));
        else assert((await page.locator('#local-uncertainty').textContent()).includes('never payment certainty'));
        return order;
      }
      let current=await visible(state);assert.equal(current.state,'UNKNOWN');assert.equal(current.local_assistance.priority,'unknown');
      v.cases.push({id:'UI93-INITIAL',status:'PASS',financial_state:current.state,advisory:'unknown'});save();
      async function action(scenario,financial,priority,keyboard){
        await page.selectOption('#scenario',scenario);
        const post=page.waitForResponse(r=>r.url()===origin+'/api/fixture'&&r.request().method()==='POST');const fresh=stateResponse();
        if(keyboard){await page.focus('#scenario');await page.keyboard.press('Tab');assert.equal(await page.evaluate(()=>document.activeElement.id),'observe');await page.keyboard.press('Enter');}
        else await page.click('#observe');
        const postResponse=await post;assert.equal(postResponse.status(),200);const financialBody=await postResponse.json();
        const getResponse=await fresh;assert.equal(getResponse.status(),200);state=await getResponse.json();const order=await visible(state);
        const {local_assistance,...financialFields}=order;
        // POST is deterministic raw Store output. GET adds local advisory data.
        assert.deepEqual(financialBody,financialFields);assert.equal(financialBody.state,financial);
        assert.equal(local_assistance.priority,priority);return order;
      }
      current=await action('approved','APPROVED','approval_context',false);
      v.cases.push({id:'UI93-LEARNED-APPROVAL',status:'PASS',financial_state:current.state,advisory:current.local_assistance.priority,post_financial_equals_get_without_advisory:true});save();
      current=await action('unknown','UNKNOWN','unknown',false);
      v.cases.push({id:'UI93-ABSTENTION',status:'PASS',financial_state:current.state,advisory:current.local_assistance.priority});save();
      current=await action('completed','COMPLETED','capture_context',true);
      const details=page.locator('details').filter({has:page.locator('#local-model-id')});await details.locator('summary').click();
      assert(await page.locator('#local-model-id').isVisible());assert.equal(await page.locator('#local-model-id').textContent(),EXPECTED_MODEL);
      assert((await details.textContent()).includes('not calibrated payment certainty'));
      const downloadPromise=page.waitForEvent('download');await page.click('#export');const download=await downloadPromise;
      assert.equal(download.suggestedFilename(),'payproof-synthetic-evidence.json');const file=path.join(out,'synthetic-export-'+width+'.json');await download.saveAs(file);assert.equal(await download.failure(),null);
      const bytes=fs.readFileSync(file);assert(bytes.length<=65536);const exported=JSON.parse(bytes);
      assert.deepEqual(Object.keys(exported).sort(),['ai_mode','mode','order','schema']);assert.equal(exported.schema,'PAYPROOF_EVIDENCE_V1');assert.equal(exported.mode,'SYNTHETIC_ONLY');
      assert.equal(exported.ai_mode,state.ai_mode);assert.equal(exported.ai_mode,await page.locator('#ai-mode').textContent());assert.deepEqual(exported.order,current);safeExport(exported);
      v.cases.push({id:'UI93-KEYBOARD-CAPTURE-EXPORT',status:'PASS',financial_state:current.state,advisory:current.local_assistance.priority,export_bytes:bytes.length,export_sha256:sha(bytes),export_actual_mode:true});
      assert.deepEqual(v.page_errors,[]);assert.deepEqual(v.failed_requests,[]);assert.deepEqual(report.external_requests,[]);
      for(const e of v.http_errors)assert(e.status===404&&e.url===origin+'/favicon.ico','Unexpected HTTP error');
      for(const e of v.console_errors)assert(e.text.includes('404')&&e.url===origin+'/favicon.ico','Unexpected console error');
      assert.deepEqual(v.posts.map(p=>p.body.scenario),['approved','unknown','completed']);
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
      await context.close();await stop(s);v.status='PASS';save();
    }
    report.status='PASS';
  }catch(e){fail(e);save();}
  finally{
    for(const s of servers)if(!s.removed){try{await stop(s);}catch(e){fail(e);report.cleanup.push({width:s.width,terminal:s.terminal||'UNKNOWN',error:String(e.message)});}}
    if(browser){try{await browser.close();report.cleanup.push({browser:'closed'});}catch(e){fail(e);}}
    if(timer)clearTimeout(timer);report.post_return=stamp();save();
    console.log(JSON.stringify(report));if(report.status!=='PASS')process.exitCode=1;
  }
}
main().catch(e=>{fail(e);report.post_return=stamp();save();console.log(JSON.stringify(report));process.exitCode=1;});
