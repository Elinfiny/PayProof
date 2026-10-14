'use strict';
// One synthetic CI attempt. Partial evidence and cleanup outcomes survive failure.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {spawn, execFileSync} = require('node:child_process');
const out = path.resolve('qa-evidence');
fs.mkdirSync(out, {recursive:true});
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const write = (name, data) => fs.writeFileSync(path.join(out, name), JSON.stringify(data, null, 2)+'\n');
function collect() {
  const steps = {npm:process.env.QA_NPM_OUTCOME, install:process.env.QA_INSTALL_OUTCOME, browser:process.env.QA_BROWSER_OUTCOME};
  const files = fs.readdirSync(out).filter(n => n.endsWith('.json') && n !== 'collection.json').map(name => {
    const b = fs.readFileSync(path.join(out,name)); JSON.parse(b); return {name,bytes:b.length,sha256:sha(b)};
  });
  write('collection.json', {schema:'PAYPROOF_QA_COLLECTION_V1',run_id:process.env.GITHUB_RUN_ID,attempt:process.env.GITHUB_RUN_ATTEMPT,steps,files,first_failed_step:Object.keys(steps).find(k=>steps[k]==='failure')||null});
  const total = fs.readdirSync(out).reduce((n,p)=>n+fs.statSync(path.join(out,p)).size,0);
  assert(total<=512*1024,'Evidence exceeds 512 KiB');
  assert(fs.readdirSync(out).every(n=>n.endsWith('.json')),'Only JSON evidence admitted');
  console.log(JSON.stringify({evidence_bytes:total,limit_bytes:512*1024}));
}
if (process.argv.includes('--collect-only')) { collect(); } else { main().catch(e=>{console.error(e.message);process.exitCode=1;}); }
async function main() {
  const started = Date.now();
  const report = {schema:'PAYPROOF_BROWSER_QA_V1',status:'RUNNING',mode:'SYNTHETIC_ONLY',ai_mode:'DETERMINISTIC_NOT_AI',run_id:process.env.GITHUB_RUN_ID,attempt:Number(process.env.GITHUB_RUN_ATTEMPT),head_sha:process.env.QA_HEAD_SHA,node:process.version,runner:{os:process.env.RUNNER_OS,image_os:process.env.ImageOS,image_version:process.env.ImageVersion,release:os.release()},limits:{global_seconds:180,retries:0,viewports:[1440,390],evidence_bytes:512*1024},binaries:[],viewports:[],first_error:null,cleanup:[],human_visual_review:'NOT_PERFORMED'};
  let browser;
  const servers=[];
  const fail = e => { if(!report.first_error) report.first_error={message:String(e.message||e).slice(0,4000),at_ms:Date.now()-started}; report.status='FAIL'; };
  const save = () => write('browser.json',report);
  const hardStop = setTimeout(()=>{
    fail(new Error('Global QA deadline 180s exceeded'));save();
    for(const s of servers) if(s.child.exitCode===null && s.child.signalCode===null){s.child.kill('SIGKILL');report.cleanup.push({width:s.width,forced:true,terminal:'UNKNOWN_AT_DEADLINE'});}
    save();process.exit(1);
  },180000);
  try {
    assert.equal(process.env.GITHUB_ACTIONS,'true','CI-only runner');
    assert.equal(report.attempt,1,'One attempt only');
    assert.match(process.version,/^v22\./);
    const core = path.dirname(require.resolve('playwright-core/package.json'));
    assert.equal(JSON.parse(fs.readFileSync(path.join(core,'package.json'))).version,'1.64.1');
    assert.equal(require('playwright/package.json').version,'1.64.1');
    const names=['chromium','chromium-headless-shell'];
    const selected=JSON.parse(fs.readFileSync(path.join(core,'browsers.json'))).browsers.filter(b=>names.includes(b.name));
    assert.deepEqual(selected.map(b=>b.name).sort(),[...names].sort());
    const registry=require(path.join(core,'lib/server/registry/index.js')).registry;
    for(const b of selected){
      assert.equal(String(b.revision),'1248');assert.equal(b.browserVersion,'156.0.8078.4');
      const executable=registry.findExecutable(b.name).executablePath();
      assert(executable && fs.statSync(executable).size>0);
      const version=execFileSync(executable,['--version'],{encoding:'utf8',timeout:10000}).trim();
      assert(version.includes('156.0.8078.4'));
      const hash=crypto.createHash('sha256');for await(const chunk of fs.createReadStream(executable))hash.update(chunk);
      report.binaries.push({name:b.name,revision:b.revision,expected_version:b.browserVersion,actual_version:version,bytes:fs.statSync(executable).size,sha256:hash.digest('hex'),executable});save();
    }
    browser=await require('playwright').chromium.launch({headless:true,executablePath:report.binaries.find(b=>b.name==='chromium-headless-shell').executable,timeout:10000});
    assert.equal(browser.version(),'156.0.8078.4');
    for(const width of [1440,390]) {
      const v={width,height:1000,cases:[],page_errors:[],console_errors:[],external_requests:[],failed_requests:[],http_errors:[],post_requests:[],status:'RUNNING'};
      report.viewports.push(v);save();
      const dir=fs.mkdtempSync(path.join(os.tmpdir(),'payproof-qa-'));
      const db=path.join(dir,'fixture.sqlite3');assert(!fs.existsSync(db));
      const child=spawn('python3',['-m','payproof.server','--port','0','--db',db],{cwd:path.resolve('.'),stdio:['ignore','pipe','pipe']});
      const s={child,width,dir,stdout:'',stderr:'',terminal:null};servers.push(s);
      const closed=new Promise(resolve=>child.once('close',(code,signal)=>{s.terminal={code,signal};resolve(s.terminal);}));
      s.closed=closed;child.stderr.on('data',b=>{s.stderr=(s.stderr+b).slice(0,8000);});
      const origin=await new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>reject(new Error('Server startup timed out')),10000);
        child.once('error',e=>{clearTimeout(timer);reject(e);});child.once('close',()=>{clearTimeout(timer);reject(new Error('Server exited before URL return'));});
        child.stdout.on('data',b=>{s.stdout=(s.stdout+b).slice(0,8000);const match=s.stdout.match(/PayProof running at (http:\/\/127\.0\.0\.1:\d+) — SYNTHETIC ONLY/);if(match){clearTimeout(timer);resolve(match[1]);}});
      });
      v.server={origin,db_new:true,db_isolated_per_viewport:true,stdout:s.stdout};
      const context=await browser.newContext({viewport:{width,height:1000},acceptDownloads:true,serviceWorkers:'block'});
      const page=await context.newPage();page.setDefaultTimeout(5000);
      let rejectedRequest=null;
      page.on('pageerror',e=>v.page_errors.push(e.message.slice(0,1000)));
      page.on('console',m=>{if(m.type()==='error')v.console_errors.push({text:m.text().slice(0,1000),location:m.location()});});
      page.on('requestfailed',r=>v.failed_requests.push({url:r.url(),error:r.failure()}));
      page.on('response',r=>{if(r.status()>=400)v.http_errors.push({url:r.url(),status:r.status()});});
      await context.route('**/*',async route=>{
        const r=route.request(),u=new URL(r.url());
        if(u.origin!==origin){v.external_requests.push(r.url());await route.abort();return;}
        if(r.method()==='POST')v.post_requests.push({path:u.pathname,body:JSON.parse(r.postData())});
        await route.continue();
      });
      const initial=page.waitForResponse(r=>r.url()===origin+'/api/state'&&r.request().method()==='GET');
      await page.goto(origin,{waitUntil:'networkidle'});
      const initialState=await (await initial).json();
      assert.equal(initialState.mode,'SYNTHETIC FIXTURES — NO PAYPAL CONNECTION');assert.equal(initialState.ai_mode,'DETERMINISTIC — NOT LIVE AI');assert.equal(initialState.contest_ready,false);
      assert.equal(initialState.orders[0].state,'UNKNOWN');
      const syncUI=async state=>{
        assert.equal(state.orders.length,1);
        const order=state.orders[0],raw=JSON.stringify(order.facts||{state:order.state,evidence:'No usable current provider facts'},null,2);
        await page.waitForFunction(({state,raw})=>document.getElementById('state').textContent===state&&document.getElementById('raw').textContent===raw&&!document.getElementById('observe').disabled,{state:order.state,raw});
        assert.equal(await page.locator('#order-id').textContent(),order.id);
        assert.equal(await page.locator('#total').textContent(),`${order.amount} ${order.currency}`);
        assert.equal(await page.locator('#source').textContent(),order.source);
        assert.equal(await page.locator('#summary').textContent(),order.explanation.text);
        assert.equal(await page.locator('#next').textContent(),order.explanation.next_step);
        assert.equal(await page.locator('#message').textContent(),'');
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
        return order;
      };
      await syncUI(initialState);v.cases.push({name:'initial-new-db',status:'PASS'});save();
      async function action(selector,endpoint,expected,keyboard=false){
        const post=page.waitForResponse(r=>r.url()===origin+endpoint&&r.request().method()==='POST');
        const read=page.waitForResponse(r=>r.url()===origin+'/api/state'&&r.request().method()==='GET');
        if(keyboard)await page.keyboard.press('Enter');else await page.click(selector);
        const response=await post;assert.equal(response.status(),200);const body=await response.json();
        const fresh=await read;assert.equal(fresh.status(),200);const state=await fresh.json();
        const order=await syncUI(state);assert.equal(order.state,expected);
        assert.deepEqual(body.order||body,order);return {body,order};
      }
      let historical;
      for(const [scenario,state] of [['approved','APPROVED'],['completed','COMPLETED'],['unknown','UNKNOWN'],['conflict','CONFLICT'],['incomplete','UNKNOWN']]){
        await page.selectOption('#scenario',scenario);
        const result=await action('#observe','/api/fixture',state);
        if(scenario==='completed')historical=result.order.last_verified;
        if(scenario==='unknown'){
          assert.equal(result.order.facts,null);assert.deepEqual(result.order.last_verified,historical);
          assert.equal(await page.locator('#previous').isVisible(),true);
          assert((await page.locator('#previous').textContent()).includes('Historical evidence: COMPLETED'));
          assert((await page.locator('#previous').textContent()).includes('This does not resolve the current outcome.'));
        }
        v.cases.push({name:'read-'+scenario,status:'PASS',state});save();
        if(scenario==='unknown'){
          const postCount=v.post_requests.length;await page.selectOption('#scenario','completed');
          await action('#observe','/api/fixture','COMPLETED');
          assert.deepEqual(v.post_requests.slice(postCount).map(r=>r.path),['/api/fixture']);
          assert.equal(await page.locator('#previous').isVisible(),false);
          v.cases.push({name:'unknown-fresh-read-reconcile-without-event-or-financial-replay',status:'PASS'});save();
        }
      }
      await page.selectOption('#scenario','completed');
      const event=await action('#event','/api/fixture-event','COMPLETED');assert.equal(event.body.disposition,'APPLIED');
      assert((await page.locator('#event-result').textContent()).includes('APPLIED'));
      v.cases.push({name:'verified-event',status:'PASS'});save();
      const duplicate=await action('#duplicate','/api/fixture-event','COMPLETED');assert.equal(duplicate.body.disposition,'DUPLICATE');assert.equal(duplicate.body.original_disposition,'APPLIED');
      assert.deepEqual(v.post_requests.at(-1).body,v.post_requests.at(-2).body);assert.deepEqual(duplicate.order,event.order);
      assert((await page.locator('#event-result').textContent()).includes('DUPLICATE'));
      v.cases.push({name:'exact-event-duplicate',status:'PASS'});save();
      await page.uncheck('#verified');
      const before=await page.evaluate(async()=>{const r=await fetch('/api/state');return {status:r.status,data:await r.json()};});assert.equal(before.status,200);
      const refused=page.waitForResponse(r=>r.url()===origin+'/api/fixture-event'&&r.request().method()==='POST');
      await page.click('#event');const rejection=await refused;rejectedRequest=rejection.request();assert.equal(rejection.status(),400);
      assert.deepEqual(await rejection.json(),{error:'Invalid input or unverified/conflicting event'});
      await page.waitForFunction(()=>document.getElementById('message').textContent==='Invalid input or unverified/conflicting event'&&!document.getElementById('observe').disabled);
      const after=await page.evaluate(async()=>{const r=await fetch('/api/state');return {status:r.status,data:await r.json()};});assert.equal(after.status,200);assert.deepEqual(after.data,before.data);
      assert.equal(await page.locator('#state').textContent(),before.data.orders[0].state);
      v.cases.push({name:'unverified-event-refused-400-state-unchanged',status:'PASS'});save();
      await page.check('#verified');await page.focus('#scenario');await page.keyboard.press('Tab');assert.equal(await page.evaluate(()=>document.activeElement.id),'observe');
      await action('#observe','/api/fixture','COMPLETED',true);
      v.cases.push({name:'keyboard-tab-enter-fresh-response',status:'PASS'});save();
      const downloadPromise=page.waitForEvent('download');await page.click('#export');const download=await downloadPromise;
      assert.equal(download.suggestedFilename(),'payproof-synthetic-evidence.json');
      const name=`download-${width}.json`;await download.saveAs(path.join(out,name));assert.equal(await download.failure(),null);
      const bytes=fs.readFileSync(path.join(out,name));assert(bytes.length>0 && bytes.length<=64*1024);
      const evidence=JSON.parse(bytes);assert.deepEqual(Object.keys(evidence).sort(),['ai_mode','mode','order','schema']);
      assert.equal(evidence.schema,'PAYPROOF_EVIDENCE_V1');assert.equal(evidence.mode,'SYNTHETIC_ONLY');assert.equal(evidence.ai_mode,'DETERMINISTIC_NOT_AI');
      assert.equal(evidence.order.state,'COMPLETED');assert.equal(evidence.order.id,'DEMO-ORDER-001');assert.equal(evidence.order.amount,'120.00');assert.equal(evidence.order.currency,'EUR');
      function sanitized(x){if(Array.isArray(x))return x.forEach(sanitized);if(x&&typeof x==='object'){for(const [k,v] of Object.entries(x)){assert(!/payer|email|secret|token|authorization|credential|password/i.test(k),`Forbidden export key ${k}`);sanitized(v);}}else if(typeof x==='string')assert(!/@|synthetic-private-field|Bearer\s/i.test(x),'Forbidden export value');}
      sanitized(evidence);assert.deepEqual(evidence.order,after.data.orders[0].state==='COMPLETED'?JSON.parse(await page.evaluate(async()=>JSON.stringify((await (await fetch('/api/state')).json()).orders[0]))):null);
      v.download={name,bytes:bytes.length,sha256:sha(bytes),schema:evidence.schema,state:evidence.order.state,sanitized:true};v.cases.push({name:'actual-downloaded-json',status:'PASS'});
      await page.waitForTimeout(150);
      assert.deepEqual(v.page_errors,[]);assert.deepEqual(v.external_requests,[]);assert.deepEqual(v.failed_requests,[]);
      assert(rejectedRequest,'Expected rejected event response not observed');
      for(const e of v.http_errors)assert((e.status===400&&e.url===origin+'/api/fixture-event')||(e.status===404&&e.url===origin+'/favicon.ico'),'Unexpected HTTP error');
      assert.equal(v.http_errors.filter(e=>e.status===400).length,1);
      for(const e of v.console_errors)assert(e.text.includes('Failed to load resource')&&((e.text.includes('400')&&e.location.url===origin+'/api/fixture-event')||(e.text.includes('404')&&e.location.url===origin+'/favicon.ico')),'Unexpected console error');
      v.expected_console_errors=v.console_errors.length;
      assert(v.post_requests.every(r=>['/api/fixture','/api/fixture-event'].includes(r.path)));
      v.cases.push({name:'console-page-network-overflow',status:'PASS',overflow:false,expected_http400:1});
      await context.close();await stopServer(s);v.server.terminal=s.terminal;v.status='PASS';save();
    }
    report.status='PASS';
  } catch(e) { fail(e);save(); }
  finally {
    for(const s of servers)if(!s.terminal){try{await stopServer(s);}catch(e){report.cleanup.push({width:s.width,error:String(e.message),terminal:s.terminal||'UNKNOWN'});fail(e);}}
    if(browser){try{await browser.close();report.cleanup.push({browser:'closed'});}catch(e){report.cleanup.push({browser_error:String(e.message)});fail(e);}}
    report.elapsed_ms=Date.now()-started;save();clearTimeout(hardStop);
    if(report.status!=='PASS')process.exitCode=1;
    console.log(JSON.stringify({status:report.status,first_error:report.first_error,viewports:report.viewports.map(v=>({width:v.width,status:v.status,completed_cases:v.cases.length}))}));
  }
  async function stopServer(s){
    if(!s.terminal){s.child.kill('SIGINT');let timer;const timeout=new Promise(resolve=>{timer=setTimeout(()=>resolve(null),5000);});const terminal=await Promise.race([s.closed,timeout]);clearTimeout(timer);if(!terminal){s.child.kill('SIGKILL');await s.closed;throw new Error('Fixture server required forced shutdown');}}
    report.cleanup.push({width:s.width,terminal:s.terminal,stdout:s.stdout,stderr:s.stderr});save();assert.deepEqual(s.terminal,{code:0,signal:null});assert.equal(s.stderr,'');fs.rmSync(s.dir,{recursive:true,force:true});
  }
}
