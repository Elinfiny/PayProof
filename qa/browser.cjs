/* Optional real-browser check. Not evidence of a run until this script succeeds. */
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
(async()=>{
  const browser=await chromium.launch({headless:true});
  const base=process.env.PAYPROOF_QA_URL||'http://127.0.0.1:8765';
  const results=[];
  try{
    for(const width of [390,1440]){
      const page=await browser.newPage({viewport:{width,height:1000}});
      const errors=[];page.on('pageerror',e=>errors.push(e.message));
      await page.goto(base);
      await page.waitForFunction(()=>document.getElementById('mode').textContent.includes('SYNTHETIC'));
      for(const [scenario,state] of [['approved','APPROVED'],['completed','COMPLETED'],['unknown','UNKNOWN'],['conflict','CONFLICT'],['incomplete','UNKNOWN']]){
        await page.selectOption('#scenario',scenario);await page.click('#observe');
        await page.waitForFunction(expected=>document.getElementById('state').textContent===expected,state);
      }
      await page.selectOption('#scenario','completed');await page.click('#event');
      await page.waitForFunction(()=>document.getElementById('event-result').textContent.includes('APPLIED'));
      await page.click('#duplicate');await page.waitForFunction(()=>document.getElementById('event-result').textContent.includes('DUPLICATE'));
      const download=page.waitForEvent('download');await page.click('#export');
      assert.equal((await download).suggestedFilename(),'payproof-synthetic-evidence.json');
      await page.focus('#scenario');await page.keyboard.press('Tab');
      assert.equal(await page.evaluate(()=>document.activeElement.id),'observe');
      await page.keyboard.press('Enter');
      await page.waitForFunction(()=>document.getElementById('state').textContent==='COMPLETED');
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
      assert.deepEqual(errors,[]);
      results.push({width,workflow:true,keyboard:true,overflow:false,errors});
      await page.close();
    }
    console.log(JSON.stringify({status:'PASS',results}));
  }finally{await browser.close();}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
