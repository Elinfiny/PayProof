'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');
const {TextEncoder} = require('node:util');
const root = path.resolve(__dirname,'..');
const html = fs.readFileSync(path.join(root,'payproof/web/index.html'),'utf8');
const js = fs.readFileSync(path.join(root,'payproof/web/app.js'),'utf8');
const marker = '// Recorded Sandbox run118: isolated saved evidence, never current order authority.';
assert.equal(js.split(marker).length,2,'Run the actual new binding from the pinned production source');
const binding = marker + js.split(marker)[1];
const embedded = html.match(/<script type="application\/json" id="recorded-run117-data">([\s\S]*?)<\/script>/);
assert.ok(embedded,'The existing document must carry its fixed same-origin record');
const original = JSON.parse(embedded[1]);
async function mount(payload) {
  let htmlWrites=0, transportCalls=0;
  const elements=new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(m=>[m[1],{
    textContent:'',hidden:false,dataset:{},dateTime:'',
    set innerHTML(_){htmlWrites++;throw new Error('HTML sink forbidden');}
  }]));
  if(payload===null) elements.delete('recorded-run117-data');
  else elements.get('recorded-run117-data').textContent=payload;
  elements.get('recorded-run-link').hidden=true;
  const sandbox={document:{getElementById:id=>elements.get(id)||null},crypto:webcrypto,TextEncoder,Uint8Array,
    fetch:()=>{transportCalls++;throw new Error('Recorded panel must not call transport');},
    attackExecuted:false};
  const context=vm.createContext(sandbox);
  vm.runInContext(binding,context,{timeout:1000});
  await vm.runInContext('recordedRun118Ready',context,{timeout:1000});
  return {elements,htmlWrites,transportCalls,attackExecuted:sandbox.attackExecuted};
}
test('reviewed real saved117 is distinct, CONFLICT and READY-with-abstention, never payment verification',async()=>{
  const view=await mount(embedded[1]);const get=id=>view.elements.get(id);
  assert.equal(get('recorded-run-status').textContent,'CONFLICT · recorded');
  assert.equal(get('recorded-run-status').dataset.evidence,'reviewed-recording');
  assert.equal(get('recorded-run-time').dateTime,'2026-10-18T19:36:29.277776Z');
  assert.equal(get('recorded-run-total').textContent,'1.00 USD');
  assert.match(get('recorded-run-model').textContent,/READY.*unknown.*abstained/);
  assert.match(get('recorded-run-context').textContent,/internal cause was not retained/);
  assert.match(html,/No payment verified/);assert.match(html,/Separate from the synthetic demo/);
  assert.match(html,/not a current live read/);assert.equal(get('recorded-run-link').hidden,false);
  assert.match(html,/https:\/\/github.com\/Elinfiny\/PayProof\/actions\/runs\/39159527253/);
  const proof=JSON.parse(get('recorded-run-proof').textContent);
  assert.equal(proof.job_id,117769703589);assert.equal(proof.head,'402f38351089c24da7ec6cde63a5d4a445aa11fc');
  assert.equal(proof.calls,2);assert.equal(proof.state,'CONFLICT');
  assert.equal(proof.explanation.text,'Order facts conflict with the registered expectation.');
  assert.equal(proof.explanation.mode,'DETERMINISTIC — NOT LIVE AI');
  assert.equal(proof.local_assistance.reason,'INVALID_OR_UNVERIFIED_EVIDENCE');
  assert.equal(proof.local_assistance.model_fingerprint,'0513952a8592ad96858b70d87da5cf3d8079b2c5e53e4e38b8dbed2e90d30662');
  assert.deepEqual(proof.payment_actions,[]);assert.equal(proof.local_assistance.financial_authority,false);
  assert.equal(view.transportCalls,0);assert.equal(view.htmlWrites,0);
});
test('a modified or absent recording fails closed without synthetic substitution or live semantics',async()=>{
  const changed=structuredClone(original);changed.state='COMPLETED';
  for(const payload of [JSON.stringify(changed),null]){
    const view=await mount(payload);const get=id=>view.elements.get(id);
    assert.equal(get('recorded-run-status').dataset.evidence,'unverified');
    assert.equal(get('recorded-run-status').textContent,'UNAVAILABLE — unverified');
    assert.equal(get('recorded-run-link').hidden,true);assert.equal(get('recorded-run-time').dateTime,'');
    assert.equal(get('recorded-run-proof').textContent,'Unavailable — unverified');
    assert.match(get('recorded-run-context').textContent,/No synthetic result is substituted/);
    assert.equal(view.transportCalls,0);
  }
});
test('hostile evidence text cannot become HTML, execute code, or create a payment action',async()=>{
  const tainted=structuredClone(original);
  tainted.explanation.text='</script><img src=x onerror="attackExecuted=true"><script>attackExecuted=true</script>';
  tainted.payment_actions=['CAPTURE'];
  const view=await mount(JSON.stringify(tainted));
  assert.equal(view.attackExecuted,false);assert.equal(view.htmlWrites,0);assert.equal(view.transportCalls,0);
  assert.equal(view.elements.get('recorded-run-status').dataset.evidence,'unverified');
  assert.equal(view.elements.get('recorded-run-proof').textContent,'Unavailable — unverified');
  assert.doesNotMatch(binding,/innerHTML|insertAdjacentHTML|eval\s*\(|new Function|fetch\s*\(/);
  assert.doesNotMatch(embedded[1],/<|>|&/,'Inline inert JSON must not contain HTML delimiters');
  assert.equal((html.match(/<script type="application\/json" id="recorded-run117-data">/g)||[]).length,1);
});

