'use strict';
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),{webcrypto}=require('node:crypto');
const html=fs.readFileSync('payproof/web/index.html','utf8');
const js='const recordedC244Ready ='+fs.readFileSync('payproof/web/app.js','utf8').split('const recordedC244Ready =')[1];
const saved=html.match(/<script type="application\/json" id="proof244-data">(.*?)<\/script>/s)[1];
async function check(text,allowed,crypto=webcrypto){
 const nodes=Object.fromEntries(['proof244-status','proof244-content','proof244-json','proof244-integrity','proof244-data'].map(id=>[id,{hidden:true,dataset:{},textContent:''}]));nodes['proof244-data'].textContent=text;
 const sandbox={byId:id=>nodes[id],crypto,TextEncoder};vm.createContext(sandbox);
 await vm.runInContext(js+'\nrecordedC244Ready;',sandbox);
 assert.equal(nodes['proof244-content'].hidden,!allowed);
 if(allowed){assert.equal(nodes['proof244-status'].textContent,'COMPLETED · recorded');assert.equal(JSON.parse(nodes['proof244-json'].textContent).cleanup.custody_files,47);}
}
(async()=>{
 await check(saved,true);await check('{',false);await check('x'.repeat(8193),false);await check(saved,false,{});
 for(const [k,v] of [['state','FAILED'],['run_id',1],['amount','100.00'],['real_money',true],['attempt',2]]){const r=JSON.parse(saved);r[k]=v;await check(JSON.stringify(r),false);}
 const old=JSON.parse(html.match(/id="recorded-run117-data">(.*?)<\/script>/s)[1]);assert.equal(old.state,'CONFLICT');assert.equal(old.local_assistance.priority,'unknown');
 assert(!/\bfetch\s*\(|XMLHttpRequest|WebSocket/.test(js));
 console.log('PASS: 9 new projection cases, original117 preserved, zero provider path');
})();
