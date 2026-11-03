'use strict';
// Run the actual browser loop against a synthetic clock and in-memory responses.
const vm=require('node:vm'), fs=require('node:fs'), assert=require('node:assert/strict');
const crypto=require('node:crypto').webcrypto;
const hash=async b=>Buffer.from(await crypto.subtle.digest('SHA-256',b)).toString('hex');
let now=1000000, calls=0;
const nodes=Object.fromEntries(['status','approve','ack','expiry'].map(id=>[id,{hidden:true,disabled:true,textContent:'',removeAttribute(){},addEventListener(){throw Error('NO_ORDER_NO_ACK');}}]));
const context={crypto,TextEncoder,TextDecoder,Uint8Array,URL,AbortController,console,
  Date:class extends Date{static now(){return now;}},
  btoa:s=>Buffer.from(s,'binary').toString('base64'),atob:s=>Buffer.from(s,'base64').toString('binary'),
  setTimeout(fn,ms){if(ms===4000){now+=ms;queueMicrotask(fn);}return 1;},clearTimeout(){},
  history:{replaceState(){}},location:{protocol:'https:',host:'v2202609412152514007.ultrasrv.de',pathname:'/buyer186'},
  window:{addEventListener(){}},module:{exports:{}},
  async fetch(path,options){
    calls++;let raw=new Uint8Array(),status=204;
    if(path==='/buyer186/key'){
      const body=JSON.parse(options.body),der=Buffer.from(body.public_key_der,'base64');
      const binding={expires_at:1600,recipient_sha256:await hash(der),run_id:'237',source:'a'.repeat(40)};
      const canonical=context.module.exports.canonical;
      const pairing_sha256=await hash(new TextEncoder().encode(canonical({binding,public_key_der:body.public_key_der,browser_cap_sha256:await hash(new TextEncoder().encode(options.headers.Authorization.slice(7)))})));
      raw=new TextEncoder().encode(JSON.stringify({binding,pairing_sha256}));status=200;
    }else assert.equal(path,'/buyer186/envelope');
    const digest=await hash(raw);
    return {status,headers:{get:()=>digest},arrayBuffer:async()=>raw.buffer};
  }
};
vm.createContext(context);
vm.runInContext(fs.readFileSync('payment186/buyer.js','utf8'),context);
context.document={getElementById:id=>nodes[id]};
(async()=>{
  await context.module.exports.start();
  assert.equal(calls,61);assert.equal(now,1236000);
  assert.equal(nodes.approve.hidden,true);assert.equal(nodes.ack.disabled,true);
  assert.match(nodes.status.textContent,/nu poate continua/);
  assert.ok(now<1300000); // Five minutes remain in the same 600s grant.
  console.log('PASS actual browser loop: 60 reads/236s, no approval, finite closure');
})().catch(e=>{console.error(e);process.exitCode=1;});
