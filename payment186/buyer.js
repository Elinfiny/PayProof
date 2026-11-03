'use strict';
// No key/token/approval in storage, console, query strings, analytics or exports.
const PaymentBuyer186 = (() => {
  const encoder = new TextEncoder();
  const hex = a => Array.from(new Uint8Array(a), b => b.toString(16).padStart(2,'0')).join('');
  const hash = async b => hex(await crypto.subtle.digest('SHA-256',b));
  const bytes = s => Uint8Array.from(atob(s),c=>c.charCodeAt(0));
  const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));
  const sorted = x => Array.isArray(x) ? x.map(sorted) : x && typeof x==='object' ? Object.fromEntries(Object.keys(x).sort().map(k=>[k,sorted(x[k])])) : x;
  const canonical = x => JSON.stringify(sorted(x));
  const need = (x) => { if(!x) throw Error('REFUSED'); };
  async function unpack(raw,binding,digest,privateKey,now=Date.now()/1000) {
    need(raw.byteLength>0 && raw.byteLength<=2048 && await hash(raw)===digest);
    const text=new TextDecoder('utf-8',{fatal:true}).decode(raw), row=JSON.parse(text);
    need(canonical(row)===text && Object.keys(row).sort().join(',')==='binding,bytes,ciphertext_base64,schema,sha256');
    need(row.schema==='PAYPROOF_BUYER_CIPHERTEXT164' && canonical(row.binding)===canonical(binding) && now<binding.expires_at && row.bytes===256);
    const cipher=bytes(row.ciphertext_base64);need(cipher.length===256 && b64(cipher)===row.ciphertext_base64 && await hash(cipher)===row.sha256);
    const plain=await crypto.subtle.decrypt({name:'RSA-OAEP'},privateKey,cipher);
    const url=new TextDecoder('utf-8',{fatal:true}).decode(plain);need(plain.byteLength<=190);
    const u=new URL(url);const order=u.searchParams.get('token');
    need(u.protocol==='https:' && u.host==='www.sandbox.paypal.com' && u.pathname==='/checkoutnow' && !u.username && !u.password && !u.hash && /^[A-Z0-9-]{1,64}$/.test(order||'') && u.search==='?token='+order);
    return {url,order,file_sha256:digest};
  }
  async function start() {
    const status=document.getElementById('status'), link=document.getElementById('approve'),ack=document.getElementById('ack');
    let capability='',key=null,receipt=null,binding=null,stopped=false,expiryTimer;
    history.replaceState(null,'',location.pathname);
    const close = message => { stopped=true;capability='';key=null;receipt=null;link.removeAttribute('href');link.hidden=true;ack.disabled=true;ack.hidden=true;status.textContent=message;if(expiryTimer)clearTimeout(expiryTimer); };
    window.addEventListener('pagehide',()=>close('Acces închis.'),{once:true});
    let calls=0;
    async function request(path,row) {
      need(!stopped && calls++<63 && (!binding || Date.now()/1000<binding.expires_at));
      const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),5000);
      try {
        const r=await fetch(path,{method:row?'POST':'GET',redirect:'error',credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',signal:controller.signal,headers:{'Authorization':'Bearer '+capability,...(row?{'Content-Type':'application/json'}:{})},body:row?JSON.stringify(row):undefined});
        need(r.status===200 || r.status===204);
        const raw=await r.arrayBuffer();need(raw.byteLength<=4096 && await hash(raw)===r.headers.get('X-Content-SHA256'));
        return {status:r.status,raw,digest:r.headers.get('X-Content-SHA256')};
      } finally {clearTimeout(timer);}
    }
    try {
      need(location.protocol==='https:' && location.host==='v2202609412152514007.ultrasrv.de');
      capability=hex(crypto.getRandomValues(new Uint8Array(32)));
      key=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},false,['encrypt','decrypt']);
      const publicDER=await crypto.subtle.exportKey('spki',key.publicKey);
      const reply=await request('/buyer186/key',{public_key_der:b64(publicDER)});
      const row=JSON.parse(new TextDecoder().decode(reply.raw));binding=row.binding;
      need(Object.keys(binding).sort().join(',')==='expires_at,recipient_sha256,run_id,source' && /^[a-f0-9]{40}$/.test(binding.source) && /^[1-9][0-9]{0,19}$/.test(binding.run_id) && binding.recipient_sha256===await hash(publicDER) && Number.isInteger(binding.expires_at));
      const pairing=await hash(encoder.encode(canonical({binding,public_key_der:b64(publicDER),browser_cap_sha256:await hash(encoder.encode(capability))})));
      need(row.pairing_sha256===pairing);
      const remaining=binding.expires_at*1000-Date.now();need(remaining>0 && remaining<=600000);
      expiryTimer=setTimeout(()=>close('Sesiunea a expirat. Accesul temporar este închis.'),remaining);
      document.getElementById('expiry').textContent='Acces valabil până la '+new Date(binding.expires_at*1000).toLocaleTimeString('ro-RO')+'.';
      status.textContent='Master verifică asocierea acestui browser. Amprentă publică: '+pairing;
      for(let n=0;n<60;n++) {
        const response=await request('/buyer186/envelope');
        if(response.status===200){receipt=await unpack(response.raw,binding,response.digest,key.privateKey);break;}
        // Same 60 reads, lower polling rate. Keep five minutes for approval.
        need(n<59 && Date.now()/1000<binding.expires_at-300);
        await new Promise(resolve=>setTimeout(resolve,4000));
      }
      need(receipt && !stopped);key=null;link.href=receipt.url;link.hidden=false;ack.hidden=false;ack.disabled=false;
      status.textContent='Comanda de test este pregătită. Deschide PayPal Sandbox, aprobă acolo, apoi revino aici.';
      ack.addEventListener('click',async()=>{
        ack.disabled=true;
        try {need(receipt);await request('/buyer186/ack',{order_id:receipt.order,file_sha256:receipt.file_sha256});close('Confirmare transmisă. Plata va fi verificată direct la PayPal.');}
        catch(_){close('Confirmarea are rezultat incert. Nu repeta operația.');}
      },{once:true});
    } catch(_){close('Sesiunea nu poate continua. Nu reîncărca pentru a repeta operația.');}
  }
  return {unpack,hash,canonical,start};
})();
if(typeof document!=='undefined') PaymentBuyer186.start();
if(typeof module!=='undefined') module.exports=PaymentBuyer186;
