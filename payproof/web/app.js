'use strict';
const byId = id => document.getElementById(id);
let current = null, lastEvent = null;
async function call(path, body) {
  const response = await fetch(path, body ? {method:'POST',headers:{'Content-Type':'application/json','X-PayProof-Request':'fixture-ui'},body:JSON.stringify(body)} : {});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request failed');
  return result;
}
async function refresh() {
  const result = await call('/api/state');
  byId('mode').textContent = result.mode;
  current = result.orders[0];
  byId('state').textContent = current.state;
  byId('state').dataset.state = current.state;
  byId('order-id').textContent = current.id;
  byId('total').textContent = `${current.amount} ${current.currency}`;
  byId('source').textContent = current.source;
  byId('observed').textContent = current.observed_at ? new Date(current.observed_at).toLocaleString() : 'No observation yet';
  byId('summary').textContent = current.explanation.text;
  byId('next').textContent = current.explanation.next_step;
  byId('raw').textContent = JSON.stringify(current.facts || {state:current.state,evidence:'No usable current provider facts'},null,2);
  byId('previous').hidden = !(current.last_verified && ['UNKNOWN','CONFLICT'].includes(current.state));
  byId('previous').textContent = current.last_verified ? `Historical evidence: ${current.last_verified.facts.state} at ${current.last_verified.observed_at}. This does not resolve the current outcome.` : '';
}
async function action(task) {
  const buttons = document.querySelectorAll('button');
  buttons.forEach(b=>b.disabled=true);
  byId('message').textContent='';
  try { await task(); await refresh(); }
  catch(error) { byId('message').textContent=error.message; }
  finally { buttons.forEach(b=>b.disabled=false); byId('duplicate').disabled=!lastEvent; }
}
byId('observe').addEventListener('click',()=>action(()=>call('/api/fixture',{scenario:byId('scenario').value})));
byId('event').addEventListener('click',()=>action(async()=>{
  const payload={scenario:byId('scenario').value,event_id:`DEMO-${crypto.randomUUID().toUpperCase()}`,verified:byId('verified').checked};
  const result=await call('/api/fixture-event',payload);
  lastEvent=payload;
  byId('event-result').textContent=`Event outcome: ${result.disposition}`;
}));
byId('duplicate').addEventListener('click',()=>action(async()=>{
  const result=await call('/api/fixture-event',lastEvent);
  byId('event-result').textContent=`Event outcome: ${result.disposition} (original: ${result.original_disposition})`;
}));
byId('export').addEventListener('click',()=>{
  if(!current)return;
  const evidence={schema:'PAYPROOF_EVIDENCE_V1',mode:'SYNTHETIC_ONLY',ai_mode:'DETERMINISTIC_NOT_AI',order:current};
  const url=URL.createObjectURL(new Blob([JSON.stringify(evidence,null,2)],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download='payproof-synthetic-evidence.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
refresh().catch(error=>byId('message').textContent=error.message);
