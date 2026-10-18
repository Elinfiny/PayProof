'use strict';
const byId = id => document.getElementById(id);
let current = null, lastEvent = null;
let currentAIMode = 'DETERMINISTIC — NOT LIVE AI';
async function call(path, body) {
  const response = await fetch(path, body ? {method:'POST',headers:{'Content-Type':'application/json','X-PayProof-Request':'fixture-ui'},body:JSON.stringify(body)} : {});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request failed');
  return result;
}
async function refresh() {
  const result = await call('/api/state');
  byId('mode').textContent = result.mode;
  currentAIMode = result.ai_mode;
  byId('ai-mode').textContent = result.ai_mode;
  current = result.orders[0];
  byId('state').textContent = current.state;
  byId('state').dataset.state = current.state;
  byId('order-id').textContent = current.id;
  byId('total').textContent = `${current.amount} ${current.currency}`;
  byId('source').textContent = current.source;
  byId('observed').textContent = current.observed_at ? new Date(current.observed_at).toLocaleString() : 'No observation yet';
  byId('summary').textContent = current.explanation.text;
  byId('next').textContent = current.explanation.next_step;
  const advice = current.local_assistance || {priority:'unknown',text:'Local model assistance unavailable.',uncertainty:true,model_fingerprint:''};
  byId('local-priority').textContent = advice.priority;
  byId('local-explanation').textContent = advice.text;
  byId('local-uncertainty').textContent = advice.uncertainty ? 'UNKNOWN — no advisory prediction.' : 'Nonbinding explanation priority; never payment certainty.';
  byId('local-model-id').textContent = advice.model_fingerprint || 'No fitted model';
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
  const evidence={schema:'PAYPROOF_EVIDENCE_V1',mode:'SYNTHETIC_ONLY',ai_mode:currentAIMode,order:current};
  const url=URL.createObjectURL(new Blob([JSON.stringify(evidence,null,2)],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download='payproof-synthetic-evidence.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
refresh().catch(error=>byId('message').textContent=error.message);


// Recorded Sandbox run118: isolated saved evidence, never current order authority.
const recordedRun118Ready = (async () => {
  const element = id => document.getElementById(id);
  const status = element('recorded-run-status');
  if (!status) return;
  const unavailable = () => {
    status.textContent = 'UNAVAILABLE — unverified';
    status.dataset.state = 'UNKNOWN';
    status.dataset.evidence = 'unverified';
    element('recorded-run-link').hidden = true;
    element('recorded-run-time').textContent = 'Unavailable';
    element('recorded-run-time').dateTime = '';
    for (const id of ['recorded-run-total','recorded-run-model','recorded-run-calls']) element(id).textContent = 'Unavailable';
    element('recorded-run-context').textContent = 'Recorded evidence is unavailable or its integrity has not been verified. No synthetic result is substituted.';
    element('recorded-run-proof').textContent = 'Unavailable — unverified';
  };
  unavailable();
  try {
    // Fixed same-origin inert payload embedded in index.html; no import/refresh/API.
    const data = element('recorded-run117-data');
    if (!data || data.textContent.length > 8192 || !crypto.subtle) return;
    const record = JSON.parse(data.textContent);
    const canonical = value => JSON.stringify(value && typeof value === 'object'
      ? (Array.isArray(value) ? value.map(v => JSON.parse(canonical(v)))
        : Object.fromEntries(Object.keys(value).sort().map(k => [k,JSON.parse(canonical(value[k]))])))
      : value);
    const bytes = new TextEncoder().encode(canonical(record));
    const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2,'0')).join('');
    if (digest !== 'ab12ba5da5f4ca98b2646f177b48568458e87b08031723d07bd44c220b25d1c4') return;
    if (record.schema !== 'PAYPROOF_RECORDED_SANDBOX_RUN_V1' ||
        record.run_id !== 39159527253 || record.job_id !== 117769703589 || record.attempt !== 1 ||
        record.state !== 'CONFLICT' || record.actual_paypal !== true || record.synthetic !== false ||
        record.calls !== 2 || record.amount !== '1.00' || record.currency !== 'USD' ||
        record.local_assistance.model_ready !== true || record.local_assistance.priority !== 'unknown' ||
        record.local_assistance.financial_authority !== false ||
        record.payment_actions.length !== 0 || record.local_assistance.payment_actions.length !== 0) return;
    status.textContent = 'CONFLICT · recorded';
    status.dataset.state = 'CONFLICT';
    status.dataset.evidence = 'reviewed-recording';
    element('recorded-run-time').textContent = record.observed_at;
    element('recorded-run-time').dateTime = record.observed_at;
    element('recorded-run-total').textContent = record.amount + ' ' + record.currency;
    element('recorded-run-model').textContent = 'Local model READY · advisory priority unknown (abstained)';
    element('recorded-run-calls').textContent = '2 · OAuth + existing-order read';
    element('recorded-run-context').textContent = 'Financial details did not pass validation. The internal cause was not retained in this receipt. READY means the local model initialized; it did not issue a valid recommendation. No payment action is available.';
    element('recorded-run-proof').textContent = JSON.stringify(record,null,2);
    element('recorded-run-link').hidden = false;
  } catch (_) {
    unavailable();
  }
})();
