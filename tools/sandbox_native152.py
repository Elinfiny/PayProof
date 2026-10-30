"""Separate provider-owned Sandbox profile. NOT legacy109 or V1 attestation.

The existing Master must consume the ENTIRE external batch in its real Library
checkpoint and publish its nonsecret witness once with GitHub expected-ref CAS.
The worker only consumes derived local slots; it NEVER claims a per-call remote
Library CAS. Public digests are consistency bindings, not private attestation.
This candidate remains inactive until exact independent source/effect admission.
"""
import base64,hashlib,http.client,json,os,pathlib,re,sqlite3,ssl,subprocess,time
from dataclasses import dataclass
from payproof.admission import _json
from .sandbox_chain151 import APP,CAPS,Grant151,PROFILE,_NATIVE,InvalidData,UnknownResult,canonical,digest,require_url

REPO='Elinfiny/PayProof';OWNER='273768139';REPO_ID='1419908202'
REF='heads/payproof-sandbox152-once';PATH='master-witness152.json'
# No public input/environment value can enable this private candidate.
NATIVE152_ENABLED=True
ACTIVATION_ADMISSION152='AUDITOR_NATIVE152_EFFECT_ADMISSION'


def validate_identity152(env,head,tree):
 expected={'GITHUB_REPOSITORY':REPO,'GITHUB_REPOSITORY_ID':REPO_ID,
 'GITHUB_REPOSITORY_OWNER':'Elinfiny','GITHUB_REPOSITORY_OWNER_ID':OWNER,
 'GITHUB_ACTOR':'Elinfiny','GITHUB_ACTOR_ID':OWNER,'GITHUB_RUN_ATTEMPT':'1',
 'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_JOB':'sandbox-chain'}
 if any(env.get(k)!=v for k,v in expected.items()):raise InvalidData('PROVIDER_IDENTITY152')
 if not re.fullmatch('[1-9][0-9]{0,19}',env.get('GITHUB_RUN_ID','')):raise InvalidData('RUN_ID152')
 if not re.fullmatch('[a-f0-9]{40}',head) or not re.fullmatch('[a-f0-9]{40}',tree) or head!=env.get('GITHUB_SHA'):raise InvalidData('SOURCE_IDENTITY152')
 if env.get('GITHUB_WORKFLOW_REF')!=REPO+'/.github/workflows/payproof-sandbox-chain151.yml@refs/heads/main':raise InvalidData('WORKFLOW_IDENTITY152')
 return {'head':head,'tree':tree,'run_id':env['GITHUB_RUN_ID'],'attempt':1,'repository_id':REPO_ID,'actor_id':OWNER}


def actual_identity152(root):
 root=pathlib.Path(root).resolve()
 def git(arg):
  return subprocess.run(['git','-C',str(root),'rev-parse',arg],capture_output=True,check=True,timeout=5,text=True).stdout.strip()
 identity=validate_identity152(os.environ,git('HEAD'),git('HEAD^{tree}'))
 # Checkout immutable source with no untracked/modified executable inputs.
 status=subprocess.run(['git','-C',str(root),'status','--porcelain','--untracked-files=all'],capture_output=True,check=True,timeout=5,text=True)
 if status.stdout:raise InvalidData('DIRTY_NATIVE_SOURCE152')
 return identity


class GitHubWitness152:
 """Concrete read-only provider route; no caller-provided HTTP or CAS callback."""
 def __init__(self):self.calls=0;self.token=os.environ.get('GITHUB_TOKEN','')
 def _get(self,path):
  if not path.startswith('/repos/'+REPO+'/git/') or self.calls>=12:raise InvalidData('WITNESS_READ_BOUND152')
  self.calls+=1;c=http.client.HTTPSConnection('api.github.com',timeout=5,context=ssl.create_default_context())
  headers={'Accept':'application/vnd.github+json','User-Agent':'PayProof152','X-GitHub-Api-Version':'2022-11-28'}
  if self.token:headers['Authorization']='Bearer '+self.token
  try:
   c.request('GET',path,headers=headers);r=c.getresponse();raw=r.read(1048577)
   if r.status!=200 or len(raw)>1048576:raise InvalidData('WITNESS_PROVIDER_READ152')
   return json.loads(raw)
  finally:c.close()
 def read(self,identity):
  p='/repos/'+REPO+'/git/';ref=self._get(p+'ref/'+REF);head=ref['object']['sha']
  if ref.get('ref')!='refs/'+REF or ref['object'].get('type')!='commit' or not re.fullmatch('[a-f0-9]{40}',head):raise InvalidData('WITNESS_REF152')
  commit=self._get(p+'commits/'+head)
  if commit.get('sha')!=head or [v['sha'] for v in commit.get('parents',[])]!=[identity['head']]:raise InvalidData('WITNESS_PARENT152')
  tree=self._get(p+'trees/'+commit['tree']['sha'])
  rows=[r for r in tree.get('tree',[]) if r.get('path')==PATH and r.get('mode')=='100644' and r.get('type')=='blob']
  if len(rows)!=1 or tree.get('truncated'):raise InvalidData('WITNESS_TREE152')
  blob=self._get(p+'blobs/'+rows[0]['sha']);raw=base64.b64decode(blob['content'],validate=False)
  if len(raw)>32768 or hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=rows[0]['sha']:raise InvalidData('WITNESS_BLOB152')
  # This immutable create-only witness branch must still identify the same commit.
  if self._get(p+'ref/'+REF)['object']['sha']!=head:raise InvalidData('WITNESS_MOVED152')
  return _json(raw),digest(raw),head


def validate_batch152(w,identity,now):
 if not isinstance(w,dict) or w.get('schema')!='PAYPROOF_MASTER_EXTERNAL_BATCH152' or w.get('state')!='CONSUMED':raise InvalidData('EXTERNAL_BATCH_STATE152')
 if w.get('identity')!=identity or w.get('app_sha256')!=APP:raise InvalidData('EXTERNAL_BATCH_BINDING152')
 if w.get('operations')!=CAPS or w.get('fake_usd')!='1.00' or w.get('real_usd')!='0.00':raise InvalidData('EXTERNAL_BATCH_SCOPE152')
 if not re.fullmatch('P151-[A-Z0-9-]{1,24}',w.get('once_prefix','')):raise InvalidData('BATCH_ONCE_PREFIX152')
 require_url(w.get('listener_url',''))
 if w.get('dynamic_targets')!='ONLY_IDS_RETURNED_BY_THIS_CHAIN_CREATE_AND_SUBSCRIPTION':raise InvalidData('DERIVED_TARGET_SCOPE152')
 nb=w.get('not_before');ex=w.get('expires_at')
 if type(nb) not in (int,float) or type(ex) not in (int,float) or not nb<=now<ex or not 0<ex-nb<=600:raise InvalidData('EXTERNAL_BATCH_EXPIRY152')
 cp=w.get('master_checkpoint',{})
 if cp.get('stable_id')!='libfile_382af1e4da2481918fc68e272db49927' or type(cp.get('version')) is not int or cp['version']<=510 or not all(re.fullmatch('[a-f0-9]{64}',cp.get(k,'')) for k in ('raw_sha256','self_sha256')):raise InvalidData('REAL_MASTER_RECEIPT_REFERENCE152')
 if w.get('independent_admission')!='EXACT_NATIVE152_ADMISSION_REQUIRED' or w.get('cost_gate')!='TOTAL_INCREMENTAL_ZERO_PROVEN':raise InvalidData('EXACT_NATIVE_ADMISSION152')
 return w


class NativePorts152:
 """Concrete GitHub-owned custody + external preconsumed batch/local once slots.

 Not a new vault, issuer, signing key, scheduler or remote CAS API. Activation
 requires a prospective review of this batch semantic, not legacy151 acceptance.
 """
 def __init__(self,root,ledger_path):
  if not NATIVE152_ENABLED or ACTIVATION_ADMISSION152!='AUDITOR_NATIVE152_EFFECT_ADMISSION':raise InvalidData('PRIVATE_NATIVE152_NOT_ADMITTED')
  self.root=pathlib.Path(root);self.identity=actual_identity152(root)
  self.witness,self.batch_digest,self.witness_commit=GitHubWitness152().read(self.identity)
  validate_batch152(self.witness,self.identity,time.time());self.path=pathlib.Path(ledger_path)
  if self.path.parent.stat().st_mode&0o077:raise InvalidData('PRIVATE_LOCAL_SLOT_DIRECTORY152')
  fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600);os.close(fd)
  with sqlite3.connect(self.path) as db:db.execute('CREATE TABLE slots (key TEXT PRIMARY KEY, metadata TEXT NOT NULL)')
  self.released=False
 def current_source(self):
  i=actual_identity152(self.root)
  if i!=self.identity:raise InvalidData('PROVIDER_DRIFT152')
  validate_batch152(self.witness,i,time.time());return digest(canonical(i).encode())
 def current_caller(self):self.current_source();return 'github:'+REPO+':'+self.identity['run_id']+':1'
 def release(self):
  source=self.current_source();caller=self.current_caller()
  if self.released:raise InvalidData('CUSTODY_ALREADY_RELEASED152')
  self.released=True
  client=os.environ.pop('PAYPROOF_PAYPAL_SANDBOX_CLIENT_ID','');secret=os.environ.pop('PAYPROOF_PAYPAL_SANDBOX_CLIENT_SECRET','')
  if not client or not secret or digest(client.encode())!=APP:raise InvalidData('EXISTING_APP_CUSTODY152')
  w=self.witness;g=Grant151(PROFILE,APP,source,caller,w['not_before'],w['expires_at'],w['once_prefix'],w['listener_url'],False,_NATIVE);g.validate(source,caller,time.time())
  return g,(client,secret)
 def reserve_and_readback(self,key,metadata):
  self.current_source()
  expected=self.witness['once_prefix']+':'+metadata.get('operation','')
  if key!=expected or metadata.get('operation') not in CAPS or metadata.get('source_sha256')!=self.current_source() or metadata.get('caller')!=self.current_caller() or metadata.get('app_sha256')!=APP or metadata.get('expires_at')!=self.witness['expires_at'] or metadata.get('fake_usd')!='1.00' or metadata.get('real_usd')!='0.00':raise InvalidData('DERIVED_LOCAL_SLOT_SCOPE152')
  with sqlite3.connect(self.path) as db:
   db.execute('BEGIN IMMEDIATE')
   try:db.execute('INSERT INTO slots VALUES (?,?)',(key,canonical(metadata)))
   except sqlite3.IntegrityError:raise InvalidData('LOCAL_SLOT_CONSUMED152') from None
  with sqlite3.connect(self.path) as db:readback=json.loads(db.execute('SELECT metadata FROM slots WHERE key=?',(key,)).fetchone()[0])
  return {'kind':'EXTERNAL_BATCH_CONSUMED_LOCAL_SLOT152','external_batch_sha256':self.batch_digest,'witness_commit':self.witness_commit,'key':key,'state':'CONSUMED','local_metadata':readback}
 def matches_receipt(self,r,key,metadata):
  return r=={'kind':'EXTERNAL_BATCH_CONSUMED_LOCAL_SLOT152','external_batch_sha256':self.batch_digest,'witness_commit':self.witness_commit,'key':key,'state':'CONSUMED','local_metadata':metadata}


@dataclass(frozen=True,repr=False)
class ProviderEvidence152:
 """Same-process scoped capability only; never a host/V1 signing attestation."""
 engine:object
 def require(self):
  e=self.engine;e.require()
  if e.grant.test_only or type(e.ledger) is not NativePorts152 or not e.webhook_id or not e.client or not e.token:raise InvalidData('PROVIDER_EVIDENCE_SCOPE152')


@dataclass(frozen=True,repr=False)
class SyntheticProviderEvidence152(ProviderEvidence152):
 """Explicit contract fixture; cannot grant network/provider custody."""
 def require(self):
  from .sandbox_chain151 import SyntheticTransport151
  e=self.engine;e.require()
  if not e.grant.test_only or type(e.transport) is not SyntheticTransport151 or not e.webhook_id or not e.client or not e.token:raise InvalidData('SYNTHETIC_PROVIDER_ONLY152')


def provider_webhook152(engine,store,headers,raw):
 cap=engine.evidence_context
 if type(cap) not in (ProviderEvidence152,SyntheticProviderEvidence152) or cap.engine is not engine:raise InvalidData('EXACT_EVIDENCE_CAPABILITY152')
 cap.require();event=json.loads(raw);h={k.lower():v for k,v in headers.items()}
 mapping={'auth_algo':'paypal-auth-algo','cert_url':'paypal-cert-url','transmission_id':'paypal-transmission-id','transmission_sig':'paypal-transmission-sig','transmission_time':'paypal-transmission-time'}
 if any(not isinstance(h.get(v),str) or not h[v] or len(h[v])>4096 for v in mapping.values()):raise InvalidData('SIGNED_HEADERS152')
 envelope={k:h[v] for k,v in mapping.items()};envelope['webhook_id']=engine.webhook_id
 body=json.dumps(envelope).encode()[:-1]+b', "webhook_event": '+raw+b'}'
 engine._active_raw=raw
 try:
  reply=engine.effect('verify','POST','/v1/notifications/verify-webhook-signature',body)
  verified=isinstance(reply,dict) and reply.get('verification_status')=='SUCCESS'
 finally:engine._active_raw=None
 if not verified:raise InvalidData('AUTHENTICITY_NOT_VERIFIED152')
 result=store.event(event,True,lambda order_id:engine.effect('event_read','GET','/v2/checkout/orders/'+order_id),'SANDBOX_CONTRACT_TEST' if engine.grant.test_only else 'PAYPAL_SANDBOX_PROVIDER152')
 from payproof.service import annotated_order,explanation_request
 from payproof.core import explain
 order=result['order'];view={'mode':'SANDBOX_CONTRACT_TEST' if engine.grant.test_only else 'PAYPAL_SANDBOX','order':annotated_order(order),'explanation':explain(order),'explanation_request':explanation_request(order),'live_ai':False,'payment_mutation_actions':[]}
 return {'disposition':result['disposition'],'view':view}
