"""One private native chain. No provider calls before actual run-bound witness.

Public workflow logging is sanitized. Approval URL, event bytes and signature
headers only traverse the authenticated private bridge. No PayPal secret export.
"""
import argparse,json,os,pathlib,stat,time
from payproof.core import Store
from .sandbox_chain151 import APP,InvalidData,UnknownResult,digest
from .sandbox_native152 import GitHubWitness152,actual_identity152,validate_batch152
from .sandbox_bridge153 import Scope153,PRIVATE,origin153
from .sandbox_bridge_client153 import BridgeClient153,FixedBridgeHTTPS153

class WitnessAbsent153(Exception):pass
class PollWitness153(GitHubWitness152):
 def _get(self,path):
  # Fixed ref404 is absence before Master create-only publication, not a retry
  # authorization for the job, grant or any PayPal operation.
  import http.client,ssl,json
  if path!='/repos/Elinfiny/PayProof/git/ref/heads/payproof-sandbox152-once':return super()._get(path)
  self.calls+=1
  if self.calls>12:raise InvalidData('WITNESS_CALL_BOUND153')
  c=http.client.HTTPSConnection('api.github.com',timeout=5,context=ssl.create_default_context())
  headers={'Accept':'application/vnd.github+json','User-Agent':'PayProof153'}
  if self.token:headers['Authorization']='Bearer '+self.token
  try:
   c.request('GET',path,headers=headers);r=c.getresponse();b=r.read(1048577)
   if r.status==404:raise WitnessAbsent153()
   if r.status!=200 or len(b)>1048576:raise UnknownResult('WITNESS_READ_UNKNOWN153')
   return json.loads(b)
  finally:c.close()

def await_witness153(root,*,clock=time.time,sleeper=time.sleep,reader_class=PollWitness153):
 from . import sandbox_bridge153
 if not sandbox_bridge153.LIVE153:raise InvalidData('NATIVE153_INACTIVE')
 if reader_class is not PollWitness153:raise InvalidData('NO_NATIVE_READER_CALLBACK153')
 identity=actual_identity152(root);deadline=clock()+120
 for n in range(24):
  if clock()>=deadline:raise InvalidData('WITNESS_WAIT_EXPIRED153')
  try:w,_,_=reader_class().read(identity)
  except WitnessAbsent153:
   if n<23:sleeper(min(5,max(0,deadline-clock())));continue
   raise InvalidData('NO_WITNESS_NO_CREDENTIAL_RELEASE153') from None
  validate_batch152(w,identity,clock());return w
 raise InvalidData('NO_WITNESS153')

def run_chain153(engine,bridge,store,*,approval_handoff=None):
 """Production invokes no callback; test-only callback models native buyer UI."""
 from .sandbox_entry151 import acquire152
 from .sandbox_bridge153 import WEBHOOK
 if engine.grant.listener_url!=bridge.scope.origin+WEBHOOK or engine.grant.app_sha256!=bridge.scope.app_sha256:raise InvalidData('EXACT_ENGINE_BRIDGE153')
 if approval_handoff is not None and not engine.grant.test_only:raise InvalidData('NO_NATIVE_BUYER_CALLBACK153')
 state='REFUSED';event_sha=None;cleanup='NOT_COMPLETED';original=None
 try:
  ready=bridge.readiness()
  if ready['run_id'] is None:bridge.bootstrap()
  elif ready['run_id']!=bridge.run_id:raise InvalidData('BOUND_RUN153')
  bridge.webhook(engine.webhook_id)
  # No event delivery needs capture_id yet; strict original-order filter is ready
  # before handing the authentic private Sandbox approval URL to the browser.
  approval=acquire152(engine,store);bridge.order(engine.order,approval);approval=None
  if approval_handoff is not None:approval_handoff(bridge)
  bridge.await_buyer()
  engine.capture_approved();engine.read_final()
  headers,raw=bridge.poll_event();event_sha=digest(raw)
  result=engine.webhook(store,headers,raw);raw=None;headers=None
  if not engine.verified_complete:raise InvalidData('NO_VERIFIED_COMPLETION153')
  if engine.created_subscription:engine.cleanup_subscription();cleanup='NEW_SUBSCRIPTION_DELETED'
  else:cleanup='PRESERVED_EXISTING'
  state='COMPLETED';return result
 except Exception as e:
  original=e;state='UNKNOWN' if isinstance(e,UnknownResult) or engine.first_unknown or bridge.first_unknown else 'REFUSED'
  if state=='UNKNOWN':cleanup='UNKNOWN_NO_PROVIDER_CLEANUP'
  raise
 finally:
  report={'state':state,'event_sha256':event_sha,'order_sha256':digest(engine.order.encode()) if engine.order else None,'capture_sha256':digest(engine.capture_id.encode()) if engine.capture_id else None,'first_unknown':'NATIVE_CHAIN_UNKNOWN153' if engine.first_unknown else 'BRIDGE_UNKNOWN153' if bridge.first_unknown else None,'cleanup':cleanup}
  try:
   if not bridge.first_unknown:
    # Exclude OAuth/subscription replies; never copy any actual credential value.
    for op,status,body in engine.private_returns:
     if op not in ('order_create','capture','final_read','verify','event_read'):continue
     if any(value and value.encode() in body for value in (engine.client,engine.secret,engine.token)):raise InvalidData('PROVIDER_SECRET_IN_ORIGINAL_NO_EXPORT153')
     bridge.original(op,status,body)
    bridge.report(report)
  except Exception:
   if original is None:original=UnknownResult('REPORT_RETENTION_UNKNOWN153')
  finally:
   # Keep the bounded private report readable until Master saves its actual
   # receipt, then explicit close or absolute capability expiry purges raw/token.
   engine.close();bridge.close()
  if original is not None and state=='COMPLETED':raise original

def private_runtime153(parent):
 # Create one private run directory; never chmod shared RUNNER_TEMP or reuse it.
 directory=pathlib.Path(parent)/'payproof153-once'
 directory.mkdir(mode=0o700,exist_ok=False)
 current=directory.lstat()
 if not stat.S_ISDIR(current.st_mode) or current.st_uid!=os.getuid() or current.st_mode&0o077:raise InvalidData('PRIVATE_RUNTIME_DIRECTORY153')
 return directory

def run_native153(root):
 from . import sandbox_bridge153
 if not sandbox_bridge153.LIVE153:raise InvalidData('NATIVE153_INACTIVE')
 # First workflow step already finished preflight/witness without PayPal env.
 # Revalidate the same immutable actual run-bound witness before secret release.
 from .sandbox_native152 import NativePorts152
 from .sandbox_chain151 import Chain151,FixedSandboxNetwork151
 from .sandbox_native152 import ProviderEvidence152
 runtime=private_runtime153(os.environ['RUNNER_TEMP'])
 ports=NativePorts152(root,runtime/'payproof153-local-slots.sqlite')
 w=ports.witness;cfg=w['bridge153'];token=os.environ.pop('PAYPROOF_BRIDGE_TOKEN','')
 scope=Scope153(ports.identity['head'],cfg['session'],APP,origin153(cfg['origin']),cfg['service_id'],cfg['issued_at'],cfg['expires_at'],False)
 scope.require(time.time())
 from .sandbox_bridge153 import WEBHOOK
 if w['listener_url']!=scope.origin+WEBHOOK:raise InvalidData('EXACT_WITNESS_LISTENER153')
 if scope.expires_at!=w['expires_at'] or scope.issued_at>w['not_before'] or cfg.get('buyer_preflight')!='OWNER_SANDBOX_BUYER_AND_ADMITTED_BROWSER_ROUTE_READY':raise InvalidData('CRITICAL_PREREQUISITES153')
 bridge=BridgeClient153(scope,token,ports.identity['run_id'],FixedBridgeHTTPS153(scope));token=None
 ready=bridge.readiness()
 if ready['run_id'] is not None:raise InvalidData('FRESH_PRIVATE_BRIDGE153')
 bridge.bootstrap() # actual private service/source/run/token before PayPal credentials
 grant,credentials=ports.release();engine=Chain151(grant,FixedSandboxNetwork151(grant),ports,source_sha256=ports.current_source(),caller=ports.current_caller())
 try:
  engine.credentials(*credentials);credentials=None;engine.oauth();engine.subscription();engine.bind_evidence(ProviderEvidence152(engine))
  store=Store(runtime/'payproof153-evidence.sqlite')
  result=run_chain153(engine,bridge,store)
  print(json.dumps({'schema':'PAYPROOF153_NATIVE_SANITIZED_RESULT','state':'COMPLETED','source':scope.source,'run_id':ports.identity['run_id'],'bridge':bridge.export(),'engine':engine.export(),'event_sha256':result['raw_sha256'],'original_payloads_exported':False},sort_keys=True))
 finally:
  if not engine.closed:engine.close()
  bridge.close()

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('phase',choices=['preflight','execute']);parser.add_argument('--root',default='.');a=parser.parse_args()
 if a.phase=='preflight':await_witness153(a.root)
 else:run_native153(a.root)
