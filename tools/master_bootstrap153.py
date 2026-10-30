"""Callable data preparation for the EXISTING sole Master's native tools.

No CAS endpoint, writer, broker or grant issuer is invented. prepare_checkpoint
produces bytes only; actual expected-version Library replacement + full readback
remain separate real calls of the existing Master before witness publication.
"""
import copy,datetime,hashlib,json,re
from .sandbox_bridge153 import Scope153,APP,WEBHOOK,InvalidData
from .sandbox_chain151 import CAPS,canonical

MASTER='libfile_382af1e4da2481918fc68e272db49927'
POLICY='libfile_6f69ae483b088191a1fffefca617bbd5'
def control_canonical153(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def digest(b):return hashlib.sha256(b).hexdigest()
def _cp(raw):
 v=json.loads(raw);expected=v['integrity']['canonical_json_sha256'];c=copy.deepcopy(v);c['integrity']['canonical_json_sha256']=None
 if digest(control_canonical153(c).encode())!=expected:raise InvalidData('MASTER_SELF153')
 return v

def actual_run153(run,head):
 expected={'repository_id':1419908202,'actor_id':273768139,'run_attempt':1,'event':'workflow_dispatch','head_sha':head,'head_branch':'main','workflow_path':'.github/workflows/payproof-sandbox-chain151.yml'}
 if any(run.get(k)!=v for k,v in expected.items()) or type(run.get('id')) is not int or run['id']<=0 or run.get('status') not in ('queued','in_progress'):raise InvalidData('ACTUAL_PROVIDER_RUN153')
 return {'head':head,'tree':run['tree'],'run_id':str(run['id']),'attempt':1,'repository_id':'1419908202','actor_id':'273768139'}

def prepare_checkpoint153(current_raw,*,stage,session,source_head,source_tree,source_admission_sha256,actual_run=None,scope=None,buyer_receipt=None,now=None,output_path=None):
 v=_cp(current_raw);before=v['revision'];now=now or datetime.datetime.now(datetime.timezone.utc).isoformat()
 if stage not in ('JOB_INTENT','JOB_CONSUMED','BATCH_INTENT','BATCH_CONSUMED'):raise InvalidData('BOOTSTRAP_STAGE153')
 if not re.fullmatch('[a-f0-9]{40}',source_head) or not re.fullmatch('[a-f0-9]{40}',source_tree) or not re.fullmatch('[a-f0-9]{64}',source_admission_sha256):raise InvalidData('EXACT_SOURCE_ADMISSION153')
 if not re.fullmatch('P153-[A-Z0-9-]{1,32}',session):raise InvalidData('SESSION153')
 boundary=v['operation']['effect_replay_boundary'];boundary=json.loads(boundary) if isinstance(boundary,str) else boundary
 own=boundary.setdefault('PayProof153',{});ledger=own.setdefault('native153',{});prior=ledger.get('stage')
 wanted={'JOB_INTENT':None,'JOB_CONSUMED':'JOB_INTENT','BATCH_INTENT':'JOB_CONSUMED','BATCH_CONSUMED':'BATCH_INTENT'}
 if prior!=wanted[stage]:raise InvalidData('EXTERNAL_ONCE_STAGE153')
 if prior is not None and (ledger['session']!=session or ledger['source_head']!=source_head or ledger['source_tree']!=source_tree or ledger['source_admission_sha256']!=source_admission_sha256):raise InvalidData('EXTERNAL_ONCE_BINDING153')
 ledger.update(stage=stage,session=session,source_head=source_head,source_tree=source_tree,source_admission_sha256=source_admission_sha256,job_dispatch_cap=1,PayPal_calls_before_batch_consumed=0)
 if stage.startswith('BATCH'):
  if type(scope) is not Scope153 or scope.test_only or scope.source!=source_head or not buyer_receipt or buyer_receipt.get('state')!='OWNER_SANDBOX_BUYER_AND_ADMITTED_BROWSER_ROUTE_READY':raise InvalidData('QUALIFIED_PRIVATE_SCOPE_AND_BUYER153')
  clock=datetime.datetime.fromisoformat(now).timestamp();scope.require(clock)
  if scope.expires_at-clock<300:raise InvalidData('INSUFFICIENT_CRITICAL_WINDOW153')
  identity=actual_run153(actual_run,source_head)
  if identity['tree']!=source_tree:raise InvalidData('ACTUAL_RUN_TREE153')
  ledger.update(identity=identity,scope=scope.public(),issued_at=scope.issued_at,operations=CAPS.copy(),buyer_receipt=buyer_receipt.copy(),state='CONSUMED' if stage=='BATCH_CONSUMED' else 'INTENT',fake_usd='1.00',real_usd='0.00')
 v['operation']['effect_replay_boundary']=canonical(boundary);v['revision']+=1
 for k in ('epoch_checkpoint_counter','material_checkpoints'):v['guard'][k]+=1
 v['created_at_utc']=now;v['previous_checkpoint_file_sha256']=digest(current_raw);v['integrity']['canonical_json_sha256']=None;v['integrity']['canonical_json_sha256']=digest(control_canonical153(v).encode())
 raw=(json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
 if output_path is not None:
  import os,pathlib
  path=pathlib.Path(output_path)
  if path.parent.stat().st_mode&0o077:raise InvalidData('PRIVATE_MASTER_PREPARATION_DIRECTORY153')
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'wb') as f:f.write(raw)
 return {'checkpoint_bytes':raw,'native_tool':'Existing Library replace_library_file','native_tool_arguments':{'library_file_id':MASTER,'expected_current_version':before,'file':str(output_path) if output_path is not None else None},'state_claim':'PREPARED_NOT_APPLIED; not a CAS/readback receipt','forbidden':'No dispatch before real JOB_CONSUMED fullbyte readback, no witness before real BATCH_CONSUMED fullbyte readback'}

def witness_from_readback153(actual_readback_raw,expected_version):
 v=_cp(actual_readback_raw)
 if v['revision']!=expected_version:raise InvalidData('ACTUAL_READBACK_VERSION153')
 b=json.loads(v['operation']['effect_replay_boundary']);l=b['PayProof153']['native153']
 if l.get('stage')!='BATCH_CONSUMED' or l.get('state')!='CONSUMED':raise InvalidData('ACTUAL_BATCH_CONSUMED153')
 scope=l['scope'];ident=l['identity']
 return {'schema':'PAYPROOF_MASTER_EXTERNAL_BATCH152','state':'CONSUMED','identity':ident,'app_sha256':APP,'operations':l['operations'],'fake_usd':'1.00','real_usd':'0.00','master_checkpoint':{'stable_id':MASTER,'version':expected_version,'raw_sha256':digest(actual_readback_raw),'self_sha256':v['integrity']['canonical_json_sha256']},'once_prefix':'P151-'+l['session'][5:][:24],'dynamic_targets':'ONLY_IDS_RETURNED_BY_THIS_CHAIN_CREATE_AND_SUBSCRIPTION','not_before':datetime.datetime.fromisoformat(v['created_at_utc']).timestamp(),'expires_at':scope['expires_at'],'listener_url':scope['origin']+WEBHOOK,'independent_admission':'EXACT_NATIVE152_ADMISSION_REQUIRED','cost_gate':'TOTAL_INCREMENTAL_ZERO_PROVEN','source_admission_sha256':l['source_admission_sha256'],'bridge153':{'session':scope['session'],'origin':scope['origin'],'service_id':scope['service_id'],'issued_at':l['issued_at'],'expires_at':scope['expires_at'],'buyer_preflight':l['buyer_receipt']['state']}}
