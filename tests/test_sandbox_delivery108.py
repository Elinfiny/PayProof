"""One NEW inert108 group; no old107 scenarios, real ENV or provider."""
from dataclasses import replace
from datetime import datetime, timezone, timedelta
import hashlib,json,sqlite3,tempfile
from pathlib import Path
from unittest.mock import patch
from payproof.admission import (OperatorConfiguration107,OperatorProfile107,
    _open_operator_session107,OwnedDispatch108,_DISPATCH_SYNTHETIC108)
from payproof.core import Store,canonical,InvalidData,UnknownResult
from payproof.local_ai_view import enable_local_assistance
from tools.sandbox_delivery107 import (source_digest107,OnceJournal107,
    open_github_operator108,preflight_github108,run_github_operator108,
    OperatorOrderReader107,reconcile_operator107)

CLIENT='PUBLIC-FAKE108-CLIENT';SECRET='PUBLIC-FAKE108-SECRET';TOKEN='PUBLIC-FAKE108-TOKEN'

def emit(number,facts):
    print(json.dumps({'record':'ORIGINAL_PUBLIC_SYNTHETIC108','scenario':number,'facts':facts},sort_keys=True),flush=True)

def refused(call):
    try:call()
    except (InvalidData,UnknownResult):return True
    return False

def config(now):
    return OperatorConfiguration107(OperatorProfile107.SYNTHETIC_FIXTURE,
        source_digest107(),'1'*40,'2'*40,'SYNTHETIC_OPERATOR108','PUBLIC_FIXTURE108',
        hashlib.sha256(CLIENT.encode()).hexdigest(),'SYNTHETIC108','10.00','EUR',
        '3'*64,'ONCE108',now-timedelta(seconds=1),now+timedelta(seconds=119))

def dispatch(cfg):
    record={'schema':'PAYPROOF_OWN_CONDITIONAL_DISPATCH108',
        'producer':'PayPal V1 conditional own journal','stable_effect_key':hashlib.sha256(canonical(['PayProof','sandbox','orders:read',cfg.client_id_sha256,cfg.order_id]).encode()).hexdigest(),
        'admission_id':'SYNTHETIC_ADMISSION108','intent_version':1,'consumed_version':2,
        'intent_sha256':'4'*64,'consumed_sha256':'5'*64,'previous_sha256':'4'*64,
        'source_commit':cfg.source_commit,'source_tree':cfg.source_tree,'source_sha256':cfg.source_sha256,
        'workflow_sha256':'6'*64,'workflow_path':'.github/workflows/payproof-sandbox-delivery108.yml',
        'repository_id':'1419908202','owner_id':'273768139','actor_id':'273768139',
        'run_id':'108','job_id':'1081','job_name':'sandbox_read','attempt':'1',
        'ref':'refs/heads/main','event':'workflow_dispatch','registered_lineage_sha256':cfg.order_lineage_sha256,
        'client_id_sha256':cfg.client_id_sha256,'order_id_sha256':hashlib.sha256(cfg.order_id.encode()).hexdigest(),
        'expected_amount':cfg.amount,'expected_currency':cfg.currency,
        'operator_allocation':cfg.operator_allocation,'credential_provenance':cfg.credential_provenance}
    admission=OwnedDispatch108(canonical(record).encode(),_DISPATCH_SYNTHETIC108,'108','1081')
    keys=('repository_id','owner_id','actor_id','attempt','ref','event','run_id','job_id','job_name','workflow_path','source_commit','source_tree','source_sha256','workflow_sha256')
    return admission,{k:record[k] for k in keys}

def group():
    now=datetime.now(timezone.utc);cfg=config(now);results=[];reads=[]
    def pair():reads.extend(['PAYPROOF_PAYPAL_SANDBOX_CLIENT_ID','PAYPROOF_PAYPAL_SANDBOX_CLIENT_SECRET']);return CLIENT,SECRET
    with tempfile.TemporaryDirectory(prefix='payproof-inert108-') as td:
        root=Path(td)
        with patch('os.environ',{}),patch('os.getenv',side_effect=AssertionError('NO_REAL_ENV108')),patch('urllib.request.build_opener',side_effect=AssertionError('NO_REAL_HTTP108')),patch('getpass.getpass',side_effect=AssertionError('NO_TTY108')):
            journal=OnceJournal107(root/'stable.sqlite')
            first=_open_operator_session107(cfg,actual_source=source_digest107,credential_reader=pair,reserve_once=journal.reserve,clock=lambda:now,profile=cfg.profile,monotonic=lambda:0)
            first.close();before=len(reads)
            changed=replace(cfg,once_id='CHANGED_ONCE108',order_lineage_sha256='7'*64,source_commit='8'*40,source_tree='9'*40)
            blocked=refused(lambda:_open_operator_session107(changed,actual_source=source_digest107,credential_reader=pair,reserve_once=journal.reserve,clock=lambda:now,profile=changed.profile,monotonic=lambda:0))
            with sqlite3.connect(journal.path) as db:
                count=db.execute('SELECT count(*) FROM operator_once107').fetchone()[0]
                metadata=json.loads(db.execute('SELECT metadata FROM operator_metadata108').fetchone()[0])
            emit(1,{'changed_lineage_once_source_refused':blocked,'additional_credential_reads':len(reads)-before,'stable_record_count':count,'original_lineage_preserved':metadata['order_lineage_sha256']==cfg.order_lineage_sha256,'external_calls':0})
            assert blocked and len(reads)==before and count==1 and metadata['order_lineage_sha256']==cfg.order_lineage_sha256
            results.append('PASS')

            admission,actual=dispatch(cfg);before=len(reads)
            checks=[refused(lambda:open_github_operator108()),
                refused(lambda:open_github_operator108(replace(cfg,profile=OperatorProfile107.GITHUB_OWNER_MANAGED_SANDBOX),journal=OnceJournal107(root/'missing.sqlite'))),
                refused(lambda:preflight_github108(cfg,admission={'consumed':True},synthetic_actual=actual)),
                refused(lambda:preflight_github108(replace(cfg,source_sha256='0'*64),admission=admission,synthetic_actual=actual)),
                refused(lambda:preflight_github108(cfg,admission=admission,synthetic_actual=dict(actual,actor_id='999'))),
                refused(lambda:preflight_github108(replace(cfg,profile=OperatorProfile107.GITHUB_OWNER_MANAGED_SANDBOX),admission=admission)),
                refused(lambda:OwnedDispatch108(admission._record,object(),'108','1081'))]
            emit(2,{'missing_source_caller_profile_external_binding_refused':checks,'additional_credential_reads':len(reads)-before,'actual_native_evidence_created':False,'external_calls':0})
            assert all(checks) and len(reads)==before
            results.append('PASS')

            mono=[0.0];reader=None;capture_probe=[]
            def monotonic():
                if mono[0]>120 and reader is not None:capture_probe.append(bool(reader._private_returns))
                return mono[0]
            session=_open_operator_session107(cfg,actual_source=source_digest107,credential_reader=pair,reserve_once=OnceJournal107(root/'late.sqlite').reserve,clock=lambda:now,profile=cfg.profile,monotonic=monotonic)
            def late(method,path,headers,body):mono[0]=200;return {'access_token':TOKEN}
            reader=OperatorOrderReader107(session,fake_transport=late);store=Store(root/'late-orders.sqlite');store.register(cfg.order_id,cfg.amount,cfg.currency)
            cleanup=[]
            try:
                report=reconcile_operator107(store,reader);first_code,first_stage=reader.first_cause,reader.first_stage
                blocked=refused(lambda:reader.get_order(cfg.order_id))
                facts={'receipt':report,'private_original_captured_before_guard':all(capture_probe) and bool(capture_probe),'private_stages':[s for s,v in reader._private_returns],
                    'first_code':first_code,'first_stage':first_stage,'same_first_cause':(reader.first_cause,reader.first_stage)==(first_code,first_stage),'next_call_refused':blocked,'calls':reader.calls,'cleanup':cleanup}
            finally:
                try:reader.close()
                except Exception:cleanup.append('CLOSE108')
            facts.update(private_returns_released=not reader._private_returns,session_closed=session._closed)
            emit(3,facts)
            assert facts['private_original_captured_before_guard'] and first_code=='OPERATOR_MONOTONIC_EXPIRED108' and first_stage=='POST_RETURN'
            assert report['state']=='UNKNOWN' and blocked and reader.calls==1 and facts['same_first_cause'] and facts['private_returns_released'] and not cleanup
            results.append('PASS')

            admission,actual=dispatch(cfg);calls=[];before=len(reads)
            def provider(method,path,headers,body):
                calls.append([method,path])
                if path=='/v1/oauth2/token':return {'access_token':TOKEN}
                return {'id':cfg.order_id,'status':'APPROVED','update_time':(now-timedelta(seconds=2)).isoformat(),
                    'purchase_units':[{'amount':{'value':cfg.amount,'currency_code':cfg.currency}}],
                    'payer':{'untrusted_text':SECRET}}
            store=Store(root/'valid-orders.sqlite');store.register(cfg.order_id,cfg.amount,cfg.currency);handle=enable_local_assistance()
            report=run_github_operator108(cfg,store=store,journal=OnceJournal107(root/'valid.sqlite'),admission=admission,
                synthetic_actual=actual,fake_credential_reader=pair,fake_transport=provider,clock=lambda:now,monotonic=lambda:0,assistance=handle)
            with store.connect() as db:effects=db.execute('SELECT count(*) FROM effects').fetchone()[0]
            sanitized=all(v not in json.dumps(report) for v in (CLIENT,SECRET,TOKEN))
            emit(4,{'orchestration':report,'fake_calls':calls,'exact_credential_field_reads':reads[before:],'effects':effects,'model_status':handle.status,'secret_free':sanitized,'actual_provider':False,'TTY_calls':0})
            assert report['primary'] is None and report['cleanup']==[] and report['receipt']['state']=='APPROVED'
            assert report['receipt']['synthetic'] is True and report['receipt']['actual_paypal'] is False and effects==0
            assert len(calls)==2 and sanitized and handle.status=='READY' and len(reads)-before==2
            assert all(report['lifecycle'].values()) and report['receipt']['local_assistance']['financial_authority'] is False
            results.append('PASS')
    return results

if __name__=='__main__':
    primary=None;results=[]
    try:results=group()
    except Exception as exc:primary={'code':'INERT108_'+type(exc).__name__,'stage':'GROUP'}
    print(json.dumps({'record':'INERT108_TERMINAL','scenario_results':results,'primary':primary,'cleanup':[],
        'actual_credentials':False,'actual_provider':False,'old107_replayed':False},sort_keys=True),flush=True)
    raise SystemExit(0 if primary is None and len(results)==4 else 1)
