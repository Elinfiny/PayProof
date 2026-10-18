"""One new inert109 group, three cases; no old groups or model training."""
from dataclasses import replace
from datetime import datetime,timezone,timedelta
import hashlib,json,tempfile,pickle
from pathlib import Path
from unittest.mock import patch
from payproof.admission import OperatorConfiguration107,OperatorProfile107,OwnedDispatch108,_DISPATCH_SYNTHETIC108
from payproof.core import Store,canonical,InvalidData,UnknownResult
from tools.sandbox_delivery107 import (source_digest107,OnceJournal107,
    _synthetic_workflow_launch109,preflight_owner_workflow109,open_owner_workflow109,run_owner_workflow109)

CLIENT='PUBLIC-FAKE109-CLIENT';SECRET='PUBLIC-FAKE109-SECRET';TOKEN='PUBLIC-FAKE109-TOKEN'
def emit(n,f):print(json.dumps({'record':'ORIGINAL_PUBLIC_SYNTHETIC109','scenario':n,'facts':f},sort_keys=True),flush=True)
def refused(call):
    try:call()
    except (InvalidData,UnknownResult,TypeError):return True
    return False

def inputs(now):
    cfg=OperatorConfiguration107(OperatorProfile107.SYNTHETIC_FIXTURE,source_digest107(),
        '1'*40,'2'*40,'SYNTHETIC_OPERATOR109','PUBLIC_FIXTURE109',hashlib.sha256(CLIENT.encode()).hexdigest(),
        'SYNTHETIC109','10.00','EUR','3'*64,'ONCE109',now-timedelta(seconds=1),now+timedelta(seconds=119))
    a={'schema':'PAYPROOF_PROVIDER_OWNER_WORKFLOW109','profile':'GITHUB_OWNER_WORKFLOW109',
        'admission_id':'SYNTHETIC109','intent_version':1,'consumed_version':2,'intent_sha256':'4'*64,'consumed_sha256':'5'*64,
        'stable_effect_key':hashlib.sha256(canonical(['PayProof','sandbox','orders:read',cfg.client_id_sha256,cfg.order_id]).encode()).hexdigest(),
        'repository':'Elinfiny/PayProof','repository_id':'1419908202','owner_id':'273768139','actor_id':'273768139',
        'ref':'refs/heads/main','event':'workflow_dispatch','attempt':'1','job_slug':'sandbox_read',
        'source_commit':cfg.source_commit,'source_tree':cfg.source_tree,'source_sha256':cfg.source_sha256,
        'workflow_path':'.github/workflows/payproof-sandbox-delivery108.yml','workflow_sha256':'6'*64,
        'client_id_sha256':cfg.client_id_sha256,'order_id_sha256':hashlib.sha256(cfg.order_id.encode()).hexdigest(),
        'amount':cfg.amount,'currency':cfg.currency,'order_lineage_sha256':cfg.order_lineage_sha256,
        'operator_allocation':cfg.operator_allocation,'credential_provenance':cfg.credential_provenance,
        'not_before':cfg.not_before.isoformat(),'expires_at':cfg.expires_at.isoformat(),'call_budget':2,'cash_usd':'0.00'}
    actual={k:a[k] for k in ('repository','repository_id','owner_id','actor_id','ref','event','attempt','job_slug','workflow_path','source_commit','source_tree','source_sha256','workflow_sha256')}
    actual.update(run_id='109',github_sha=cfg.source_commit,workflow_ref='Elinfiny/PayProof/'+a['workflow_path']+'@refs/heads/main',workflow_source_sha=cfg.source_commit)
    return cfg,a,actual

def group():
    now=datetime.now(timezone.utc);cfg,a,actual=inputs(now);reads=[];results=[]
    def pair():reads.extend(['PAYPROOF_PAYPAL_SANDBOX_CLIENT_ID','PAYPROOF_PAYPAL_SANDBOX_CLIENT_SECRET']);return CLIENT,SECRET
    with tempfile.TemporaryDirectory(prefix='payproof-inert109-') as td:
        root=Path(td)
        with patch('os.environ',{}),patch('os.getenv',side_effect=AssertionError('NO_REAL_ENV109')),patch('urllib.request.build_opener',side_effect=AssertionError('NO_REAL_HTTP109')),patch('getpass.getpass',side_effect=AssertionError('NO_TTY109')),patch('payproof.local_ai.fit',side_effect=AssertionError('NO_MODEL_RETRAIN109')):
            checks=[refused(lambda:open_owner_workflow109()),
                refused(lambda:open_owner_workflow109(cfg,a,journal=OnceJournal107(root/'missing.sqlite'),fake_credential_reader=pair)),
                refused(lambda:_synthetic_workflow_launch109(cfg,dict(a,source_sha256='0'*64),actual)),
                refused(lambda:_synthetic_workflow_launch109(cfg,a,dict(actual,actor_id='999'))),
                refused(lambda:_synthetic_workflow_launch109(cfg,dict(a,unexpected=True),actual)),
                refused(lambda:_synthetic_workflow_launch109(cfg,dict(a,admission_id='X'*1000),actual))]
            emit(1,{'missing_launch_source_caller_shape_bounds_refused':checks,'credential_reads':len(reads),'network_calls':0})
            assert all(checks) and not reads;results.append('PASS')

            launch=_synthetic_workflow_launch109(cfg,a,actual);native_cfg=replace(cfg,profile=OperatorProfile107.GITHUB_OWNER_WORKFLOW109)
            old=OwnedDispatch108(b'{}',_DISPATCH_SYNTHETIC108,'109','1091')
            checks=[refused(lambda:preflight_owner_workflow109(native_cfg,a,launch=launch)),
                refused(lambda:_synthetic_workflow_launch109(native_cfg,a,actual)),
                refused(lambda:preflight_owner_workflow109(cfg,a,launch=old)),
                refused(lambda:preflight_owner_workflow109(cfg,a,launch={'native':True})),
                refused(lambda:_synthetic_workflow_launch109(cfg,dict(a,run_id='999'),actual)),
                refused(lambda:_synthetic_workflow_launch109(cfg,dict(a,job_id='999'),actual)),
                refused(lambda:pickle.dumps(launch))]
            emit(2,{'synthetic_old_evidence_and_public_run_job_refused':checks,'credential_reads':len(reads),'native_launch_created':False,'numeric_job_id_fabricated':False})
            assert all(checks) and not reads;results.append('PASS')

            calls=[]
            def provider(method,path,headers,body):
                calls.append([method,path])
                if path=='/v1/oauth2/token':return {'access_token':TOKEN}
                return {'id':cfg.order_id,'status':'APPROVED','update_time':(now-timedelta(seconds=2)).isoformat(),
                    'purchase_units':[{'amount':{'value':cfg.amount,'currency_code':cfg.currency}}],'payer':{'text':SECRET}}
            store=Store(root/'orders.sqlite');store.register(cfg.order_id,cfg.amount,cfg.currency)
            report=run_owner_workflow109(cfg,a,store=store,journal=OnceJournal107(root/'once.sqlite'),launch=launch,
                fake_credential_reader=pair,fake_transport=provider,clock=lambda:now,monotonic=lambda:0,assistance=None)
            with store.connect() as db:effects=db.execute('SELECT count(*) FROM effects').fetchone()[0]
            safe=all(v not in json.dumps(report) for v in (CLIENT,SECRET,TOKEN))
            emit(3,{'orchestration':report,'fake_calls':calls,'exact_fake_credential_field_reads':reads,'secret_free':safe,
                'effects':effects,'model_retrained':False,'local_advisory':'EXISTING_NONFINANCIAL_ABSTENTION_NO_FIT','TTY_calls':0,'actual_provider':False})
            assert report['primary'] is None and report['cleanup']==[] and report['receipt']['state']=='APPROVED'
            assert report['receipt']['synthetic'] and not report['receipt']['actual_paypal'] and len(calls)==2 and len(reads)==2 and safe and effects==0
            assert all(report['lifecycle'].values()) and report['receipt']['local_assistance']['financial_authority'] is False
            assert report['receipt']['local_assistance']['priority']=='unknown' and report['receipt']['workflow109']['trust_origin']=='SYNTHETIC_WORKFLOW109'
            results.append('PASS')
    return results

if __name__=='__main__':
    primary=None;results=[]
    try:results=group()
    except Exception as exc:primary={'code':'INERT109_'+type(exc).__name__,'stage':'GROUP'}
    print(json.dumps({'record':'INERT109_TERMINAL','scenario_results':results,'primary':primary,'cleanup':[],
        'actual_credentials':False,'actual_provider':False,'old_groups_replayed':False,'model_retrained':False},sort_keys=True),flush=True)
    raise SystemExit(0 if primary is None and len(results)==3 else 1)
