"""One NEW four-case synthetic diagnostic group; no real network or replay."""
from datetime import datetime,timezone,timedelta
import hashlib,json,pathlib,tempfile
from unittest.mock import patch
from payproof.core import Store
from tools.sandbox_delivery107 import (_FIXED111,source_digest111,fixture_key111,
    _synthetic_fixture111,OnceJournal107,run_fixture111,FixtureProducer111)
CLIENT='PUBLIC-FAKE114-CLIENT';SECRET='PUBLIC-FAKE114-SECRET';TOKEN='PUBLIC-FAKE114-TOKEN'
RAW='PRIVATE-RAW-PII114-SENTINEL';CLEANUP='PRIVATE-CLEANUP114-SENTINEL'

def inputs():
    now=datetime.now(timezone.utc);r=dict(_FIXED111,source_commit='1'*40,source_tree='2'*40,
        source_sha256=source_digest111(),workflow_sha256='3'*64,client_id_sha256=hashlib.sha256(CLIENT.encode()).hexdigest(),
        intent_version=1,consumed_version=2,intent_sha256='4'*64,consumed_sha256='5'*64,
        not_before=(now-timedelta(seconds=1)).isoformat(),expires_at=(now+timedelta(seconds=118)).isoformat(),
        call_budget=4,operator_allocation='PUBLIC_SYNTHETIC_DIAGNOSTIC114',credential_provenance='PUBLIC_FAKE_PAIR114')
    r['stable_effect_key']=fixture_key111(r['client_id_sha256'])
    a={k:r[k] for k in ('repository','repository_id','owner_id','actor_id','ref','event','attempt','job_slug','workflow_path','source_commit','source_tree','source_sha256','workflow_sha256')}
    a.update(run_id='114',github_sha=r['source_commit'],workflow_ref='Elinfiny/PayProof/'+r['workflow_path']+'@refs/heads/main',workflow_source_sha=r['source_commit'])
    return now,r,a

def case(n,root):
    now,r,a=inputs();launch=_synthetic_fixture111(r,a);calls=[];mono=[0.0];oid='INERT114'+str(n)
    def provider(method,path,headers,body):
        calls.append([method,path])
        if path=='/v1/oauth2/token':return {'access_token':TOKEN}
        if method=='POST':return {'id':oid,'status':'CREATED','private':RAW}
        assert path=='/v2/checkout/orders/'+oid
        result={'id':oid,'status':'COMPLETED' if n==2 else 'CREATED',
            'purchase_units':[{'amount':{'value':'2.00' if n==2 else '1.00','currency_code':'USD'}}],
            'payer':{'name':RAW},'private_token':TOKEN}
        if n not in (1,4):result['update_time']=(now-timedelta(seconds=2)).isoformat()
        if n==3:mono[0]=121.0
        return result
    close=FixtureProducer111.close
    def failing_close(reader):close(reader);raise RuntimeError(CLEANUP)
    args=dict(store=Store(root/'orders.sqlite'),journal=OnceJournal107(root/'once.sqlite'),launch=launch,
        fake_credentials=lambda:(CLIENT,SECRET),fake_transport=provider,clock=lambda:now,monotonic=lambda:mono[0])
    if n==4:
        with patch.object(FixtureProducer111,'close',failing_close):report=run_fixture111(r,**args)
    else:report=run_fixture111(r,**args)
    create=report['qualified_creation114'];diag=report['diagnostic114']
    assert create['id']==oid and create['status']=='CREATED' and create['amount']=='1.00' and create['currency']=='USD'
    assert create['intent']=='CAPTURE' and not create['payment_source_in_request'] and create['sandbox'] and not create['real_payment_executed']
    assert create['application_sha256']==r['client_id_sha256'] and create['stable_effect_key']==r['stable_effect_key'] and create['source_sha256']==r['source_sha256']
    assert report['receipt'] is None and len(calls)==report['calls']==4 and all(report['lifecycle'].values())
    assert all(s not in json.dumps(report) for s in (CLIENT,SECRET,TOKEN,RAW,CLEANUP))
    if n in (1,4):
        assert report['primary']=={'code':'FIXTURE_UNKNOWN111','stage':'FIXTURE_GET111'}
        assert diag['code']=='FRESHNESS_MISSING114' and diag['fields']['freshness']=={'present':False,'valid':False}
        assert report['cleanup']==(['FIXTURE_READER_CLOSE111'] if n==4 else [])
    elif n==2:
        assert report['primary']=={'code':'FIXTURE_UNKNOWN111','stage':'FIXTURE_GET111'} and diag['code']=='AMOUNT_CURRENCY_CONFLICT114'
        assert diag['fields']['amount_currency']['valid'] is False and not diag['projection_valid']
    else:
        assert report['primary']=={'code':'FIXTURE_RETURN_LATE_OR_SCOPE111','stage':'POST_RETURN'}
        assert diag['code']=='POST_RETURN_SCOPE_OR_DEADLINE114' and diag['fields'] is None
        assert report['original_capture']['late_original_preserved_before_refusal']
    return {'report':report,'fake_calls':calls,'durable_create_survives_cleanup':True,'paid_asserted':False,
        'real_provider':False,'new_API_after_failure':0,'secret_raw_cleanup_sentinel_exported':False}

if __name__=='__main__':
    results=[]
    with tempfile.TemporaryDirectory(prefix='payproof-inert114-') as td:
        with patch('urllib.request.build_opener',side_effect=AssertionError('NO_REAL_HTTP114')),patch('os.environ',{}),patch('getpass.getpass',side_effect=AssertionError('NO_TTY114')),patch('payproof.local_ai.fit',side_effect=AssertionError('NO_MODEL_FIT114')):
            for n in range(1,5):
                root=pathlib.Path(td)/str(n);root.mkdir(mode=0o700)
                try:facts=case(n,root);status='PASS'
                except Exception as exc:facts={'first_error_type':type(exc).__name__};status='FAIL_NO_REPLAY'
                print(json.dumps({'record':'ORIGINAL_PUBLIC_SYNTHETIC114','scenario':n,'status':status,'facts':facts},sort_keys=True),flush=True);results.append(status)
    print(json.dumps({'record':'INERT114_TERMINAL','scenario_results':results,'actual_credentials':False,'actual_provider':False,'historical_groups_replayed':False,'model_fit':0,'cleanup':[]},sort_keys=True),flush=True)
    raise SystemExit(0 if results==['PASS']*4 else 1)
