"""One new four-scenario inert group. Public fake values, no real transport."""
from datetime import datetime,timezone,timedelta
import copy,hashlib,json,pathlib,sqlite3,tempfile
from unittest.mock import patch
from payproof.core import Store,InvalidData,UnknownResult
from tools.sandbox_delivery107 import (_FIXED111,source_digest111,fixture_key111,
    _synthetic_fixture111,OnceJournal107,run_fixture111,open_fixture111)
CLIENT='PUBLIC-FAKE111-CLIENT';SECRET='PUBLIC-FAKE111-SECRET';TOKEN='PUBLIC-FAKE111-TOKEN'

def inputs():
    now=datetime.now(timezone.utc);r=dict(_FIXED111,source_commit='1'*40,source_tree='2'*40,
        source_sha256=source_digest111(),workflow_sha256='3'*64,client_id_sha256=hashlib.sha256(CLIENT.encode()).hexdigest(),
        intent_version=1,consumed_version=2,intent_sha256='4'*64,consumed_sha256='5'*64,
        not_before=(now-timedelta(seconds=1)).isoformat(),expires_at=(now+timedelta(seconds=118)).isoformat(),
        call_budget=4,operator_allocation='PUBLIC_SYNTHETIC111',credential_provenance='PUBLIC_FAKE_PAIR111')
    r['stable_effect_key']=fixture_key111(r['client_id_sha256'])
    actual={k:r[k] for k in ('repository','repository_id','owner_id','actor_id','ref','event','attempt','job_slug','workflow_path','source_commit','source_tree','source_sha256','workflow_sha256')}
    actual.update(run_id='111',github_sha=r['source_commit'],workflow_ref='Elinfiny/PayProof/'+r['workflow_path']+'@refs/heads/main',workflow_source_sha=r['source_commit'])
    return now,r,actual

def refused(f):
    try:f()
    except (InvalidData,UnknownResult):return True
    return False

def case(n,root):
    now,r,actual=inputs();reads=[];calls=[]
    def pair():reads.append('PAIR_PUBLIC_FAKE');return CLIENT,SECRET
    if n==1:
        checks=[refused(lambda:_synthetic_fixture111(dict(r,source_sha256='0'*64),actual)),refused(lambda:_synthetic_fixture111(r,dict(actual,actor_id='999')))]
        assert all(checks) and not reads
        return {'bad_source_caller_refused':checks,'credential_lookups':0,'network_calls':0}
    launch=_synthetic_fixture111(r,actual)
    if n==2:
        checks=[]
        for state in ('CONSUMED','UNKNOWN'):
            journal=OnceJournal107(root/(state+'.sqlite'));journal.reserve(r['stable_effect_key'],{'fixture':'PUBLIC_TEST111'})
            with sqlite3.connect(journal.path) as db:db.execute('UPDATE operator_once107 SET state=?',(state,))
            checks.append(refused(lambda:open_fixture111(r,journal=journal,launch=launch,fake_credentials=pair)))
        assert all(checks) and not reads
        changed=dict(r,source_commit='6'*40,source_tree='7'*40)
        assert fixture_key111(changed['client_id_sha256'])==r['stable_effect_key']
        return {'consumed_unknown_refused':checks,'credential_lookups':0,'POST':0,'source_nonce_cannot_rearm_key':True}
    mono=[0.0]
    def provider(method,path,headers,body):
        calls.append([method,path])
        if path=='/v1/oauth2/token':return {'access_token':TOKEN}
        if method=='POST':
            assert json.loads(body)=={'intent':'CAPTURE','purchase_units':[{'amount':{'value':'1.00','currency_code':'USD'}}]}
            if n==4:mono[0]=121.0
            return {'id':'SYNTHETIC111','status':'CREATED','private_extra':SECRET}
        assert path=='/v2/checkout/orders/SYNTHETIC111'
        return {'id':'SYNTHETIC111','status':'CREATED','update_time':(now-timedelta(seconds=2)).isoformat(),
            'purchase_units':[{'amount':{'value':'1.00','currency_code':'USD'}}],'private_extra':SECRET}
    store=Store(root/'orders.sqlite');report=run_fixture111(r,store=store,journal=OnceJournal107(root/'once.sqlite'),
        launch=launch,fake_credentials=pair,fake_transport=provider,clock=lambda:now,monotonic=lambda:mono[0])
    assert all(v not in json.dumps(report) for v in (CLIENT,SECRET,TOKEN))
    if n==3:
        assert report['primary'] is None and report['receipt']['state']=='CREATED' and report['receipt']['amount']=='1.00' and report['receipt']['currency']=='USD'
        assert report['receipt']['lineage']['id']==report['receipt']['lineage']['read_id']=='SYNTHETIC111'
        assert report['receipt']['synthetic'] and not report['receipt']['actual_paypal'] and len(calls)==4
        assert sum(p=='/v2/checkout/orders' for _,p in calls)==1 and sum(m=='GET' for m,_ in calls)==1
        assert all(report['lifecycle'].values()) and not report['cleanup']
        return {'report':report,'fake_calls':calls,'financial_effects':0,'paid_asserted':False,'local_create_journal_records':1,'retry':0}
    assert report['primary']=={'code':'FIXTURE_RETURN_LATE_OR_SCOPE111','stage':'POST_RETURN'}
    assert report['receipt'] is None and len(calls)==2 and report['original_capture']['last_kind']=='CREATE'
    assert report['original_capture']['late_original_preserved_before_refusal'] and all(report['lifecycle'].values())
    return {'report':report,'fake_calls':calls,'GET':0,'retry':0,'first_unknown_preserved':True}

if __name__=='__main__':
    results=[]
    with tempfile.TemporaryDirectory(prefix='payproof-inert111-') as td:
        with patch('urllib.request.build_opener',side_effect=AssertionError('NO_REAL_HTTP111')),patch('os.environ',{}),patch('getpass.getpass',side_effect=AssertionError('NO_TTY111')),patch('payproof.local_ai.fit',side_effect=AssertionError('NO_MODEL_FIT111')):
            for n in range(1,5):
                root=pathlib.Path(td)/str(n);root.mkdir(mode=0o700)
                try:facts=case(n,root);status='PASS'
                except Exception as exc:facts={'first_error_type':type(exc).__name__};status='FAIL_NO_REPLAY'
                print(json.dumps({'record':'ORIGINAL_PUBLIC_SYNTHETIC111','scenario':n,'status':status,'facts':facts},sort_keys=True),flush=True);results.append(status)
    print(json.dumps({'record':'INERT111_TERMINAL','scenario_results':results,'actual_credentials':False,'actual_provider':False,'old_groups_replayed':False,'model_fit':0,'cleanup':[]},sort_keys=True),flush=True)
    raise SystemExit(0 if results==['PASS']*4 else 1)
